//! Per-source-layer scratch + index for random-access body extraction.
//!
//! Spec 02 §2.3 mandates two-pass access to input layers, but assembly's
//! [`emit_layer`](crate::assemble::emit::emit_layer) consumes regular
//! file bodies in path-lex order — not the entry-stream order the
//! `tar` crate iterator delivers. The naive shape (one `open()` +
//! forward-walk-to-`entry_idx` per body) is **quadratic** in the number
//! of regular files in the layer: a 10k-entry layer is walked 10k
//! times, paying the gzip/zstd decoder over and over.
//!
//! This module flips that into linear work. On first access to a
//! layer:
//!
//! 1. The (decompressed) tar bytes are streamed into a scratch file
//!    under `<scratch_root>/decompressed/<diff_id>.tar`. Compressed
//!    inputs decompress exactly once; uncompressed inputs are still
//!    copied so callers don't have to special-case the original blob's
//!    transport-specific addressing (docker-archive `take`-bounded
//!    handles, dir-transport blob paths, etc.).
//! 2. The scratch file is walked once to build a `Vec<EntryRecord>`
//!    indexed by `entry_idx`, capturing `(meta, body_offset, body_size)`
//!    via [`tar::Entry::raw_file_position`]. The walk drains each body
//!    to advance the iterator; no body bytes are retained in memory.
//!
//! Subsequent body reads then become a `seek + take` on the flat
//! scratch file — no tar parsing, no decompression. Total work per
//! emitted layer is O(decompress + index + sum of body sizes).
//!
//! ## Sharing across rayon workers
//!
//! [`emit_layers`](crate::assemble::emit::emit_layers) builds one
//! [`LayerCache`] per `(image_id, layer_idx)` referenced by any
//! candidate, *before* dispatching to the rayon pool, then hands a
//! shared `&HashMap` to every worker. A source layer feeding multiple
//! output candidates (the common case after dedup + dissolve) is
//! decompressed and indexed exactly once.
//!
//! ## Sparse files
//!
//! `tar::Entry::raw_file_position` is only meaningful for contiguous
//! bodies. GNU sparse entries would index to bogus offsets — but
//! container layers in practice never carry sparse files, and the
//! squash pass already streams them as if they were contiguous, so the
//! contract is consistent end-to-end. If a future input ever produces
//! sparse entries, this module will surface them as wrong body bytes;
//! that is a known boundary, called out here so the failure mode is
//! discoverable.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::input::model::LayerHandle;
use crate::tar_io::reader::{EntryMeta, Reader};
use crate::{Error, Result};

/// One entry's location and metadata within a decompressed scratch tar.
#[derive(Debug, Clone)]
struct EntryRecord {
    meta: EntryMeta,
    body_offset: u64,
    body_size: u64,
}

/// Decompressed-scratch + per-entry index for one source layer.
#[derive(Debug)]
pub struct LayerCache {
    /// Path to the decompressed tar on disk. Lives under the run's
    /// scratch root and is cleaned up with the rest of scratch (spec 07
    /// §7.6) — the cache itself owns no cleanup logic.
    scratch_path: PathBuf,
    /// One record per `entry_idx`, matching the `enumerate()` index the
    /// squash pass assigns in [`crate::squash::apply::apply_layer`].
    /// Includes PAX/meta entries verbatim so indices line up.
    index: Vec<EntryRecord>,
}

impl LayerCache {
    /// Materialise `handle` into a decompressed scratch file under
    /// `<scratch_dir>/decompressed/<diff_id>.tar` (creating the
    /// subdirectory lazily) and walk it once to build the per-entry
    /// index.
    ///
    /// The scratch path is content-addressed by the layer's `diff_id`,
    /// so re-running the build for the same layer in the same scratch
    /// is a no-op on the I/O side: an existing scratch file is reused
    /// verbatim and only the index walk repeats. (The walk is cheap
    /// next to the original decompression.)
    ///
    /// # Errors
    ///
    /// * [`Error::Io`] for filesystem failures creating the scratch
    ///   directory, copying the layer body, or reading the index.
    /// * Whatever [`LayerHandle::open`] surfaces for opener / decoder
    ///   failures (missing blob, bad magic bytes).
    /// * Tar-stream malformations from the index walk surface as
    ///   [`Error::MalformedInput`] via the [`Reader`] adapter.
    pub fn build(handle: &LayerHandle, scratch_dir: &Path) -> Result<Self> {
        let dir = scratch_dir.join("decompressed");
        fs::create_dir_all(&dir)?;
        let scratch_path = dir.join(format!("{}.tar", handle.diff_id.digest()));

        if !scratch_path.exists() {
            // Stage to a sibling `.partial` so a crash mid-decompress
            // never leaves a half-decompressed file under the
            // content-addressed name. Rename is atomic within the
            // directory on POSIX, mirroring the publish dance in
            // [`crate::assemble::emit::emit_layer`].
            let tmp = scratch_path.with_extension("tar.partial");
            {
                let mut src = handle.open()?;
                let mut dst = File::create(&tmp)?;
                io::copy(&mut src, &mut dst)?;
                dst.sync_all()?;
            }
            fs::rename(&tmp, &scratch_path)?;
        }

        let index = build_index(&scratch_path)?;
        Ok(Self { scratch_path, index })
    }

    /// Number of indexed entries (matches the squash pass's
    /// `entry_idx` range).
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// `true` when the layer carried no entries at all (an empty tar).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Invoke `f` with the entry's metadata and a `Read` positioned at
    /// the start of its body, bounded to `meta.size` bytes. The closure
    /// shape matches [`crate::tar_io::reopen::with_entry_body`] so call
    /// sites can swap one for the other.
    ///
    /// # Errors
    ///
    /// * [`Error::MalformedInput`] if `entry_idx` is out of range for
    ///   this cache — the index was computed against a different
    ///   stream (or the squash pass produced a stale record).
    /// * [`Error::Io`] for any filesystem failure reopening or seeking
    ///   the scratch file.
    /// * Whatever `f` returns, propagated unchanged.
    pub fn read_body<F, T>(&self, entry_idx: usize, f: F) -> Result<T>
    where
        F: FnOnce(&EntryMeta, &mut dyn Read) -> Result<T>,
    {
        let record = self.index.get(entry_idx).ok_or_else(|| {
            Error::MalformedInput(format!(
                "entry index {entry_idx} out of range (have {} entries)",
                self.index.len()
            ))
        })?;
        let mut file = File::open(&self.scratch_path)?;
        file.seek(SeekFrom::Start(record.body_offset))?;
        let mut bounded = file.take(record.body_size);
        f(&record.meta, &mut bounded)
    }
}

/// Walk `path` once with the existing [`Reader`] and capture each
/// entry's `(meta, body_offset, body_size)`. The body is drained to a
/// sink so the iterator can advance to the next entry; no body bytes
/// are retained.
fn build_index(path: &Path) -> Result<Vec<EntryRecord>> {
    let file = File::open(path)?;
    let mut reader = Reader::new(file);
    let mut entries = reader.entries()?;
    let mut out = Vec::new();
    while let Some(entry) = entries.next() {
        let mut entry = entry?;
        let body_offset = entry.raw_file_position();
        let meta = entry.meta().clone();
        let body_size = meta.size;
        io::copy(&mut entry, &mut io::sink())?;
        out.push(EntryRecord {
            meta,
            body_offset,
            body_size,
        });
    }
    Ok(out)
}

/// Build [`LayerCache`]s for every `(image_id, layer_idx)` pair in
/// `needed`, returning a map keyed on that pair so the assembly workers
/// can look caches up directly.
///
/// `needed` is taken as a `BTreeSet` so the materialisation order is
/// deterministic across runs — any failure mid-build surfaces against
/// the same layer every time.
///
/// # Errors
///
/// * [`Error::Validation`] if a `(image_id, layer_idx)` pair is out of
///   range for `images_layers`.
/// * Anything [`LayerCache::build`] surfaces for the underlying layer.
pub fn build_for_layers(
    needed: &BTreeSet<(usize, usize)>,
    images_layers: &[Vec<LayerHandle>],
    scratch_dir: &Path,
) -> Result<BTreeMap<(usize, usize), Arc<LayerCache>>> {
    let mut map = BTreeMap::new();
    for &(image_id, layer_idx) in needed {
        let handle = images_layers
            .get(image_id)
            .and_then(|v| v.get(layer_idx))
            .ok_or_else(|| {
                Error::Validation(format!(
                    "image_id {image_id} / layer_idx {layer_idx} out of range while building layer cache",
                ))
            })?;
        let cache = LayerCache::build(handle, scratch_dir)?;
        map.insert((image_id, layer_idx), Arc::new(cache));
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::io::{Cursor, Write as _};
    use std::str::FromStr;
    use std::sync::Arc;

    use flate2::Compression as GzCompression;
    use flate2::write::GzEncoder;
    use oci_spec::image::Digest;
    use tar::{Builder, EntryType, Header};
    use tempfile::TempDir;

    use super::*;
    use crate::tar_io::reader::EntryKind;

    fn build_tarball(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut tb = Builder::new(&mut buf);
            tb.mode(tar::HeaderMode::Deterministic);
            for (path, body) in entries {
                let mut h = Header::new_gnu();
                h.set_entry_type(EntryType::Regular);
                h.set_path(path).unwrap();
                h.set_mode(0o644);
                h.set_uid(0);
                h.set_gid(0);
                h.set_size(body.len() as u64);
                h.set_cksum();
                tb.append(&h, *body).unwrap();
            }
            tb.finish().unwrap();
        }
        buf
    }

    fn sha256_digest(hex: &str) -> Digest {
        Digest::from_str(&format!("sha256:{hex}")).unwrap()
    }

    fn handle_for_uncompressed(bytes: Vec<u8>, diff_id_hex: &str) -> LayerHandle {
        let bytes = Arc::new(bytes);
        let bytes_for_open = bytes.clone();
        LayerHandle::new(
            sha256_digest(&"a".repeat(64)),
            sha256_digest(diff_id_hex),
            bytes.len() as u64,
            "application/vnd.oci.image.layer.v1.tar".into(),
            move || {
                let cursor = Cursor::new((*bytes_for_open).clone());
                Ok(Box::new(cursor) as Box<dyn Read + Send + 'static>)
            },
        )
        .unwrap()
    }

    fn handle_for_gzipped(uncompressed: Vec<u8>, diff_id_hex: &str) -> LayerHandle {
        let mut gz = GzEncoder::new(Vec::new(), GzCompression::fast());
        gz.write_all(&uncompressed).unwrap();
        let compressed = gz.finish().unwrap();
        let arc = Arc::new(compressed);
        let arc_for_open = arc.clone();
        LayerHandle::new(
            sha256_digest(&"b".repeat(64)),
            sha256_digest(diff_id_hex),
            arc.len() as u64,
            "application/vnd.oci.image.layer.v1.tar+gzip".into(),
            move || {
                let cursor = Cursor::new((*arc_for_open).clone());
                Ok(Box::new(cursor) as Box<dyn Read + Send + 'static>)
            },
        )
        .unwrap()
    }

    fn read_body_to_vec(cache: &LayerCache, entry_idx: usize) -> Vec<u8> {
        cache
            .read_body(entry_idx, |_, body| {
                let mut out = Vec::new();
                body.read_to_end(&mut out)?;
                Ok(out)
            })
            .unwrap()
    }

    #[test]
    fn build_indexes_every_entry_in_iteration_order() {
        let scratch = TempDir::new().unwrap();
        let tar = build_tarball(&[("a", b"alpha"), ("b", b"bravo"), ("c", b"charlie")]);
        let handle = handle_for_uncompressed(tar, &"1".repeat(64));
        let cache = LayerCache::build(&handle, scratch.path()).unwrap();

        assert_eq!(cache.len(), 3);
        assert_eq!(read_body_to_vec(&cache, 0), b"alpha");
        assert_eq!(read_body_to_vec(&cache, 1), b"bravo");
        assert_eq!(read_body_to_vec(&cache, 2), b"charlie");
    }

    #[test]
    fn read_body_is_independent_of_call_order() {
        // The whole point of the index is constant-cost random access
        // — calling out-of-order or repeating an index must yield the
        // same bytes every time.
        let scratch = TempDir::new().unwrap();
        let tar = build_tarball(&[("a", b"alpha"), ("b", b"bravo"), ("c", b"charlie")]);
        let handle = handle_for_uncompressed(tar, &"2".repeat(64));
        let cache = LayerCache::build(&handle, scratch.path()).unwrap();

        assert_eq!(read_body_to_vec(&cache, 2), b"charlie");
        assert_eq!(read_body_to_vec(&cache, 0), b"alpha");
        assert_eq!(read_body_to_vec(&cache, 0), b"alpha");
        assert_eq!(read_body_to_vec(&cache, 1), b"bravo");
    }

    #[test]
    fn read_body_meta_matches_header() {
        let scratch = TempDir::new().unwrap();
        let tar = build_tarball(&[("etc/hostname", b"hello\n")]);
        let handle = handle_for_uncompressed(tar, &"3".repeat(64));
        let cache = LayerCache::build(&handle, scratch.path()).unwrap();

        cache
            .read_body(0, |meta, _| {
                assert_eq!(meta.path.to_str().unwrap(), "etc/hostname");
                assert_eq!(meta.kind, EntryKind::Regular);
                assert_eq!(meta.size, 6);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn out_of_range_entry_idx_is_malformed_input() {
        let scratch = TempDir::new().unwrap();
        let tar = build_tarball(&[("a", b"x")]);
        let handle = handle_for_uncompressed(tar, &"4".repeat(64));
        let cache = LayerCache::build(&handle, scratch.path()).unwrap();

        let err = cache.read_body(99, |_, _| Ok(())).unwrap_err();
        match err {
            Error::MalformedInput(msg) => assert!(msg.contains("entry index 99"), "got: {msg}"),
            other => panic!("expected MalformedInput, got {other:?}"),
        }
    }

    #[test]
    fn gzipped_layer_decompresses_to_scratch_once() {
        // Decompressed scratch is content-addressed by diff_id, so a
        // second build call against the same handle reuses the file
        // on disk without re-running the decoder.
        let scratch = TempDir::new().unwrap();
        let tar = build_tarball(&[("a", b"alpha"), ("b", b"bravo")]);
        let diff_id_hex = "5".repeat(64);
        let handle = handle_for_gzipped(tar, &diff_id_hex);

        let cache_a = LayerCache::build(&handle, scratch.path()).unwrap();
        assert_eq!(read_body_to_vec(&cache_a, 0), b"alpha");
        assert_eq!(read_body_to_vec(&cache_a, 1), b"bravo");

        let scratch_path = scratch.path().join("decompressed").join(format!("{diff_id_hex}.tar"));
        assert!(scratch_path.is_file(), "scratch file should exist after build");
        let mtime_before = fs::metadata(&scratch_path).unwrap().modified().unwrap();

        // Second build call: same scratch dir, same handle → file
        // already present, no rewrite.
        let cache_b = LayerCache::build(&handle, scratch.path()).unwrap();
        let mtime_after = fs::metadata(&scratch_path).unwrap().modified().unwrap();
        assert_eq!(mtime_before, mtime_after, "scratch file must not be rewritten on second build");
        assert_eq!(read_body_to_vec(&cache_b, 0), b"alpha");
    }

    #[test]
    fn empty_tar_yields_empty_index() {
        let scratch = TempDir::new().unwrap();
        // Two zero blocks = canonical empty tar trailer.
        let tar = vec![0u8; 1024];
        let handle = handle_for_uncompressed(tar, &"6".repeat(64));
        let cache = LayerCache::build(&handle, scratch.path()).unwrap();

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn build_for_layers_materialises_each_referenced_pair() {
        let scratch = TempDir::new().unwrap();
        let tar0 = build_tarball(&[("a", b"alpha")]);
        let tar1 = build_tarball(&[("b", b"bravo"), ("c", b"charlie")]);
        let h0 = handle_for_uncompressed(tar0, &"7".repeat(64));
        let h1 = handle_for_uncompressed(tar1, &"8".repeat(64));
        let images_layers = vec![vec![h0, h1]];

        let needed: BTreeSet<(usize, usize)> = [(0usize, 0usize), (0, 1)].into_iter().collect();
        let map = build_for_layers(&needed, &images_layers, scratch.path()).unwrap();

        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&(0, 0)).unwrap().len(), 1);
        assert_eq!(map.get(&(0, 1)).unwrap().len(), 2);
    }

    #[test]
    fn build_for_layers_validation_error_on_out_of_range() {
        let scratch = TempDir::new().unwrap();
        let images_layers: Vec<Vec<LayerHandle>> = Vec::new();
        let needed: BTreeSet<(usize, usize)> = [(5usize, 0usize)].into_iter().collect();
        let err = build_for_layers(&needed, &images_layers, scratch.path()).unwrap_err();
        match err {
            Error::Validation(msg) => assert!(msg.contains("image_id 5"), "got: {msg}"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn index_enumeration_matches_reader_iterator() {
        // The cache's `entry_idx` must line up with the squash pass's
        // `Reader::entries().enumerate()` index. Build a tar with a
        // mix of kinds (the tar crate may or may not emit long-name
        // PAX records as separate iterator items depending on header
        // length; we don't depend on that — only on parity with what
        // the iterator yields).
        let scratch = TempDir::new().unwrap();
        let tar = build_tarball(&[("a", b"alpha"), ("b", b"bravo"), ("c", b"charlie")]);
        let handle = handle_for_uncompressed(tar.clone(), &"9".repeat(64));
        let cache = LayerCache::build(&handle, scratch.path()).unwrap();

        // Re-walk the same bytes via the public Reader and confirm
        // each enumerate-position resolves to the same path.
        let mut reader = Reader::new(Cursor::new(tar));
        let mut entries = reader.entries().unwrap();
        let mut i = 0usize;
        while let Some(entry) = entries.next() {
            let entry = entry.unwrap();
            cache
                .read_body(i, |meta, _| {
                    assert_eq!(meta.path, entry.meta().path, "mismatch at index {i}");
                    Ok(())
                })
                .unwrap();
            i += 1;
        }
        assert_eq!(i, cache.len());
    }
}
