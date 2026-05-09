//! Tar entry emission (spec 07 §7.4).
//!
//! [`emit_layer`] is the single-pass digest-and-write entry point: given
//! one [`CandidateLayer`] from the dedup partition, it streams every
//! entry into a fresh PAX tar blob on disk, computing the SHA-256 of the
//! tar bytes en route. No intermediate file ever exists; body bytes for
//! regular files are re-opened straight from the originating input layer
//! (spec 02 §2.3) and piped through the writer in one shot.
//!
//! ## Writer pipeline
//!
//! ```text
//! tar_io::Writer ─► HashingWriter (SHA-256) ─► BufWriter ─► File
//! ```
//!
//! The hashing happens on the path between the tar writer and the file,
//! so the final digest is exactly the SHA-256 of the bytes that landed
//! on disk — which, for an uncompressed layer, is also the layer's
//! `diff_id` (spec 07 §7.2 / §7.3).
//!
//! ## Atomic publish (spec 07 §7.6)
//!
//! The blob is first written to `<scratch>/blobs/sha256/.tmp-<pid>-<n>`,
//! `fsync`'d, then renamed onto `<scratch>/blobs/sha256/<digest-hex>`.
//! A run that aborts mid-assembly leaves no entries in the digest
//! namespace — only a stale `.tmp-*` file the caller may sweep.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::dedup::membership::ImageSet;
use crate::dedup::partition::CandidateLayer;
use crate::input::model::LayerHandle;
use crate::squash::index::SquashedEntry;
use crate::tar_io::layer_cache::{LayerCache, build_for_layers};
use crate::tar_io::reader::{EntryKind, EntryMeta};
use crate::tar_io::writer::Writer;
use crate::timestamp::T0;
use crate::{Error, Result};

use super::digest::{HashingWriter, hex_encode};

/// One emitted output blob — the per-layer accounting record spec 07
/// §7.7 / spec 10 §10.6 want surfaced in the run summary.
#[derive(Debug, Clone)]
pub struct EmittedLayer {
    /// Membership the layer was assembled for (spec 05 §5.4 partition
    /// key). Carried through verbatim for the summary's `vs-naive`
    /// column.
    pub membership: ImageSet,
    /// SHA-256 of the tar bytes that landed on disk. For uncompressed
    /// layers this is also the `diff_id` (spec 07 §7.3).
    pub digest: [u8; 32],
    /// Bytes the writer pipeline produced. Equals the on-disk size of
    /// the final blob.
    pub size: u64,
    /// Final on-disk path (`<scratch>/blobs/sha256/<digest-hex>`).
    pub path: PathBuf,
}

impl EmittedLayer {
    /// Lower-case hex form of the SHA-256 digest, without the `sha256:`
    /// prefix. This is the on-disk filename and the form spec 09's
    /// `blobs/sha256/<hex>` layout uses.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        hex_encode(&self.digest)
    }
}

/// Process-wide counter for temp-file names. Combined with the pid, it
/// makes the temp path unique per emit call without needing a randomness
/// source.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Assemble one candidate layer into a tar blob on disk.
///
/// The layer's entries are emitted in the lex path order the
/// [`CandidateLayer::entries`] [`BTreeMap`] yields — exactly the order
/// spec 05 §5.5 prescribes and spec 11 §11.6 reproducibility relies on.
///
/// `images_layers` is a slice indexed by [`InputImageId::0`](crate::squash::index::InputImageId),
/// matching `lib::run`'s argv-order convention. Each per-image inner
/// slice holds that image's layers in bottom-up manifest order, so
/// `images_layers[entry.image_id.0][entry.layer_idx]` resolves the
/// originating layer's [`LayerHandle`] for body-copy.
///
/// `t0` is the run-wide invocation timestamp captured by spec 06 §6.1;
/// it lands as every entry's tar `mtime`. Negative values (pre-1970
/// sentinels per spec 06 §6.6) are clamped to 0 because tar's `mtime`
/// field is unsigned — the `created` field on the image config still
/// carries the original value verbatim via [`T0::to_rfc3339`].
///
/// `scratch_root` is the directory the run's `blobs/sha256/` tree is
/// rooted at. It is created lazily; callers do not need to pre-create it.
///
/// # Errors
///
/// * [`Error::Io`] on any filesystem failure (create, write, fsync,
///   rename).
/// * [`Error::Validation`] if the layer references an `image_id` /
///   `layer_idx` not present in `images_layers`, or if a re-opened
///   regular-file body's size disagrees with the squash record (the
///   underlying input layer changed under the run, or squash's
///   bookkeeping is corrupt).
/// * Whatever the underlying [`Writer`] / [`with_entry_body`] surface
///   for tar-stream malformations.
pub fn emit_layer(
    layer: &CandidateLayer,
    images_layers: &[Vec<LayerHandle>],
    t0: T0,
    scratch_root: &Path,
) -> Result<EmittedLayer> {
    // Single-layer entry point: build a per-call cache for just this
    // layer's needs. The shared `emit_layers` path builds one cache
    // covering every output layer's needs and reuses it across rayon
    // workers — that's where the source-once decompress wins matter.
    let cache_map = build_for_layers(&needed_sources(std::iter::once(layer)), images_layers, scratch_root)?;
    emit_layer_with_cache(layer, &cache_map, t0, scratch_root)
}

fn emit_layer_with_cache(
    layer: &CandidateLayer,
    cache_map: &BTreeMap<(usize, usize), Arc<LayerCache>>,
    t0: T0,
    scratch_root: &Path,
) -> Result<EmittedLayer> {
    let blobs_dir = scratch_root.join("blobs").join("sha256");
    fs::create_dir_all(&blobs_dir)?;

    let tmp_path = blobs_dir.join(temp_name());
    let mtime = u64::try_from(t0.as_unix_seconds()).unwrap_or(0);

    // Stream entries through the writer pipeline. The inner block scopes
    // the tar writer so it is dropped (its trailer flushed) before we
    // reach for the hasher.
    //
    // Two-pass iteration over `layer.entries` (which is BTreeMap-ordered
    // by path): non-hardlinks first, hardlinks second. Tar extractors
    // resolve `LNKTYPE` entries by calling `link(2)` at extraction time,
    // which requires the target path to already exist on disk in this
    // layer's diff. Emitting regular files (and the rest) before the
    // hardlinks that name them satisfies that ordering even when a
    // hardlink lex-precedes its target. `dedup::colocate` already
    // ensured every per-image layer hardlink's target lives in the
    // same layer and rewrote chains to point at the terminal regular,
    // so a single ordered pass over hardlinks suffices here.
    let (digest, size, file) = {
        let file = File::create(&tmp_path)?;
        let buffered = BufWriter::new(file);
        let mut hashing = HashingWriter::new(buffered);
        {
            let mut writer = Writer::new(&mut hashing);
            for (path, entry) in &layer.entries {
                if entry.kind != EntryKind::Hardlink {
                    emit_entry(&mut writer, cache_map, path, entry, mtime)?;
                }
            }
            for (path, entry) in &layer.entries {
                if entry.kind == EntryKind::Hardlink {
                    emit_entry(&mut writer, cache_map, path, entry, mtime)?;
                }
            }
            writer.finish()?;
        }
        hashing.flush()?;
        let (mut buffered, digest, size) = hashing.finalize();
        buffered.flush()?;
        let file = buffered
            .into_inner()
            .map_err(|e| Error::Io(io::Error::other(format!("BufWriter flush failed: {e}"))))?;
        (digest, size, file)
    };
    file.sync_all()?;
    drop(file);

    let final_path = blobs_dir.join(hex_encode(&digest));
    // Rename is atomic within a directory on POSIX; if the final path
    // already exists (a previous identical run, perhaps), the new temp
    // simply overwrites it — content is by-construction identical.
    fs::rename(&tmp_path, &final_path).map_err(|e| {
        // Best-effort cleanup of the temp on rename failure; ignore the
        // unlink error itself so we surface the original cause.
        let _ = fs::remove_file(&tmp_path);
        Error::Io(io::Error::new(
            e.kind(),
            format!("rename {} -> {} failed: {e}", tmp_path.display(), final_path.display()),
        ))
    })?;
    sync_dir_best_effort(&blobs_dir);

    Ok(EmittedLayer {
        membership: layer.membership.clone(),
        digest,
        size,
        path: final_path,
    })
}

/// Assemble every candidate layer into tar blobs on disk, with bounded
/// parallelism (spec 07 §7.5).
///
/// Layers are dispatched to a private [`rayon::ThreadPool`] sized to
/// `jobs`. Each task calls [`emit_layer`] independently — no readers are
/// shared across threads (every task opens its own [`LayerHandle`] streams
/// via the cloned `Arc`-backed opener closure on [`LayerHandle`]).
///
/// `jobs == 0` requests the rayon default (logical CPU count), matching
/// spec 10 `--jobs` semantics. Higher values are passed through verbatim.
///
/// Returned [`EmittedLayer`]s are in the lex `ImageSet` order of the
/// input map's iteration — the same order spec 11 §11.6 relies on.
/// Concurrency does not change output bytes: each layer's tar entries
/// come from its own `BTreeMap` (lex path order) and the per-blob digest
/// is path-content invariant, so every successful run for a given
/// `(layers, images_layers, t0)` triple produces byte-identical blobs.
///
/// # Errors
///
/// * Anything [`emit_layer`] surfaces. The first error wins; remaining
///   already-running tasks finish (their successful output blobs are
///   left on disk under their own digest names — spec 07 §7.6 only
///   forbids partial / temp files in the digest namespace, and rename is
///   the last step so a successful task produces a fully-formed blob).
/// * [`Error::Io`] wrapping a [`rayon::ThreadPoolBuildError`] if the
///   thread pool cannot be created (an OS resource exhaustion, in
///   practice — spec 10 §10.7 maps it onto exit code 1 like any other
///   I/O error).
pub fn emit_layers(
    layers: &BTreeMap<ImageSet, CandidateLayer>,
    images_layers: &[Vec<LayerHandle>],
    t0: T0,
    scratch_root: &Path,
    jobs: usize,
) -> Result<Vec<EmittedLayer>> {
    if layers.is_empty() {
        return Ok(Vec::new());
    }
    // Pre-pass: decompress + index every source layer referenced by any
    // candidate exactly once, *before* the rayon workers fan out. The
    // cache is `Arc`-shared across workers, so a source feeding several
    // output candidates pays the decompress cost once total — not once
    // per output. This is the change that turns emit's body-fetch from
    // O(N²) per layer into O(N).
    let cache_map = build_for_layers(&needed_sources(layers.values()), images_layers, scratch_root)?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build()
        .map_err(|e| Error::Io(io::Error::other(format!("rayon thread pool build failed: {e}"))))?;
    let layer_vec: Vec<&CandidateLayer> = layers.values().collect();
    pool.install(|| {
        layer_vec
            .par_iter()
            .map(|l| emit_layer_with_cache(l, &cache_map, t0, scratch_root))
            .collect::<Result<Vec<_>>>()
    })
}

#[inline(never)]
fn emit_entry<W: Write>(
    writer: &mut Writer<W>,
    cache_map: &BTreeMap<(usize, usize), Arc<LayerCache>>,
    path: &Path,
    entry: &SquashedEntry,
    mtime: u64,
) -> Result<()> {
    let meta = entry_meta_for(path, entry, mtime);
    if matches!(entry.kind, EntryKind::Regular) && entry.size > 0 {
        let key = (entry.image_id.0, entry.layer_idx);
        let cache = cache_map.get(&key).ok_or_else(|| {
            Error::Validation(format!(
                "no LayerCache for image_id {} / layer_idx {} (cache pre-pass missed this pair)",
                key.0, key.1,
            ))
        })?;
        let declared = entry.size;
        cache.read_body(entry.entry_idx, |body_meta, body| {
            if body_meta.size != declared {
                return Err(Error::Validation(format!(
                    "body size for {} disagrees with squash record: expected {declared}, found {}",
                    path.display(),
                    body_meta.size,
                )));
            }
            writer.append(&meta, &mut *body)
        })
    } else {
        writer.append(&meta, io::empty())
    }
}

/// Collect every `(image_id, layer_idx)` pair that any candidate layer
/// in the iterator references for a regular-file body. Used by both
/// [`emit_layer`] and [`emit_layers`] to drive the cache pre-pass.
fn needed_sources<'a, I>(layers: I) -> BTreeSet<(usize, usize)>
where
    I: IntoIterator<Item = &'a CandidateLayer>,
{
    let mut needed = BTreeSet::new();
    for layer in layers {
        for entry in layer.entries.values() {
            if matches!(entry.kind, EntryKind::Regular) && entry.size > 0 {
                needed.insert((entry.image_id.0, entry.layer_idx));
            }
        }
    }
    needed
}

fn entry_meta_for(path: &Path, entry: &SquashedEntry, mtime: u64) -> EntryMeta {
    EntryMeta {
        path: path.to_path_buf(),
        kind: entry.kind,
        size: entry.size,
        mode: entry.mode,
        uid: entry.uid,
        gid: entry.gid,
        mtime,
        // Numeric-only ownership per spec 02 §2.4 — uname/gname are
        // forced empty by the writer regardless, but spelling it out
        // here matches the spec 03 §3.5 / spec 04 §4.2 contract.
        uname: None,
        gname: None,
        link_target: entry.link_target.clone(),
        rdev: entry.rdev,
        xattrs: entry.xattrs.clone(),
    }
}

fn temp_name() -> String {
    let n = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    format!(".tmp-{}-{}", std::process::id(), n)
}

/// `fsync` a directory entry on Unix-like systems so the rename of the
/// blob inside it survives a crash. On platforms where opening a
/// directory for writing is not supported, this is a no-op — the rename
/// is still atomic, only the durability guarantee weakens.
fn sync_dir_best_effort(dir: &Path) {
    if let Ok(f) = File::open(dir) {
        // Errors here are non-fatal: the rename has already landed in
        // the kernel's view of the directory, and downstream readers
        // will see the new entry. Durability across a sudden crash is
        // the only guarantee we'd lose.
        let _ = f.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{Cursor, Read};
    use std::str::FromStr;
    use std::sync::Arc;

    use oci_spec::image::Digest;
    use sha2::{Digest as ShaDigest, Sha256};
    use tar::{Builder, EntryType, Header};

    use super::*;
    use crate::squash::index::{InputImageId, SquashedEntry};
    use crate::tar_io::reader::{EntryKind, Reader};

    fn build_input_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
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

    fn fixture_layer(bytes: Vec<u8>) -> LayerHandle {
        let arc = Arc::new(bytes);
        let arc_for_open = arc.clone();
        LayerHandle::new(
            Digest::from_str(&format!("sha256:{}", "a".repeat(64))).unwrap(),
            Digest::from_str(&format!("sha256:{}", "b".repeat(64))).unwrap(),
            arc.len() as u64,
            "application/vnd.oci.image.layer.v1.tar".into(),
            move || {
                let cursor = Cursor::new((*arc_for_open).clone());
                Ok(Box::new(cursor) as Box<dyn Read + Send + 'static>)
            },
        )
        .unwrap()
    }

    fn entry(image_id: usize, layer_idx: usize, entry_idx: usize, kind: EntryKind, size: u64) -> SquashedEntry {
        SquashedEntry {
            image_id: InputImageId(image_id),
            layer_idx,
            entry_idx,
            kind,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size,
            content_hash: None,
            xattrs: BTreeMap::new(),
            link_target: None,
            rdev: None,
        }
    }

    fn singleton_membership(id: usize) -> ImageSet {
        ImageSet::singleton(InputImageId(id))
    }

    fn read_back(bytes: &[u8]) -> Vec<(EntryMeta, Vec<u8>)> {
        let mut reader = Reader::new(Cursor::new(bytes.to_vec()));
        let mut out = Vec::new();
        let mut entries = reader.entries().unwrap();
        for e in entries.by_ref() {
            let mut e = e.unwrap();
            let mut body = Vec::new();
            std::io::Read::read_to_end(&mut e, &mut body).unwrap();
            out.push((e.meta().clone(), body));
        }
        out
    }

    #[test]
    fn empty_layer_emits_just_trailer() {
        let scratch = tempfile::tempdir().unwrap();
        let layer = CandidateLayer {
            membership: singleton_membership(0),
            entries: BTreeMap::new(),
        };
        let emitted = emit_layer(&layer, &[vec![]], T0::from_unix_seconds(0), scratch.path()).unwrap();

        assert_eq!(emitted.size, 1024, "trailer is two zero blocks");
        let bytes = fs::read(&emitted.path).unwrap();
        assert_eq!(bytes.len(), 1024);
        assert!(bytes.iter().all(|&b| b == 0));

        let mut h = Sha256::new();
        h.update(&bytes);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(emitted.digest, expected);
        assert_eq!(
            emitted.path.file_name().unwrap().to_str().unwrap(),
            hex_encode(&expected)
        );
    }

    #[test]
    fn single_regular_file_round_trips() {
        let scratch = tempfile::tempdir().unwrap();
        let body = b"hello world\n";
        let input_tar = build_input_tar(&[("etc/hostname", body)]);
        let handle = fixture_layer(input_tar);

        let mut entries = BTreeMap::new();
        entries.insert(
            PathBuf::from("etc/hostname"),
            entry(0, 0, 0, EntryKind::Regular, body.len() as u64),
        );
        let layer = CandidateLayer {
            membership: singleton_membership(0),
            entries,
        };

        let emitted = emit_layer(&layer, &[vec![handle]], T0::from_unix_seconds(0), scratch.path()).unwrap();

        let bytes = fs::read(&emitted.path).unwrap();
        let read = read_back(&bytes);
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].0.path, PathBuf::from("etc/hostname"));
        assert_eq!(read[0].0.kind, EntryKind::Regular);
        assert_eq!(read[0].0.size, body.len() as u64);
        assert_eq!(read[0].1, body);
    }

    #[test]
    fn digest_matches_on_disk_bytes() {
        let scratch = tempfile::tempdir().unwrap();
        let input_tar = build_input_tar(&[("a", b"alpha"), ("b", b"bravo")]);
        let handle = fixture_layer(input_tar);

        let mut entries = BTreeMap::new();
        entries.insert(PathBuf::from("a"), entry(0, 0, 0, EntryKind::Regular, 5));
        entries.insert(PathBuf::from("b"), entry(0, 0, 1, EntryKind::Regular, 5));
        let layer = CandidateLayer {
            membership: singleton_membership(0),
            entries,
        };

        let emitted = emit_layer(&layer, &[vec![handle]], T0::from_unix_seconds(123), scratch.path()).unwrap();

        let bytes = fs::read(&emitted.path).unwrap();
        let mut h = Sha256::new();
        h.update(&bytes);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(emitted.digest, expected);
        assert_eq!(emitted.size, bytes.len() as u64);
    }

    #[test]
    fn lex_path_order_inside_layer_is_preserved() {
        let scratch = tempfile::tempdir().unwrap();
        let input_tar = build_input_tar(&[("z", b"z"), ("a", b"a"), ("m", b"m")]);
        let handle = fixture_layer(input_tar);

        // Insert into the layer in non-sorted order to confirm the
        // BTreeMap-driven iteration sorts on emission.
        let mut entries = BTreeMap::new();
        entries.insert(PathBuf::from("z"), entry(0, 0, 0, EntryKind::Regular, 1));
        entries.insert(PathBuf::from("a"), entry(0, 0, 1, EntryKind::Regular, 1));
        entries.insert(PathBuf::from("m"), entry(0, 0, 2, EntryKind::Regular, 1));
        let layer = CandidateLayer {
            membership: singleton_membership(0),
            entries,
        };

        let emitted = emit_layer(&layer, &[vec![handle]], T0::from_unix_seconds(0), scratch.path()).unwrap();
        let bytes = fs::read(&emitted.path).unwrap();
        let read = read_back(&bytes);
        let paths: Vec<_> = read.iter().map(|(m, _)| m.path.to_str().unwrap().to_string()).collect();
        assert_eq!(paths, vec!["a", "m", "z"]);
    }

    #[test]
    fn directory_and_symlink_emit_with_no_body_lookup() {
        // Directories and symlinks have no body bytes, so the layer
        // assembler must not try to re-open the input tar for them.
        // We exercise this by passing an *empty* layers list — any
        // re-open attempt would surface as an Error::Validation.
        let scratch = tempfile::tempdir().unwrap();

        let mut dir_e = entry(0, 0, 0, EntryKind::Directory, 0);
        dir_e.mode = 0o755;
        let mut link_e = entry(0, 0, 1, EntryKind::Symlink, 0);
        link_e.link_target = Some(PathBuf::from("etc/hostname"));

        let mut entries = BTreeMap::new();
        entries.insert(PathBuf::from("etc"), dir_e);
        entries.insert(PathBuf::from("etc/hostname.link"), link_e);
        let layer = CandidateLayer {
            membership: singleton_membership(0),
            entries,
        };

        // No layers passed at all — body lookup never happens.
        let emitted = emit_layer(&layer, &[vec![]], T0::from_unix_seconds(0), scratch.path()).unwrap();
        let read = read_back(&fs::read(&emitted.path).unwrap());
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].0.kind, EntryKind::Directory);
        assert_eq!(read[1].0.kind, EntryKind::Symlink);
        assert_eq!(read[1].0.link_target.as_deref(), Some(Path::new("etc/hostname")));
    }

    #[test]
    fn hardlink_emits_with_link_target_no_body() {
        // Hardlinks land in the per-image layer per spec 05 §5.6 with
        // size=0 and a link_target — the writer encodes them as
        // LNKTYPE. No body re-open is needed.
        let scratch = tempfile::tempdir().unwrap();
        let mut hl = entry(0, 0, 0, EntryKind::Hardlink, 0);
        hl.link_target = Some(PathBuf::from("etc/hostname"));
        let mut entries = BTreeMap::new();
        entries.insert(PathBuf::from("etc/hostname.alias"), hl);
        let layer = CandidateLayer {
            membership: singleton_membership(0),
            entries,
        };

        let emitted = emit_layer(&layer, &[vec![]], T0::from_unix_seconds(0), scratch.path()).unwrap();
        let read = read_back(&fs::read(&emitted.path).unwrap());
        assert_eq!(read[0].0.kind, EntryKind::Hardlink);
        assert_eq!(read[0].0.link_target.as_deref(), Some(Path::new("etc/hostname")));
    }

    #[test]
    fn t0_lands_as_mtime_on_every_entry() {
        let scratch = tempfile::tempdir().unwrap();
        let input_tar = build_input_tar(&[("a", b"x")]);
        let handle = fixture_layer(input_tar);

        let mut entries = BTreeMap::new();
        entries.insert(PathBuf::from("a"), entry(0, 0, 0, EntryKind::Regular, 1));
        let layer = CandidateLayer {
            membership: singleton_membership(0),
            entries,
        };

        let t0 = T0::from_unix_seconds(1_700_000_000);
        let emitted = emit_layer(&layer, &[vec![handle]], t0, scratch.path()).unwrap();
        let read = read_back(&fs::read(&emitted.path).unwrap());
        assert_eq!(read[0].0.mtime, 1_700_000_000);
    }

    #[test]
    fn negative_t0_clamps_to_zero_for_tar_mtime() {
        // tar mtime is unsigned. Spec 06 §6.6 keeps the *original*
        // T0 in the OCI `created` field, but tar can't represent
        // negative seconds — clamp to 0.
        let scratch = tempfile::tempdir().unwrap();
        let input_tar = build_input_tar(&[("a", b"x")]);
        let handle = fixture_layer(input_tar);

        let mut entries = BTreeMap::new();
        entries.insert(PathBuf::from("a"), entry(0, 0, 0, EntryKind::Regular, 1));
        let layer = CandidateLayer {
            membership: singleton_membership(0),
            entries,
        };

        let emitted = emit_layer(&layer, &[vec![handle]], T0::from_unix_seconds(-99), scratch.path()).unwrap();
        let read = read_back(&fs::read(&emitted.path).unwrap());
        assert_eq!(read[0].0.mtime, 0);
    }

    #[test]
    fn xattrs_propagate_into_output() {
        let scratch = tempfile::tempdir().unwrap();
        let input_tar = build_input_tar(&[("a", b"x")]);
        let handle = fixture_layer(input_tar);

        let mut e = entry(0, 0, 0, EntryKind::Regular, 1);
        e.xattrs.insert(b"user.flag".to_vec(), b"on".to_vec());
        e.xattrs.insert(b"security.capability".to_vec(), vec![1, 2, 3]);

        let mut entries = BTreeMap::new();
        entries.insert(PathBuf::from("a"), e);
        let layer = CandidateLayer {
            membership: singleton_membership(0),
            entries,
        };

        let emitted = emit_layer(&layer, &[vec![handle]], T0::from_unix_seconds(0), scratch.path()).unwrap();
        let read = read_back(&fs::read(&emitted.path).unwrap());
        let xattrs = &read[0].0.xattrs;
        assert_eq!(xattrs.len(), 2);
        assert_eq!(xattrs.get(&b"user.flag"[..].to_vec()).unwrap(), b"on");
        assert_eq!(
            xattrs.get(&b"security.capability"[..].to_vec()).unwrap(),
            &vec![1u8, 2, 3]
        );
    }

    #[test]
    fn body_re_opens_at_correct_entry_idx() {
        // The candidate layer references entry_idx 1 inside an input
        // tar that has three files. The assembler must seek through
        // the first entry to land on the second one.
        let scratch = tempfile::tempdir().unwrap();
        let input_tar = build_input_tar(&[("a.txt", b"alpha"), ("b.txt", b"bravo"), ("c.txt", b"charlie")]);
        let handle = fixture_layer(input_tar);

        let mut entries = BTreeMap::new();
        entries.insert(PathBuf::from("b.txt"), entry(0, 0, 1, EntryKind::Regular, 5));
        let layer = CandidateLayer {
            membership: singleton_membership(0),
            entries,
        };

        let emitted = emit_layer(&layer, &[vec![handle]], T0::from_unix_seconds(0), scratch.path()).unwrap();
        let read = read_back(&fs::read(&emitted.path).unwrap());
        assert_eq!(read[0].1, b"bravo");
    }

    #[test]
    fn missing_image_id_is_validation_error() {
        let scratch = tempfile::tempdir().unwrap();
        let mut entries = BTreeMap::new();
        // image_id 5, but only one image-slot in the lookup table.
        entries.insert(PathBuf::from("a"), entry(5, 0, 0, EntryKind::Regular, 1));
        let layer = CandidateLayer {
            membership: ImageSet::singleton(InputImageId(5)),
            entries,
        };
        let err = emit_layer(&layer, &[vec![]], T0::from_unix_seconds(0), scratch.path()).unwrap_err();
        match err {
            Error::Validation(msg) => assert!(msg.contains("image_id 5"), "got: {msg}"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn missing_layer_idx_is_validation_error() {
        let scratch = tempfile::tempdir().unwrap();
        let input_tar = build_input_tar(&[("a", b"x")]);
        let handle = fixture_layer(input_tar);
        let mut entries = BTreeMap::new();
        // layer_idx 3, but the image has only one layer.
        entries.insert(PathBuf::from("a"), entry(0, 3, 0, EntryKind::Regular, 1));
        let layer = CandidateLayer {
            membership: singleton_membership(0),
            entries,
        };
        let err = emit_layer(&layer, &[vec![handle]], T0::from_unix_seconds(0), scratch.path()).unwrap_err();
        match err {
            Error::Validation(msg) => assert!(msg.contains("layer_idx 3"), "got: {msg}"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn body_size_mismatch_is_validation_error() {
        let scratch = tempfile::tempdir().unwrap();
        let input_tar = build_input_tar(&[("a", b"actually-eight")]);
        let handle = fixture_layer(input_tar);
        let mut entries = BTreeMap::new();
        // Squash recorded size=3 for an entry whose actual body is
        // longer — surface as Validation rather than corrupting the
        // output blob.
        entries.insert(PathBuf::from("a"), entry(0, 0, 0, EntryKind::Regular, 3));
        let layer = CandidateLayer {
            membership: singleton_membership(0),
            entries,
        };
        let err = emit_layer(&layer, &[vec![handle]], T0::from_unix_seconds(0), scratch.path()).unwrap_err();
        match err {
            Error::Validation(msg) => assert!(msg.contains("body size"), "got: {msg}"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn output_filename_is_lowercase_sha256_hex() {
        let scratch = tempfile::tempdir().unwrap();
        let layer = CandidateLayer {
            membership: singleton_membership(0),
            entries: BTreeMap::new(),
        };
        let emitted = emit_layer(&layer, &[vec![]], T0::from_unix_seconds(0), scratch.path()).unwrap();
        let name = emitted.path.file_name().unwrap().to_str().unwrap();
        assert_eq!(name.len(), 64);
        assert!(name.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(name, emitted.digest_hex());
    }

    #[test]
    fn blobs_dir_is_created_under_scratch() {
        let scratch = tempfile::tempdir().unwrap();
        // Pass a fresh scratch path that does not yet contain
        // blobs/sha256 — emit must create it lazily.
        let nested = scratch.path().join("nested");
        let layer = CandidateLayer {
            membership: singleton_membership(0),
            entries: BTreeMap::new(),
        };
        let emitted = emit_layer(&layer, &[vec![]], T0::from_unix_seconds(0), &nested).unwrap();
        assert!(emitted.path.starts_with(nested.join("blobs").join("sha256")));
        assert!(nested.join("blobs").join("sha256").is_dir());
    }

    #[test]
    fn determinism_two_runs_produce_identical_blobs() {
        // Spec 11 §11.6: byte-identical output for the same input + T0.
        let scratch_a = tempfile::tempdir().unwrap();
        let scratch_b = tempfile::tempdir().unwrap();
        let input_tar = build_input_tar(&[("a", b"alpha"), ("b", b"bravo")]);
        let h_a = fixture_layer(input_tar.clone());
        let h_b = fixture_layer(input_tar);

        let make_layer = || {
            let mut entries = BTreeMap::new();
            entries.insert(PathBuf::from("a"), entry(0, 0, 0, EntryKind::Regular, 5));
            entries.insert(PathBuf::from("b"), entry(0, 0, 1, EntryKind::Regular, 5));
            CandidateLayer {
                membership: singleton_membership(0),
                entries,
            }
        };

        let t0 = T0::from_unix_seconds(42);
        let a = emit_layer(&make_layer(), &[vec![h_a]], t0, scratch_a.path()).unwrap();
        let b = emit_layer(&make_layer(), &[vec![h_b]], t0, scratch_b.path()).unwrap();
        assert_eq!(a.digest, b.digest);
        assert_eq!(a.size, b.size);
        let bytes_a = fs::read(&a.path).unwrap();
        let bytes_b = fs::read(&b.path).unwrap();
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn temp_file_is_removed_after_successful_emit() {
        // The temp pattern is `.tmp-<pid>-<n>`. After emit_layer
        // returns Ok, no `.tmp-*` files should remain.
        let scratch = tempfile::tempdir().unwrap();
        let layer = CandidateLayer {
            membership: singleton_membership(0),
            entries: BTreeMap::new(),
        };
        emit_layer(&layer, &[vec![]], T0::from_unix_seconds(0), scratch.path()).unwrap();
        let blobs_dir = scratch.path().join("blobs").join("sha256");
        let stragglers: Vec<_> = fs::read_dir(&blobs_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with(".tmp-"))
            .collect();
        assert!(stragglers.is_empty(), "leftover temp files: {stragglers:?}");
    }

    #[test]
    fn membership_is_carried_through() {
        let scratch = tempfile::tempdir().unwrap();
        let m = ImageSet::from_ids([InputImageId(0), InputImageId(2)]);
        let layer = CandidateLayer {
            membership: m.clone(),
            entries: BTreeMap::new(),
        };
        let emitted = emit_layer(&layer, &[vec![]], T0::from_unix_seconds(0), scratch.path()).unwrap();
        assert_eq!(emitted.membership, m);
    }

    #[test]
    fn temp_name_unique_per_call() {
        let a = temp_name();
        let b = temp_name();
        assert_ne!(a, b);
        assert!(a.starts_with(".tmp-"));
        assert!(b.starts_with(".tmp-"));
    }

    fn make_layer(membership: ImageSet, paths: &[(&str, &[u8], usize)]) -> CandidateLayer {
        let mut entries = BTreeMap::new();
        for (path, body, idx) in paths {
            entries.insert(
                PathBuf::from(*path),
                entry(0, 0, *idx, EntryKind::Regular, body.len() as u64),
            );
        }
        CandidateLayer { membership, entries }
    }

    #[test]
    fn emit_layers_empty_input_returns_empty_vec() {
        let scratch = tempfile::tempdir().unwrap();
        let layers: BTreeMap<ImageSet, CandidateLayer> = BTreeMap::new();
        let out = emit_layers(&layers, &[], T0::from_unix_seconds(0), scratch.path(), 0).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn emit_layers_returns_results_in_btreemap_order() {
        // Insertion order in the BTreeMap is fixed by ImageSet's lex
        // ordering. The returned Vec must mirror that order regardless
        // of how rayon scheduled the workers.
        let scratch = tempfile::tempdir().unwrap();
        let input_tar = build_input_tar(&[("a", b"alpha"), ("b", b"bravo"), ("c", b"charlie")]);
        let h = fixture_layer(input_tar);

        let mut layers = BTreeMap::new();
        // ImageSet's Ord is lex over the sorted-Vec backing. {0} < {0,1} < {1}.
        layers.insert(
            ImageSet::singleton(InputImageId(0)),
            make_layer(ImageSet::singleton(InputImageId(0)), &[("a", b"alpha", 0)]),
        );
        layers.insert(
            ImageSet::from_ids([InputImageId(0), InputImageId(1)]),
            make_layer(
                ImageSet::from_ids([InputImageId(0), InputImageId(1)]),
                &[("b", b"bravo", 1)],
            ),
        );
        layers.insert(
            ImageSet::singleton(InputImageId(1)),
            make_layer(ImageSet::singleton(InputImageId(1)), &[("c", b"charlie", 2)]),
        );

        let out = emit_layers(
            &layers,
            &[vec![h.clone()], vec![h]],
            T0::from_unix_seconds(0),
            scratch.path(),
            2,
        )
        .unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].membership, ImageSet::singleton(InputImageId(0)));
        assert_eq!(
            out[1].membership,
            ImageSet::from_ids([InputImageId(0), InputImageId(1)])
        );
        assert_eq!(out[2].membership, ImageSet::singleton(InputImageId(1)));
    }

    #[test]
    fn emit_layers_parallel_matches_serial_byte_for_byte() {
        // Spec 07 §7.5: concurrency must not change output bytes. Run
        // the same layer set serially (jobs=1) and in parallel (jobs=4)
        // and assert every blob's digest and size match.
        let scratch_serial = tempfile::tempdir().unwrap();
        let scratch_parallel = tempfile::tempdir().unwrap();
        let input_tar = build_input_tar(&[
            ("a", b"alpha"),
            ("b", b"bravo"),
            ("c", b"charlie"),
            ("d", b"delta"),
            ("e", b"echo"),
        ]);
        let make_handle = || fixture_layer(input_tar.clone());

        let make_layers = || {
            let mut layers = BTreeMap::new();
            for (i, (path, body)) in [
                ("a", &b"alpha"[..]),
                ("b", &b"bravo"[..]),
                ("c", &b"charlie"[..]),
                ("d", &b"delta"[..]),
                ("e", &b"echo"[..]),
            ]
            .iter()
            .enumerate()
            {
                let m = ImageSet::singleton(InputImageId(i));
                layers.insert(m.clone(), make_layer(m, &[(path, body, i)]));
            }
            layers
        };

        let images_serial: Vec<Vec<LayerHandle>> = (0..5).map(|_| vec![make_handle()]).collect();
        let images_parallel: Vec<Vec<LayerHandle>> = (0..5).map(|_| vec![make_handle()]).collect();

        let serial = emit_layers(
            &make_layers(),
            &images_serial,
            T0::from_unix_seconds(7),
            scratch_serial.path(),
            1,
        )
        .unwrap();
        let parallel = emit_layers(
            &make_layers(),
            &images_parallel,
            T0::from_unix_seconds(7),
            scratch_parallel.path(),
            4,
        )
        .unwrap();

        assert_eq!(serial.len(), parallel.len());
        for (s, p) in serial.iter().zip(parallel.iter()) {
            assert_eq!(s.membership, p.membership);
            assert_eq!(s.digest, p.digest);
            assert_eq!(s.size, p.size);
            let bytes_s = fs::read(&s.path).unwrap();
            let bytes_p = fs::read(&p.path).unwrap();
            assert_eq!(bytes_s, bytes_p);
        }
    }

    #[test]
    fn emit_layers_jobs_zero_falls_back_to_default() {
        // jobs=0 routes to rayon's default thread count. Just confirm
        // the call succeeds and produces the expected blobs.
        let scratch = tempfile::tempdir().unwrap();
        let input_tar = build_input_tar(&[("a", b"alpha")]);
        let h = fixture_layer(input_tar);
        let mut layers = BTreeMap::new();
        layers.insert(
            ImageSet::singleton(InputImageId(0)),
            make_layer(ImageSet::singleton(InputImageId(0)), &[("a", b"alpha", 0)]),
        );
        let out = emit_layers(&layers, &[vec![h]], T0::from_unix_seconds(0), scratch.path(), 0).unwrap();
        assert_eq!(out.len(), 1);
        assert!(out[0].path.is_file());
    }

    #[test]
    fn emit_layers_propagates_first_error() {
        // One layer references an out-of-range image_id; emit_layers
        // must surface a Validation error rather than silently dropping
        // the offending layer.
        let scratch = tempfile::tempdir().unwrap();
        let input_tar = build_input_tar(&[("a", b"x")]);
        let h = fixture_layer(input_tar);

        let mut layers = BTreeMap::new();
        layers.insert(
            ImageSet::singleton(InputImageId(0)),
            make_layer(ImageSet::singleton(InputImageId(0)), &[("a", b"x", 0)]),
        );
        // image_id 9 doesn't exist in images_layers — Validation error.
        let mut bad_entries = BTreeMap::new();
        bad_entries.insert(PathBuf::from("a"), entry(9, 0, 0, EntryKind::Regular, 1));
        layers.insert(
            ImageSet::singleton(InputImageId(9)),
            CandidateLayer {
                membership: ImageSet::singleton(InputImageId(9)),
                entries: bad_entries,
            },
        );

        let err = emit_layers(&layers, &[vec![h]], T0::from_unix_seconds(0), scratch.path(), 2).unwrap_err();
        match err {
            Error::Validation(_) => {}
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn emit_layers_no_temp_files_remain_after_success() {
        let scratch = tempfile::tempdir().unwrap();
        let input_tar = build_input_tar(&[("a", b"alpha"), ("b", b"bravo")]);
        let mut layers = BTreeMap::new();
        for (i, (path, body)) in [("a", &b"alpha"[..]), ("b", &b"bravo"[..])].iter().enumerate() {
            let m = ImageSet::singleton(InputImageId(i));
            layers.insert(m.clone(), make_layer(m, &[(path, body, i)]));
        }
        let images: Vec<Vec<LayerHandle>> = (0..2).map(|_| vec![fixture_layer(input_tar.clone())]).collect();
        emit_layers(&layers, &images, T0::from_unix_seconds(0), scratch.path(), 4).unwrap();

        let blobs_dir = scratch.path().join("blobs").join("sha256");
        let stragglers: Vec<_> = fs::read_dir(&blobs_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with(".tmp-"))
            .collect();
        assert!(stragglers.is_empty(), "leftover temp files: {stragglers:?}");
    }
}
