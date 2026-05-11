//! Whiteout / opaque-dir layer application (spec 03 §3.2).
//!
//! Walks an input image's layer stack bottom-up and folds each tar
//! entry into a [`SquashedFs`] index. The three on-disk dialects from
//! spec 03 §3.2 are decoded into the index primitives that
//! [`crate::squash::index`] already exposes:
//!
//! * `dir/.wh.<name>` whiteout → [`SquashedFs::remove_subtree`] on
//!   `dir/<name>` (drops the path and any descendants if it was a
//!   directory). The marker itself is not stored.
//! * `dir/.wh..wh..opq` opaque-directory marker →
//!   [`SquashedFs::clear_subtree`] on `dir` (hides every existing
//!   child while preserving `dir`'s own metadata). The marker itself
//!   is not stored.
//! * Anything else → [`SquashedFs::insert`].
//!
//! Hardlinks are stored as-is with [`EntryKind::Hardlink`]; spec 03
//! §3.3's "demote to regular file when the target is whited out" pass
//! runs in [`crate::squash::hardlink`] *after* the apply pass has
//! settled the index.
//!
//! Regular-file bodies are SHA-256 hashed in-place as they stream past
//! — never spooled to disk — and the digest is stored on the resulting
//! [`SquashedEntry::content_hash`] (spec 03 §3.4 / spec 04 §4.4).
//! Non-regular entries have a zero-length body, so no hashing happens
//! there. Draining is mandatory in either case because the underlying
//! `tar::Entries` iterator advances by skipping over unread bodies,
//! and we want failures (truncated layer, premature EOF) to surface
//! here, not several stages later.

use std::ffi::OsStr;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::Result;
use crate::input::LayerHandle;
use crate::squash::index::{InputImageId, SquashedEntry, SquashedFs};
use crate::tar_io::reader::{EntryKind, Reader};

/// Whiteout filename prefix per OCI image-spec / aufs convention.
const WHITEOUT_PREFIX: &[u8] = b".wh.";
/// Opaque-directory marker filename. Note this also starts with
/// `.wh.` — the explicit-marker check must run *before* the generic
/// whiteout-prefix check.
const OPAQUE_MARKER: &[u8] = b".wh..wh..opq";

/// Apply an image's layer stack into a fresh [`SquashedFs`] index.
///
/// Layers are processed bottom-up in the order given by the image
/// manifest (spec 03 §3.2). The returned index reflects the
/// container-visible filesystem just before the spec 03 §3.3 hardlink
/// resolution pass runs.
///
/// # Errors
///
/// * [`crate::Error::Io`] for any read failure on a layer's tar
///   stream (truncated blob, decoder error, etc.).
/// * [`crate::Error::MalformedInput`] from the underlying compression
///   layer (magic-byte cross-check) or tar parser.
pub fn apply_image(image_id: InputImageId, layers: &[LayerHandle]) -> Result<SquashedFs> {
    let mut fs = SquashedFs::new();
    for (layer_idx, layer) in layers.iter().enumerate() {
        apply_layer(&mut fs, image_id, layer_idx, layer)?;
    }
    Ok(fs)
}

/// Fold a single layer into `fs` in place.
///
/// Exposed at module scope (rather than inlined into [`apply_image`])
/// so future callers — e.g. an incremental squasher that re-applies a
/// single rewritten layer — can reuse the per-layer logic without
/// constructing a synthetic [`LayerHandle`] vector.
///
/// # Errors
///
/// * [`crate::Error::Io`] for any read failure on the layer's tar
///   stream (truncated blob, decoder error, etc.).
/// * [`crate::Error::MalformedInput`] from the underlying compression
///   layer (magic-byte cross-check) or tar parser.
pub fn apply_layer(fs: &mut SquashedFs, image_id: InputImageId, layer_idx: usize, layer: &LayerHandle) -> Result<()> {
    let raw = layer.open()?;
    let mut reader = Reader::new(raw);
    let entries = reader.entries()?;
    for (entry_idx, entry) in entries.enumerate() {
        let mut entry = entry?;
        let meta = entry.meta().clone();

        // Drain the body before the next iteration borrows the
        // underlying reader. For regular files we feed it through a
        // SHA-256 hasher as we go (spec 03 §3.4 — single streaming
        // pass, no spool to disk). Non-regular kinds carry zero-length
        // bodies so the copy is a no-op.
        let content_hash = if meta.kind.has_body() {
            let mut hasher = HashSink(Sha256::new());
            io::copy(&mut entry, &mut hasher)?;
            Some(hasher.0.finalize().into())
        } else {
            None
        };
        drop(entry);

        // PAX/GNU meta records (e.g. `pax_global_header`) are not
        // filesystem entries. The tar crate already folds per-entry
        // PAX extensions into the next entry's metadata, so anything
        // surfacing as `Meta` here is safe to skip outright.
        if matches!(meta.kind, EntryKind::Meta) {
            continue;
        }

        let path = normalise_path(&meta.path);
        if path.as_os_str().is_empty() {
            // A bare `./` or `/` directory entry has no addressable
            // location in the index. Dropping it matches what
            // overlayfs does with the implicit root.
            continue;
        }

        if let Some(action) = whiteout_action(&path) {
            match action {
                Whiteout::Opaque { dir } => {
                    fs.clear_subtree(&dir);
                }
                Whiteout::Remove { victim } => {
                    fs.remove_subtree(&victim);
                }
            }
            continue;
        }

        // Hardlink targets reference another entry in the same archive,
        // so they must live in the same normalised namespace as the
        // paths we key on — otherwise a tar that writes `./usr/bin/perl`
        // for the link target but `usr/bin/perl` for the file itself
        // will fail to resolve in [`crate::squash::hardlink`]. Symlink
        // targets are left raw: they're runtime path lookups that may
        // be relative (`../foo`) and have no business being normalised
        // against our index keys.
        let link_target = match (meta.kind, meta.link_target) {
            (EntryKind::Hardlink, Some(t)) => Some(normalise_path(&t)),
            (_, t) => t,
        };

        fs.insert(
            path,
            SquashedEntry {
                image_id,
                layer_idx,
                entry_idx,
                kind: meta.kind,
                mode: meta.mode,
                uid: meta.uid,
                gid: meta.gid,
                size: meta.size,
                content_hash,
                xattrs: meta.xattrs,
                link_target,
                rdev: meta.rdev,
            },
        );
    }
    Ok(())
}

/// `io::Write` adapter over [`Sha256`] so [`io::copy`] can pump the
/// body through the hasher without an intermediate buffer. The `Write`
/// impl on `Sha256` exists in newer `sha2` releases but we adapt
/// explicitly to keep behaviour pinned: `write_all` always succeeds
/// (the hasher cannot short-write) and `flush` is a no-op.
struct HashSink(Sha256);

impl Write for HashSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Outcome of decoding a tar entry's path as a whiteout marker.
#[derive(Debug)]
enum Whiteout {
    /// `dir/.wh..wh..opq`: hide every strict descendant of `dir`.
    Opaque { dir: PathBuf },
    /// `dir/.wh.<name>`: drop `dir/<name>` and any descendants.
    Remove { victim: PathBuf },
}

fn whiteout_action(path: &Path) -> Option<Whiteout> {
    let file_name = path.file_name()?;
    let name = file_name.as_bytes();

    if name == OPAQUE_MARKER {
        let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
        return Some(Whiteout::Opaque { dir });
    }

    let victim_name = name.strip_prefix(WHITEOUT_PREFIX)?;
    if victim_name.is_empty() {
        // A bare `.wh.` with no suffix has no target — treat it as
        // not-a-marker rather than silently dropping the whole parent.
        return None;
    }
    let mut victim = path.parent().map(Path::to_path_buf).unwrap_or_default();
    victim.push(OsStr::from_bytes(victim_name));
    Some(Whiteout::Remove { victim })
}

/// Normalise a tar entry path to the form the index keys on.
///
/// Strips a leading `./` or `/`, then collapses any trailing `/`.
/// Without this, `./etc/.wh.foo` and `etc/foo` would key on different
/// paths and the whiteout would no-op.
fn normalise_path(path: &Path) -> PathBuf {
    let mut bytes = path.as_os_str().as_bytes();
    if let Some(rest) = bytes.strip_prefix(b"./") {
        bytes = rest;
    } else if let Some(rest) = bytes.strip_prefix(b"/") {
        bytes = rest;
    }
    while bytes.last() == Some(&b'/') {
        bytes = &bytes[..bytes.len() - 1];
    }
    PathBuf::from(OsStr::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{Cursor, Read};
    use std::sync::Arc;

    use oci_spec::image::Digest;
    use std::str::FromStr;
    use tar::{Builder, EntryType, Header};

    use super::*;

    fn sha256_digest(hex: &str) -> Digest {
        Digest::from_str(&format!("sha256:{hex}")).unwrap()
    }

    /// Build a layer handle that reopens a fresh `Cursor` over a
    /// pre-built uncompressed tarball each call.
    fn handle_for(bytes: Vec<u8>) -> LayerHandle {
        let bytes = Arc::new(bytes);
        let opener_bytes = Arc::clone(&bytes);
        LayerHandle::new(
            sha256_digest(&"a".repeat(64)),
            sha256_digest(&"b".repeat(64)),
            bytes.len() as u64,
            "application/vnd.oci.image.layer.v1.tar".into(),
            move || Ok(Box::new(Cursor::new((*opener_bytes).clone())) as Box<dyn Read + Send + 'static>),
        )
        .unwrap()
    }

    /// Assemble a tar with a sequence of synthetic entries described
    /// by `(path, kind, body, link_target)` tuples.
    fn build_tar(entries: &[TarEntry]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut tb = Builder::new(&mut buf);
            tb.mode(tar::HeaderMode::Deterministic);
            for e in entries {
                let mut h = Header::new_gnu();
                h.set_entry_type(e.entry_type);
                h.set_path(e.path).unwrap();
                if let Some(target) = e.link_target {
                    h.set_link_name(target).unwrap();
                }
                h.set_mode(e.mode);
                h.set_uid(0);
                h.set_gid(0);
                h.set_size(e.body.len() as u64);
                h.set_cksum();
                tb.append(&h, e.body).unwrap();
            }
            tb.finish().unwrap();
        }
        buf
    }

    struct TarEntry<'a> {
        path: &'a str,
        entry_type: EntryType,
        mode: u32,
        body: &'a [u8],
        link_target: Option<&'a str>,
    }

    fn file<'a>(path: &'a str, body: &'a [u8]) -> TarEntry<'a> {
        TarEntry {
            path,
            entry_type: EntryType::Regular,
            mode: 0o644,
            body,
            link_target: None,
        }
    }

    fn dir(path: &str) -> TarEntry<'_> {
        TarEntry {
            path,
            entry_type: EntryType::Directory,
            mode: 0o755,
            body: &[],
            link_target: None,
        }
    }

    fn whiteout(path: &str) -> TarEntry<'_> {
        // Whiteouts are encoded in tar as zero-byte regular files —
        // the marker is *purely* in the filename.
        TarEntry {
            path,
            entry_type: EntryType::Regular,
            mode: 0o000,
            body: &[],
            link_target: None,
        }
    }

    fn symlink<'a>(path: &'a str, target: &'a str) -> TarEntry<'a> {
        TarEntry {
            path,
            entry_type: EntryType::Symlink,
            mode: 0o777,
            body: &[],
            link_target: Some(target),
        }
    }

    fn hardlink<'a>(path: &'a str, target: &'a str) -> TarEntry<'a> {
        TarEntry {
            path,
            entry_type: EntryType::Link,
            mode: 0o644,
            body: &[],
            link_target: Some(target),
        }
    }

    #[test]
    fn empty_layer_stack_yields_empty_index() {
        let fs = apply_image(InputImageId(0), &[]).unwrap();
        assert!(fs.is_empty());
    }

    #[test]
    fn single_layer_inserts_each_entry() {
        let bytes = build_tar(&[
            dir("etc/"),
            file("etc/hostname", b"node-a\n"),
            file("etc/hosts", b"127.0.0.1 localhost\n"),
        ]);
        let fs = apply_image(InputImageId(7), &[handle_for(bytes)]).unwrap();
        assert_eq!(fs.len(), 3);

        let etc = fs.get(Path::new("etc")).expect("dir entry");
        assert_eq!(etc.kind, EntryKind::Directory);
        assert_eq!(etc.image_id, InputImageId(7));
        assert_eq!(etc.layer_idx, 0);
        assert_eq!(etc.entry_idx, 0);

        let hostname = fs.get(Path::new("etc/hostname")).expect("file entry");
        assert_eq!(hostname.kind, EntryKind::Regular);
        assert_eq!(hostname.size, b"node-a\n".len() as u64);
        assert_eq!(hostname.entry_idx, 1);
    }

    #[test]
    fn upper_layer_overwrites_lower_layer_metadata() {
        let lower = build_tar(&[file("etc/hostname", b"original\n")]);
        let upper = build_tar(&[file("etc/hostname", b"replaced-content\n")]);
        let fs = apply_image(InputImageId(0), &[handle_for(lower), handle_for(upper)]).unwrap();

        let entry = fs.get(Path::new("etc/hostname")).unwrap();
        // The upper layer wins on layer_idx + size.
        assert_eq!(entry.layer_idx, 1);
        assert_eq!(entry.size, b"replaced-content\n".len() as u64);
    }

    #[test]
    fn whiteout_drops_target_and_marker_is_not_stored() {
        let lower = build_tar(&[dir("etc/"), file("etc/hostname", b"x"), file("etc/hosts", b"y")]);
        let upper = build_tar(&[whiteout("etc/.wh.hostname")]);
        let fs = apply_image(InputImageId(0), &[handle_for(lower), handle_for(upper)]).unwrap();

        assert!(!fs.contains(Path::new("etc/hostname")));
        assert!(fs.contains(Path::new("etc/hosts")), "sibling untouched");
        // The whiteout marker itself must never appear in the index.
        assert!(!fs.contains(Path::new("etc/.wh.hostname")));
    }

    #[test]
    fn whiteout_on_directory_drops_subtree() {
        let lower = build_tar(&[
            dir("var/"),
            dir("var/log/"),
            file("var/log/syslog", b"line1\n"),
            file("var/log/messages", b"line2\n"),
            file("var/run.pid", b"42"),
        ]);
        let upper = build_tar(&[whiteout("var/.wh.log")]);
        let fs = apply_image(InputImageId(0), &[handle_for(lower), handle_for(upper)]).unwrap();

        assert!(fs.contains(Path::new("var")));
        assert!(!fs.contains(Path::new("var/log")));
        assert!(!fs.contains(Path::new("var/log/syslog")));
        assert!(!fs.contains(Path::new("var/log/messages")));
        // Sibling outside the whited-out subtree survives.
        assert!(fs.contains(Path::new("var/run.pid")));
    }

    #[test]
    fn whiteout_for_missing_path_is_silently_dropped() {
        // Spec 03 §3.2: "a whiteout for a path that does not exist in
        // the current squashed view is silently dropped (it is a
        // no-op, not an error)".
        let lower = build_tar(&[file("etc/hosts", b"y")]);
        let upper = build_tar(&[whiteout("etc/.wh.never_existed")]);
        let fs = apply_image(InputImageId(0), &[handle_for(lower), handle_for(upper)]).unwrap();
        assert_eq!(fs.len(), 1);
        assert!(fs.contains(Path::new("etc/hosts")));
    }

    #[test]
    fn whiteout_at_root_drops_top_level_entry() {
        let lower = build_tar(&[file("toplevel", b"data"), file("other", b"keep")]);
        let upper = build_tar(&[whiteout(".wh.toplevel")]);
        let fs = apply_image(InputImageId(0), &[handle_for(lower), handle_for(upper)]).unwrap();
        assert!(!fs.contains(Path::new("toplevel")));
        assert!(fs.contains(Path::new("other")));
    }

    #[test]
    fn opaque_dir_clears_descendants_but_keeps_directory() {
        let lower = build_tar(&[
            dir("var/"),
            dir("var/cache/"),
            file("var/cache/a", b"a"),
            file("var/cache/b", b"b"),
            file("etc/hosts", b"y"),
        ]);
        let upper = build_tar(&[whiteout("var/cache/.wh..wh..opq")]);
        let fs = apply_image(InputImageId(0), &[handle_for(lower), handle_for(upper)]).unwrap();

        assert!(fs.contains(Path::new("var/cache")), "opaque dir itself stays");
        assert!(!fs.contains(Path::new("var/cache/a")));
        assert!(!fs.contains(Path::new("var/cache/b")));
        // Outside the opaque subtree is untouched.
        assert!(fs.contains(Path::new("var")));
        assert!(fs.contains(Path::new("etc/hosts")));
    }

    #[test]
    fn opaque_marker_distinguished_from_generic_whiteout_prefix() {
        // The opaque marker filename also starts with `.wh.`. If the
        // generic-prefix branch ran first it would compute a victim
        // of `.wh..opq` — wrong. This test pins the precedence.
        let lower = build_tar(&[
            dir("d/"),
            file("d/inner", b"keep-or-drop"),
            file("d/.wh..opq", b"do-not-create"),
        ]);
        let upper = build_tar(&[whiteout("d/.wh..wh..opq")]);
        let fs = apply_image(InputImageId(0), &[handle_for(lower), handle_for(upper)]).unwrap();

        // `d` survives; everything inside it is gone.
        assert!(fs.contains(Path::new("d")));
        assert!(!fs.contains(Path::new("d/inner")));
        assert!(!fs.contains(Path::new("d/.wh..opq")));
    }

    #[test]
    fn opaque_marker_at_root_clears_everything() {
        let lower = build_tar(&[file("a", b"1"), dir("d/"), file("d/x", b"2")]);
        let upper = build_tar(&[whiteout(".wh..wh..opq")]);
        let fs = apply_image(InputImageId(0), &[handle_for(lower), handle_for(upper)]).unwrap();
        assert!(fs.is_empty(), "opaque-at-root drops every entry");
    }

    #[test]
    fn hardlinks_are_stored_with_link_target() {
        let bytes = build_tar(&[
            file("etc/hostname", b"node\n"),
            hardlink("etc/hostname.alias", "etc/hostname"),
        ]);
        let fs = apply_image(InputImageId(0), &[handle_for(bytes)]).unwrap();
        let alias = fs.get(Path::new("etc/hostname.alias")).unwrap();
        assert_eq!(alias.kind, EntryKind::Hardlink);
        assert_eq!(alias.link_target.as_deref(), Some(Path::new("etc/hostname")));
    }

    #[test]
    fn hardlink_target_is_normalised_to_match_index_keys() {
        // Some packagers (notably bootc / certain perl builds) emit
        // hardlinks with a `./` prefix on the target even though the
        // referenced file itself was stored without one. Without
        // normalisation the hardlink resolver can't find the target
        // and rejects an otherwise-valid image.
        let bytes = build_tar(&[
            file("usr/bin/perl", b"#!/bin/sh\n"),
            hardlink("usr/bin/perl5.36.0", "./usr/bin/perl"),
        ]);
        let fs = apply_image(InputImageId(0), &[handle_for(bytes)]).unwrap();
        let alias = fs.get(Path::new("usr/bin/perl5.36.0")).unwrap();
        assert_eq!(alias.kind, EntryKind::Hardlink);
        assert_eq!(alias.link_target.as_deref(), Some(Path::new("usr/bin/perl")));
    }

    #[test]
    fn symlinks_round_trip_link_target() {
        let bytes = build_tar(&[
            file("etc/hostname", b"node\n"),
            symlink("etc/hostname.link", "hostname"),
        ]);
        let fs = apply_image(InputImageId(0), &[handle_for(bytes)]).unwrap();
        let link = fs.get(Path::new("etc/hostname.link")).unwrap();
        assert_eq!(link.kind, EntryKind::Symlink);
        assert_eq!(link.link_target.as_deref(), Some(Path::new("hostname")));
    }

    #[test]
    fn dot_slash_prefix_is_normalised() {
        // A whiteout written as `./etc/.wh.foo` must drop the lower
        // layer's `etc/foo` even though the raw paths differ.
        let lower = build_tar(&[file("etc/foo", b"old")]);
        let upper = build_tar(&[whiteout("./etc/.wh.foo")]);
        let fs = apply_image(InputImageId(0), &[handle_for(lower), handle_for(upper)]).unwrap();
        assert!(!fs.contains(Path::new("etc/foo")));
    }

    #[test]
    fn trailing_slash_on_directories_is_stripped() {
        let bytes = build_tar(&[dir("etc/")]);
        let fs = apply_image(InputImageId(0), &[handle_for(bytes)]).unwrap();
        // Index keys on `etc`, not `etc/`.
        assert!(fs.contains(Path::new("etc")));
        assert_eq!(fs.len(), 1);
    }

    #[test]
    fn entry_idx_counts_position_in_layer_stream() {
        let bytes = build_tar(&[file("a", b"1"), file("b", b"2"), file("c", b"3")]);
        let fs = apply_image(InputImageId(0), &[handle_for(bytes)]).unwrap();
        assert_eq!(fs.get(Path::new("a")).unwrap().entry_idx, 0);
        assert_eq!(fs.get(Path::new("b")).unwrap().entry_idx, 1);
        assert_eq!(fs.get(Path::new("c")).unwrap().entry_idx, 2);
    }

    #[test]
    fn whiteout_positions_do_not_shift_subsequent_entry_idx() {
        // Whiteouts consume an iteration step in the tar stream just
        // like any other entry. The entry that follows must record
        // its actual stream position, not a "logical" insert count.
        let upper = build_tar(&[whiteout(".wh.gone"), file("kept", b"data")]);
        let fs = apply_image(InputImageId(0), &[handle_for(upper)]).unwrap();
        let kept = fs.get(Path::new("kept")).unwrap();
        // Whiteout was at position 0 in the stream, so `kept` is at 1.
        assert_eq!(kept.entry_idx, 1);
    }

    #[test]
    fn xattrs_and_modes_propagate_into_the_index() {
        // Build a regular file with a setuid bit; xattrs are exercised
        // in the reader's own tests, so we focus on what `apply` adds.
        let mut buf = Vec::new();
        {
            let mut tb = Builder::new(&mut buf);
            tb.mode(tar::HeaderMode::Deterministic);
            let mut h = Header::new_gnu();
            h.set_entry_type(EntryType::Regular);
            h.set_path("usr/bin/sudo").unwrap();
            h.set_mode(0o4755); // setuid + 0755
            h.set_uid(0);
            h.set_gid(0);
            h.set_size(0);
            h.set_cksum();
            tb.append(&h, std::io::empty()).unwrap();
            tb.finish().unwrap();
        }
        let fs = apply_image(InputImageId(0), &[handle_for(buf)]).unwrap();
        let entry = fs.get(Path::new("usr/bin/sudo")).unwrap();
        assert_eq!(entry.mode & 0o7777, 0o4755);
        // Sanity: the xattrs field is the byte-keyed map the rest of
        // the pipeline consumes (no synthetic xattrs are added here).
        let xattrs: &BTreeMap<Vec<u8>, Vec<u8>> = &entry.xattrs;
        assert!(xattrs.is_empty());
    }

    #[test]
    fn multi_layer_subtree_replacement_via_whiteout_then_recreate() {
        // Layer 0 creates a tree; layer 1 whites the root of it out;
        // layer 2 recreates the directory with new content. This is
        // the canonical "recreate the dir" flow.
        let l0 = build_tar(&[dir("opt/"), dir("opt/app/"), file("opt/app/v1", b"old")]);
        let l1 = build_tar(&[whiteout("opt/.wh.app")]);
        let l2 = build_tar(&[dir("opt/app/"), file("opt/app/v2", b"new")]);
        let fs = apply_image(InputImageId(0), &[handle_for(l0), handle_for(l1), handle_for(l2)]).unwrap();

        assert!(fs.contains(Path::new("opt/app")));
        assert!(fs.contains(Path::new("opt/app/v2")));
        assert!(!fs.contains(Path::new("opt/app/v1")));
        // The recreated entries come from the topmost layer.
        assert_eq!(fs.get(Path::new("opt/app/v2")).unwrap().layer_idx, 2);
    }

    #[test]
    fn truncated_layer_surfaces_io_error() {
        // A tar that ends mid-body (size declared 100, only 4 bytes
        // present) must surface the read failure during apply — not
        // silently leave a partial entry in the index.
        let mut buf = Vec::new();
        {
            let mut h = Header::new_gnu();
            h.set_entry_type(EntryType::Regular);
            h.set_path("oops").unwrap();
            h.set_mode(0o644);
            h.set_uid(0);
            h.set_gid(0);
            h.set_size(100);
            h.set_cksum();
            buf.extend_from_slice(h.as_bytes());
            buf.extend_from_slice(b"abcd");
            // No padding, no trailer — body is short.
        }
        let err = apply_image(InputImageId(0), &[handle_for(buf)]).unwrap_err();
        // The exact variant depends on whether the tar parser or the
        // body drainer hits EOF first; both map to `Io`.
        match err {
            crate::Error::Io(_) => {}
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn bare_wh_prefix_with_no_suffix_is_treated_as_a_regular_file() {
        // `.wh.` on its own has no victim — it should not delete the
        // parent directory. We treat it as an ordinary (if oddly named)
        // entry rather than silently dropping the parent.
        let lower = build_tar(&[dir("etc/"), file("etc/hosts", b"y")]);
        let upper = build_tar(&[file("etc/.wh.", b"")]);
        let fs = apply_image(InputImageId(0), &[handle_for(lower), handle_for(upper)]).unwrap();
        assert!(fs.contains(Path::new("etc")));
        assert!(fs.contains(Path::new("etc/hosts")));
        assert!(fs.contains(Path::new("etc/.wh.")));
    }

    fn sha256_of(bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest as _, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }

    #[test]
    fn regular_file_body_is_sha256_hashed_in_place() {
        // Spec 03 §3.4 / spec 04 §4.4: the squash pass hashes regular-
        // file bodies in a single streaming pass and stashes the
        // digest on the entry. Verify the hash matches the expected
        // SHA-256 for a non-trivial body.
        let body: Vec<u8> = (0u8..=255).cycle().take(50_000).collect();
        let bytes = build_tar(&[file("data/blob", &body)]);
        let fs = apply_image(InputImageId(0), &[handle_for(bytes)]).unwrap();
        let entry = fs.get(Path::new("data/blob")).unwrap();
        assert_eq!(entry.kind, EntryKind::Regular);
        assert_eq!(entry.size, body.len() as u64);
        assert_eq!(entry.content_hash, Some(sha256_of(&body)));
    }

    #[test]
    fn empty_regular_file_hashes_to_sha256_of_empty_input() {
        // A zero-byte file still has a defined SHA-256 (the empty
        // hash). Pinning this so dedup (spec 05) sees zero-byte files
        // as identical regardless of their original layer.
        let bytes = build_tar(&[file("empty", b"")]);
        let fs = apply_image(InputImageId(0), &[handle_for(bytes)]).unwrap();
        let entry = fs.get(Path::new("empty")).unwrap();
        assert_eq!(entry.size, 0);
        assert_eq!(entry.content_hash, Some(sha256_of(b"")));
    }

    #[test]
    fn non_regular_kinds_have_no_content_hash() {
        // Hardlinks, symlinks, and directories carry no body, so the
        // hash field is `None`. Spec 03 §3.3's demote pass is the only
        // path that may later fill in a hardlink's hash from its
        // target's regular entry.
        let bytes = build_tar(&[
            dir("d/"),
            file("d/target", b"contents"),
            symlink("d/sym", "target"),
            hardlink("d/hard", "d/target"),
        ]);
        let fs = apply_image(InputImageId(0), &[handle_for(bytes)]).unwrap();
        assert_eq!(fs.get(Path::new("d")).unwrap().content_hash, None);
        assert_eq!(fs.get(Path::new("d/sym")).unwrap().content_hash, None);
        assert_eq!(fs.get(Path::new("d/hard")).unwrap().content_hash, None);
        assert_eq!(
            fs.get(Path::new("d/target")).unwrap().content_hash,
            Some(sha256_of(b"contents"))
        );
    }

    #[test]
    fn upper_layer_overwrite_replaces_content_hash() {
        // When an upper layer overwrites a file, the surviving entry's
        // content_hash must reflect the upper layer's bytes, not a
        // stale hash of the lower-layer body.
        let lower = build_tar(&[file("etc/hostname", b"original-bytes")]);
        let upper = build_tar(&[file("etc/hostname", b"new-bytes")]);
        let fs = apply_image(InputImageId(0), &[handle_for(lower), handle_for(upper)]).unwrap();
        let entry = fs.get(Path::new("etc/hostname")).unwrap();
        assert_eq!(entry.content_hash, Some(sha256_of(b"new-bytes")));
    }

    #[test]
    fn identical_bodies_in_different_layers_share_a_hash() {
        // Spec 04 §4.4: SHA-256 gives "no false positives" on equal
        // content. Two files with the same body in different layers/
        // images must compare equal on `content_hash` so dedup can
        // coalesce them later.
        let bytes_a = build_tar(&[file("a/file", b"shared-body\n")]);
        let bytes_b = build_tar(&[file("b/file", b"shared-body\n")]);
        let fs_a = apply_image(InputImageId(0), &[handle_for(bytes_a)]).unwrap();
        let fs_b = apply_image(InputImageId(1), &[handle_for(bytes_b)]).unwrap();
        let h_a = fs_a.get(Path::new("a/file")).unwrap().content_hash;
        let h_b = fs_b.get(Path::new("b/file")).unwrap().content_hash;
        assert_eq!(h_a, h_b);
        assert!(h_a.is_some());
    }

    #[test]
    fn opener_failure_propagates() {
        // If the layer can't even be opened, the apply pass surfaces
        // the underlying error verbatim.
        let handle = LayerHandle::new(
            sha256_digest(&"a".repeat(64)),
            sha256_digest(&"b".repeat(64)),
            0,
            "application/vnd.oci.image.layer.v1.tar".into(),
            || Err(crate::Error::MalformedInput("blob missing".into())),
        )
        .unwrap();
        let err = apply_image(InputImageId(0), &[handle]).unwrap_err();
        match err {
            crate::Error::MalformedInput(msg) => assert_eq!(msg, "blob missing"),
            other => panic!("unexpected variant: {other:?}"),
        }
    }
}
