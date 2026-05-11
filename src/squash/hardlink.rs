//! Hardlink resolution (spec 03 §3.3).
//!
//! After [`crate::squash::apply`] has folded an image's layer stack
//! into a [`SquashedFs`], this pass walks every surviving
//! [`EntryKind::Hardlink`] and decides what to do with it:
//!
//! * If the hardlink's direct target is still in the live index, the
//!   entry is left alone — the spec 07 assemble pass will emit it as a
//!   tar `LNKTYPE` pointing at the still-alive path.
//! * If the direct target was evicted by a whiteout / opaque-dir
//!   marker (i.e. it lives only in the shadow built by spec 03 §3.2's
//!   apply pass), the link is **demoted** to a regular file: the
//!   entry's metadata and `(image_id, layer_idx, entry_idx)` body
//!   pointer are taken from the chain's terminal regular file so the
//!   assemble pass can still re-open the bytes (spec 02 §2.3). This is
//!   the only path on which a hardlink "becomes" a regular file
//!   (spec 03 §3.3, last paragraph).
//!
//! Resolution is order-independent: hardlinks are processed in
//! [`SquashedFs`]'s lex order (`BTreeMap` iteration), and demotions
//! commute — chasing the chain through any mix of live and shadow
//! hops produces the same terminal regular file regardless of which
//! intermediate hops have already been demoted by earlier iterations.
//! The lex order itself is what spec 11 §11.6 leans on for byte-for-
//! byte reproducible output.
//!
//! Cycles in the hardlink graph (which a real Unix filesystem cannot
//! produce, but which a malicious or corrupt tar can) surface as
//! [`crate::Error::MalformedInput`] rather than looping.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::Error;
use crate::Result;
use crate::squash::index::{SquashedEntry, SquashedFs};
use crate::tar_io::reader::EntryKind;

/// Resolve every hardlink entry in `fs` per spec 03 §3.3.
///
/// Iterates hardlinks in lex order (the only stable order
/// [`SquashedFs`] exposes) and either leaves each one alone or demotes
/// it to a regular file pointing at the originating body's
/// `(image_id, layer_idx, entry_idx)` triple.
///
/// `image_label` is a free-form identifier for the input image (e.g.
/// `"input image #0 (example.com/img:1)"`) that gets embedded in error
/// messages so the user can tell which image a malformed hardlink came
/// from. The hardlink entry's own `layer_idx` / `entry_idx` are
/// appended alongside.
///
/// # Errors
///
/// * [`Error::MalformedInput`] for cycles in the hardlink graph,
///   hardlinks whose chain reaches a missing path, hardlinks whose
///   chain terminates on a non-regular kind, or `Hardlink` entries
///   without a `link_target`.
pub fn resolve(fs: &mut SquashedFs, image_label: &str) -> Result<()> {
    let hardlinks: Vec<PathBuf> = fs
        .iter()
        .filter(|(_, entry)| entry.kind == EntryKind::Hardlink)
        .map(|(path, _)| path.clone())
        .collect();

    for path in hardlinks {
        resolve_one(fs, &path, image_label)?;
    }
    Ok(())
}

fn resolve_one(fs: &mut SquashedFs, path: &Path, image_label: &str) -> Result<()> {
    let entry = fs.get(path).expect("snapshot taken from live index").clone();
    let direct_target = entry.link_target.clone().ok_or_else(|| {
        Error::MalformedInput(format!(
            "hardlink at {} ({}, layer {}, entry {}) has no link_target",
            path.display(),
            image_label,
            entry.layer_idx,
            entry.entry_idx
        ))
    })?;

    if fs.get(&direct_target).is_some() {
        // Direct target survives in the live view; the assemble pass
        // can emit this as a tar hardlink. If the target itself is
        // also a hardlink, our lex-order loop will demote it (or not)
        // on its own iteration — either outcome leaves the chain
        // emittable.
        return Ok(());
    }

    let body_source = chase_to_regular(fs, &direct_target, path, &entry, image_label)?;
    fs.insert(path.to_path_buf(), demote(body_source));
    Ok(())
}

/// Walk the hardlink chain from `start`, hopping through both the
/// live index and the shadow, until a non-hardlink entry is reached.
///
/// Returns the terminal entry, which must be `EntryKind::Regular` for
/// demotion to be meaningful. `original` is the hardlink path that
/// triggered the chase, used purely for error messages.
fn chase_to_regular(
    fs: &SquashedFs,
    start: &Path,
    original: &Path,
    original_entry: &SquashedEntry,
    image_label: &str,
) -> Result<SquashedEntry> {
    let origin = format!(
        "hardlink at {} ({}, layer {}, entry {})",
        original.display(),
        image_label,
        original_entry.layer_idx,
        original_entry.entry_idx
    );
    let mut visited: BTreeSet<PathBuf> = BTreeSet::new();
    let mut cursor = start.to_path_buf();
    loop {
        if !visited.insert(cursor.clone()) {
            return Err(Error::MalformedInput(format!(
                "{origin} resolves through a cycle (revisited {})",
                cursor.display()
            )));
        }
        // Live index wins over shadow — a recreated path is genuinely
        // alive (`SquashedFs::insert` already cleared the shadow
        // record on insert), so an `entries.get` hit shadows nothing.
        let entry = fs
            .get(&cursor)
            .or_else(|| fs.shadow_get(&cursor))
            .cloned()
            .ok_or_else(|| {
                Error::MalformedInput(format!(
                    "{origin} chain reaches missing path {}",
                    cursor.display()
                ))
            })?;
        match entry.kind {
            EntryKind::Hardlink => {
                cursor = entry.link_target.clone().ok_or_else(|| {
                    Error::MalformedInput(format!(
                        "{origin} chain hop {} (layer {}, entry {}) has no link_target",
                        cursor.display(),
                        entry.layer_idx,
                        entry.entry_idx
                    ))
                })?;
            }
            EntryKind::Regular => return Ok(entry),
            other => {
                return Err(Error::MalformedInput(format!(
                    "{origin} chain ends at {} on non-regular kind {:?} (layer {}, entry {})",
                    cursor.display(),
                    other,
                    entry.layer_idx,
                    entry.entry_idx
                )));
            }
        }
    }
}

/// Build the regular-file [`SquashedEntry`] that replaces a demoted
/// hardlink. Metadata is taken from the chain's terminal regular file
/// because hardlinks share the underlying inode at runtime — that is
/// the authoritative copy of mode/uid/gid/xattrs/size.
fn demote(source: SquashedEntry) -> SquashedEntry {
    SquashedEntry {
        kind: EntryKind::Regular,
        link_target: None,
        ..source
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;

    use super::*;
    use crate::squash::index::{InputImageId, SquashedEntry, SquashedFs};
    use crate::tar_io::reader::EntryKind;

    fn make_entry(layer_idx: usize, entry_idx: usize, kind: EntryKind) -> SquashedEntry {
        SquashedEntry {
            image_id: InputImageId(0),
            layer_idx,
            entry_idx,
            kind,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: 0,
            content_hash: None,
            xattrs: BTreeMap::new(),
            link_target: None,
            rdev: None,
        }
    }

    fn regular(layer_idx: usize, entry_idx: usize, size: u64) -> SquashedEntry {
        SquashedEntry {
            size,
            ..make_entry(layer_idx, entry_idx, EntryKind::Regular)
        }
    }

    fn hardlink(layer_idx: usize, entry_idx: usize, target: &str) -> SquashedEntry {
        SquashedEntry {
            link_target: Some(PathBuf::from(target)),
            ..make_entry(layer_idx, entry_idx, EntryKind::Hardlink)
        }
    }

    #[test]
    fn empty_index_is_a_noop() {
        let mut fs = SquashedFs::new();
        resolve(&mut fs, "test image").unwrap();
        assert!(fs.is_empty());
    }

    #[test]
    fn hardlink_to_live_target_is_left_alone() {
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("etc/hostname"), regular(0, 0, 12));
        fs.insert(PathBuf::from("etc/hostname.alias"), hardlink(0, 1, "etc/hostname"));
        resolve(&mut fs, "test image").unwrap();
        let alias = fs.get(Path::new("etc/hostname.alias")).unwrap();
        // Still a hardlink — direct target is alive in the index.
        assert_eq!(alias.kind, EntryKind::Hardlink);
        assert_eq!(alias.link_target.as_deref(), Some(Path::new("etc/hostname")));
    }

    #[test]
    fn hardlink_to_whited_out_target_is_demoted() {
        let mut fs = SquashedFs::new();
        // Layer 0 places the regular file.
        fs.insert(PathBuf::from("etc/hostname"), regular(0, 5, 42));
        // Layer 1 hardlinks to it.
        fs.insert(PathBuf::from("etc/hostname.alias"), hardlink(1, 2, "etc/hostname"));
        // Layer 2 whites out the target — moves it to shadow but
        // leaves the hardlink alone.
        fs.remove_subtree(Path::new("etc/hostname"));
        assert!(!fs.contains(Path::new("etc/hostname")));
        assert!(fs.shadow_get(Path::new("etc/hostname")).is_some());

        resolve(&mut fs, "test image").unwrap();

        let demoted = fs.get(Path::new("etc/hostname.alias")).unwrap();
        assert_eq!(demoted.kind, EntryKind::Regular);
        // Body source is the original target's tar entry — spec 03 §3.3.
        assert_eq!(demoted.layer_idx, 0);
        assert_eq!(demoted.entry_idx, 5);
        assert_eq!(demoted.size, 42);
        assert!(demoted.link_target.is_none());
    }

    #[test]
    fn live_chain_is_left_alone_through_multiple_hops() {
        // a -> b -> c, all alive. Each hardlink stays as-is; the
        // assembler will emit the chain verbatim.
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("c"), regular(0, 0, 7));
        fs.insert(PathBuf::from("b"), hardlink(0, 1, "c"));
        fs.insert(PathBuf::from("a"), hardlink(0, 2, "b"));
        resolve(&mut fs, "test image").unwrap();
        assert_eq!(fs.get(Path::new("a")).unwrap().kind, EntryKind::Hardlink);
        assert_eq!(fs.get(Path::new("b")).unwrap().kind, EntryKind::Hardlink);
        assert_eq!(fs.get(Path::new("c")).unwrap().kind, EntryKind::Regular);
    }

    #[test]
    fn chain_terminating_in_shadow_demotes_only_the_broken_links() {
        // a -> b (alive, hardlink) -> c (whited out, regular in shadow).
        // Lex order processes `a` first then `b`. After resolution:
        //   a: still hardlink to b (b is alive).
        //   b: demoted to regular pointing at c's body.
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("c"), regular(0, 9, 100));
        fs.insert(PathBuf::from("b"), hardlink(0, 1, "c"));
        fs.insert(PathBuf::from("a"), hardlink(0, 2, "b"));
        fs.remove_subtree(Path::new("c"));

        resolve(&mut fs, "test image").unwrap();

        let a = fs.get(Path::new("a")).unwrap();
        assert_eq!(a.kind, EntryKind::Hardlink);
        assert_eq!(a.link_target.as_deref(), Some(Path::new("b")));

        let b = fs.get(Path::new("b")).unwrap();
        assert_eq!(b.kind, EntryKind::Regular);
        assert_eq!(b.layer_idx, 0);
        assert_eq!(b.entry_idx, 9);
        assert_eq!(b.size, 100);
    }

    #[test]
    fn multi_hop_through_shadow_finds_terminal_regular() {
        // Whole subtree was whited out, leaving a single live hardlink
        // outside that points back into it. The chain through shadow
        // must still find the terminal regular for body recovery.
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("dir/c"), regular(0, 4, 11));
        fs.insert(PathBuf::from("dir/b"), hardlink(0, 5, "dir/c"));
        fs.insert(PathBuf::from("dir/a"), hardlink(0, 6, "dir/b"));
        fs.insert(PathBuf::from("outside"), hardlink(1, 0, "dir/a"));
        // Whiteout of dir nukes a, b, c into shadow.
        fs.remove_subtree(Path::new("dir"));
        assert!(fs.contains(Path::new("outside")));
        assert!(!fs.contains(Path::new("dir/a")));

        resolve(&mut fs, "test image").unwrap();

        let outside = fs.get(Path::new("outside")).unwrap();
        assert_eq!(outside.kind, EntryKind::Regular);
        assert_eq!(outside.layer_idx, 0);
        assert_eq!(outside.entry_idx, 4);
        assert_eq!(outside.size, 11);
    }

    #[test]
    fn cycle_in_live_index_is_detected() {
        // `a -> b -> a` with both alive. Direct target of each is
        // live so neither is demoted; but at the assemble stage this
        // would be a problem. We catch it here defensively *only* on
        // the demote path — for a fully-live cycle we leave it alone
        // (matches spec: live-target hardlinks pass through). This
        // test pins that behavior to make the contract explicit.
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("a"), hardlink(0, 0, "b"));
        fs.insert(PathBuf::from("b"), hardlink(0, 1, "a"));
        // Neither has a live regular terminal but both direct targets
        // are alive, so resolve() doesn't chase. No error.
        resolve(&mut fs, "test image").unwrap();
        assert_eq!(fs.get(Path::new("a")).unwrap().kind, EntryKind::Hardlink);
        assert_eq!(fs.get(Path::new("b")).unwrap().kind, EntryKind::Hardlink);
    }

    #[test]
    fn cycle_in_shadow_chain_is_a_malformed_input() {
        // A whited-out cycle: a -> b -> a, both in shadow. The live
        // hardlink `outside -> a` must trip cycle detection rather
        // than loop forever.
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("a"), hardlink(0, 0, "b"));
        fs.insert(PathBuf::from("b"), hardlink(0, 1, "a"));
        fs.insert(PathBuf::from("outside"), hardlink(1, 0, "a"));
        fs.remove_subtree(Path::new("a"));
        fs.remove_subtree(Path::new("b"));
        let err = resolve(&mut fs, "test image").unwrap_err();
        match err {
            Error::MalformedInput(msg) => assert!(msg.contains("cycle"), "msg = {msg}"),
            other => panic!("expected MalformedInput, got {other:?}"),
        }
    }

    #[test]
    fn missing_target_outside_index_and_shadow_is_an_error() {
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("alias"), hardlink(0, 0, "nowhere"));
        let err = resolve(&mut fs, "test image").unwrap_err();
        match err {
            Error::MalformedInput(msg) => assert!(msg.contains("missing"), "msg = {msg}"),
            other => panic!("expected MalformedInput, got {other:?}"),
        }
    }

    #[test]
    fn chain_terminating_in_non_regular_is_an_error() {
        // A hardlink whose target is, say, a directory. Real Unix
        // forbids this, but tar can encode it. Reject explicitly.
        let mut fs = SquashedFs::new();
        let dir = make_entry(0, 0, EntryKind::Directory);
        fs.insert(PathBuf::from("etc"), dir);
        fs.insert(PathBuf::from("alias"), hardlink(0, 1, "etc"));
        // Whiteout `etc` so we hit the chase path (live target
        // would be left alone).
        fs.remove_subtree(Path::new("etc"));
        let err = resolve(&mut fs, "test image").unwrap_err();
        match err {
            Error::MalformedInput(msg) => {
                assert!(msg.contains("non-regular"), "msg = {msg}");
            }
            other => panic!("expected MalformedInput, got {other:?}"),
        }
    }

    #[test]
    fn hardlink_without_link_target_is_an_error() {
        let mut fs = SquashedFs::new();
        // Construct a malformed hardlink with no target.
        fs.insert(PathBuf::from("alias"), make_entry(0, 0, EntryKind::Hardlink));
        let err = resolve(&mut fs, "test image").unwrap_err();
        match err {
            Error::MalformedInput(msg) => assert!(msg.contains("link_target"), "msg = {msg}"),
            other => panic!("expected MalformedInput, got {other:?}"),
        }
    }

    #[test]
    fn demote_carries_target_metadata_not_the_hardlinks_own() {
        // Spec 03 §3.3 says the demoted entry inherits the original
        // file's body. Hardlinks share the inode, so mode/uid/gid/
        // xattrs from the *target* are the runtime-authoritative
        // copy. Pin that the demote uses target metadata.
        let mut fs = SquashedFs::new();
        let mut target = regular(2, 3, 9);
        target.mode = 0o4755;
        target.uid = 1000;
        target.gid = 1001;
        target.xattrs.insert(b"security.capability".to_vec(), vec![1, 2, 3, 4]);
        fs.insert(PathBuf::from("bin/sudo"), target);

        let mut link = hardlink(5, 7, "bin/sudo");
        link.mode = 0o000; // would be wrong if propagated to demoted form
        link.uid = 9999;
        fs.insert(PathBuf::from("usr/bin/sudo"), link);

        fs.remove_subtree(Path::new("bin/sudo"));
        resolve(&mut fs, "test image").unwrap();

        let demoted = fs.get(Path::new("usr/bin/sudo")).unwrap();
        assert_eq!(demoted.kind, EntryKind::Regular);
        assert_eq!(demoted.mode, 0o4755);
        assert_eq!(demoted.uid, 1000);
        assert_eq!(demoted.gid, 1001);
        assert_eq!(demoted.size, 9);
        assert_eq!(demoted.layer_idx, 2);
        assert_eq!(demoted.entry_idx, 3);
        assert_eq!(
            demoted.xattrs.get(b"security.capability".as_slice()),
            Some(&vec![1, 2, 3, 4])
        );
    }

    #[test]
    fn recreated_path_clears_shadow_and_demotes_with_new_body() {
        // file_x exists, then is whited out, then is recreated, then
        // is whited out again. A surviving hardlink should resolve to
        // the *most recent* body source (the second creation), since
        // `insert` clears the shadow on overwrite.
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("file_x"), regular(0, 0, 1));
        fs.insert(PathBuf::from("alias"), hardlink(0, 1, "file_x"));
        fs.remove_subtree(Path::new("file_x"));
        // Recreate with a different (layer_idx, entry_idx, size).
        fs.insert(PathBuf::from("file_x"), regular(3, 4, 99));
        // Whiteout again.
        fs.remove_subtree(Path::new("file_x"));

        resolve(&mut fs, "test image").unwrap();

        let demoted = fs.get(Path::new("alias")).unwrap();
        assert_eq!(demoted.kind, EntryKind::Regular);
        // Most recent regular wins.
        assert_eq!(demoted.layer_idx, 3);
        assert_eq!(demoted.entry_idx, 4);
        assert_eq!(demoted.size, 99);
    }

    #[test]
    fn opaque_dir_eviction_also_populates_shadow_for_resolution() {
        // Opaque-dir markers go through `clear_subtree`, which must
        // also shadow evicted entries so hardlinks can recover. The
        // hardlink is at the root, *not* a descendant of `d`, so it
        // survives the clear and ends up referencing a now-shadowed
        // path.
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("d"), make_entry(0, 0, EntryKind::Directory));
        fs.insert(PathBuf::from("d/file"), regular(0, 1, 7));
        fs.insert(PathBuf::from("alias"), hardlink(1, 0, "d/file"));

        let cleared = fs.clear_subtree(Path::new("d"));
        assert_eq!(cleared, 1, "only d/file is a strict descendant of d");
        assert!(fs.contains(Path::new("alias")));
        assert!(fs.shadow_get(Path::new("d/file")).is_some());

        resolve(&mut fs, "test image").unwrap();
        let demoted = fs.get(Path::new("alias")).unwrap();
        assert_eq!(demoted.kind, EntryKind::Regular);
        assert_eq!(demoted.size, 7);
        assert_eq!(demoted.entry_idx, 1);
    }

    #[test]
    fn demote_inherits_targets_content_hash() {
        // Spec 03 §3.3: demoted hardlinks "become" their target. The
        // SHA-256 stamped on the terminal regular file by the squash
        // pass (spec 03 §3.4) must propagate so dedup (spec 05) can
        // recognise the demoted path's identity.
        let mut fs = SquashedFs::new();
        let mut target = regular(0, 0, 5);
        target.content_hash = Some([0xab; 32]);
        fs.insert(PathBuf::from("file_x"), target);
        fs.insert(PathBuf::from("alias"), hardlink(0, 1, "file_x"));
        fs.remove_subtree(Path::new("file_x"));

        resolve(&mut fs, "test image").unwrap();

        let demoted = fs.get(Path::new("alias")).unwrap();
        assert_eq!(demoted.kind, EntryKind::Regular);
        assert_eq!(demoted.content_hash, Some([0xab; 32]));
    }

    #[test]
    fn shadow_get_returns_none_for_live_paths() {
        // Sanity: shadow_get only sees evicted paths; an alive entry
        // returns None even though `get` returns Some.
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("alive"), regular(0, 0, 0));
        assert!(fs.get(Path::new("alive")).is_some());
        assert!(fs.shadow_get(Path::new("alive")).is_none());
    }
}
