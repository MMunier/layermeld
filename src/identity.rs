//! `FileIdentity` tuple and equality (spec 04).
//!
//! Two filesystem entries are "the same file" iff every field of the
//! [`FileIdentity`] tuple matches byte-for-byte. The dedup pass
//! (spec 05) consumes this predicate to group equal entries across
//! squashed images and decide layer placement.
//!
//! The tuple is the spec 04 §4.1 field set verbatim — `path`, `kind`,
//! `mode`, `uid`, `gid`, `size`, `content_hash`, `link_target`, `rdev`,
//! `xattrs` — minus everything spec 04 §4.2 explicitly excludes
//! (mtime/atime/ctime, uname/gname, layer-of-origin bookkeeping,
//! original tar dialect). Those exclusions are enforced *here*: a
//! [`SquashedEntry`] does not even carry mtime / uname / gname per
//! spec 03 §3.5, and the bookkeeping fields it does carry are simply
//! never read by [`FileIdentity::from_squashed`].
//!
//! ## Ordering / hashing
//!
//! `Eq + Hash + Ord` are derived so callers can use a `FileIdentity`
//! directly as a map key. The xattr map keeps its `BTreeMap`
//! representation so two equal identities serialise identically — spec
//! 04 §4.1 calls this out explicitly. `Ord` is the lex-tuple order
//! over the fields in declaration order, with `path` first, which
//! matches the iteration order spec 11 §11.6 leans on for
//! reproducibility.
//!
//! ## Hardlink collapse (spec 04 §4.2 last bullet)
//!
//! [`FileIdentity::from_squashed`] collapses a surviving
//! [`EntryKind::Hardlink`] entry into a `Regular`-kinded identity:
//! kind becomes `Regular`, `link_target` is dropped (spec 04 §4.1
//! reserves it for symlinks), and the originating
//! `(image_id, layer_idx, entry_idx)` plus `link_target` pointer that
//! the [`SquashedEntry`] carried are discarded. `content_hash`
//! follows whatever the entry recorded — for surviving hardlinks the
//! squash pass left it as `None` (spec 03 §3.4), for demoted
//! hardlinks [`crate::squash::hardlink::resolve`] inherited the
//! terminal regular's hash (spec 03 §3.3).
//!
//! Spec 05 §5.6 places hardlinks in the per-image layer regardless,
//! so the surviving-hardlink-with-`None`-hash case never participates
//! in cross-image dedup grouping in practice — but the collapse is
//! still defined here so the predicate is total.
//!
//! Other kinds (`Symlink`, `Directory`, `CharDevice`, `BlockDevice`,
//! `Fifo`) pass through unchanged. `Meta` entries are dropped at the apply
//! layer (spec 03 §3.2) and must not reach the identity builder; the
//! builder asserts this in debug builds and treats them as `Regular`
//! in release builds rather than panicking on otherwise-recoverable
//! malformed input.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::squash::index::SquashedEntry;
use crate::tar_io::reader::EntryKind;

/// Spec 04 §4.1 identity tuple. See the module doc for field-by-field
/// rationale and the explicit-exclusions list from spec 04 §4.2.
///
/// `Eq + Hash + Ord` make this a map / set key for the dedup pass.
/// Field declaration order is the `Ord` tiebreak order, with `path`
/// first to match spec 11 §11.6's lex-iteration determinism rule.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct FileIdentity {
    /// Absolute path inside the rootfs (spec 04 §4.3 — path is part
    /// of identity).
    pub path: PathBuf,
    /// Kind in the spec 04 §4.1 set: `Regular`, `Symlink`,
    /// `Directory`, `CharDevice`, `BlockDevice`, `Fifo`. `Hardlink`
    /// is collapsed to `Regular` by [`Self::from_squashed`] per spec
    /// 04 §4.2 last bullet; `Meta` never reaches here.
    pub kind: EntryKind,
    /// Permission bits including setuid/setgid/sticky.
    pub mode: u32,
    /// Numeric uid (uname is spec 04 §4.2-excluded).
    pub uid: u64,
    /// Numeric gid (gname is spec 04 §4.2-excluded).
    pub gid: u64,
    /// Body size in bytes; zero for every non-regular kind.
    pub size: u64,
    /// SHA-256 of the body bytes for regular files (spec 04 §4.4),
    /// `None` for every other kind.
    pub content_hash: Option<[u8; 32]>,
    /// Symlink target. Reserved for `Symlink` per spec 04 §4.1; every
    /// other kind sets this to `None` — including the collapsed
    /// `Hardlink → Regular` case, whose link target is bookkeeping
    /// the assemble pass uses but is not part of identity.
    pub link_target: Option<PathBuf>,
    /// `(major, minor)` for `CharDevice` / `BlockDevice`, `None`
    /// otherwise.
    pub rdev: Option<(u32, u32)>,
    /// Ordered xattr map. Keys are byte strings (Linux xattr names
    /// are not required to be valid UTF-8); the `BTreeMap` ordering
    /// is part of the equality predicate so equal identities serialise
    /// identically (spec 04 §4.1).
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl FileIdentity {
    /// Pure conversion from a [`SquashedEntry`] at `path`.
    ///
    /// * mtime / uname / gname are not on `SquashedEntry` to begin with
    ///   (spec 03 §3.5 / spec 04 §4.2) — nothing to strip here.
    /// * Bookkeeping fields (`image_id`, `layer_idx`, `entry_idx`) are
    ///   ignored. They name the originating tar entry for the
    ///   assemble pass; they are not part of identity.
    /// * `EntryKind::Hardlink` collapses to [`EntryKind::Regular`] and
    ///   `link_target` is cleared (spec 04 §4.2 last bullet).
    /// * `link_target` is preserved verbatim only for
    ///   [`EntryKind::Symlink`]; every other kind sets it to `None`.
    /// * `rdev` is preserved only for [`EntryKind::CharDevice`] /
    ///   [`EntryKind::BlockDevice`]; clearing it on other kinds keeps
    ///   identity hashing stable against an over-eager reader that
    ///   stamps a stray `(0, 0)` on a regular file.
    /// * `content_hash` passes through (`Some` for regular files
    ///   including demoted hardlinks, `None` otherwise) — see spec
    ///   03 §3.4 / §3.3.
    #[must_use]
    pub fn from_squashed(path: PathBuf, entry: &SquashedEntry) -> Self {
        debug_assert!(
            !matches!(entry.kind, EntryKind::Meta),
            "Meta entries are filtered at apply time and must not reach FileIdentity"
        );

        let kind = match entry.kind {
            // Spec 04 §4.2 last bullet: hardlinks dedup against their
            // target's regular form. `Meta` should never get here
            // (debug_assert above); falls through as `Regular` in
            // release rather than panic.
            EntryKind::Hardlink | EntryKind::Meta => EntryKind::Regular,
            other => other,
        };

        let link_target = match kind {
            EntryKind::Symlink => entry.link_target.clone(),
            _ => None,
        };

        let rdev = match kind {
            EntryKind::CharDevice | EntryKind::BlockDevice => entry.rdev,
            _ => None,
        };

        Self {
            path,
            kind,
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            size: entry.size,
            content_hash: entry.content_hash,
            link_target,
            rdev,
            xattrs: entry.xattrs.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::squash::index::{InputImageId, SquashedEntry};

    fn entry(kind: EntryKind) -> SquashedEntry {
        SquashedEntry {
            image_id: InputImageId(7),
            layer_idx: 3,
            entry_idx: 11,
            kind,
            mode: 0o644,
            uid: 1000,
            gid: 100,
            size: 0,
            content_hash: None,
            xattrs: BTreeMap::new(),
            link_target: None,
            rdev: None,
        }
    }

    fn regular_with_hash(size: u64, hash: [u8; 32]) -> SquashedEntry {
        SquashedEntry {
            size,
            content_hash: Some(hash),
            ..entry(EntryKind::Regular)
        }
    }

    #[test]
    fn regular_file_round_trips_all_identity_fields() {
        let mut e = regular_with_hash(42, [0xab; 32]);
        e.mode = 0o4755;
        e.uid = 0;
        e.gid = 1;
        e.xattrs.insert(b"user.note".to_vec(), b"hi".to_vec());
        e.xattrs.insert(b"security.capability".to_vec(), vec![1, 2, 3]);

        let id = FileIdentity::from_squashed(PathBuf::from("usr/bin/foo"), &e);

        assert_eq!(id.path, PathBuf::from("usr/bin/foo"));
        assert_eq!(id.kind, EntryKind::Regular);
        assert_eq!(id.mode, 0o4755);
        assert_eq!(id.uid, 0);
        assert_eq!(id.gid, 1);
        assert_eq!(id.size, 42);
        assert_eq!(id.content_hash, Some([0xab; 32]));
        assert!(id.link_target.is_none());
        assert!(id.rdev.is_none());
        assert_eq!(id.xattrs.len(), 2);
        assert_eq!(
            id.xattrs.get(b"user.note".as_slice()).map(Vec::as_slice),
            Some(&b"hi"[..])
        );
    }

    #[test]
    fn bookkeeping_fields_do_not_influence_identity() {
        // Spec 04 §4.2: image_id / layer_idx / entry_idx are not part
        // of identity. Two entries differing only in those must hash
        // and compare equal.
        let mut a = regular_with_hash(5, [0u8; 32]);
        let mut b = regular_with_hash(5, [0u8; 32]);
        a.image_id = InputImageId(0);
        a.layer_idx = 0;
        a.entry_idx = 0;
        b.image_id = InputImageId(99);
        b.layer_idx = 7;
        b.entry_idx = 12345;

        let ia = FileIdentity::from_squashed(PathBuf::from("etc/passwd"), &a);
        let ib = FileIdentity::from_squashed(PathBuf::from("etc/passwd"), &b);

        assert_eq!(ia, ib);
        let mut set: HashSet<FileIdentity> = HashSet::new();
        set.insert(ia.clone());
        assert!(set.contains(&ib));
    }

    #[test]
    fn hardlink_collapses_to_regular_and_drops_link_target() {
        // Spec 04 §4.2 last bullet: a hardlink in image B that points
        // at a regular file with the same identity as image A's
        // regular dedups together. Identity-time we collapse the
        // hardlink kind and drop the target pointer (spec 04 §4.1
        // reserves link_target for symlinks).
        let mut h = entry(EntryKind::Hardlink);
        h.link_target = Some(PathBuf::from("etc/hostname"));
        h.size = 0; // hardlink headers carry size=0; the demoted form fills it in
        let id = FileIdentity::from_squashed(PathBuf::from("etc/hostname.alias"), &h);
        assert_eq!(id.kind, EntryKind::Regular);
        assert!(id.link_target.is_none());
    }

    #[test]
    fn demoted_hardlink_identity_matches_its_target() {
        // After spec 03 §3.3, a demoted hardlink carries the
        // terminal regular's metadata + content_hash. At identity
        // time it should hash equal to a regular file at the same
        // path with that metadata. Path differs here so they're not
        // equal — spec 04 §4.3 keeps path in identity — but the
        // *non-path* fields must match exactly.
        let target = regular_with_hash(99, [0xcd; 32]);
        // Mimic the demote: regular kind, target's metadata + hash.
        let demoted = SquashedEntry {
            kind: EntryKind::Regular,
            link_target: None,
            ..target.clone()
        };
        let id_target = FileIdentity::from_squashed(PathBuf::from("file"), &target);
        let id_demoted = FileIdentity::from_squashed(PathBuf::from("alias"), &demoted);

        assert_ne!(id_target, id_demoted, "paths differ → identities differ");
        // But every non-path field is equal:
        assert_eq!(id_target.kind, id_demoted.kind);
        assert_eq!(id_target.mode, id_demoted.mode);
        assert_eq!(id_target.uid, id_demoted.uid);
        assert_eq!(id_target.gid, id_demoted.gid);
        assert_eq!(id_target.size, id_demoted.size);
        assert_eq!(id_target.content_hash, id_demoted.content_hash);
    }

    #[test]
    fn symlink_preserves_link_target_and_drops_rdev() {
        let mut s = entry(EntryKind::Symlink);
        s.link_target = Some(PathBuf::from("../bin/sh"));
        // Bogus rdev on a symlink must be cleared to keep identity stable.
        s.rdev = Some((12, 34));
        let id = FileIdentity::from_squashed(PathBuf::from("usr/bin/sh"), &s);
        assert_eq!(id.kind, EntryKind::Symlink);
        assert_eq!(id.link_target.as_deref(), Some(Path::new("../bin/sh")));
        assert!(id.rdev.is_none());
        assert!(id.content_hash.is_none());
    }

    #[test]
    fn char_and_block_devices_preserve_rdev() {
        let mut c = entry(EntryKind::CharDevice);
        c.rdev = Some((1, 3));
        let id = FileIdentity::from_squashed(PathBuf::from("dev/null"), &c);
        assert_eq!(id.kind, EntryKind::CharDevice);
        assert_eq!(id.rdev, Some((1, 3)));
        assert!(id.link_target.is_none());

        let mut b = entry(EntryKind::BlockDevice);
        b.rdev = Some((8, 0));
        let id = FileIdentity::from_squashed(PathBuf::from("dev/sda"), &b);
        assert_eq!(id.kind, EntryKind::BlockDevice);
        assert_eq!(id.rdev, Some((8, 0)));
    }

    #[test]
    fn directory_identity_carries_metadata_only() {
        let mut d = entry(EntryKind::Directory);
        d.mode = 0o0755;
        d.uid = 0;
        d.gid = 0;
        d.xattrs.insert(b"user.flag".to_vec(), b"on".to_vec());
        // A reader that stamped stray rdev / link_target on a dir
        // must not leak through.
        d.rdev = Some((9, 9));
        d.link_target = Some(PathBuf::from("nonsense"));

        let id = FileIdentity::from_squashed(PathBuf::from("etc"), &d);
        assert_eq!(id.kind, EntryKind::Directory);
        assert_eq!(id.size, 0);
        assert!(id.content_hash.is_none());
        assert!(id.link_target.is_none());
        assert!(id.rdev.is_none());
        assert_eq!(
            id.xattrs.get(b"user.flag".as_slice()).map(Vec::as_slice),
            Some(&b"on"[..])
        );
    }

    #[test]
    fn fifo_identity_has_no_body_or_link_or_rdev() {
        let id = FileIdentity::from_squashed(PathBuf::from("var/run/foo.sock"), &entry(EntryKind::Fifo));
        assert_eq!(id.kind, EntryKind::Fifo);
        assert_eq!(id.size, 0);
        assert!(id.content_hash.is_none());
        assert!(id.link_target.is_none());
        assert!(id.rdev.is_none());
    }

    #[test]
    fn equal_xattrs_in_different_insertion_order_compare_equal() {
        // BTreeMap normalises insertion order; spec 04 §4.1 says the
        // ordering is part of the predicate so equal identities
        // serialise identically.
        let mut a = entry(EntryKind::Regular);
        let mut b = entry(EntryKind::Regular);
        a.xattrs.insert(b"a".to_vec(), b"1".to_vec());
        a.xattrs.insert(b"b".to_vec(), b"2".to_vec());
        b.xattrs.insert(b"b".to_vec(), b"2".to_vec());
        b.xattrs.insert(b"a".to_vec(), b"1".to_vec());

        let ia = FileIdentity::from_squashed(PathBuf::from("p"), &a);
        let ib = FileIdentity::from_squashed(PathBuf::from("p"), &b);
        assert_eq!(ia, ib);
        // And the iteration order is identical:
        let ka: Vec<_> = ia.xattrs.keys().collect();
        let kb: Vec<_> = ib.xattrs.keys().collect();
        assert_eq!(ka, kb);
    }

    #[test]
    fn differing_xattr_values_break_equality() {
        let mut a = entry(EntryKind::Regular);
        let mut b = entry(EntryKind::Regular);
        a.xattrs.insert(b"k".to_vec(), b"v1".to_vec());
        b.xattrs.insert(b"k".to_vec(), b"v2".to_vec());
        assert_ne!(
            FileIdentity::from_squashed(PathBuf::from("p"), &a),
            FileIdentity::from_squashed(PathBuf::from("p"), &b)
        );
    }

    #[test]
    fn differing_mode_uid_gid_or_size_break_equality() {
        let base = regular_with_hash(10, [0; 32]);
        let id_base = FileIdentity::from_squashed(PathBuf::from("p"), &base);

        let mut m = base.clone();
        m.mode = 0o600;
        assert_ne!(id_base, FileIdentity::from_squashed(PathBuf::from("p"), &m));

        let mut u = base.clone();
        u.uid = 1;
        assert_ne!(id_base, FileIdentity::from_squashed(PathBuf::from("p"), &u));

        let mut g = base.clone();
        g.gid = 1;
        assert_ne!(id_base, FileIdentity::from_squashed(PathBuf::from("p"), &g));

        let mut s = base.clone();
        s.size = 11;
        assert_ne!(id_base, FileIdentity::from_squashed(PathBuf::from("p"), &s));
    }

    #[test]
    fn differing_content_hash_breaks_equality_among_regulars() {
        let a = regular_with_hash(5, [0xaa; 32]);
        let b = regular_with_hash(5, [0xbb; 32]);
        assert_ne!(
            FileIdentity::from_squashed(PathBuf::from("p"), &a),
            FileIdentity::from_squashed(PathBuf::from("p"), &b)
        );
    }

    #[test]
    fn differing_paths_break_equality_even_for_byte_identical_bodies() {
        // Spec 04 §4.3: same body at different paths is *not* the
        // same file. Two regular files with identical metadata + hash
        // at different paths must hash distinct.
        let r = regular_with_hash(5, [0xaa; 32]);
        let ia = FileIdentity::from_squashed(PathBuf::from("usr/bin/foo"), &r);
        let ib = FileIdentity::from_squashed(PathBuf::from("usr/bin/bar"), &r);
        assert_ne!(ia, ib);
    }

    #[test]
    fn identity_is_usable_as_btreemap_key_and_yields_lex_path_order() {
        // The dedup pass needs `FileIdentity` as a map key (spec 05
        // §5.1's grouping). Pin that the derived Ord puts `path`
        // first, which spec 11 §11.6 leans on for lex-iteration
        // determinism.
        let r = regular_with_hash(0, [0; 32]);
        let mut set: BTreeSet<FileIdentity> = BTreeSet::new();
        set.insert(FileIdentity::from_squashed(PathBuf::from("z"), &r));
        set.insert(FileIdentity::from_squashed(PathBuf::from("a"), &r));
        set.insert(FileIdentity::from_squashed(PathBuf::from("m"), &r));
        let paths: Vec<_> = set.iter().map(|i| i.path.to_string_lossy().into_owned()).collect();
        assert_eq!(paths, vec!["a", "m", "z"]);
    }

    #[test]
    fn hardlink_and_regular_with_matching_target_metadata_hash_equal() {
        // Spec 04 §4.2: regular in image A and a hardlink in image B
        // that, after demotion / target lookup, exposes the same
        // identity tuple must dedup. We mimic the post-resolve state:
        // the hardlink in B has been demoted (kind=Regular, hash
        // inherited from target), the regular in A is unchanged.
        // Their identities at the same path must be equal.
        let a = regular_with_hash(20, [0x11; 32]);
        let mut h = entry(EntryKind::Hardlink);
        h.link_target = Some(PathBuf::from("etc/hostname"));
        let demoted = SquashedEntry {
            kind: EntryKind::Regular,
            link_target: None,
            size: 20,
            content_hash: Some([0x11; 32]),
            ..h
        };
        let ia = FileIdentity::from_squashed(PathBuf::from("etc/hostname"), &a);
        let ib = FileIdentity::from_squashed(PathBuf::from("etc/hostname"), &demoted);
        assert_eq!(ia, ib);
    }
}
