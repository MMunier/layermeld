//! `SquashedFs` map type (spec 03 §3.1).
//!
//! For each input image the squash pass folds its layer stack into a
//! single logical view: the filesystem a process inside a freshly
//! started container would see. That view lives entirely in memory as a
//! [`BTreeMap`]-backed `path -> SquashedEntry` index — never as
//! unpacked bytes on disk (spec 02's no-spool rule).
//!
//! Each [`SquashedEntry`] carries enough header metadata to satisfy
//! spec 04's [`crate::identity::FileIdentity`] builder, plus the
//! `(image_id, layer_idx, entry_idx)` triple that lets spec 07's
//! assemble pass re-open the originating tar entry on a second pass
//! without unpacking. Mtime, uname, and gname are deliberately absent
//! — see spec 06 / spec 04 §4.2.
//!
//! [`SquashedFs`] is intentionally policy-free: it offers the *index*
//! primitives (insert, remove, subtree removal) that spec 03 §3.2's
//! whiteout / opaque-dir handling builds on top of. The
//! whiteout-decoding policy itself lives in [`crate::squash::apply`].
//!
//! Whiteouts and opaque-dir markers move evicted entries into a
//! shadow map rather than discarding them outright. The shadow is a
//! private side channel that spec 03 §3.3 (hardlink resolution) reads
//! when a hardlink's target was whited out from the live view: the
//! evicted regular file's `(image_id, layer_idx, entry_idx)` is the
//! only way the assemble pass can still re-open the body bytes.
//! `insert` clears any shadow record for the path it is overwriting,
//! so a recreated path is genuinely live again.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::tar_io::reader::EntryKind;

/// Index into the run's array of input images.
///
/// One id per input, assigned by [`crate::lib::run`] in argv order.
/// Carried on every [`SquashedEntry`] so the assemble pass can re-open
/// the originating layer's tar stream by `(image_id, layer_idx,
/// entry_idx)` per spec 02 §2.3.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct InputImageId(pub usize);

/// A single entry in the squashed view of an input image.
///
/// Field set is the union of spec 03 §3.1 and what spec 04 §4.1's
/// `FileIdentity` builder consumes. The `(image_id, layer_idx,
/// entry_idx)` triple uniquely names the originating tar entry so the
/// assembler can re-open it (spec 02 §2.3) without keeping a body
/// cursor alive across passes.
#[derive(Debug, Clone)]
pub struct SquashedEntry {
    /// Which input image this entry was squashed from.
    pub image_id: InputImageId,
    /// 0-based index of the layer within that image's manifest
    /// `layers[]` (bottom-up, matching spec 03 §3.2's apply order).
    pub layer_idx: usize,
    /// 0-based index of the entry within its layer's tar stream.
    pub entry_idx: usize,
    /// Normalised entry kind. `Hardlink` survives here so spec 03 §3.3
    /// can resolve / demote it; spec 04 §4.2 collapses it to `Regular`
    /// at identity time.
    pub kind: EntryKind,
    /// Permission bits including setuid/setgid/sticky (spec 03 §3.5).
    pub mode: u32,
    /// Numeric uid (uname is not stored — spec 03 §3.5 / spec 04 §4.2).
    pub uid: u64,
    /// Numeric gid (gname is not stored — spec 03 §3.5 / spec 04 §4.2).
    pub gid: u64,
    /// Body size for regular files; zero for every other kind.
    pub size: u64,
    /// SHA-256 of the body bytes for regular files, computed in a
    /// single streaming pass during [`crate::squash::apply`] (spec 03
    /// §3.4 / spec 04 §4.4). `None` for every non-regular kind, and
    /// also `None` on a freshly-built `Hardlink` entry — spec 03 §3.3
    /// only fills it in if the link is demoted to a regular file, in
    /// which case the demoted entry inherits the chain's terminal
    /// regular-file hash.
    pub content_hash: Option<[u8; 32]>,
    /// PAX `SCHILY.xattr.*` / `LIBARCHIVE.xattr.*` records, prefix
    /// stripped. Kept as bytes because Linux xattr names are not
    /// required to be valid UTF-8 (and matches the byte-keyed map the
    /// reader emits).
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Symlink target or hardlink target path. `None` for every other
    /// kind.
    pub link_target: Option<PathBuf>,
    /// `(major, minor)` for char/block devices, otherwise `None`.
    pub rdev: Option<(u32, u32)>,
}

/// Squashed filesystem index: `path -> SquashedEntry`.
///
/// Backed by a [`BTreeMap`] so iteration is lex-ordered and
/// deterministic, which spec 11 §11.6 leans on for byte-for-byte
/// reproducible output.
#[derive(Debug, Clone, Default)]
pub struct SquashedFs {
    entries: BTreeMap<PathBuf, SquashedEntry>,
    /// Most-recent-alive metadata for paths that were evicted by a
    /// whiteout / opaque-dir marker. Spec 03 §3.3's hardlink
    /// resolution consults this when a link's target is no longer in
    /// the live view, so it can recover the originating
    /// `(image_id, layer_idx, entry_idx)` for body bytes.
    shadow: BTreeMap<PathBuf, SquashedEntry>,
}

impl SquashedFs {
    /// Construct an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries currently in the index.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when the index has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert or overwrite the entry at `path`.
    ///
    /// Returns the previous entry at that path, if any. Spec 03 §3.2's
    /// "regular entry" rule maps directly to a single `insert` call —
    /// directory metadata is replaced but children are untouched
    /// because nothing else references them.
    ///
    /// A successful insert also clears any shadow record at `path`:
    /// the path is live again, so spec 03 §3.3 must not see a stale
    /// pre-whiteout entry there.
    pub fn insert(&mut self, path: PathBuf, entry: SquashedEntry) -> Option<SquashedEntry> {
        self.shadow.remove(&path);
        self.entries.insert(path, entry)
    }

    /// Borrow the entry at `path`, if any.
    #[must_use]
    pub fn get(&self, path: &Path) -> Option<&SquashedEntry> {
        self.entries.get(path)
    }

    /// `true` iff an entry is currently indexed at `path`.
    #[must_use]
    pub fn contains(&self, path: &Path) -> bool {
        self.entries.contains_key(path)
    }

    /// Remove the entry at `path`, if any. Does **not** touch
    /// descendants — see [`Self::remove_subtree`] for whiteout
    /// semantics.
    ///
    /// The removed entry is shadowed (see [`Self::shadow_get`]) so
    /// spec 03 §3.3's hardlink resolution can still find its body
    /// source.
    pub fn remove(&mut self, path: &Path) -> Option<SquashedEntry> {
        let removed = self.entries.remove(path);
        if let Some(entry) = &removed {
            self.shadow.insert(path.to_path_buf(), entry.clone());
        }
        removed
    }

    /// Remove `path` and every strict descendant.
    ///
    /// This is the index primitive that spec 03 §3.2's whiteout
    /// (`dir/.wh.name`) decodes into: delete the named entry, and if
    /// it was a directory, sweep everything underneath. Returns the
    /// total number of entries removed (including `path` itself, if
    /// present), which the apply pass uses to detect no-op whiteouts.
    ///
    /// Each evicted entry is shadowed so spec 03 §3.3 can recover
    /// body sources for hardlinks whose target was inside this
    /// subtree.
    pub fn remove_subtree(&mut self, path: &Path) -> usize {
        let to_remove = self.descendants_and_self(path);
        let removed = to_remove.len();
        for p in to_remove {
            if let Some(entry) = self.entries.remove(&p) {
                self.shadow.insert(p, entry);
            }
        }
        removed
    }

    /// Remove every strict descendant of `dir`, leaving `dir` itself
    /// in place.
    ///
    /// This is the index primitive that spec 03 §3.2's opaque-directory
    /// marker (`.wh..wh..opq`) decodes into: hide every child of the
    /// containing directory while keeping the directory's own metadata.
    /// Returns the number of descendants removed.
    ///
    /// Each evicted descendant is shadowed so spec 03 §3.3 can
    /// recover body sources for surviving hardlinks that pointed
    /// inside the cleared subtree.
    pub fn clear_subtree(&mut self, dir: &Path) -> usize {
        let to_remove: Vec<PathBuf> = self
            .entries
            .keys()
            .filter(|k| is_strict_descendant(k, dir))
            .cloned()
            .collect();
        let removed = to_remove.len();
        for p in to_remove {
            if let Some(entry) = self.entries.remove(&p) {
                self.shadow.insert(p, entry);
            }
        }
        removed
    }

    /// Borrow the shadow record at `path`, if any.
    ///
    /// The shadow holds entries that were evicted from the live view
    /// by a whiteout or opaque-dir marker. Spec 03 §3.3 uses this to
    /// find body sources for hardlinks whose direct target is no
    /// longer in [`Self::get`]. Outside of hardlink resolution there
    /// is no reason to consult it — the shadow is *not* part of the
    /// container-visible filesystem.
    #[must_use]
    pub fn shadow_get(&self, path: &Path) -> Option<&SquashedEntry> {
        self.shadow.get(path)
    }

    /// Iterate `(path, entry)` in lex order.
    pub fn iter(&self) -> impl Iterator<Item = (&PathBuf, &SquashedEntry)> {
        self.entries.iter()
    }

    /// Iterate paths in lex order.
    pub fn paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.entries.keys()
    }

    fn descendants_and_self(&self, path: &Path) -> Vec<PathBuf> {
        self.entries
            .keys()
            .filter(|k| k.as_path() == path || is_strict_descendant(k, path))
            .cloned()
            .collect()
    }
}

/// `true` iff `candidate` is a strict descendant of `ancestor`.
///
/// Component-wise comparison so `etc/hostname` is *not* a descendant of
/// `etc/host` (which a naïve `starts_with` on string bytes would get
/// wrong).
fn is_strict_descendant(candidate: &Path, ancestor: &Path) -> bool {
    if candidate == ancestor {
        return false;
    }
    let mut cands = candidate.components();
    for anc in ancestor.components() {
        if cands.next() != Some(anc) {
            return false;
        }
    }
    // At least one further component must remain to qualify as a
    // *strict* descendant.
    cands.next().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(layer_idx: usize, entry_idx: usize, kind: EntryKind) -> SquashedEntry {
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

    #[test]
    fn new_is_empty() {
        let fs = SquashedFs::new();
        assert!(fs.is_empty());
        assert_eq!(fs.len(), 0);
        assert!(fs.iter().next().is_none());
    }

    #[test]
    fn insert_then_get_round_trips() {
        let mut fs = SquashedFs::new();
        let prev = fs.insert(PathBuf::from("etc/hostname"), entry(0, 1, EntryKind::Regular));
        assert!(prev.is_none());
        let got = fs.get(Path::new("etc/hostname")).unwrap();
        assert_eq!(got.layer_idx, 0);
        assert_eq!(got.entry_idx, 1);
        assert_eq!(got.kind, EntryKind::Regular);
        assert!(fs.contains(Path::new("etc/hostname")));
        assert_eq!(fs.len(), 1);
    }

    #[test]
    fn insert_overwrites_and_returns_previous() {
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("a"), entry(0, 0, EntryKind::Regular));
        let prev = fs
            .insert(PathBuf::from("a"), entry(2, 9, EntryKind::Regular))
            .expect("previous entry should be returned");
        assert_eq!(prev.layer_idx, 0);
        let got = fs.get(Path::new("a")).unwrap();
        assert_eq!(got.layer_idx, 2);
        assert_eq!(got.entry_idx, 9);
        // Overwrite must not duplicate.
        assert_eq!(fs.len(), 1);
    }

    #[test]
    fn remove_drops_only_the_named_path() {
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("etc/hostname"), entry(0, 0, EntryKind::Regular));
        fs.insert(PathBuf::from("etc/hosts"), entry(0, 1, EntryKind::Regular));
        let removed = fs.remove(Path::new("etc/hostname")).expect("present");
        assert_eq!(removed.entry_idx, 0);
        assert!(!fs.contains(Path::new("etc/hostname")));
        assert!(fs.contains(Path::new("etc/hosts")));
        assert_eq!(fs.len(), 1);
    }

    #[test]
    fn remove_missing_returns_none() {
        let mut fs = SquashedFs::new();
        assert!(fs.remove(Path::new("nope")).is_none());
    }

    #[test]
    fn remove_subtree_drops_path_and_descendants() {
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("var"), entry(0, 0, EntryKind::Directory));
        fs.insert(PathBuf::from("var/log"), entry(0, 1, EntryKind::Directory));
        fs.insert(PathBuf::from("var/log/syslog"), entry(0, 2, EntryKind::Regular));
        fs.insert(PathBuf::from("var/run"), entry(0, 3, EntryKind::Directory));
        fs.insert(PathBuf::from("etc"), entry(0, 4, EntryKind::Directory));

        let removed = fs.remove_subtree(Path::new("var/log"));
        assert_eq!(removed, 2, "var/log + var/log/syslog");
        assert!(!fs.contains(Path::new("var/log")));
        assert!(!fs.contains(Path::new("var/log/syslog")));
        // Sibling untouched.
        assert!(fs.contains(Path::new("var/run")));
        // Parent untouched.
        assert!(fs.contains(Path::new("var")));
        // Unrelated subtree untouched.
        assert!(fs.contains(Path::new("etc")));
    }

    #[test]
    fn remove_subtree_returns_zero_for_missing_path() {
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("etc"), entry(0, 0, EntryKind::Directory));
        assert_eq!(fs.remove_subtree(Path::new("nope")), 0);
        assert_eq!(fs.len(), 1);
    }

    #[test]
    fn remove_subtree_does_not_touch_prefix_lookalikes() {
        // Naïve byte-prefix matching would incorrectly treat
        // `etc/hostname` as a descendant of `etc/host`.
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("etc/host"), entry(0, 0, EntryKind::Regular));
        fs.insert(PathBuf::from("etc/hostname"), entry(0, 1, EntryKind::Regular));
        let removed = fs.remove_subtree(Path::new("etc/host"));
        assert_eq!(removed, 1);
        assert!(!fs.contains(Path::new("etc/host")));
        assert!(fs.contains(Path::new("etc/hostname")));
    }

    #[test]
    fn clear_subtree_drops_descendants_only() {
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("var"), entry(0, 0, EntryKind::Directory));
        fs.insert(PathBuf::from("var/log"), entry(0, 1, EntryKind::Directory));
        fs.insert(PathBuf::from("var/log/syslog"), entry(0, 2, EntryKind::Regular));
        fs.insert(PathBuf::from("var/run"), entry(0, 3, EntryKind::Directory));
        fs.insert(PathBuf::from("etc"), entry(0, 4, EntryKind::Directory));

        let removed = fs.clear_subtree(Path::new("var"));
        assert_eq!(removed, 3, "var/log + var/log/syslog + var/run");
        // The directory itself stays — opaque-dir markers hide children, not the dir.
        assert!(fs.contains(Path::new("var")));
        assert!(!fs.contains(Path::new("var/log")));
        assert!(!fs.contains(Path::new("var/log/syslog")));
        assert!(!fs.contains(Path::new("var/run")));
        assert!(fs.contains(Path::new("etc")));
    }

    #[test]
    fn clear_subtree_on_missing_dir_is_noop() {
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("etc"), entry(0, 0, EntryKind::Directory));
        // Even when the dir is absent, every existing path is checked
        // against it; the operation simply finds no descendants.
        assert_eq!(fs.clear_subtree(Path::new("nope")), 0);
        assert_eq!(fs.len(), 1);
    }

    #[test]
    fn iter_is_lex_ordered() {
        let mut fs = SquashedFs::new();
        // Insert in non-sorted order; BTreeMap must yield sorted.
        fs.insert(PathBuf::from("etc/hosts"), entry(0, 0, EntryKind::Regular));
        fs.insert(PathBuf::from("bin/sh"), entry(0, 1, EntryKind::Regular));
        fs.insert(PathBuf::from("etc/hostname"), entry(0, 2, EntryKind::Regular));
        let paths: Vec<_> = fs.paths().map(|p| p.to_string_lossy().into_owned()).collect();
        assert_eq!(paths, vec!["bin/sh", "etc/hostname", "etc/hosts"]);
    }

    #[test]
    fn iter_yields_matching_entries() {
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("a"), entry(0, 5, EntryKind::Regular));
        fs.insert(PathBuf::from("b"), entry(1, 7, EntryKind::Directory));
        let collected: Vec<_> = fs
            .iter()
            .map(|(p, e)| (p.to_string_lossy().into_owned(), e.entry_idx))
            .collect();
        assert_eq!(collected, vec![("a".to_owned(), 5), ("b".to_owned(), 7)]);
    }

    #[test]
    fn xattrs_and_link_target_are_preserved_verbatim() {
        let mut e = entry(0, 0, EntryKind::Symlink);
        e.link_target = Some(PathBuf::from("hostname"));
        e.xattrs.insert(b"user.flag".to_vec(), b"on".to_vec());
        e.xattrs.insert(b"security.capability".to_vec(), vec![1, 2, 3]);

        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("etc/hostname.link"), e);
        let got = fs.get(Path::new("etc/hostname.link")).unwrap();
        assert_eq!(got.kind, EntryKind::Symlink);
        assert_eq!(got.link_target.as_deref(), Some(Path::new("hostname")));
        assert_eq!(got.xattrs.len(), 2);
        assert_eq!(
            got.xattrs.get(b"user.flag".as_slice()).map(Vec::as_slice),
            Some(&b"on"[..])
        );
        assert_eq!(
            got.xattrs.get(b"security.capability".as_slice()).map(Vec::as_slice),
            Some(&[1, 2, 3][..])
        );
    }

    #[test]
    fn rdev_is_carried_for_devices() {
        let mut e = entry(0, 0, EntryKind::CharDevice);
        e.rdev = Some((1, 3));
        let mut fs = SquashedFs::new();
        fs.insert(PathBuf::from("dev/null"), e);
        assert_eq!(fs.get(Path::new("dev/null")).unwrap().rdev, Some((1, 3)));
    }

    #[test]
    fn input_image_id_is_orderable_and_hashable() {
        // Sanity: derives compile and behave so callers can use it as
        // a map key / sort key in dedup (spec 05).
        use std::collections::BTreeSet;
        let mut s = BTreeSet::new();
        s.insert(InputImageId(2));
        s.insert(InputImageId(0));
        s.insert(InputImageId(1));
        s.insert(InputImageId(0)); // duplicate
        let collected: Vec<_> = s.into_iter().map(|id| id.0).collect();
        assert_eq!(collected, vec![0, 1, 2]);
    }

    #[test]
    fn is_strict_descendant_handles_components() {
        assert!(is_strict_descendant(Path::new("var/log"), Path::new("var")));
        assert!(is_strict_descendant(Path::new("var/log/sys"), Path::new("var")));
        assert!(!is_strict_descendant(Path::new("var"), Path::new("var")));
        assert!(!is_strict_descendant(Path::new("var"), Path::new("var/log")));
        assert!(!is_strict_descendant(Path::new("etc/hostname"), Path::new("etc/host")));
        assert!(!is_strict_descendant(Path::new("etc"), Path::new("var")));
    }
}
