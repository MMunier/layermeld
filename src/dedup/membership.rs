//! Naive + effective membership (spec 05 §5.1).
//!
//! For every entry `e` in the union of squashed-fs indexes, spec 05
//! §5.1 defines its **naive membership** as the set of input images
//! that contain a byte-equal [`FileIdentity`] at the same path:
//!
//! ```text
//! naive(e) = { i ∈ 0..N : e ∈ entries(i) }
//! ```
//!
//! Path is part of identity (spec 04 §4.3) so "byte-equal at the same
//! path" reduces to "the [`FileIdentity`] tuples are equal" — the
//! grouping key is therefore [`FileIdentity`] itself, with no separate
//! path field tracked alongside.
//!
//! This module is the policy-free arithmetic layer: it groups entries
//! by identity and reports the membership sets. The spec 05 §5.6
//! "hardlinks always go to per-image layers" rule is *not* applied
//! here — it is a placement decision the spec 05 §5.4 partition step
//! handles. Naive membership is computed for hardlinks too, since
//! [`FileIdentity::from_squashed`] collapses them to `Regular` per spec
//! 04 §4.2 last bullet, and the spec's `eff` formula in §5.1 is defined
//! for every entry uniformly.
//!
//! Effective membership (spec 05 §5.1's full formula) lives in this
//! same module — see the next subtask in `TODO.md`.

use std::collections::BTreeMap;

use crate::identity::FileIdentity;
use crate::squash::index::{InputImageId, SquashedFs};

/// Sorted, deduplicated set of [`InputImageId`]s.
///
/// Used as both the naive-membership and effective-membership value
/// type, and (in the partition step, spec 05 §5.2) as a map key
/// identifying a candidate output layer. The internal representation
/// is a sorted `Vec` so that:
///
/// * `Eq + Hash + Ord` derive cleanly and produce a canonical bit-by-bit
///   identical encoding for equal sets — the partition keys this on.
/// * Set intersection (the spec 05 §5.1 effective-membership formula's
///   `∩`) is a linear merge of two sorted runs.
/// * `len()` is the spec 05 §5.3 sort key (descending `|M|`); the lex
///   tiebreaker falls out of the derived `Ord`.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Default)]
pub struct ImageSet {
    ids: Vec<InputImageId>,
}

impl ImageSet {
    /// Empty set. Equivalent to [`Self::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Singleton `{id}`.
    #[must_use]
    pub fn singleton(id: InputImageId) -> Self {
        Self { ids: vec![id] }
    }

    /// Build from a possibly-unsorted, possibly-duplicated iterator.
    /// Output is canonicalised: sorted ascending and deduplicated.
    pub fn from_ids<I: IntoIterator<Item = InputImageId>>(iter: I) -> Self {
        let mut ids: Vec<_> = iter.into_iter().collect();
        ids.sort();
        ids.dedup();
        Self { ids }
    }

    /// Number of images in the set — spec 05 §5.3's `|M|`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// `true` iff the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// `true` iff `id` is in the set.
    #[must_use]
    pub fn contains(&self, id: InputImageId) -> bool {
        self.ids.binary_search(&id).is_ok()
    }

    /// Iterate ids in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = InputImageId> + '_ {
        self.ids.iter().copied()
    }

    /// Insert `id`, returning `true` iff it was not already present.
    /// Maintains the sorted-deduplicated invariant.
    pub fn insert(&mut self, id: InputImageId) -> bool {
        match self.ids.binary_search(&id) {
            Ok(_) => false,
            Err(i) => {
                self.ids.insert(i, id);
                true
            }
        }
    }

    /// Set intersection. Linear-time merge of two sorted runs.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        let mut out = Vec::with_capacity(self.ids.len().min(other.ids.len()));
        let (mut i, mut j) = (0usize, 0usize);
        while i < self.ids.len() && j < other.ids.len() {
            match self.ids[i].cmp(&other.ids[j]) {
                std::cmp::Ordering::Less => i += 1,
                std::cmp::Ordering::Greater => j += 1,
                std::cmp::Ordering::Equal => {
                    out.push(self.ids[i]);
                    i += 1;
                    j += 1;
                }
            }
        }
        Self { ids: out }
    }

    /// `true` iff `self ⊆ other`.
    #[must_use]
    pub fn is_subset(&self, other: &Self) -> bool {
        let (mut i, mut j) = (0usize, 0usize);
        while i < self.ids.len() && j < other.ids.len() {
            match self.ids[i].cmp(&other.ids[j]) {
                std::cmp::Ordering::Less => return false,
                std::cmp::Ordering::Greater => j += 1,
                std::cmp::Ordering::Equal => {
                    i += 1;
                    j += 1;
                }
            }
        }
        i == self.ids.len()
    }
}

/// Compute naive membership per spec 05 §5.1.
///
/// Visits every `(path, entry)` pair across every input squashed
/// filesystem, builds the [`FileIdentity`] for each, and accumulates
/// the set of image ids that present that identity at that path.
///
/// The image id is read from each entry's
/// [`crate::squash::index::SquashedEntry::image_id`] — `lib::run`
/// stamps that field at squash time. The slice index is *not* used as
/// a fallback id, because callers may pass squashed images in any
/// order; the entry's `image_id` is the authoritative naming.
///
/// Result iteration order is lex over [`FileIdentity`] (path-first per
/// spec 04 §4.1's `Ord`), which matches the determinism rule in spec
/// 11 §11.6 — useful both for tests and for downstream stages that
/// stream the grouping out.
#[must_use]
pub fn naive_membership(images: &[SquashedFs]) -> BTreeMap<FileIdentity, ImageSet> {
    let mut out: BTreeMap<FileIdentity, ImageSet> = BTreeMap::new();
    for fs in images {
        for (path, entry) in fs.iter() {
            let id = FileIdentity::from_squashed(path.clone(), entry);
            out.entry(id).or_default().insert(entry.image_id);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::*;
    use crate::squash::index::{InputImageId, SquashedEntry, SquashedFs};
    use crate::tar_io::reader::EntryKind;

    fn entry(image: usize, kind: EntryKind) -> SquashedEntry {
        SquashedEntry {
            image_id: InputImageId(image),
            layer_idx: 0,
            entry_idx: 0,
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

    fn regular(image: usize, size: u64, hash: [u8; 32]) -> SquashedEntry {
        SquashedEntry {
            size,
            content_hash: Some(hash),
            ..entry(image, EntryKind::Regular)
        }
    }

    fn fs_of(image: usize, items: &[(&str, SquashedEntry)]) -> SquashedFs {
        let mut fs = SquashedFs::new();
        for (path, e) in items {
            assert_eq!(e.image_id.0, image, "test setup: image_id must match fs id");
            fs.insert(PathBuf::from(*path), e.clone());
        }
        fs
    }

    // ------------------ ImageSet tests ------------------

    #[test]
    fn image_set_default_is_empty() {
        let s = ImageSet::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.iter().count(), 0);
    }

    #[test]
    fn image_set_from_ids_sorts_and_dedups() {
        let s = ImageSet::from_ids([InputImageId(2), InputImageId(0), InputImageId(2), InputImageId(1)]);
        let got: Vec<_> = s.iter().map(|i| i.0).collect();
        assert_eq!(got, vec![0, 1, 2]);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn image_set_singleton_and_contains() {
        let s = ImageSet::singleton(InputImageId(5));
        assert!(s.contains(InputImageId(5)));
        assert!(!s.contains(InputImageId(0)));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn image_set_insert_returns_whether_new() {
        let mut s = ImageSet::new();
        assert!(s.insert(InputImageId(1)));
        assert!(s.insert(InputImageId(0)));
        assert!(!s.insert(InputImageId(1))); // duplicate
        let got: Vec<_> = s.iter().map(|i| i.0).collect();
        assert_eq!(got, vec![0, 1]);
    }

    #[test]
    fn image_set_intersect_is_set_intersection() {
        let a = ImageSet::from_ids([InputImageId(0), InputImageId(1), InputImageId(3)]);
        let b = ImageSet::from_ids([InputImageId(1), InputImageId(2), InputImageId(3)]);
        let got: Vec<_> = a.intersect(&b).iter().map(|i| i.0).collect();
        assert_eq!(got, vec![1, 3]);
    }

    #[test]
    fn image_set_intersect_with_empty_is_empty() {
        let a = ImageSet::from_ids([InputImageId(0), InputImageId(1)]);
        let empty = ImageSet::new();
        assert!(a.intersect(&empty).is_empty());
        assert!(empty.intersect(&a).is_empty());
    }

    #[test]
    fn image_set_intersect_disjoint_is_empty() {
        let a = ImageSet::from_ids([InputImageId(0), InputImageId(2)]);
        let b = ImageSet::from_ids([InputImageId(1), InputImageId(3)]);
        assert!(a.intersect(&b).is_empty());
    }

    #[test]
    fn image_set_intersect_self_is_self() {
        let a = ImageSet::from_ids([InputImageId(7), InputImageId(2), InputImageId(5)]);
        assert_eq!(a.intersect(&a), a);
    }

    #[test]
    fn image_set_is_subset_handles_edges() {
        let empty = ImageSet::new();
        let a = ImageSet::from_ids([InputImageId(0), InputImageId(1)]);
        let b = ImageSet::from_ids([InputImageId(0), InputImageId(1), InputImageId(2)]);
        let c = ImageSet::from_ids([InputImageId(2), InputImageId(3)]);

        assert!(empty.is_subset(&a));
        assert!(a.is_subset(&a));
        assert!(a.is_subset(&b));
        assert!(!b.is_subset(&a));
        assert!(!a.is_subset(&c));
        assert!(!c.is_subset(&a));
    }

    #[test]
    fn image_set_eq_ignores_construction_order() {
        let a = ImageSet::from_ids([InputImageId(1), InputImageId(0), InputImageId(2)]);
        let b = ImageSet::from_ids([InputImageId(2), InputImageId(0), InputImageId(1)]);
        assert_eq!(a, b);
    }

    #[test]
    fn image_set_ord_is_descending_len_friendly() {
        // The derived Ord is lex on the sorted Vec — *not* by len.
        // Spec 05 §5.3 sort key is descending len with lex as
        // tiebreaker; the partition step is responsible for combining
        // them. Pin the lex behaviour here so we know what we have.
        let small = ImageSet::from_ids([InputImageId(0)]);
        let big = ImageSet::from_ids([InputImageId(0), InputImageId(1)]);
        assert!(small < big, "lex: same prefix, shorter is smaller");

        let a = ImageSet::from_ids([InputImageId(0), InputImageId(2)]);
        let b = ImageSet::from_ids([InputImageId(1)]);
        assert!(a < b, "lex on first element wins");
    }

    #[test]
    fn image_set_is_hashable() {
        // Partition uses ImageSet as a HashMap key.
        use std::collections::HashSet;
        let mut s: HashSet<ImageSet> = HashSet::new();
        s.insert(ImageSet::from_ids([InputImageId(0), InputImageId(1)]));
        assert!(s.contains(&ImageSet::from_ids([InputImageId(1), InputImageId(0)])));
        assert!(!s.contains(&ImageSet::from_ids([InputImageId(0)])));
    }

    // ------------------ naive_membership tests ------------------

    #[test]
    fn naive_membership_empty_input_is_empty_map() {
        let out = naive_membership(&[]);
        assert!(out.is_empty());
    }

    #[test]
    fn naive_membership_empty_filesystems_yield_empty_map() {
        let out = naive_membership(&[SquashedFs::new(), SquashedFs::new()]);
        assert!(out.is_empty());
    }

    #[test]
    fn naive_membership_single_image_singletons_only() {
        let fs = fs_of(
            0,
            &[
                ("etc/hostname", regular(0, 5, [0xaa; 32])),
                ("usr/bin/sh", regular(0, 100, [0xbb; 32])),
            ],
        );
        let out = naive_membership(&[fs]);
        assert_eq!(out.len(), 2);
        for set in out.values() {
            assert_eq!(set, &ImageSet::singleton(InputImageId(0)));
        }
    }

    #[test]
    fn naive_membership_groups_byte_equal_identities_across_images() {
        let shared = regular(0, 42, [0xab; 32]);
        let shared_b = SquashedEntry {
            image_id: InputImageId(1),
            ..shared.clone()
        };
        let fs0 = fs_of(0, &[("etc/hostname", shared)]);
        let fs1 = fs_of(1, &[("etc/hostname", shared_b)]);

        let out = naive_membership(&[fs0, fs1]);
        assert_eq!(out.len(), 1, "byte-equal identity collapses across images");
        let set = out.values().next().unwrap();
        assert_eq!(*set, ImageSet::from_ids([InputImageId(0), InputImageId(1)]));
    }

    #[test]
    fn naive_membership_differs_on_content_hash() {
        let a = regular(0, 5, [0xaa; 32]);
        let b = regular(1, 5, [0xbb; 32]);
        let fs0 = fs_of(0, &[("etc/hostname", a)]);
        let fs1 = fs_of(1, &[("etc/hostname", b)]);

        let out = naive_membership(&[fs0, fs1]);
        assert_eq!(out.len(), 2, "different content_hash → different identities");
        for set in out.values() {
            assert_eq!(set.len(), 1);
        }
    }

    #[test]
    fn naive_membership_differs_on_path() {
        // Path is part of identity (spec 04 §4.3).
        let body = regular(0, 5, [0xaa; 32]);
        let body_b = SquashedEntry {
            image_id: InputImageId(1),
            ..body.clone()
        };
        let fs0 = fs_of(0, &[("etc/hostname", body)]);
        let fs1 = fs_of(1, &[("etc/hosts", body_b)]);

        let out = naive_membership(&[fs0, fs1]);
        assert_eq!(out.len(), 2);
        // Each identity is local to its image.
        for (id, set) in &out {
            let expected = if id.path == std::path::Path::new("etc/hostname") {
                ImageSet::singleton(InputImageId(0))
            } else {
                ImageSet::singleton(InputImageId(1))
            };
            assert_eq!(set, &expected);
        }
    }

    #[test]
    fn naive_membership_three_images_partial_overlap() {
        // Same identity in {0,2}, different in 1, plus per-image content.
        let shared = regular(0, 1, [0x01; 32]);
        let shared_in_2 = SquashedEntry {
            image_id: InputImageId(2),
            ..shared.clone()
        };
        // Image 1 has a different body at the same path.
        let other = regular(1, 1, [0x02; 32]);

        let fs0 = fs_of(0, &[("a", shared.clone()), ("b", regular(0, 0, [0x10; 32]))]);
        let fs1 = fs_of(1, &[("a", other)]);
        let fs2 = fs_of(2, &[("a", shared_in_2), ("c", regular(2, 0, [0x20; 32]))]);

        let out = naive_membership(&[fs0, fs1, fs2]);
        // Distinct identities: shared@a (in 0,2), other@a (in 1),
        // b@0 (in 0), c@2 (in 2). Total 4.
        assert_eq!(out.len(), 4);

        let mut counts_by_set: BTreeMap<Vec<usize>, usize> = BTreeMap::new();
        for set in out.values() {
            let key: Vec<usize> = set.iter().map(|i| i.0).collect();
            *counts_by_set.entry(key).or_default() += 1;
        }
        // {0,2} appears once (shared@a), {0} once (b), {1} once (a in 1), {2} once (c).
        assert_eq!(counts_by_set.get(&vec![0, 2]).copied(), Some(1));
        assert_eq!(counts_by_set.get(&vec![0]).copied(), Some(1));
        assert_eq!(counts_by_set.get(&vec![1]).copied(), Some(1));
        assert_eq!(counts_by_set.get(&vec![2]).copied(), Some(1));
    }

    #[test]
    fn naive_membership_invariant_to_image_argument_order() {
        // The image_id is read off the entry, not the slice index, so
        // shuffling the input slice must not change the result.
        let a = regular(0, 1, [0xaa; 32]);
        let b = SquashedEntry {
            image_id: InputImageId(1),
            ..a.clone()
        };
        let fs0 = fs_of(0, &[("p", a)]);
        let fs1 = fs_of(1, &[("p", b)]);

        let out_forward = naive_membership(&[fs0.clone(), fs1.clone()]);
        let out_reversed = naive_membership(&[fs1, fs0]);
        assert_eq!(out_forward, out_reversed);
    }

    #[test]
    fn naive_membership_groups_hardlink_with_regular_target() {
        // Spec 04 §4.2 collapses Hardlink to Regular at identity time,
        // so a hardlink in image B at the same path with the same
        // post-collapse identity as a regular file in image A groups
        // with it. Spec 05 §5.6 (per-image placement) is a *partition*
        // concern, not a membership concern.
        let reg = regular(0, 0, [0xcd; 32]); // hardlinks survive with size=0/hash=None most often,
        // but to drive the dedup we model the case where the demoted
        // hardlink (from spec 03 §3.3) carries the target's hash.
        let hl_demoted = SquashedEntry {
            image_id: InputImageId(1),
            kind: EntryKind::Regular,
            link_target: None,
            ..reg.clone()
        };
        let fs0 = fs_of(0, &[("p", reg)]);
        let fs1 = fs_of(1, &[("p", hl_demoted)]);
        let out = naive_membership(&[fs0, fs1]);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out.values().next().unwrap(),
            &ImageSet::from_ids([InputImageId(0), InputImageId(1)])
        );
    }

    #[test]
    fn naive_membership_iteration_is_path_lex_ordered() {
        // Spec 11 §11.6 wants deterministic iteration.
        let fs = fs_of(
            0,
            &[
                ("z", regular(0, 0, [0; 32])),
                ("a", regular(0, 0, [0; 32])),
                ("m", regular(0, 0, [0; 32])),
            ],
        );
        let out = naive_membership(&[fs]);
        let paths: Vec<_> = out.keys().map(|i| i.path.to_string_lossy().into_owned()).collect();
        assert_eq!(paths, vec!["a", "m", "z"]);
    }

    #[test]
    fn naive_membership_directories_and_symlinks_group_normally() {
        // Membership is computed for every kind, not just regulars.
        // A directory with the same metadata in two images should
        // share an identity.
        let dir0 = entry(0, EntryKind::Directory);
        let dir1 = entry(1, EntryKind::Directory);
        let mut sym0 = entry(0, EntryKind::Symlink);
        sym0.link_target = Some(PathBuf::from("hostname"));
        let mut sym1 = entry(1, EntryKind::Symlink);
        sym1.link_target = Some(PathBuf::from("hostname"));

        let fs0 = fs_of(0, &[("etc", dir0), ("etc/host.alias", sym0)]);
        let fs1 = fs_of(1, &[("etc", dir1), ("etc/host.alias", sym1)]);

        let out = naive_membership(&[fs0, fs1]);
        assert_eq!(out.len(), 2);
        for set in out.values() {
            assert_eq!(*set, ImageSet::from_ids([InputImageId(0), InputImageId(1)]));
        }
    }
}
