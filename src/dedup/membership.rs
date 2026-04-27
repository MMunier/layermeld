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
//! Effective membership (spec 05 §5.1's full formula) is computed by
//! [`effective_membership`] in this same module. It refines naive
//! membership by partitioning each entry's naive set into
//! **ancestor-equivalence classes**: two images sit in the same class
//! iff they agree (byte-equal [`FileIdentity`]) on every strict
//! ancestor of the entry's path. Each class becomes one eff value, and
//! the entry is emitted into one layer per class (its body bytes are
//! duplicated across classes — the price of overlayfs correctness, see
//! spec 05 §5.4).

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

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

/// Compute effective membership per spec 05 §5.1.
///
/// For each entry `e` in `naive`, partitions `naive(e)` into
/// **ancestor-equivalence classes**: two images sit in the same class
/// iff for every strict ancestor `A` of `e.path` they have byte-equal
/// [`FileIdentity`] at `A` (or both lack an entry at `A`).
///
/// The result is a map keyed by the same [`FileIdentity`] tuples as
/// `naive`, mapping each entry to the list of distinct eff classes
/// that the spec 05 §5.2 partition step will use as candidate-layer
/// keys. Every returned class is a non-empty subset of `naive(e)`,
/// the classes are pairwise disjoint, and their union equals
/// `naive(e)` — as required by spec 05 §5.1's "the entry appears once
/// per ancestor-equivalence class" rule.
///
/// Root-level entries (no strict ancestors) yield a single class
/// equal to `naive(e)` itself: the intersection over an empty family
/// of ancestor sets is the universe, and that universe is bounded
/// above by `naive(e)`.
///
/// Per-class iteration order inside each `Vec<ImageSet>` is
/// deterministic (lex over the ancestor-identity tuple), which spec
/// 11 §11.6's reproducibility rule benefits from.
///
/// `images` may be passed in any order: the per-image lookup is keyed
/// off [`SquashedEntry::image_id`] (read from the first entry of each
/// non-empty filesystem) rather than the slice index, mirroring the
/// `image_id`-on-entry convention [`naive_membership`] already uses.
/// Empty filesystems contribute nothing — they cannot appear in any
/// `naive(e)` to begin with — and are simply skipped during lookup-
/// table construction.
///
/// # Panics
///
/// Panics if `naive` references an `image_id` not present in any
/// non-empty `images[i].image_id`. That would mean the caller built
/// `naive` against a different image set than the one passed here, an
/// internal inconsistency this function does not try to recover from.
///
/// [`SquashedEntry::image_id`]: crate::squash::index::SquashedEntry::image_id
#[must_use]
pub fn effective_membership(
    images: &[SquashedFs],
    naive: &BTreeMap<FileIdentity, ImageSet>,
) -> BTreeMap<FileIdentity, Vec<ImageSet>> {
    // Lookup: image_id -> &SquashedFs. Read off the first entry of
    // each non-empty fs (each fs's entries share an image_id by
    // construction in `lib::run`). Empty fses don't appear in any
    // naive(e), so the lookup never needs them.
    let by_id: HashMap<InputImageId, &SquashedFs> = images
        .iter()
        .filter_map(|fs| fs.iter().next().map(|(_, e)| (e.image_id, fs)))
        .collect();

    let mut out: BTreeMap<FileIdentity, Vec<ImageSet>> = BTreeMap::new();
    for (id, naive_set) in naive {
        let ancestors: Vec<&Path> = strict_ancestors(&id.path);

        if ancestors.is_empty() {
            // Spec 05 §5.1: with no strict ancestors the intersection
            // is over an empty family, which leaves naive(e) itself.
            out.insert(id.clone(), vec![naive_set.clone()]);
            continue;
        }

        // Group `naive(e)` by the per-image tuple of ancestor
        // identities. `Option<FileIdentity>` lets a missing ancestor
        // entry act as its own equivalence value — two images that
        // both lack `A` agree on `A`, two that disagree on whether
        // `A` exists end up in different classes. Spec 05 §5.4.4 says
        // a well-formed input never reaches the latter case for any
        // ancestor where `M ⊆ M_eff`, but we don't *enforce*
        // well-formedness here; this is a partition function, not a
        // validator.
        let mut groups: BTreeMap<Vec<Option<FileIdentity>>, Vec<InputImageId>> = BTreeMap::new();
        for image_id in naive_set.iter() {
            let fs = by_id
                .get(&image_id)
                .copied()
                .expect("image_id from naive(e) must resolve to a known SquashedFs");
            let key: Vec<Option<FileIdentity>> = ancestors
                .iter()
                .map(|a| {
                    fs.get(a)
                        .map(|entry| FileIdentity::from_squashed(a.to_path_buf(), entry))
                })
                .collect();
            groups.entry(key).or_default().push(image_id);
        }

        let classes: Vec<ImageSet> = groups.into_values().map(ImageSet::from_ids).collect();
        out.insert(id.clone(), classes);
    }
    out
}

/// Strict ancestors of `path`, excluding `path` itself and the empty
/// (relative-root) path.
///
/// Tar paths in this codebase are stripped of leading `./` and `/`
/// (see `squash::apply`), so the empty path appears as
/// `Path::ancestors()`'s terminal element on every input — filtering
/// it out is the right thing to do uniformly.
///
/// Visible to sibling dedup modules (the partition step in spec 05
/// §5.4.2 needs the same enumeration).
pub(super) fn strict_ancestors(path: &Path) -> Vec<&Path> {
    path.ancestors().skip(1).filter(|a| !a.as_os_str().is_empty()).collect()
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

    // ------------------ effective_membership tests ------------------

    fn dir(image: usize, mode: u32) -> SquashedEntry {
        SquashedEntry {
            mode,
            ..entry(image, EntryKind::Directory)
        }
    }

    /// Look up the only eff class for `path` in `out`, asserting
    /// there is exactly one and returning its [`ImageSet`].
    fn unique_class(out: &BTreeMap<FileIdentity, Vec<ImageSet>>, path: &str) -> ImageSet {
        let key = out
            .keys()
            .find(|k| k.path == Path::new(path))
            .unwrap_or_else(|| panic!("no entry for {path}"));
        let classes = out.get(key).unwrap();
        assert_eq!(classes.len(), 1, "expected one eff class at {path}, got {classes:?}");
        classes[0].clone()
    }

    /// Collect every eff class for `path`, sorted ascending so tests
    /// can assert against a stable order regardless of internal map
    /// iteration order.
    fn classes_at(out: &BTreeMap<FileIdentity, Vec<ImageSet>>, path: &str) -> Vec<ImageSet> {
        let key = out
            .keys()
            .find(|k| k.path == Path::new(path))
            .unwrap_or_else(|| panic!("no entry for {path}"));
        let mut classes = out.get(key).cloned().unwrap();
        classes.sort();
        classes
    }

    #[test]
    fn effective_root_entry_is_one_class_equal_to_naive() {
        // No strict ancestors → single class = naive(e).
        let fs0 = fs_of(0, &[("etc", dir(0, 0o755))]);
        let fs1 = fs_of(1, &[("etc", dir(1, 0o755))]);
        let naive = naive_membership(&[fs0.clone(), fs1.clone()]);
        let eff = effective_membership(&[fs0, fs1], &naive);
        let cls = unique_class(&eff, "etc");
        assert_eq!(cls, ImageSet::from_ids([InputImageId(0), InputImageId(1)]));
    }

    #[test]
    fn effective_when_all_ancestors_agree_equals_naive() {
        // Every image has identical `etc` and `etc/sub` directories.
        // The file `etc/sub/c` is shared too. eff(c) = naive(c).
        let body = regular(0, 1, [0xab; 32]);
        let body1 = SquashedEntry {
            image_id: InputImageId(1),
            ..body.clone()
        };
        let body2 = SquashedEntry {
            image_id: InputImageId(2),
            ..body.clone()
        };
        let mk = |i: usize, b: SquashedEntry| {
            fs_of(
                i,
                &[("etc", dir(i, 0o755)), ("etc/sub", dir(i, 0o755)), ("etc/sub/c", b)],
            )
        };
        let fs0 = mk(0, body);
        let fs1 = mk(1, body1);
        let fs2 = mk(2, body2);
        let naive = naive_membership(&[fs0.clone(), fs1.clone(), fs2.clone()]);
        let eff = effective_membership(&[fs0, fs1, fs2], &naive);
        let cls = unique_class(&eff, "etc/sub/c");
        assert_eq!(
            cls,
            ImageSet::from_ids([InputImageId(0), InputImageId(1), InputImageId(2)])
        );
    }

    #[test]
    fn effective_splits_on_disagreeing_ancestor_mode() {
        // The shadow-problem driver: file is byte-equal across all
        // three images, but image 0's `etc` has mode 0700 while
        // images 1 and 2 use 0755. eff splits naive {0,1,2} into
        // {0} and {1,2}.
        let body0 = regular(0, 1, [0xab; 32]);
        let body1 = SquashedEntry {
            image_id: InputImageId(1),
            ..body0.clone()
        };
        let body2 = SquashedEntry {
            image_id: InputImageId(2),
            ..body0.clone()
        };
        let fs0 = fs_of(0, &[("etc", dir(0, 0o700)), ("etc/c", body0)]);
        let fs1 = fs_of(1, &[("etc", dir(1, 0o755)), ("etc/c", body1)]);
        let fs2 = fs_of(2, &[("etc", dir(2, 0o755)), ("etc/c", body2)]);

        let naive = naive_membership(&[fs0.clone(), fs1.clone(), fs2.clone()]);
        // The body identity at `etc/c` is shared across all three.
        assert_eq!(
            naive
                .iter()
                .find(|(k, _)| k.path == Path::new("etc/c"))
                .map(|(_, v)| v.clone()),
            Some(ImageSet::from_ids([InputImageId(0), InputImageId(1), InputImageId(2)]))
        );

        let eff = effective_membership(&[fs0, fs1, fs2], &naive);
        let mut classes = classes_at(&eff, "etc/c");
        classes.sort();
        assert_eq!(
            classes,
            vec![
                ImageSet::singleton(InputImageId(0)),
                ImageSet::from_ids([InputImageId(1), InputImageId(2)]),
            ]
        );

        // Union of classes equals naive(e) and they are pairwise
        // disjoint — spec 05 §5.1's invariant.
        let mut union = ImageSet::new();
        for c in &classes {
            for id in c.iter() {
                assert!(union.insert(id), "classes must be pairwise disjoint");
            }
        }
        assert_eq!(
            union,
            ImageSet::from_ids([InputImageId(0), InputImageId(1), InputImageId(2)])
        );
    }

    #[test]
    fn effective_handles_multiple_ancestors_disagreeing_at_different_levels() {
        // `a/b/c`. Image 0: a@0700, b@0755. Image 1: a@0755, b@0700.
        // Image 2: a@0755, b@0755. The body c is shared across all.
        // No two images agree on the full ancestor chain, so each
        // image gets its own eff class.
        let body = regular(0, 1, [0xcd; 32]);
        let body1 = SquashedEntry {
            image_id: InputImageId(1),
            ..body.clone()
        };
        let body2 = SquashedEntry {
            image_id: InputImageId(2),
            ..body.clone()
        };
        let fs0 = fs_of(0, &[("a", dir(0, 0o700)), ("a/b", dir(0, 0o755)), ("a/b/c", body)]);
        let fs1 = fs_of(1, &[("a", dir(1, 0o755)), ("a/b", dir(1, 0o700)), ("a/b/c", body1)]);
        let fs2 = fs_of(2, &[("a", dir(2, 0o755)), ("a/b", dir(2, 0o755)), ("a/b/c", body2)]);

        let naive = naive_membership(&[fs0.clone(), fs1.clone(), fs2.clone()]);
        let eff = effective_membership(&[fs0, fs1, fs2], &naive);
        let classes = classes_at(&eff, "a/b/c");
        // Three singleton classes — none of the images agree pairwise
        // on the full ancestor tuple.
        assert_eq!(classes.len(), 3);
        for c in &classes {
            assert_eq!(c.len(), 1);
        }
    }

    #[test]
    fn effective_singleton_naive_yields_singleton_class() {
        // A file that exists only in image 0 has naive = {0}; eff
        // must be {0} regardless of what other images look like.
        let body = regular(0, 1, [0x01; 32]);
        let fs0 = fs_of(0, &[("etc", dir(0, 0o755)), ("etc/c", body)]);
        let fs1 = fs_of(1, &[("etc", dir(1, 0o755))]);
        let naive = naive_membership(&[fs0.clone(), fs1.clone()]);
        let eff = effective_membership(&[fs0, fs1], &naive);
        let cls = unique_class(&eff, "etc/c");
        assert_eq!(cls, ImageSet::singleton(InputImageId(0)));
    }

    #[test]
    fn effective_missing_ancestor_is_its_own_equivalence_value() {
        // Image 0 has `a/c` but no explicit `a` directory entry.
        // Image 1 has both. The body at `a/c` is byte-equal in both.
        // The two images disagree on whether `a` exists (None vs
        // Some(...)), so they end up in different eff classes.
        let body0 = regular(0, 1, [0xee; 32]);
        let body1 = SquashedEntry {
            image_id: InputImageId(1),
            ..body0.clone()
        };
        let fs0 = fs_of(0, &[("a/c", body0)]); // no `a` dir
        let fs1 = fs_of(1, &[("a", dir(1, 0o755)), ("a/c", body1)]);
        let naive = naive_membership(&[fs0.clone(), fs1.clone()]);
        // Body identity is shared.
        assert_eq!(
            naive
                .iter()
                .find(|(k, _)| k.path == Path::new("a/c"))
                .map(|(_, v)| v.clone()),
            Some(ImageSet::from_ids([InputImageId(0), InputImageId(1)]))
        );

        let eff = effective_membership(&[fs0, fs1], &naive);
        let classes = classes_at(&eff, "a/c");
        assert_eq!(classes.len(), 2);
        assert_eq!(
            classes,
            vec![
                ImageSet::singleton(InputImageId(0)),
                ImageSet::singleton(InputImageId(1)),
            ]
        );
    }

    #[test]
    fn effective_invariant_to_image_argument_order() {
        let body0 = regular(0, 1, [0xab; 32]);
        let body1 = SquashedEntry {
            image_id: InputImageId(1),
            ..body0.clone()
        };
        let fs0 = fs_of(0, &[("etc", dir(0, 0o700)), ("etc/c", body0)]);
        let fs1 = fs_of(1, &[("etc", dir(1, 0o755)), ("etc/c", body1)]);
        let naive_fwd = naive_membership(&[fs0.clone(), fs1.clone()]);
        let naive_rev = naive_membership(&[fs1.clone(), fs0.clone()]);
        let eff_fwd = effective_membership(&[fs0.clone(), fs1.clone()], &naive_fwd);
        let eff_rev = effective_membership(&[fs1, fs0], &naive_rev);
        assert_eq!(eff_fwd, eff_rev);
    }

    #[test]
    fn effective_iteration_is_path_lex_ordered() {
        // Spec 11 §11.6 reproducibility. The keys of `effective_membership`
        // are the same FileIdentity tuples as `naive`, so they iterate
        // in lex (path-first) order.
        let fs = fs_of(
            0,
            &[
                ("z", regular(0, 0, [0; 32])),
                ("a", regular(0, 0, [0; 32])),
                ("m", regular(0, 0, [0; 32])),
            ],
        );
        let naive = naive_membership(std::slice::from_ref(&fs));
        let eff = effective_membership(&[fs], &naive);
        let paths: Vec<_> = eff.keys().map(|i| i.path.to_string_lossy().into_owned()).collect();
        assert_eq!(paths, vec!["a", "m", "z"]);
    }

    #[test]
    fn effective_empty_input_yields_empty_map() {
        let eff = effective_membership(&[], &BTreeMap::new());
        assert!(eff.is_empty());
    }

    #[test]
    fn effective_root_directory_entries_get_one_class() {
        // Multiple root-level dirs across images. Each lives in a
        // single class equal to its naive set, since neither has a
        // strict ancestor.
        let fs0 = fs_of(0, &[("etc", dir(0, 0o755)), ("var", dir(0, 0o755))]);
        let fs1 = fs_of(1, &[("etc", dir(1, 0o755)), ("var", dir(1, 0o755))]);
        let naive = naive_membership(&[fs0.clone(), fs1.clone()]);
        let eff = effective_membership(&[fs0, fs1], &naive);
        // Every root-level entry has exactly one eff class.
        for (id, classes) in &eff {
            assert_eq!(classes.len(), 1, "root entry {id:?} should have one class");
        }
    }

    #[test]
    fn effective_classes_partition_naive_set_under_disagreement() {
        // Stress: 4 images, two ancestor-agreement clusters of two.
        // eff splits naive(file)={0,1,2,3} into {0,1} and {2,3}.
        let body = regular(0, 1, [0xde; 32]);
        let mk_body = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..body.clone()
        };
        // Group A: images 0,1 share etc@0700.
        // Group B: images 2,3 share etc@0755.
        let fs0 = fs_of(0, &[("etc", dir(0, 0o700)), ("etc/c", mk_body(0))]);
        let fs1 = fs_of(1, &[("etc", dir(1, 0o700)), ("etc/c", mk_body(1))]);
        let fs2 = fs_of(2, &[("etc", dir(2, 0o755)), ("etc/c", mk_body(2))]);
        let fs3 = fs_of(3, &[("etc", dir(3, 0o755)), ("etc/c", mk_body(3))]);

        let naive = naive_membership(&[fs0.clone(), fs1.clone(), fs2.clone(), fs3.clone()]);
        let eff = effective_membership(&[fs0, fs1, fs2, fs3], &naive);
        let classes = classes_at(&eff, "etc/c");
        assert_eq!(
            classes,
            vec![
                ImageSet::from_ids([InputImageId(0), InputImageId(1)]),
                ImageSet::from_ids([InputImageId(2), InputImageId(3)]),
            ]
        );
    }

    #[test]
    fn effective_subset_of_naive_for_each_class() {
        // Generic invariant: every produced class is ⊆ naive(e).
        let body = regular(0, 1, [0x77; 32]);
        let body1 = SquashedEntry {
            image_id: InputImageId(1),
            ..body.clone()
        };
        let fs0 = fs_of(0, &[("a", dir(0, 0o755)), ("a/c", body)]);
        let fs1 = fs_of(1, &[("a", dir(1, 0o700)), ("a/c", body1)]);
        let naive = naive_membership(&[fs0.clone(), fs1.clone()]);
        let eff = effective_membership(&[fs0, fs1], &naive);
        for (id, classes) in &eff {
            let n = naive.get(id).expect("eff key must come from naive");
            for c in classes {
                assert!(c.is_subset(n), "class {c:?} not a subset of naive {n:?} for {id:?}");
                assert!(!c.is_empty(), "class must be non-empty");
            }
        }
    }

    #[test]
    fn effective_handles_naive_referencing_unrelated_image_slice_ordering() {
        // image_id is read off entries, not slice positions. Pass
        // images out of id order; effective_membership must still
        // resolve ancestor lookups correctly.
        let body0 = regular(0, 1, [0x55; 32]);
        let body2 = SquashedEntry {
            image_id: InputImageId(2),
            ..body0.clone()
        };
        let fs0 = fs_of(0, &[("etc", dir(0, 0o755)), ("etc/c", body0)]);
        let fs2 = fs_of(2, &[("etc", dir(2, 0o755)), ("etc/c", body2)]);

        let naive = naive_membership(&[fs2.clone(), fs0.clone()]);
        let eff = effective_membership(&[fs2, fs0], &naive);
        let cls = unique_class(&eff, "etc/c");
        assert_eq!(cls, ImageSet::from_ids([InputImageId(0), InputImageId(2)]));
    }

    #[test]
    fn strict_ancestors_filters_self_and_empty_root() {
        let a: Vec<&Path> = strict_ancestors(Path::new("etc/sub/c"));
        assert_eq!(a, vec![Path::new("etc/sub"), Path::new("etc")]);

        let b: Vec<&Path> = strict_ancestors(Path::new("etc"));
        assert!(b.is_empty(), "no strict ancestors for a root-level path");

        let c: Vec<&Path> = strict_ancestors(Path::new(""));
        assert!(c.is_empty(), "empty path has no ancestors");
    }
}
