//! Subset-layer partition construction (spec 05 §5.2, §5.4).
//!
//! Given the per-image [`SquashedFs`] views and the
//! [`effective_membership`](super::membership::effective_membership) map,
//! this module produces one [`CandidateLayer`] per distinct non-empty
//! `eff` value. Each layer carries the entries that the spec 07 assemble
//! pass will emit as a single tar blob.
//!
//! ## What lives in a layer
//!
//! * **Files** (every kind that is not a directory or hardlink). Placed
//!   into `L(M_eff)` per spec 05 §5.4.2 rule 1. A file whose naive
//!   membership splits into multiple ancestor-equivalence classes
//!   appears once per class — its body bytes are duplicated across
//!   those classes' layers (spec 05 §5.1).
//! * **Directories.** Placed into their natural layer `L(M_D)`, AND
//!   into every smaller subset layer `L(M) ⊆ M_D` whose contents
//!   include any descendant of the directory (spec 05 §5.4.2 rule 2).
//!   Every emission uses the same single [`SquashedEntry`]'s metadata
//!   — by spec 05 §5.4.4 that metadata is byte-equal across every
//!   image in `M_D`, so the choice of source image doesn't change the
//!   output.
//! * **Hardlinks.** Always placed in the per-image layer `L({i})` per
//!   spec 05 §5.6, regardless of what eff says about the
//!   identity-collapsed version.
//!
//! ## Source records
//!
//! Each entry in a [`CandidateLayer`] is a [`SquashedEntry`] carrying
//! the full `(image_id, layer_idx, entry_idx)` triple the assemble pass
//! needs to re-open body bytes (spec 02 §2.3). When multiple images in
//! a layer's membership all carry byte-equal entries at the same path
//! (which is the *definition* of an eff class), the stored source is
//! deterministic: the entry from the smallest [`InputImageId`] wins.
//! Metadata is identical across the choices — only the bookkeeping
//! triple differs — so picking a canonical one keeps the output
//! reproducible (spec 11 §11.6).
//!
//! ## Determinism
//!
//! The result is a [`BTreeMap`] keyed on [`ImageSet`], iterated in lex
//! order over the sorted internal `Vec`. Inside each layer, entries
//! iterate in lex path order (also `BTreeMap`-backed). This matches
//! spec 11 §11.6's reproducibility rule and is what spec 05 §5.3's
//! per-image stack ordering will then re-key by descending `|M|` with
//! lex tiebreak.

use std::collections::btree_map::Entry::{Occupied, Vacant};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use crate::identity::FileIdentity;
use crate::squash::index::{InputImageId, SquashedEntry, SquashedFs};
use crate::tar_io::reader::EntryKind;

use super::membership::{ImageSet, strict_ancestors};

/// One candidate output layer: a membership set plus the entries it
/// carries.
///
/// Entries are keyed by path and stored as [`SquashedEntry`] clones so
/// the assemble pass has the originating `(image_id, layer_idx,
/// entry_idx)` triple plus all the metadata the spec 07 tar writer
/// needs without having to re-traverse the input squash indexes.
#[derive(Debug, Clone)]
pub struct CandidateLayer {
    /// The eff-class this layer is `L(M)` for. Every entry in
    /// [`Self::entries`] is either:
    /// * a file with `M_eff(file) == membership` (spec 05 §5.4.2
    ///   rule 1), or
    /// * a directory present because `membership ⊆ M_D` and at least
    ///   one descendant of the directory lives in this layer (spec 05
    ///   §5.4.2 rule 2), or
    /// * a hardlink with `membership == singleton(image_id)` (spec
    ///   05 §5.6).
    pub membership: ImageSet,
    /// `path -> source SquashedEntry`. Lex-ordered iteration falls
    /// out of the `BTreeMap` backing.
    pub entries: BTreeMap<PathBuf, SquashedEntry>,
}

/// Build the spec 05 §5.2 candidate-layer partition.
///
/// `images` and `eff` must be consistent: every [`FileIdentity`] key in
/// `eff` corresponds to at least one `(path, entry)` pair somewhere in
/// `images`, and every [`ImageSet`] in `eff`'s value lists is a
/// non-empty subset of `naive(identity)`. Both are produced by
/// [`super::membership::naive_membership`] and
/// [`super::membership::effective_membership`] respectively, so the
/// preconditions hold by construction in `lib::run`.
///
/// `images` may be passed in any order: per-image lookups are keyed on
/// [`SquashedEntry::image_id`] (read off the first entry of each
/// non-empty fs), mirroring the convention `naive_membership` /
/// `effective_membership` already use.
///
/// # Panics
///
/// * If a non-hardlink entry's [`FileIdentity`] is missing from `eff`,
///   or no eff class for it contains the entry's `image_id`. Both
///   would mean `images`/`eff` were built against different inputs,
///   which is an internal inconsistency this function does not
///   recover from.
/// * If a layer's membership references an `image_id` not present in
///   any non-empty `images[i].image_id` — same reasoning.
#[must_use]
pub fn partition(
    images: &[SquashedFs],
    eff: &BTreeMap<FileIdentity, Vec<ImageSet>>,
) -> BTreeMap<ImageSet, CandidateLayer> {
    let by_id: HashMap<InputImageId, &SquashedFs> = images
        .iter()
        .filter_map(|fs| fs.iter().next().map(|(_, e)| (e.image_id, fs)))
        .collect();

    let mut layers: BTreeMap<ImageSet, CandidateLayer> = BTreeMap::new();

    // Pass 1: place every (path, entry) into its eff-class layer
    // (or into its singleton {i} for hardlinks per spec 05 §5.6).
    for fs in images {
        for (path, entry) in fs.iter() {
            let membership = membership_for(entry, path, eff);
            insert_canonical(&mut layers, membership, path.clone(), entry.clone());
        }
    }

    // Pass 2: for every layer L(M), make sure every strict ancestor
    // of every contained path is itself present in L(M) (spec 05
    // §5.4.2 rule 2). Spec 05 §5.4.4 guarantees that for any path P
    // in L(M) and any ancestor A of P, every image in M agrees on
    // A's identity, so reading A from any one image in M (we pick
    // the smallest id, deterministically) yields the canonical
    // directory entry for L(M).
    let layer_keys: Vec<ImageSet> = layers.keys().cloned().collect();
    for m in layer_keys {
        let Some(canonical_id) = m.iter().next() else {
            continue;
        };
        let canonical_fs = *by_id
            .get(&canonical_id)
            .expect("layer membership references unknown image");
        let paths: Vec<PathBuf> = layers[&m].entries.keys().cloned().collect();
        for p in paths {
            for ancestor in strict_ancestors(&p) {
                let layer = layers.get_mut(&m).expect("layer present");
                if layer.entries.contains_key(ancestor) {
                    continue;
                }
                let Some(anc_entry) = canonical_fs.get(ancestor) else {
                    debug_assert!(
                        false,
                        "ancestor {} of {} missing in image {}: spec 05 §5.4.4 should rule this out",
                        ancestor.display(),
                        p.display(),
                        canonical_id.0,
                    );
                    continue;
                };
                layer.entries.insert(ancestor.to_path_buf(), anc_entry.clone());
            }
        }
    }

    layers
}

/// Resolve the layer-membership an `(path, entry)` belongs to.
fn membership_for(
    entry: &SquashedEntry,
    path: &std::path::Path,
    eff: &BTreeMap<FileIdentity, Vec<ImageSet>>,
) -> ImageSet {
    if matches!(entry.kind, EntryKind::Hardlink) {
        // Spec 05 §5.6: hardlinks are emitted into the per-image
        // layer of their source image, never into a shared subset.
        return ImageSet::singleton(entry.image_id);
    }
    let id = FileIdentity::from_squashed(path.to_path_buf(), entry);
    let classes = eff
        .get(&id)
        .expect("eff missing identity for a squash-input entry; images/eff are inconsistent");
    classes
        .iter()
        .find(|c| c.contains(entry.image_id))
        .cloned()
        .expect("no eff class for this identity contains the entry's image_id")
}

/// Insert `(path, entry)` into `layers[membership]`, creating the
/// layer if missing. When the path is already present (multiple
/// images in this membership all carry byte-equal entries — that's
/// exactly what the membership *means*), keep the entry from the
/// smallest [`InputImageId`] for deterministic source selection
/// (spec 11 §11.6).
fn insert_canonical(
    layers: &mut BTreeMap<ImageSet, CandidateLayer>,
    membership: ImageSet,
    path: PathBuf,
    entry: SquashedEntry,
) {
    let layer = layers.entry(membership.clone()).or_insert_with(|| CandidateLayer {
        membership,
        entries: BTreeMap::new(),
    });
    match layer.entries.entry(path) {
        Vacant(slot) => {
            slot.insert(entry);
        }
        Occupied(mut slot) => {
            if entry.image_id < slot.get().image_id {
                slot.insert(entry);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::super::membership::{effective_membership, naive_membership};
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

    fn dir(image: usize, mode: u32) -> SquashedEntry {
        SquashedEntry {
            mode,
            ..entry(image, EntryKind::Directory)
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

    fn build(images: &[SquashedFs]) -> BTreeMap<ImageSet, CandidateLayer> {
        let naive = naive_membership(images);
        let eff = effective_membership(images, &naive);
        partition(images, &eff)
    }

    fn paths_in(layer: &CandidateLayer) -> Vec<String> {
        layer.entries.keys().map(|p| p.to_string_lossy().into_owned()).collect()
    }

    fn ids(xs: &[usize]) -> ImageSet {
        ImageSet::from_ids(xs.iter().copied().map(InputImageId))
    }

    #[test]
    fn empty_inputs_yield_no_layers() {
        let layers = build(&[]);
        assert!(layers.is_empty());
    }

    #[test]
    fn empty_filesystems_yield_no_layers() {
        let layers = build(&[SquashedFs::new(), SquashedFs::new()]);
        assert!(layers.is_empty());
    }

    #[test]
    fn single_image_produces_one_singleton_layer() {
        // All entries land in L({0}).
        let fs = fs_of(
            0,
            &[
                ("etc", dir(0, 0o755)),
                ("etc/hostname", regular(0, 5, [0xaa; 32])),
                ("usr", dir(0, 0o755)),
                ("usr/bin", dir(0, 0o755)),
                ("usr/bin/sh", regular(0, 100, [0xbb; 32])),
            ],
        );
        let layers = build(&[fs]);
        assert_eq!(layers.len(), 1);
        let layer = layers.get(&ids(&[0])).expect("singleton {0} layer");
        assert_eq!(layer.membership, ids(&[0]));
        assert_eq!(
            paths_in(layer),
            vec!["etc", "etc/hostname", "usr", "usr/bin", "usr/bin/sh"]
        );
    }

    #[test]
    fn fully_shared_image_produces_one_full_subset_layer() {
        // Two images with byte-identical content collapse to a single
        // L({0,1}) layer.
        let mk = |i: usize| {
            fs_of(
                i,
                &[
                    ("etc", dir(i, 0o755)),
                    ("etc/hostname", {
                        SquashedEntry {
                            image_id: InputImageId(i),
                            ..regular(0, 5, [0xab; 32])
                        }
                    }),
                ],
            )
        };
        let layers = build(&[mk(0), mk(1)]);
        assert_eq!(layers.len(), 1);
        let l = layers.get(&ids(&[0, 1])).expect("L({0,1}) present");
        assert_eq!(paths_in(l), vec!["etc", "etc/hostname"]);
    }

    #[test]
    fn disjoint_images_produce_two_singleton_layers() {
        let fs0 = fs_of(0, &[("a", regular(0, 1, [0x11; 32]))]);
        let fs1 = fs_of(1, &[("b", regular(1, 1, [0x22; 32]))]);
        let layers = build(&[fs0, fs1]);
        assert_eq!(layers.len(), 2);
        assert_eq!(paths_in(layers.get(&ids(&[0])).unwrap()), vec!["a"]);
        assert_eq!(paths_in(layers.get(&ids(&[1])).unwrap()), vec!["b"]);
    }

    #[test]
    fn three_images_partial_overlap_produce_distinct_layers() {
        // Same identity for `etc/c` shared in {0,2}, image 1 has its
        // own different copy. Plus per-image extras.
        let body = regular(0, 1, [0x42; 32]);
        let body2 = SquashedEntry {
            image_id: InputImageId(2),
            ..body.clone()
        };
        let other = regular(1, 1, [0xff; 32]);
        let fs0 = fs_of(
            0,
            &[
                ("etc", dir(0, 0o755)),
                ("etc/c", body),
                ("etc/x", regular(0, 0, [0x10; 32])),
            ],
        );
        let fs1 = fs_of(1, &[("etc", dir(1, 0o755)), ("etc/c", other)]);
        let fs2 = fs_of(
            2,
            &[
                ("etc", dir(2, 0o755)),
                ("etc/c", body2),
                ("etc/y", regular(2, 0, [0x20; 32])),
            ],
        );

        let layers = build(&[fs0, fs1, fs2]);

        // Expected layers:
        //  L({0,1,2}) — etc directory (shared across all three)
        //  L({0,2}) — etc/c (shared in {0,2}) + etc (duplicated dir)
        //  L({0}) — etc/x + etc (duplicated dir)
        //  L({1}) — etc/c (the disagreeing body) + etc (duplicated dir)
        //  L({2}) — etc/y + etc (duplicated dir)
        let l_full = layers.get(&ids(&[0, 1, 2])).expect("L({0,1,2}) for shared etc");
        assert_eq!(paths_in(l_full), vec!["etc"]);

        let l_02 = layers.get(&ids(&[0, 2])).expect("L({0,2}) for shared etc/c");
        assert_eq!(paths_in(l_02), vec!["etc", "etc/c"]);

        let l0 = layers.get(&ids(&[0])).expect("L({0}) for image-0-only etc/x");
        assert_eq!(paths_in(l0), vec!["etc", "etc/x"]);

        let l1 = layers.get(&ids(&[1])).expect("L({1}) for image-1's etc/c");
        assert_eq!(paths_in(l1), vec!["etc", "etc/c"]);

        let l2 = layers.get(&ids(&[2])).expect("L({2}) for image-2-only etc/y");
        assert_eq!(paths_in(l2), vec!["etc", "etc/y"]);
    }

    #[test]
    fn disagreeing_ancestor_splits_file_across_two_layers() {
        // Body is byte-equal in both images at `etc/c`, but image 0's
        // `etc` has 0700 and image 1's has 0755. eff splits naive
        // {0,1} into {0} and {1}; the file appears once per class.
        let body = regular(0, 1, [0x77; 32]);
        let body1 = SquashedEntry {
            image_id: InputImageId(1),
            ..body.clone()
        };
        let fs0 = fs_of(0, &[("etc", dir(0, 0o700)), ("etc/c", body)]);
        let fs1 = fs_of(1, &[("etc", dir(1, 0o755)), ("etc/c", body1)]);

        let layers = build(&[fs0, fs1]);

        // No L({0,1}) for the file because eff(file) split.
        // The two etc directories are distinct identities, so they
        // each land in their own singleton layer.
        assert!(
            !layers.contains_key(&ids(&[0, 1])),
            "no shared layer when ancestors disagree"
        );
        let l0 = layers.get(&ids(&[0])).unwrap();
        let l1 = layers.get(&ids(&[1])).unwrap();
        assert_eq!(paths_in(l0), vec!["etc", "etc/c"]);
        assert_eq!(paths_in(l1), vec!["etc", "etc/c"]);
        // Bodies are the same hash across the two layers — the
        // duplication is the price of overlayfs correctness.
        assert_eq!(
            l0.entries[Path::new("etc/c")].content_hash,
            l1.entries[Path::new("etc/c")].content_hash,
        );
    }

    #[test]
    fn directory_duplicates_into_smaller_subset_layers_with_descendants() {
        // `etc` has the same identity in {0,1,2} (M_D = {0,1,2}).
        // `etc/shared` is byte-equal in all three (in L({0,1,2})).
        // `etc/only0` exists only in image 0 (in L({0})).
        // `etc/only1` exists only in image 1 (in L({1})).
        // Expected: `etc` directory entry appears in L({0,1,2}) (its
        // natural layer), L({0}), and L({1}). It does NOT appear in
        // L({2}) because there are no image-2-only descendants.
        let mk = |i: usize| dir(i, 0o755);
        let shared = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 1, [0xcd; 32])
        };
        let fs0 = fs_of(
            0,
            &[
                ("etc", mk(0)),
                ("etc/shared", shared(0)),
                ("etc/only0", regular(0, 0, [0x00; 32])),
            ],
        );
        let fs1 = fs_of(
            1,
            &[
                ("etc", mk(1)),
                ("etc/shared", shared(1)),
                ("etc/only1", regular(1, 0, [0x01; 32])),
            ],
        );
        let fs2 = fs_of(2, &[("etc", mk(2)), ("etc/shared", shared(2))]);

        let layers = build(&[fs0, fs1, fs2]);

        let l_full = layers.get(&ids(&[0, 1, 2])).expect("L({0,1,2})");
        assert_eq!(paths_in(l_full), vec!["etc", "etc/shared"]);

        let l0 = layers.get(&ids(&[0])).expect("L({0})");
        assert_eq!(paths_in(l0), vec!["etc", "etc/only0"]);

        let l1 = layers.get(&ids(&[1])).expect("L({1})");
        assert_eq!(paths_in(l1), vec!["etc", "etc/only1"]);

        // Image 2 has no exclusive content; its singleton layer
        // should not exist.
        assert!(
            !layers.contains_key(&ids(&[2])),
            "no L({{2}}) when image 2 has nothing exclusive"
        );
    }

    #[test]
    fn directory_natural_layer_is_largest_subset_carrying_it() {
        // `a/b` shared in {0,1,2}, file `a/b/c` only in image 0.
        // The directories `a` and `a/b` should land in L({0,1,2})
        // (their natural M_D = {0,1,2}), and also be duplicated into
        // L({0}) because image 0's exclusive `a/b/c` lives there.
        let body = regular(0, 1, [0xee; 32]);
        let mk = |i: usize| {
            let entries = if i == 0 {
                vec![
                    ("a".to_string(), dir(i, 0o755)),
                    ("a/b".to_string(), dir(i, 0o755)),
                    ("a/b/c".to_string(), body.clone()),
                ]
            } else {
                vec![("a".to_string(), dir(i, 0o755)), ("a/b".to_string(), dir(i, 0o755))]
            };
            let mut fs = SquashedFs::new();
            for (p, mut e) in entries {
                e.image_id = InputImageId(i);
                fs.insert(PathBuf::from(p), e);
            }
            fs
        };

        let layers = build(&[mk(0), mk(1), mk(2)]);

        let l_full = layers.get(&ids(&[0, 1, 2])).expect("L({0,1,2}) for shared dirs");
        assert_eq!(paths_in(l_full), vec!["a", "a/b"]);

        let l0 = layers.get(&ids(&[0])).expect("L({0}) for a/b/c");
        // Both ancestors duplicated in.
        assert_eq!(paths_in(l0), vec!["a", "a/b", "a/b/c"]);
    }

    #[test]
    fn duplicated_directory_entry_uses_consistent_metadata() {
        // The directory's identity is the same across M_D, so any
        // image's view of it must serialise to the same metadata.
        // Spec 5.4.2 rule 2 explicitly: same single FileIdentity in
        // every layer it appears.
        let only0 = regular(0, 0, [0x99; 32]);
        let etc = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            mode: 0o0750,
            uid: 0,
            gid: 0,
            ..dir(i, 0o0750)
        };
        let fs0 = fs_of(0, &[("etc", etc(0)), ("etc/only0", only0)]);
        let fs1 = fs_of(1, &[("etc", etc(1))]);

        let layers = build(&[fs0, fs1]);

        let l01 = layers.get(&ids(&[0, 1])).expect("L({0,1}) carries the shared etc");
        let l0 = layers
            .get(&ids(&[0]))
            .expect("L({0}) carries etc/only0 + duplicated etc");

        let etc01 = &l01.entries[Path::new("etc")];
        let etc0 = &l0.entries[Path::new("etc")];
        assert_eq!(etc01.kind, etc0.kind);
        assert_eq!(etc01.mode, etc0.mode);
        assert_eq!(etc01.uid, etc0.uid);
        assert_eq!(etc01.gid, etc0.gid);
        assert_eq!(etc01.xattrs, etc0.xattrs);
    }

    #[test]
    fn hardlinks_go_into_per_image_layer() {
        // Hardlink in image 0, demoted-or-not, must land in L({0}).
        let mut h = entry(0, EntryKind::Hardlink);
        h.link_target = Some(PathBuf::from("etc/hostname"));
        let target = regular(0, 5, [0x55; 32]);

        let fs0 = fs_of(
            0,
            &[
                ("etc", dir(0, 0o755)),
                ("etc/hostname", target),
                ("etc/hostname.alias", h),
            ],
        );
        let layers = build(&[fs0]);
        assert_eq!(layers.len(), 1);
        let l0 = layers.get(&ids(&[0])).unwrap();
        // Hardlink is in {0} (the only layer); its EntryKind survives.
        let alias = &l0.entries[Path::new("etc/hostname.alias")];
        assert_eq!(alias.kind, EntryKind::Hardlink);
        assert_eq!(alias.link_target.as_deref(), Some(Path::new("etc/hostname")));
    }

    #[test]
    fn hardlink_in_otherwise_shared_image_still_goes_to_per_image_layer() {
        // Two images with identical content, one has an extra hardlink.
        // The hardlink must NOT join L({0,1}) — spec 5.6.
        let mut h = entry(0, EntryKind::Hardlink);
        h.link_target = Some(PathBuf::from("etc/hostname"));
        let mk_target = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 5, [0xaa; 32])
        };
        let mk_etc = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..dir(0, 0o755)
        };

        let fs0 = fs_of(
            0,
            &[("etc", mk_etc(0)), ("etc/hostname", mk_target(0)), ("etc/alias", h)],
        );
        let fs1 = fs_of(1, &[("etc", mk_etc(1)), ("etc/hostname", mk_target(1))]);

        let layers = build(&[fs0, fs1]);

        let l01 = layers.get(&ids(&[0, 1])).expect("shared regular content");
        assert_eq!(paths_in(l01), vec!["etc", "etc/hostname"]);

        let l0 = layers.get(&ids(&[0])).expect("hardlink lives here");
        // Ancestor `etc` is duplicated in (rule 2).
        assert_eq!(paths_in(l0), vec!["etc", "etc/alias"]);
        assert_eq!(l0.entries[Path::new("etc/alias")].kind, EntryKind::Hardlink);
    }

    #[test]
    fn duplicated_entry_picks_smallest_image_id_as_source() {
        // When multiple images carry byte-equal entries (the very
        // definition of an eff class), the stored source must be
        // deterministic. Smallest image_id wins.
        let mk_etc = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            layer_idx: i, // force a difference in bookkeeping
            entry_idx: i,
            ..dir(0, 0o755)
        };
        let fs0 = fs_of(0, &[("etc", mk_etc(0))]);
        let fs1 = fs_of(1, &[("etc", mk_etc(1))]);

        // Argument order shouldn't change which source wins.
        let layers_fwd = build(&[fs0.clone(), fs1.clone()]);
        let layers_rev = build(&[fs1, fs0]);

        let etc_fwd = &layers_fwd.get(&ids(&[0, 1])).unwrap().entries[Path::new("etc")];
        let etc_rev = &layers_rev.get(&ids(&[0, 1])).unwrap().entries[Path::new("etc")];
        assert_eq!(etc_fwd.image_id, InputImageId(0));
        assert_eq!(etc_rev.image_id, InputImageId(0));
        assert_eq!(etc_fwd.layer_idx, 0);
        assert_eq!(etc_rev.layer_idx, 0);
    }

    #[test]
    fn result_is_image_argument_order_invariant() {
        let body = regular(0, 1, [0x77; 32]);
        let body1 = SquashedEntry {
            image_id: InputImageId(1),
            ..body.clone()
        };
        let fs0 = fs_of(0, &[("etc", dir(0, 0o755)), ("etc/c", body)]);
        let fs1 = fs_of(1, &[("etc", dir(1, 0o755)), ("etc/c", body1)]);

        let fwd = build(&[fs0.clone(), fs1.clone()]);
        let rev = build(&[fs1, fs0]);

        // Compare layer keys + paths; SquashedEntry doesn't derive Eq
        // (bookkeeping triple may differ legitimately), so we compare
        // by (path-set, identity per path).
        let by_layer = |m: &BTreeMap<ImageSet, CandidateLayer>| {
            m.iter().map(|(k, l)| (k.clone(), paths_in(l))).collect::<Vec<_>>()
        };
        assert_eq!(by_layer(&fwd), by_layer(&rev));
    }

    #[test]
    fn entries_iterate_in_lex_path_order() {
        let e = |path, body: [u8; 32]| (path, regular(0, 0, body));
        let fs = fs_of(
            0,
            &[e("z", [0; 32]), e("a/b", [1; 32]), e("a", [2; 32]), e("m", [3; 32])],
        );
        // Override the dir-shaped 'a' to be a directory; the `regular`
        // helper above produced a regular file at that path, so adjust
        // the test data: replace 'a' with a directory.
        let mut fs = fs;
        fs.insert(PathBuf::from("a"), dir(0, 0o755));

        let layers = build(&[fs]);
        let l0 = layers.get(&ids(&[0])).unwrap();
        let paths = paths_in(l0);
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted, "lex order");
    }

    #[test]
    fn root_level_entries_have_no_ancestors_to_duplicate() {
        // A root-level directory in only one image should not pull in
        // any ancestor — there are none.
        let fs0 = fs_of(0, &[("etc", dir(0, 0o755))]);
        let fs1 = fs_of(1, &[("var", dir(1, 0o755))]);
        let layers = build(&[fs0, fs1]);
        assert_eq!(paths_in(layers.get(&ids(&[0])).unwrap()), vec!["etc"]);
        assert_eq!(paths_in(layers.get(&ids(&[1])).unwrap()), vec!["var"]);
    }

    #[test]
    fn symlinks_and_devices_partition_like_files() {
        // Non-regular, non-directory, non-hardlink entries follow the
        // same eff-class placement as regular files.
        let mut sym0 = entry(0, EntryKind::Symlink);
        sym0.link_target = Some(PathBuf::from("hostname"));
        let mut sym1 = entry(1, EntryKind::Symlink);
        sym1.link_target = Some(PathBuf::from("hostname"));

        let fs0 = fs_of(0, &[("etc", dir(0, 0o755)), ("etc/host.alias", sym0)]);
        let fs1 = fs_of(1, &[("etc", dir(1, 0o755)), ("etc/host.alias", sym1)]);

        let layers = build(&[fs0, fs1]);
        // Single shared layer with both the dir and the symlink.
        assert_eq!(layers.len(), 1);
        let l = layers.get(&ids(&[0, 1])).unwrap();
        assert_eq!(paths_in(l), vec!["etc", "etc/host.alias"]);
        assert_eq!(l.entries[Path::new("etc/host.alias")].kind, EntryKind::Symlink);
    }

    #[test]
    fn every_layer_has_entries_for_all_ancestors_of_every_path() {
        // Spec 5.4.2 invariant: no layer relies on an implicit ancestor.
        let body = regular(0, 1, [0x88; 32]);
        let body1 = SquashedEntry {
            image_id: InputImageId(1),
            ..body.clone()
        };
        let fs0 = fs_of(
            0,
            &[
                ("usr", dir(0, 0o755)),
                ("usr/share", dir(0, 0o755)),
                ("usr/share/doc", dir(0, 0o755)),
                ("usr/share/doc/r", body),
            ],
        );
        let fs1 = fs_of(
            1,
            &[
                ("usr", dir(1, 0o755)),
                ("usr/share", dir(1, 0o755)),
                ("usr/share/doc", dir(1, 0o755)),
                ("usr/share/doc/r", body1),
            ],
        );

        let layers = build(&[fs0, fs1]);
        for layer in layers.values() {
            for path in layer.entries.keys() {
                for ancestor in path.ancestors().skip(1) {
                    if ancestor.as_os_str().is_empty() {
                        continue;
                    }
                    assert!(
                        layer.entries.contains_key(ancestor),
                        "layer {:?} missing ancestor {} of {}",
                        layer.membership,
                        ancestor.display(),
                        path.display()
                    );
                }
            }
        }
    }
}
