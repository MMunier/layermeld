//! `min-layer-size` dissolve pass (spec 05 §5.5).
//!
//! After [`super::partition`] builds the candidate layer set from
//! effective membership, some subset layers may be too small for the
//! per-layer fixed overhead (manifest descriptor, `rootfs.diff_ids`
//! entry, end-of-archive trailer, per-file 512-byte tar headers) to
//! pay for itself. The dissolve pass walks those layers in descending
//! `|M|` order with lex tiebreak, estimates each layer's tar size per
//! spec 05 §5.5.1, and re-emits files from below-threshold layers
//! into the largest non-dissolved subset layer that still contains
//! the source image (5.5.2). Per-image layers (`|M| = 1`) are the
//! absorbers of last resort and are never dissolved (5.5.3); they are
//! created on demand when no smaller existing subset is available.
//!
//! The pass mutates the partition in place: dissolved layers are
//! removed; surviving and newly-created destination layers grow with
//! the migrated file plus any ancestor directory entries needed to
//! preserve the spec 05 §5.4.2 invariant ("every layer contains
//! explicit entries for all ancestors of every path it carries"). The
//! ancestor identity is taken from the smallest [`InputImageId`] in
//! the destination's membership — by spec 05 §5.4.4 every image in
//! `M_L'` agrees on every ancestor's identity, so the choice doesn't
//! change output bytes (mirrors the canonical-source policy in the
//! partition step).
//!
//! ## Determinism
//!
//! All ordering is deterministic for spec 11 §11.6 reproducibility:
//!
//! * Visit order: descending `|M|` then ascending lex on `M`.
//! * Per dissolved layer, files iterate in lex path order (`BTreeMap`-
//!   backed) and per-image migration iterates `M` in ascending order.
//! * Destination tiebreak: largest `|M'|`, then ascending lex on `M'`.
//!
//! ## Single-pass termination
//!
//! Visit order means a layer is only ever "fed" by larger-`|M|`
//! dissolutions; by the time it is visited, all such absorptions are
//! complete and its current size is final. A layer that crosses the
//! threshold *upward* via absorption simply stops being a dissolve
//! candidate (5.5.4 last paragraph). The pass therefore terminates
//! after one descending sweep.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry::{Occupied, Vacant};
use std::path::{Path, PathBuf};

use crate::squash::index::{InputImageId, SquashedEntry, SquashedFs};
use crate::tar_io::pax;
use crate::tar_io::reader::EntryKind;

use super::membership::{ImageSet, strict_ancestors};
use super::partition::CandidateLayer;

/// Tar block size (POSIX.1-1988).
const BLOCK: u64 = 512;
/// Two zero blocks at end-of-archive.
const TRAILER: u64 = 1024;
/// SCHILY xattr key prefix per spec 02 §2.4.
const SCHILY_XATTR: &[u8] = b"SCHILY.xattr.";

/// Default `--min-layer-size` per spec 05 §5.5.1: 16 KiB.
pub const DEFAULT_MIN_LAYER_SIZE: u64 = 16 * 1024;

/// Estimate the on-disk tar size of `layer` per spec 05 §5.5.1.
///
/// Sums per-entry header + xattr extended-header padding + body
/// padding, plus the 1024-byte end-of-archive trailer. No file body
/// is opened; every input is already in the [`SquashedEntry`].
///
/// The formula intentionally tracks the dominant costs (per-file
/// header + body padding + xattr blob) and ignores second-order
/// items the spec does not enumerate (PAX records for long
/// path/linkpath/large uid/gid/large size, the additional 512-byte
/// header that fronts the xattr extended-header entry itself). That
/// matches what spec 05 §5.5.1 codifies — the dissolve threshold is
/// a budget heuristic, not a byte-exact predictor.
#[must_use]
pub fn estimated_tar_size(layer: &CandidateLayer) -> u64 {
    let mut total: u64 = TRAILER;
    for entry in layer.entries.values() {
        total = total.saturating_add(per_entry_size(entry));
    }
    total
}

fn per_entry_size(entry: &SquashedEntry) -> u64 {
    let mut sz = BLOCK;
    let xblob = encoded_xattr_blob_len(&entry.xattrs);
    if xblob > 0 {
        sz = sz.saturating_add(round_up_block(xblob));
    }
    let body = if matches!(entry.kind, EntryKind::Regular) {
        entry.size
    } else {
        0
    };
    sz.saturating_add(round_up_block(body))
}

fn round_up_block(n: u64) -> u64 {
    n.div_ceil(BLOCK).saturating_mul(BLOCK)
}

fn encoded_xattr_blob_len(xattrs: &BTreeMap<Vec<u8>, Vec<u8>>) -> u64 {
    if xattrs.is_empty() {
        return 0;
    }
    let records: Vec<(Vec<u8>, Vec<u8>)> = xattrs
        .iter()
        .map(|(k, v)| {
            let mut key = Vec::with_capacity(SCHILY_XATTR.len() + k.len());
            key.extend_from_slice(SCHILY_XATTR);
            key.extend_from_slice(k);
            (key, v.clone())
        })
        .collect();
    pax::encode_records(&records).len() as u64
}

/// Run the spec 05 §5.5 dissolve pass on `layers` in place.
///
/// `min_layer_size == 0` skips the pass entirely (spec 05 §5.5.5):
/// the partition is emitted as-is.
///
/// `images` must be the same slice that built `layers`; it is read
/// only to source ancestor directory entries (spec 05 §5.5.4) for
/// destinations that absorb a migrated file but did not previously
/// carry the file's ancestors. As elsewhere in `dedup`, the lookup
/// is keyed on [`SquashedEntry::image_id`] — the slice index is not
/// used as a fallback id.
///
/// # Panics
///
/// * If a dissolved layer's membership references an `image_id` not
///   present in any non-empty `images[i].image_id`. Same internal-
///   consistency contract as [`super::partition::partition`].
pub fn dissolve(layers: &mut BTreeMap<ImageSet, CandidateLayer>, images: &[SquashedFs], min_layer_size: u64) {
    if min_layer_size == 0 {
        return;
    }

    let by_id: BTreeMap<InputImageId, &SquashedFs> = images
        .iter()
        .filter_map(|fs| fs.iter().next().map(|(_, e)| (e.image_id, fs)))
        .collect();

    let mut keys: Vec<ImageSet> = layers.keys().filter(|m| m.len() >= 2).cloned().collect();
    // Descending |M|, ascending lex tiebreak.
    keys.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));

    for m in keys {
        let Some(layer) = layers.get(&m) else {
            continue;
        };
        if estimated_tar_size(layer) >= min_layer_size {
            continue;
        }
        // Dissolve. Take ownership of the layer's entries; the layer
        // itself is removed from the partition.
        let layer = layers.remove(&m).expect("present");
        let entries: Vec<(PathBuf, SquashedEntry)> = layer.entries.into_iter().collect();

        for (path, entry) in entries {
            // Every entry in the dissolved layer must end up *somewhere*
            // — otherwise leaf directories shared across all images
            // (the canonical example: an empty `tmp` shared by every
            // image) would silently disappear from the output, breaking
            // spec 11 §11.5 round-trip equality. Non-leaf directories
            // would also be added to the destination via the ancestor-
            // backfill in `migrate_into`, but relying on that means a
            // directory only survives when something below it happens
            // to migrate, so the explicit migration here is the
            // load-bearing one. Hardlinks per spec 05 §5.6 never live
            // in a shared layer, so we don't expect to see them with
            // |M| ≥ 2; if one slipped through, the singleton fallback
            // below is the spec-compliant home.
            for image_id in m.iter() {
                let dest = pick_destination(&m, image_id, layers);
                migrate_into(layers, &dest, &path, &entry, &by_id);
            }
        }
    }
}

/// Pick the destination layer for a file from dissolved layer `m`,
/// for image `image_id ∈ m`. Spec 05 §5.5.2: largest existing subset
/// `M' ⊊ m` with `image_id ∈ M'`; tiebreak ascending lex on `M'`. If
/// none exists, fall back to the per-image layer `{image_id}`.
fn pick_destination(m: &ImageSet, image_id: InputImageId, layers: &BTreeMap<ImageSet, CandidateLayer>) -> ImageSet {
    let mut best: Option<&ImageSet> = None;
    for candidate in layers.keys() {
        if candidate == m {
            continue;
        }
        if !candidate.contains(image_id) {
            continue;
        }
        if !candidate.is_subset(m) {
            continue;
        }
        // `is_subset` is reflexive — guard against the unlikely case
        // where `candidate.len() == m.len()` (would mean `candidate ==
        // m`, already filtered above, but be explicit so the strict-
        // proper-subset rule from 5.5.2 stays visible).
        if candidate.len() >= m.len() {
            continue;
        }
        best = match best {
            None => Some(candidate),
            Some(b) if candidate.len() > b.len() => Some(candidate),
            Some(b) if candidate.len() == b.len() && candidate < b => Some(candidate),
            _ => best,
        };
    }
    best.cloned().unwrap_or_else(|| ImageSet::singleton(image_id))
}

/// Insert `(path, entry)` into the destination layer, creating it if
/// missing, and back-fill any strict ancestors per spec 05 §5.5.4.
fn migrate_into(
    layers: &mut BTreeMap<ImageSet, CandidateLayer>,
    dest: &ImageSet,
    path: &Path,
    entry: &SquashedEntry,
    by_id: &BTreeMap<InputImageId, &SquashedFs>,
) {
    let dest_layer = layers.entry(dest.clone()).or_insert_with(|| CandidateLayer {
        membership: dest.clone(),
        entries: BTreeMap::new(),
    });
    match dest_layer.entries.entry(path.to_path_buf()) {
        Vacant(slot) => {
            slot.insert(entry.clone());
        }
        Occupied(mut slot) => {
            // Same canonical-source policy as the partition step:
            // smallest image_id wins for byte-equal entries (spec 11
            // §11.6 determinism). Identical-content entries can
            // legitimately race here when two dissolved layers feed
            // the same destination through different images.
            if entry.image_id < slot.get().image_id {
                slot.insert(entry.clone());
            }
        }
    }

    let canonical_id = dest.iter().next().expect("dest membership is non-empty");
    let canonical_fs = *by_id
        .get(&canonical_id)
        .expect("dest membership references unknown image");
    for ancestor in strict_ancestors(path) {
        if dest_layer.entries.contains_key(ancestor) {
            continue;
        }
        let Some(anc_entry) = canonical_fs.get(ancestor) else {
            // Spec 05 §5.5.4: M_L' ⊆ M_eff(f) ⊆ naive(ancestor), so
            // every image in M_L' carries every strict ancestor of
            // f.path. Reaching this branch means the partition was
            // built against different inputs than the slice we got.
            debug_assert!(
                false,
                "ancestor {} of {} missing in image {} during dissolve",
                ancestor.display(),
                path.display(),
                canonical_id.0,
            );
            continue;
        };
        dest_layer.entries.insert(ancestor.to_path_buf(), anc_entry.clone());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::super::membership::{effective_membership, naive_membership};
    use super::super::partition::partition;
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

    fn ids(xs: &[usize]) -> ImageSet {
        ImageSet::from_ids(xs.iter().copied().map(InputImageId))
    }

    fn build(images: &[SquashedFs]) -> BTreeMap<ImageSet, CandidateLayer> {
        let naive = naive_membership(images);
        let eff = effective_membership(images, &naive);
        partition(images, &eff)
    }

    fn paths_in(layer: &CandidateLayer) -> Vec<String> {
        layer.entries.keys().map(|p| p.to_string_lossy().into_owned()).collect()
    }

    // ----- estimated_tar_size --------------------------------------

    #[test]
    fn empty_layer_is_just_the_trailer() {
        let layer = CandidateLayer {
            membership: ids(&[0]),
            entries: BTreeMap::new(),
        };
        assert_eq!(estimated_tar_size(&layer), 1024);
    }

    #[test]
    fn single_zero_byte_regular_costs_one_header_plus_trailer() {
        let mut layer = CandidateLayer {
            membership: ids(&[0]),
            entries: BTreeMap::new(),
        };
        layer.entries.insert(PathBuf::from("a"), regular(0, 0, [0; 32]));
        // 512 (header) + 0 (body) + 1024 (trailer) = 1536
        assert_eq!(estimated_tar_size(&layer), 1536);
    }

    #[test]
    fn body_is_padded_to_block_boundary() {
        let mut layer = CandidateLayer {
            membership: ids(&[0]),
            entries: BTreeMap::new(),
        };
        // 1-byte body rounds up to a 512-byte block.
        layer.entries.insert(PathBuf::from("a"), regular(0, 1, [0; 32]));
        assert_eq!(estimated_tar_size(&layer), 512 + 512 + 1024);
        // 513-byte body needs two blocks.
        layer.entries.insert(PathBuf::from("b"), regular(0, 513, [1; 32]));
        // a: 512+512, b: 512+1024
        assert_eq!(estimated_tar_size(&layer), 512 + 512 + 512 + 1024 + 1024);
    }

    #[test]
    fn directory_costs_only_a_header() {
        let mut layer = CandidateLayer {
            membership: ids(&[0]),
            entries: BTreeMap::new(),
        };
        layer.entries.insert(PathBuf::from("etc"), dir(0, 0o755));
        // 512 header + 0 body padding + 1024 trailer
        assert_eq!(estimated_tar_size(&layer), 512 + 1024);
    }

    #[test]
    fn xattrs_add_a_padded_pax_blob() {
        let mut e = regular(0, 0, [0; 32]);
        e.xattrs.insert(b"user.flag".to_vec(), b"on".to_vec());
        let mut layer = CandidateLayer {
            membership: ids(&[0]),
            entries: BTreeMap::new(),
        };
        layer.entries.insert(PathBuf::from("a"), e);
        // pax record: <len> SCHILY.xattr.user.flag=on\n; padded to 512.
        let est = estimated_tar_size(&layer);
        assert_eq!(est, 512 + 512 + 1024);
    }

    #[test]
    fn xattrs_blob_above_one_block_pads_to_two() {
        // Build a value that pushes the encoded record past 512 bytes.
        let mut e = regular(0, 0, [0; 32]);
        e.xattrs.insert(b"user.big".to_vec(), vec![b'a'; 600]);
        let mut layer = CandidateLayer {
            membership: ids(&[0]),
            entries: BTreeMap::new(),
        };
        layer.entries.insert(PathBuf::from("a"), e);
        // 512 (header) + 1024 (xblob padded to 2 blocks) + 0 + 1024
        assert_eq!(estimated_tar_size(&layer), 512 + 1024 + 1024);
    }

    // ----- dissolve --------------------------------------------------

    #[test]
    fn min_zero_is_no_op() {
        // Build a tiny shared layer that would normally dissolve.
        let r = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 1, [0xa; 32])
        };
        let fs0 = fs_of(0, &[("a", r(0))]);
        let fs1 = fs_of(1, &[("a", r(1))]);
        let mut layers = build(&[fs0.clone(), fs1.clone()]);
        let before = layers.clone();
        dissolve(&mut layers, &[fs0, fs1], 0);
        assert_eq!(layers.keys().collect::<Vec<_>>(), before.keys().collect::<Vec<_>>());
        assert_eq!(layers[&ids(&[0, 1])].entries.len(), before[&ids(&[0, 1])].entries.len());
    }

    #[test]
    fn layer_above_threshold_is_kept() {
        // Single 4 KiB body in shared layer => well above the 16 KiB
        // threshold once headers + body are counted? No, 4096 bytes
        // body + 512 hdr + 1024 trailer = 5632 < 16 KiB. Use 32 KiB.
        let r = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 32 * 1024, [0xab; 32])
        };
        let fs0 = fs_of(0, &[("a", r(0))]);
        let fs1 = fs_of(1, &[("a", r(1))]);
        let mut layers = build(&[fs0.clone(), fs1.clone()]);
        dissolve(&mut layers, &[fs0, fs1], DEFAULT_MIN_LAYER_SIZE);
        assert!(layers.contains_key(&ids(&[0, 1])), "shared layer kept");
    }

    #[test]
    fn small_shared_layer_dissolves_into_per_image_layers() {
        // |M|=2, no smaller proper subset exists except singletons.
        // Both images get a singleton layer with the migrated file.
        let r = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 1, [0xcd; 32])
        };
        let fs0 = fs_of(0, &[("etc", dir(0, 0o755)), ("etc/c", r(0))]);
        let fs1 = fs_of(1, &[("etc", dir(1, 0o755)), ("etc/c", r(1))]);

        let mut layers = build(&[fs0.clone(), fs1.clone()]);
        // Sanity: shared layer present before dissolve.
        assert!(layers.contains_key(&ids(&[0, 1])));

        dissolve(&mut layers, &[fs0, fs1], DEFAULT_MIN_LAYER_SIZE);

        assert!(!layers.contains_key(&ids(&[0, 1])), "dissolved");
        let l0 = layers.get(&ids(&[0])).expect("L({0}) created/extended");
        let l1 = layers.get(&ids(&[1])).expect("L({1}) created/extended");
        // Both ended up with the file plus its `etc` ancestor.
        assert_eq!(paths_in(l0), vec!["etc", "etc/c"]);
        assert_eq!(paths_in(l1), vec!["etc", "etc/c"]);
        // Body content_hash is preserved across the duplication.
        assert_eq!(l0.entries[Path::new("etc/c")].content_hash, Some([0xcd; 32]),);
        assert_eq!(l1.entries[Path::new("etc/c")].content_hash, Some([0xcd; 32]),);
    }

    #[test]
    fn small_shared_layer_dissolves_into_largest_existing_subset() {
        // Three images. M={0,1,2} carries one tiny file. M={0,1} also
        // exists (carries something larger so it stays). Dissolving
        // {0,1,2} should send the file into {0,1} (largest proper
        // subset containing 0 and 1) and into {2} (singleton fallback
        // for image 2).
        let tiny = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 1, [0x42; 32])
        };
        let big = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 32 * 1024, [0x99; 32])
        };
        // Shared dir + tiny file across all three.
        // Big file shared in {0,1} only.
        let fs0 = fs_of(0, &[("etc", dir(0, 0o755)), ("etc/tiny", tiny(0)), ("etc/big", big(0))]);
        let fs1 = fs_of(1, &[("etc", dir(1, 0o755)), ("etc/tiny", tiny(1)), ("etc/big", big(1))]);
        let fs2 = fs_of(2, &[("etc", dir(2, 0o755)), ("etc/tiny", tiny(2))]);

        let mut layers = build(&[fs0.clone(), fs1.clone(), fs2.clone()]);
        // Sanity pre-dissolve.
        assert!(layers.contains_key(&ids(&[0, 1, 2])));
        assert!(layers.contains_key(&ids(&[0, 1])));

        dissolve(&mut layers, &[fs0, fs1, fs2], DEFAULT_MIN_LAYER_SIZE);

        // {0,1,2} is gone (was tiny: just `etc` dir + 1-byte file).
        assert!(!layers.contains_key(&ids(&[0, 1, 2])));
        // {0,1} survives (32 KiB body keeps it well above threshold)
        // and absorbed `etc/tiny` for both image 0 and image 1.
        let l01 = layers.get(&ids(&[0, 1])).expect("kept");
        assert!(l01.entries.contains_key(Path::new("etc/tiny")));
        assert!(l01.entries.contains_key(Path::new("etc/big")));
        // Image 2 had no smaller existing subset to absorb the file
        // (no L({0,2}), L({1,2}), L({2})), so a singleton layer was
        // created.
        let l2 = layers.get(&ids(&[2])).expect("L({2}) created as fallback");
        assert_eq!(paths_in(l2), vec!["etc", "etc/tiny"]);
    }

    #[test]
    fn dissolved_destination_creates_per_image_layer_if_absent() {
        // Single shared 2-image layer below threshold, no per-image
        // layers exist before dissolve. Both must be created.
        let r = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 1, [0xef; 32])
        };
        let fs0 = fs_of(0, &[("a", r(0))]);
        let fs1 = fs_of(1, &[("a", r(1))]);

        let mut layers = build(&[fs0.clone(), fs1.clone()]);
        assert!(!layers.contains_key(&ids(&[0])), "no L({{0}}) initially");
        assert!(!layers.contains_key(&ids(&[1])), "no L({{1}}) initially");

        dissolve(&mut layers, &[fs0, fs1], DEFAULT_MIN_LAYER_SIZE);

        assert!(layers.contains_key(&ids(&[0])));
        assert!(layers.contains_key(&ids(&[1])));
    }

    #[test]
    fn ancestor_dirs_are_added_to_destination() {
        // Deep nested file in tiny shared layer; per-image dest gets
        // the file plus all strict ancestors.
        let r = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 1, [0x77; 32])
        };
        let fs0 = fs_of(
            0,
            &[
                ("usr", dir(0, 0o755)),
                ("usr/share", dir(0, 0o755)),
                ("usr/share/doc", dir(0, 0o755)),
                ("usr/share/doc/r", r(0)),
            ],
        );
        let fs1 = fs_of(
            1,
            &[
                ("usr", dir(1, 0o755)),
                ("usr/share", dir(1, 0o755)),
                ("usr/share/doc", dir(1, 0o755)),
                ("usr/share/doc/r", r(1)),
            ],
        );

        let mut layers = build(&[fs0.clone(), fs1.clone()]);
        dissolve(&mut layers, &[fs0, fs1], DEFAULT_MIN_LAYER_SIZE);

        for i in [0usize, 1] {
            let l = layers.get(&ids(&[i])).expect("singleton present");
            for p in ["usr", "usr/share", "usr/share/doc", "usr/share/doc/r"] {
                assert!(
                    l.entries.contains_key(Path::new(p)),
                    "L({{{i}}}) should have {p} after dissolve"
                );
            }
        }
    }

    #[test]
    fn cascade_descending_size() {
        // Two tiny shared layers: {0,1,2} and {0,1}. Both below
        // threshold. {0,1,2} visits first, dissolves into {0,1} +
        // {2}. {0,1} is still tiny (now slightly grown but still
        // tiny), gets visited next, dissolves into {0} + {1}.
        let r = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 1, [0x11; 32])
        };
        let s = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 1, [0x22; 32])
        };
        // r is shared in {0,1,2}; s is shared in {0,1} only.
        let fs0 = fs_of(0, &[("a", r(0)), ("b", s(0))]);
        let fs1 = fs_of(1, &[("a", r(1)), ("b", s(1))]);
        let fs2 = fs_of(2, &[("a", r(2))]);

        let mut layers = build(&[fs0.clone(), fs1.clone(), fs2.clone()]);
        dissolve(&mut layers, &[fs0, fs1, fs2], DEFAULT_MIN_LAYER_SIZE);

        assert!(!layers.contains_key(&ids(&[0, 1, 2])));
        assert!(!layers.contains_key(&ids(&[0, 1])));
        // After both dissolves, image 0's stack picks up a + b from
        // L({0}); image 1 from L({1}); image 2's a from L({2}).
        let l0 = layers.get(&ids(&[0])).expect("L({0})");
        let l1 = layers.get(&ids(&[1])).expect("L({1})");
        let l2 = layers.get(&ids(&[2])).expect("L({2})");
        assert!(l0.entries.contains_key(Path::new("a")));
        assert!(l0.entries.contains_key(Path::new("b")));
        assert!(l1.entries.contains_key(Path::new("a")));
        assert!(l1.entries.contains_key(Path::new("b")));
        assert!(l2.entries.contains_key(Path::new("a")));
        // image 2 never had b, so L({2}) shouldn't suddenly contain it.
        assert!(!l2.entries.contains_key(Path::new("b")));
    }

    #[test]
    fn destination_grown_above_threshold_is_kept() {
        // L({0,1,2}) is small and dissolves. Its content + L({0,1})'s
        // own large content keep L({0,1}) above threshold. L({0,1})
        // should not itself be dissolved when later visited.
        let big = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 32 * 1024, [0xaa; 32])
        };
        let tiny = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 1, [0xbb; 32])
        };
        let fs0 = fs_of(0, &[("a", big(0)), ("b", tiny(0))]);
        let fs1 = fs_of(1, &[("a", big(1)), ("b", tiny(1))]);
        let fs2 = fs_of(2, &[("b", tiny(2))]);

        let mut layers = build(&[fs0.clone(), fs1.clone(), fs2.clone()]);
        dissolve(&mut layers, &[fs0, fs1, fs2], DEFAULT_MIN_LAYER_SIZE);

        assert!(!layers.contains_key(&ids(&[0, 1, 2])), "tiny shared layer dissolved");
        assert!(layers.contains_key(&ids(&[0, 1])), "big layer kept");
    }

    #[test]
    fn destination_grown_above_threshold_via_absorption_is_kept() {
        // L({0,1,2}) is small. L({0,1}) is also small on its own, but
        // visit order is {0,1,2} first, then {0,1}. Each absorbs from
        // {0,1,2}. If after absorption {0,1} crosses the threshold,
        // it's kept; otherwise it dissolves further. Here we craft
        // sizes so {0,1} crosses threshold post-absorption.
        let chunk = |i: usize, h: u8, sz: u64| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, sz, [h; 32])
        };
        // {0,1,2} contributes `t` (~9 KiB) to absorbers — close to but
        // under threshold on its own (9 KiB + 512 hdr + 1024 trailer
        // ≈ 10.5 KiB).
        let t = |i: usize| chunk(i, 0xaa, 9 * 1024);
        // {0,1} carries `s` (~7 KiB) on its own — also under threshold.
        let s = |i: usize| chunk(i, 0xbb, 7 * 1024);
        let fs0 = fs_of(0, &[("t", t(0)), ("s", s(0))]);
        let fs1 = fs_of(1, &[("t", t(1)), ("s", s(1))]);
        let fs2 = fs_of(2, &[("t", t(2))]);

        let mut layers = build(&[fs0.clone(), fs1.clone(), fs2.clone()]);
        // Sanity: pre-dissolve {0,1} is below threshold.
        let pre = estimated_tar_size(&layers[&ids(&[0, 1])]);
        assert!(pre < DEFAULT_MIN_LAYER_SIZE, "pre {pre}");
        // Pre-dissolve {0,1,2} is also below threshold.
        let pre012 = estimated_tar_size(&layers[&ids(&[0, 1, 2])]);
        assert!(pre012 < DEFAULT_MIN_LAYER_SIZE);

        dissolve(&mut layers, &[fs0, fs1, fs2], DEFAULT_MIN_LAYER_SIZE);
        // {0,1,2} dissolved into {0,1} + {2}. After absorption {0,1}
        // carries both s (7 KiB) and t (9 KiB) ≈ 16 KiB — above the
        // 16 KiB threshold once headers and padding are counted.
        assert!(!layers.contains_key(&ids(&[0, 1, 2])));
        assert!(layers.contains_key(&ids(&[0, 1])), "absorbed past threshold, kept");
        let post = estimated_tar_size(&layers[&ids(&[0, 1])]);
        assert!(post >= DEFAULT_MIN_LAYER_SIZE, "post {post}");
    }

    #[test]
    fn destination_tiebreak_picks_lex_smallest() {
        // M = {0,1,2,3}; subsets of size 3 carrying image 0:
        //   {0,1,2}, {0,1,3}, {0,2,3}. Lex smallest = {0,1,2}.
        // We craft the inputs so all three exist with non-trivial
        // size and a tiny {0,1,2,3} below threshold dissolves into
        // them. Image 0 picks {0,1,2}.
        let big = |i: usize, h: u8| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 32 * 1024, [h; 32])
        };
        let tiny = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 1, [0xcc; 32])
        };
        // Make L({0,1,2,3}) carry only the tiny file.
        // L({0,1,2}) carries a big file shared by 0,1,2.
        // L({0,1,3}) carries a big file shared by 0,1,3.
        // L({0,2,3}) carries a big file shared by 0,2,3.
        let fs0 = fs_of(
            0,
            &[
                ("t", tiny(0)),
                ("a012", big(0, 0xa1)),
                ("a013", big(0, 0xa2)),
                ("a023", big(0, 0xa3)),
            ],
        );
        let fs1 = fs_of(1, &[("t", tiny(1)), ("a012", big(1, 0xa1)), ("a013", big(1, 0xa2))]);
        let fs2 = fs_of(2, &[("t", tiny(2)), ("a012", big(2, 0xa1)), ("a023", big(2, 0xa3))]);
        let fs3 = fs_of(3, &[("t", tiny(3)), ("a013", big(3, 0xa2)), ("a023", big(3, 0xa3))]);

        let mut layers = build(&[fs0.clone(), fs1.clone(), fs2.clone(), fs3.clone()]);
        assert!(layers.contains_key(&ids(&[0, 1, 2, 3])));
        dissolve(&mut layers, &[fs0, fs1, fs2, fs3], DEFAULT_MIN_LAYER_SIZE);

        assert!(!layers.contains_key(&ids(&[0, 1, 2, 3])));
        // Image 0's tiny file should now sit in L({0,1,2}) (lex
        // smallest |M|=3 subset containing 0).
        let l012 = layers.get(&ids(&[0, 1, 2])).expect("kept");
        assert!(l012.entries.contains_key(Path::new("t")));
        // L({0,1,3}) and L({0,2,3}) should NOT have absorbed image
        // 0's copy (image 1 and image 2 each picked their own lex-
        // smallest, both also {0,1,2}).
        let l013 = layers.get(&ids(&[0, 1, 3])).expect("kept");
        let l023 = layers.get(&ids(&[0, 2, 3])).expect("kept");
        // Image 3's pick: subsets of size 3 containing 3 are {0,1,3}
        // and {0,2,3}; lex smallest is {0,1,3}.
        assert!(l013.entries.contains_key(Path::new("t")));
        assert!(!l023.entries.contains_key(Path::new("t")));
    }

    #[test]
    fn singletons_are_never_dissolved_even_if_below_threshold() {
        // Single tiny per-image layer. Pass should leave it alone.
        let fs0 = fs_of(0, &[("a", regular(0, 1, [0x33; 32]))]);
        let mut layers = build(std::slice::from_ref(&fs0));
        dissolve(&mut layers, std::slice::from_ref(&fs0), DEFAULT_MIN_LAYER_SIZE);
        assert!(layers.contains_key(&ids(&[0])));
    }

    #[test]
    fn directory_only_layer_dissolves_into_singletons() {
        // L({0,1,2}) carrying just the shared `etc` directory (rule
        // 2 duplicate of M_D's natural layer) below threshold —
        // should dissolve. The smaller per-image layers already carry
        // their own `etc` from partition pass 2 backfill; dissolve
        // re-emits `etc` from the dissolved layer into each
        // destination too, which the `Occupied` branch in
        // `migrate_into` resolves via the smallest-`image_id`
        // canonical-source policy. Either way the destination ends up
        // with a byte-equal `etc` entry.
        let only0 = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 0, [0x44; 32])
        };
        let only1 = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 0, [0x55; 32])
        };
        let only2 = |i: usize| SquashedEntry {
            image_id: InputImageId(i),
            ..regular(0, 0, [0x66; 32])
        };
        // Each image has a different file under etc; etc itself is
        // shared with identical metadata. L({0,1,2}) ends up with
        // just `etc`.
        let fs0 = fs_of(0, &[("etc", dir(0, 0o755)), ("etc/x0", only0(0))]);
        let fs1 = fs_of(1, &[("etc", dir(1, 0o755)), ("etc/x1", only1(1))]);
        let fs2 = fs_of(2, &[("etc", dir(2, 0o755)), ("etc/x2", only2(2))]);

        let mut layers = build(&[fs0.clone(), fs1.clone(), fs2.clone()]);
        let l_full = &layers[&ids(&[0, 1, 2])];
        assert_eq!(paths_in(l_full), vec!["etc"]);
        // Below threshold (one directory: 512+1024 = 1536 < 16384).
        dissolve(&mut layers, &[fs0, fs1, fs2], DEFAULT_MIN_LAYER_SIZE);

        assert!(!layers.contains_key(&ids(&[0, 1, 2])), "dissolved");
        // Singletons still carry their own etc directory + file from
        // the partition pass (unchanged in shape, possibly rebound to
        // a smaller `image_id` source by the dissolve migration).
        for (i, name) in [(0, "etc/x0"), (1, "etc/x1"), (2, "etc/x2")] {
            let l = &layers[&ids(&[i])];
            assert!(l.entries.contains_key(Path::new("etc")));
            assert!(l.entries.contains_key(Path::new(name)));
        }
    }

    #[test]
    fn leaf_directory_in_dissolved_layer_lands_in_per_image_destination() {
        // Spec 11 §11.5 round-trip regression: a leaf directory shared
        // by every image (the canonical case is an empty `tmp` dir
        // present in every image of a corpus) used to be silently
        // dropped by dissolve because the original implementation
        // skipped `EntryKind::Directory` entries on the assumption
        // that a non-leaf dir would be re-added via the
        // file-migration ancestor-backfill. For a leaf dir nothing
        // ever back-fills it, so the entry vanished from the output —
        // breaking `FS(i) == FS'(i)` for every image. The fix removes
        // the directory short-circuit so leaf dirs migrate like
        // anything else.
        let fs0 = fs_of(0, &[("tmp", dir(0, 0o1777))]);
        let fs1 = fs_of(1, &[("tmp", dir(1, 0o1777))]);

        let mut layers = build(&[fs0.clone(), fs1.clone()]);
        // Partition: only L({0,1}) exists, carrying just `tmp`.
        assert_eq!(layers.len(), 1);
        assert!(layers.contains_key(&ids(&[0, 1])));

        dissolve(&mut layers, &[fs0, fs1], DEFAULT_MIN_LAYER_SIZE);

        assert!(!layers.contains_key(&ids(&[0, 1])), "dissolved");
        // Leaf `tmp` must have landed in each per-image fallback.
        for i in [0, 1] {
            let l = layers
                .get(&ids(&[i]))
                .unwrap_or_else(|| panic!("L({{{i}}}) created on demand"));
            assert!(
                l.entries.contains_key(Path::new("tmp")),
                "leaf directory `tmp` lost from L({{{i}}}) after dissolve",
            );
        }
    }
}
