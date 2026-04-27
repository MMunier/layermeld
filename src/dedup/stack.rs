//! Per-image layer stack ordering (spec 05 §5.3).
//!
//! Given the candidate-layer partition produced by [`super::partition`]
//! (and possibly mutated by [`super::dissolve`]), this module yields the
//! ordered list of layer keys for a given input image, ready to be
//! assembled into that image's OCI manifest in spec 08.
//!
//! Spec 05 §5.3 defines the order as:
//!
//! 1. Every subset layer `M` such that `i ∈ M`, ordered first by
//!    **descending `|M|`** (largest subsets — most universal content —
//!    applied first), then by ascending lexicographic order of `M` as a
//!    tiebreaker. The fully-shared layer is therefore always first.
//! 2. The per-image layer `{i}` itself, applied last.
//!
//! Rule 2 falls out of rule 1: `{i}` has `|M| = 1`, the smallest
//! possible non-empty membership for image `i`, so under
//! "descending `|M|`, ascending lex" it always sorts last among layers
//! `i` belongs to. No special-case needed.
//!
//! `ImageSet`'s derived `Ord` is lex over its sorted-`Vec` internal
//! representation — exactly the "ascending lexicographic order of the
//! image ids in `M`" the spec calls for.
//!
//! Layers that do not actually exist in the partition are not emitted:
//! if image `i` has no exclusive content (so `L({i})` was never created
//! by the partition or dissolve passes), the stack simply ends at the
//! smallest existing layer that contains `i`. Spec 05 §5.5.2 only
//! guarantees `{i}` exists "as an absorber of last resort" *during*
//! dissolve when a smaller layer is needed — after dissolve the layer
//! set is final, and a non-existent `{i}` means image `i` has nothing
//! that requires its own layer.

use std::cmp::Reverse;
use std::collections::BTreeMap;

use crate::squash::index::InputImageId;

use super::membership::ImageSet;
use super::partition::CandidateLayer;

/// Ordered layer-key list for image `i`'s output stack (spec 05 §5.3).
///
/// Returns the keys of every layer in `layers` whose membership
/// contains `image`, sorted by descending `|M|` and then by ascending
/// lex on `M`. The bottom of the stack (first applied) comes first; the
/// top (last applied — typically `{image}`) comes last.
///
/// Cloning the `ImageSet`s rather than borrowing keeps the result
/// independent of `layers`'s lifetime, which is convenient for
/// downstream stages (spec 07 assemble / spec 08 manifest) that want to
/// hold the order while mutating per-layer accounting.
#[must_use]
pub fn stack_for_image(layers: &BTreeMap<ImageSet, CandidateLayer>, image: InputImageId) -> Vec<ImageSet> {
    let mut keys: Vec<ImageSet> = layers.keys().filter(|m| m.contains(image)).cloned().collect();
    keys.sort_by(|a, b| Reverse(a.len()).cmp(&Reverse(b.len())).then_with(|| a.cmp(b)));
    keys
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::squash::index::InputImageId;

    fn ids(xs: &[usize]) -> ImageSet {
        ImageSet::from_ids(xs.iter().copied().map(InputImageId))
    }

    fn empty_layer(membership: ImageSet) -> CandidateLayer {
        CandidateLayer {
            membership,
            entries: BTreeMap::new(),
        }
    }

    fn layers_for(keys: &[ImageSet]) -> BTreeMap<ImageSet, CandidateLayer> {
        keys.iter().cloned().map(|k| (k.clone(), empty_layer(k))).collect()
    }

    #[test]
    fn empty_partition_yields_empty_stack() {
        let layers: BTreeMap<ImageSet, CandidateLayer> = BTreeMap::new();
        assert!(stack_for_image(&layers, InputImageId(0)).is_empty());
    }

    #[test]
    fn image_not_in_any_layer_yields_empty_stack() {
        let layers = layers_for(&[ids(&[0]), ids(&[1])]);
        assert!(stack_for_image(&layers, InputImageId(2)).is_empty());
    }

    #[test]
    fn singleton_only_yields_singleton_stack() {
        let layers = layers_for(&[ids(&[0])]);
        assert_eq!(stack_for_image(&layers, InputImageId(0)), vec![ids(&[0])]);
    }

    #[test]
    fn fully_shared_then_per_image_in_two_image_setup() {
        // Spec 05 §5.3 example: with N = 2 the stack for image 0 is
        // L({0,1}) then L({0}).
        let layers = layers_for(&[ids(&[0, 1]), ids(&[0]), ids(&[1])]);
        assert_eq!(stack_for_image(&layers, InputImageId(0)), vec![ids(&[0, 1]), ids(&[0])],);
        assert_eq!(stack_for_image(&layers, InputImageId(1)), vec![ids(&[0, 1]), ids(&[1])],);
    }

    #[test]
    fn descending_size_orders_full_then_partials_then_singleton() {
        // Image 0 is in L({0,1,2,3}), L({0,1,2}), L({0,1}), L({0}).
        let layers = layers_for(&[
            ids(&[0, 1, 2, 3]),
            ids(&[0, 1, 2]),
            ids(&[0, 1]),
            ids(&[0]),
            ids(&[1, 2]), // image 0 not in this one
        ]);
        assert_eq!(
            stack_for_image(&layers, InputImageId(0)),
            vec![ids(&[0, 1, 2, 3]), ids(&[0, 1, 2]), ids(&[0, 1]), ids(&[0])],
        );
    }

    #[test]
    fn lex_tiebreak_at_equal_size() {
        // Image 0 is in three |M|=2 layers: {0,1}, {0,2}, {0,3}.
        // Lex tiebreak: {0,1} < {0,2} < {0,3}.
        let layers = layers_for(&[ids(&[0, 1]), ids(&[0, 2]), ids(&[0, 3])]);
        assert_eq!(
            stack_for_image(&layers, InputImageId(0)),
            vec![ids(&[0, 1]), ids(&[0, 2]), ids(&[0, 3])],
        );
    }

    #[test]
    fn lex_tiebreak_at_equal_size_with_full_shared_first() {
        // Full-shared L({0,1,2,3}) sorts first. Among |M|=3 layers
        // image 0 belongs to ({0,1,2}, {0,1,3}, {0,2,3}), lex order
        // applies. Then the |M|=2 layers, then the singleton.
        let layers = layers_for(&[
            ids(&[0, 1, 2, 3]),
            ids(&[0, 2, 3]),
            ids(&[0, 1, 2]),
            ids(&[0, 1, 3]),
            ids(&[0, 1]),
            ids(&[0, 3]),
            ids(&[0]),
        ]);
        assert_eq!(
            stack_for_image(&layers, InputImageId(0)),
            vec![
                ids(&[0, 1, 2, 3]),
                ids(&[0, 1, 2]),
                ids(&[0, 1, 3]),
                ids(&[0, 2, 3]),
                ids(&[0, 1]),
                ids(&[0, 3]),
                ids(&[0]),
            ],
        );
    }

    #[test]
    fn per_image_layer_lands_last_when_present() {
        // {i} is the smallest possible layer containing i, so under
        // "descending |M|" it sorts last regardless of what else exists.
        let layers = layers_for(&[ids(&[0, 1, 2]), ids(&[0, 1]), ids(&[0])]);
        let stack = stack_for_image(&layers, InputImageId(0));
        assert_eq!(*stack.last().unwrap(), ids(&[0]));
    }

    #[test]
    fn missing_per_image_layer_is_simply_omitted() {
        // Image 0 has no exclusive content, so L({0}) doesn't exist.
        // The stack ends at the smallest existing layer image 0 is in.
        let layers = layers_for(&[ids(&[0, 1, 2]), ids(&[0, 1])]);
        assert_eq!(
            stack_for_image(&layers, InputImageId(0)),
            vec![ids(&[0, 1, 2]), ids(&[0, 1])],
        );
    }

    #[test]
    fn other_images_are_filtered_out() {
        // Verify the filter actually drops layers not containing `image`.
        let layers = layers_for(&[
            ids(&[0, 1]),
            ids(&[0, 2]),
            ids(&[1, 2]), // not in image 0's stack
            ids(&[0]),
            ids(&[1]), // not in image 0's stack
            ids(&[2]), // not in image 0's stack
        ]);
        assert_eq!(
            stack_for_image(&layers, InputImageId(0)),
            vec![ids(&[0, 1]), ids(&[0, 2]), ids(&[0])],
        );
    }

    #[test]
    fn order_is_independent_of_btreemap_iteration() {
        // BTreeMap iterates keys in their derived Ord, which is lex
        // over the sorted-Vec backing — *not* descending-size. The
        // helper must re-sort, so the result must not match raw
        // BTreeMap iteration order for non-trivial cases.
        let layers = layers_for(&[ids(&[0, 1, 2]), ids(&[0, 1]), ids(&[0])]);
        let stack = stack_for_image(&layers, InputImageId(0));
        // Raw BTreeMap key order (lex): {0}, {0,1}, {0,1,2}
        let raw: Vec<ImageSet> = layers.keys().cloned().collect();
        assert_ne!(stack, raw);
        // Sorted-by-spec result: {0,1,2}, {0,1}, {0}
        assert_eq!(stack, vec![ids(&[0, 1, 2]), ids(&[0, 1]), ids(&[0])]);
    }

    #[test]
    fn every_layer_containing_image_appears_exactly_once() {
        // Spec §5.3: "every member layer of image i is present in its
        // stack". And present once.
        let layers = layers_for(&[
            ids(&[0, 1, 2, 3]),
            ids(&[0, 1, 2]),
            ids(&[0, 2, 3]),
            ids(&[0, 1]),
            ids(&[0, 3]),
            ids(&[0]),
            ids(&[1, 2, 3]),
            ids(&[1, 2]),
        ]);
        let stack = stack_for_image(&layers, InputImageId(0));
        let expected: Vec<ImageSet> = layers.keys().filter(|m| m.contains(InputImageId(0))).cloned().collect();
        assert_eq!(stack.len(), expected.len());
        for k in &expected {
            assert_eq!(stack.iter().filter(|s| *s == k).count(), 1);
        }
    }
}
