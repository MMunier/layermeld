//! Hardlink target co-location for per-image layers.
//!
//! Spec 05 §5.6 / spec 02 §2.6 say hardlinks live in the per-image
//! layer `{i}` and may reference targets that live in a shared layer
//! below them. That model is correct when a runtime *applies* layers
//! to a unified rootfs (overlayfs, vfs): by the time the per-image
//! layer is processed, the target's path already exists in the merged
//! view and the hardlink resolves naturally.
//!
//! In practice some loaders — notably `podman load` and `docker load`
//! when reading a docker-archive tar — extract each layer tar into an
//! isolated diff directory before composing the rootfs. A `LNKTYPE`
//! entry in the per-image layer that names a path which lives only in
//! a sibling shared layer fails: the tar extractor calls `link(2)` and
//! the target isn't on disk in this layer's diff dir.
//!
//! This pass is a workaround: for every hardlink in a per-image layer,
//! ensure its target's regular-file entry is *also* in that same
//! layer. The hardlink stays a hardlink; its target's body bytes get
//! duplicated across the shared layer (where it still lives for image
//! `j ≠ i`) and the per-image layer (where it lives so this image's
//! tar can resolve the hardlink without crossing layer boundaries).
//!
//! Hardlink chains (`A → B → C`, all alive after
//! [`crate::squash::hardlink::resolve`]) are flattened here: every
//! hardlink in a per-image layer is rewritten to point directly at
//! the chain's terminal regular file. This avoids relying on tar
//! extractors handling deferred / out-of-order hardlink resolution
//! within a single layer — a quirk that varies between extractors.
//!
//! ## Cost
//!
//! Co-locating duplicates the target's body bytes once per image
//! that hardlinks to it. For typical images this is a handful of
//! KiB (perl interpreter aliases, busybox applets) — negligible
//! compared to layer overhead. Spec 05's dedup benefit on the
//! shared layer is preserved for every image that *doesn't* hardlink
//! to the file.
//!
//! ## When it runs
//!
//! After [`crate::dedup::dissolve`] but before
//! [`crate::assemble::emit::emit_layers`]. Dissolve never moves
//! hardlinks (they're always in `{i}`, never in `|M| ≥ 2` layers per
//! spec 05 §5.6) so the partition shape is final by the time we run.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::squash::index::{InputImageId, SquashedEntry, SquashedFs};
use crate::tar_io::reader::EntryKind;

use super::membership::ImageSet;
use super::partition::CandidateLayer;

/// For every per-image layer `L({i})` in `layers`, ensure each
/// hardlink's target is co-located in the same layer with a `Regular`
/// entry, and rewrite hardlinks pointing through chains to point
/// directly at the chain's terminal regular file.
///
/// `images` must be the same per-image [`SquashedFs`] slice that
/// [`super::partition::partition`] was driven from — used here only
/// to resolve hardlink chains via the canonical view of each image.
///
/// Layers with `|M| ≥ 2` are skipped: per spec 05 §5.6 they cannot
/// contain hardlinks, so there is nothing to co-locate.
///
/// # Panics
///
/// * If a per-image layer's membership references an `image_id` that
///   has no corresponding non-empty entry in `images`. Same internal-
///   inconsistency contract as [`super::partition::partition`].
pub fn colocate_hardlink_targets(layers: &mut BTreeMap<ImageSet, CandidateLayer>, images: &[SquashedFs]) {
    let by_id: BTreeMap<InputImageId, &SquashedFs> = images
        .iter()
        .filter_map(|fs| fs.iter().next().map(|(_, e)| (e.image_id, fs)))
        .collect();

    let layer_keys: Vec<ImageSet> = layers.keys().cloned().collect();
    for m in layer_keys {
        if m.len() != 1 {
            continue;
        }
        let canonical_id = m.iter().next().expect("singleton membership has exactly one id");
        let Some(canonical_fs) = by_id.get(&canonical_id).copied() else {
            // Empty image (no live entries): partition could not have
            // placed anything in {i}, so the per-image layer is either
            // missing or empty. Nothing to co-locate.
            continue;
        };

        // Collect rewrites first (immutable borrow of layer.entries),
        // then apply them (mutable borrow). Lex order is stable.
        let hardlinks: Vec<(PathBuf, PathBuf)> = layers[&m]
            .entries
            .iter()
            .filter(|(_, e)| matches!(e.kind, EntryKind::Hardlink))
            .filter_map(|(path, e)| e.link_target.as_ref().map(|t| (path.clone(), t.clone())))
            .collect();

        for (link_path, direct_target) in hardlinks {
            let Some(terminal) = chase_to_terminal(canonical_fs, &direct_target) else {
                // The chain is malformed (no terminal regular found in
                // the canonical view). `squash::hardlink::resolve` would
                // already have demoted the link in that case, so by the
                // time we get here every surviving hardlink should chase
                // cleanly. If somehow it doesn't, leaving the layer as-is
                // means the assemble pass writes a hardlink the loader
                // can't follow — same failure mode as before this pass
                // existed, no regression.
                continue;
            };

            let layer = layers.get_mut(&m).expect("layer present");

            // 1. Rewrite the hardlink's link_target to point directly
            //    at the chain's terminal regular file's path. Flattens
            //    `A → B → C` to `A → C` so the layer's tar doesn't
            //    require the extractor to handle hardlink-to-hardlink
            //    chains within one stream.
            if let Some(link_entry) = layer.entries.get_mut(&link_path) {
                link_entry.link_target = Some(terminal.path.clone());
            }

            // 2. Co-locate the terminal regular's entry at its path
            //    inside this layer if not already present. The shared
            //    layer keeps its own copy for images that *don't*
            //    hardlink to this path; both versions are byte-equal so
            //    overlay-style layer stacking is unaffected.
            layer.entries.entry(terminal.path).or_insert(terminal.entry);
        }
    }
}

/// One terminal-regular result of [`chase_to_terminal`].
struct Terminal {
    /// Canonical path of the terminal regular file in the image's
    /// squashed view.
    path: PathBuf,
    /// The terminal entry itself, ready to insert into a candidate
    /// layer.
    entry: SquashedEntry,
}

/// Walk the hardlink chain starting at `path` in `fs`, returning the
/// first non-`Hardlink` entry encountered when its kind is `Regular`.
///
/// Returns `None` for chains that terminate on a non-regular entry,
/// chains that revisit a path (cycles — defensible against malformed
/// input even though `squash::hardlink::resolve` already rejects them),
/// and chains that reach a missing path.
fn chase_to_terminal(fs: &SquashedFs, path: &Path) -> Option<Terminal> {
    let mut visited: BTreeSet<PathBuf> = BTreeSet::new();
    let mut cursor = path.to_path_buf();
    loop {
        if !visited.insert(cursor.clone()) {
            return None;
        }
        let entry = fs.get(&cursor)?;
        match entry.kind {
            EntryKind::Regular => {
                return Some(Terminal {
                    path: cursor,
                    entry: entry.clone(),
                });
            }
            EntryKind::Hardlink => {
                let next = entry.link_target.clone()?;
                cursor = next;
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::super::membership::ImageSet;
    use super::super::partition::CandidateLayer;
    use super::*;
    use crate::squash::index::{InputImageId, SquashedEntry, SquashedFs};
    use crate::tar_io::reader::EntryKind;

    fn make_entry(image: usize, kind: EntryKind) -> SquashedEntry {
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

    fn regular(image: usize, size: u64) -> SquashedEntry {
        SquashedEntry {
            size,
            ..make_entry(image, EntryKind::Regular)
        }
    }

    fn hardlink(image: usize, target: &str) -> SquashedEntry {
        SquashedEntry {
            link_target: Some(PathBuf::from(target)),
            ..make_entry(image, EntryKind::Hardlink)
        }
    }

    fn fs_with(image: usize, items: &[(&str, SquashedEntry)]) -> SquashedFs {
        let mut fs = SquashedFs::new();
        for (path, e) in items {
            fs.insert(PathBuf::from(*path), e.clone());
        }
        let _ = image;
        fs
    }

    fn layer_with(membership: ImageSet, items: &[(&str, SquashedEntry)]) -> CandidateLayer {
        let mut entries = BTreeMap::new();
        for (path, e) in items {
            entries.insert(PathBuf::from(*path), e.clone());
        }
        CandidateLayer { membership, entries }
    }

    #[test]
    fn empty_input_is_a_noop() {
        let mut layers: BTreeMap<ImageSet, CandidateLayer> = BTreeMap::new();
        colocate_hardlink_targets(&mut layers, &[]);
        assert!(layers.is_empty());
    }

    #[test]
    fn layer_without_hardlinks_is_unchanged() {
        let m = ImageSet::singleton(InputImageId(0));
        let fs = fs_with(0, &[("etc/hostname", regular(0, 5))]);
        let mut layers = BTreeMap::new();
        layers.insert(m.clone(), layer_with(m, &[("etc/hostname", regular(0, 5))]));
        let before = layers.clone();
        colocate_hardlink_targets(&mut layers, &[fs]);
        // BTreeMap of clones equals only when contents do — pin
        // unchanged keys + entry counts.
        assert_eq!(layers.len(), before.len());
        for (k, v) in &before {
            assert_eq!(layers[k].entries.len(), v.entries.len());
        }
    }

    #[test]
    fn target_in_shared_layer_is_pulled_into_per_image_layer() {
        // Image 0 has a hardlink in {0} pointing at a regular file
        // that the partition placed in {0,1}. Co-locate must add the
        // regular file to {0} so the per-image tar can resolve it.
        let m_shared = ImageSet::from_ids([InputImageId(0), InputImageId(1)]);
        let m_per = ImageSet::singleton(InputImageId(0));

        let fs0 = fs_with(
            0,
            &[
                ("usr/bin/perl", regular(0, 1024)),
                ("usr/bin/perl5.40.1", hardlink(0, "usr/bin/perl")),
            ],
        );
        let fs1 = fs_with(1, &[("usr/bin/perl", regular(1, 1024))]);

        let mut layers = BTreeMap::new();
        layers.insert(
            m_shared.clone(),
            layer_with(m_shared.clone(), &[("usr/bin/perl", regular(0, 1024))]),
        );
        layers.insert(
            m_per.clone(),
            layer_with(m_per.clone(), &[("usr/bin/perl5.40.1", hardlink(0, "usr/bin/perl"))]),
        );

        colocate_hardlink_targets(&mut layers, &[fs0, fs1]);

        // Per-image layer now contains both the hardlink and the target.
        let per = &layers[&m_per].entries;
        assert!(per.contains_key(&PathBuf::from("usr/bin/perl5.40.1")));
        assert!(per.contains_key(&PathBuf::from("usr/bin/perl")));
        assert_eq!(per[&PathBuf::from("usr/bin/perl")].kind, EntryKind::Regular);
        // Hardlink still points at the same direct target (no chain
        // here so flatten is a no-op on link_target).
        let hl = &per[&PathBuf::from("usr/bin/perl5.40.1")];
        assert_eq!(hl.kind, EntryKind::Hardlink);
        assert_eq!(hl.link_target.as_deref(), Some(Path::new("usr/bin/perl")));

        // Shared layer is untouched — image 1 still pulls the file
        // from there.
        assert_eq!(layers[&m_shared].entries.len(), 1);
        assert!(layers[&m_shared].entries.contains_key(&PathBuf::from("usr/bin/perl")));
    }

    #[test]
    fn chain_is_flattened_to_terminal_regular() {
        // a → b → c, all alive in image 0. After co-locate, `a`'s
        // link_target is rewritten to `c` (skipping `b`) and `c` is
        // pulled into the per-image layer.
        let m_per = ImageSet::singleton(InputImageId(0));
        let fs0 = fs_with(
            0,
            &[("c", regular(0, 7)), ("b", hardlink(0, "c")), ("a", hardlink(0, "b"))],
        );

        let mut layers = BTreeMap::new();
        layers.insert(m_per.clone(), layer_with(m_per.clone(), &[("a", hardlink(0, "b"))]));

        colocate_hardlink_targets(&mut layers, &[fs0]);

        let entries = &layers[&m_per].entries;
        // `c` got pulled in as a Regular.
        assert!(entries.contains_key(&PathBuf::from("c")));
        assert_eq!(entries[&PathBuf::from("c")].kind, EntryKind::Regular);
        // `a`'s link_target rewritten to `c` so a single-pass tar
        // extractor doesn't need `b` present.
        let a = &entries[&PathBuf::from("a")];
        assert_eq!(a.kind, EntryKind::Hardlink);
        assert_eq!(a.link_target.as_deref(), Some(Path::new("c")));
    }

    #[test]
    fn shared_layer_with_2_images_is_skipped() {
        // |M| ≥ 2 layers cannot contain hardlinks per spec 05 §5.6.
        // Even if a hardlink slipped in (a bug elsewhere), the
        // co-locate pass scopes itself to per-image layers so it
        // doesn't paper over partition bugs in shared layers.
        let m_shared = ImageSet::from_ids([InputImageId(0), InputImageId(1)]);
        let fs0 = fs_with(0, &[("regular", regular(0, 1))]);
        let fs1 = fs_with(1, &[("regular", regular(1, 1))]);

        let mut layers = BTreeMap::new();
        layers.insert(
            m_shared.clone(),
            layer_with(
                m_shared.clone(),
                &[
                    ("regular", regular(0, 1)),
                    // Synthetic — wouldn't normally appear here.
                    ("alias", hardlink(0, "regular")),
                ],
            ),
        );
        let before = layers[&m_shared].entries.len();
        colocate_hardlink_targets(&mut layers, &[fs0, fs1]);
        assert_eq!(layers[&m_shared].entries.len(), before);
    }

    #[test]
    fn target_already_present_in_layer_is_not_duplicated() {
        // Hardlink and its target both land in {0} from partition.
        // Co-locate finds the target already there and is a no-op
        // for that path.
        let m = ImageSet::singleton(InputImageId(0));
        let fs0 = fs_with(0, &[("target", regular(0, 4)), ("alias", hardlink(0, "target"))]);
        let mut layers = BTreeMap::new();
        layers.insert(
            m.clone(),
            layer_with(
                m.clone(),
                &[("target", regular(0, 4)), ("alias", hardlink(0, "target"))],
            ),
        );
        let before = layers[&m].entries.len();
        colocate_hardlink_targets(&mut layers, &[fs0]);
        assert_eq!(layers[&m].entries.len(), before);
    }

    #[test]
    fn cycle_in_chain_is_safely_ignored() {
        // a → b → a — pathological input. `squash::hardlink::resolve`
        // would already reject this, but defensively: co-locate must
        // not loop. The hardlink stays as-is; the loader will fail to
        // resolve it (same as before this pass), no regression.
        let m = ImageSet::singleton(InputImageId(0));
        let fs0 = fs_with(0, &[("a", hardlink(0, "b")), ("b", hardlink(0, "a"))]);
        let mut layers = BTreeMap::new();
        layers.insert(m.clone(), layer_with(m.clone(), &[("a", hardlink(0, "b"))]));
        colocate_hardlink_targets(&mut layers, &[fs0]);
        // `a` left unchanged; nothing pulled in (no terminal regular).
        assert_eq!(layers[&m].entries.len(), 1);
        assert!(layers[&m].entries.contains_key(&PathBuf::from("a")));
    }

    #[test]
    fn missing_image_for_singleton_layer_is_a_noop() {
        // images slice doesn't carry a fs for image 0 (empty image).
        // The partition wouldn't normally produce a non-empty {0}
        // layer in that case, but defensively co-locate must not
        // panic — it just leaves the layer alone.
        let m = ImageSet::singleton(InputImageId(0));
        let mut layers = BTreeMap::new();
        layers.insert(m.clone(), layer_with(m.clone(), &[("a", hardlink(0, "b"))]));
        colocate_hardlink_targets(&mut layers, &[]);
        assert_eq!(layers[&m].entries.len(), 1);
    }
}
