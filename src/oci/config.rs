//! Image config rewrite (spec 08 §8.1).
//!
//! Given an input image's parsed [`ImageConfiguration`] and the per-image
//! ordered output stack (spec 05 §5.3 — descending `|M|`, lex tiebreak,
//! per-image layer last), this module produces the fresh image config
//! the squashed image will publish under spec 09 §9.1's
//! `blobs/sha256/<digest>` tree.
//!
//! ## What carries over verbatim
//!
//! - `architecture`, `os`, optional `os.version` / `os.features` /
//!   `variant` (top-level platform fields).
//! - The inner `config` substructure: `User`, `ExposedPorts`, `Env`,
//!   `Entrypoint`, `Cmd`, `Volumes`, `WorkingDir`, `Labels`, `StopSignal`.
//!   Spec §8.1 also lists `Healthcheck` and `ArgsEscaped`; the `oci-spec`
//!   v0.7 typed model does not surface those, so they are silently
//!   dropped at parse time on input and never appear on output. That is
//!   the spec §8.4a "round-trip through `oci-spec` is the canonical
//!   schema for both directions" contract.
//!
//! ## What is rewritten
//!
//! - `created` is replaced with `T0` (spec 06) formatted via
//!   [`T0::to_rfc3339`]. The original input value is dropped.
//! - `rootfs.type` is forced to `"layers"`. `rootfs.diff_ids` becomes the
//!   ordered list of output-layer `diff_ids` in spec §5.3 order. Each
//!   `diff_id` is spelled `sha256:<hex>` per OCI image config v1.
//! - `history` is replaced with one synthetic entry per output layer in
//!   `diff_ids` order. Each entry has `created = T0` and a deterministic
//!   `created_by` string per spec §8.1 — see [`created_by_for`]. The
//!   `comment`, `author`, and `empty_layer` fields are omitted.
//!
//! ## What is dropped outright
//!
//! - The top-level `author` field (only the carry-over list of §8.1 is
//!   preserved).
//! - Any Docker-specific top-level fields the input carried (`config.Image`,
//!   `container`, `container_config`, `docker_version`, ...). These are
//!   not modelled by `oci-spec`'s `ImageConfiguration` so they were
//!   already dropped at parse time on input — the output is a strict OCI
//!   image config v1 by construction.
//!
//! ## Determinism
//!
//! Spec 11 §11.6 requires byte-identical output for the same input set
//! plus pinned `T0`. This module's contribution: `created_by` strings
//! are pure functions of an `ImageSet`'s ordered ids, `diff_ids` follow
//! a deterministic stack order, and field ordering inside the JSON
//! document is whatever `oci-spec` emits (a pure function of the crate
//! version pinned in `Cargo.toml`). Together these mean two runs over
//! the same inputs produce byte-equal config blobs.

use oci_spec::image::{HistoryBuilder, ImageConfiguration, ImageConfigurationBuilder, RootFsBuilder};

use crate::Error;
use crate::Result;
use crate::assemble::digest::hex_encode;
use crate::assemble::emit::EmittedLayer;
use crate::dedup::membership::ImageSet;
use crate::squash::index::InputImageId;
use crate::timestamp::T0;

/// Build the synthetic `created_by` string spec §8.1 prescribes for an
/// output layer's `history` entry.
///
/// The format is part of the spec 11 determinism contract — every byte
/// here is reproducible from the membership set alone:
///
/// * `|M| == 1`: `"layermeld: per-image layer for image-<i>"`
///   where `<i>` is the input image's argv index (the `usize` inside
///   [`InputImageId`]).
/// * `|M| > 1`: `"layermeld: shared layer for {<i₁>,<i₂>,...}"`
///   with the ids in ascending order, comma-separated, no whitespace.
///   Ascending order falls out of [`ImageSet`]'s sorted-`Vec` backing
///   so callers cannot accidentally pass a reordered membership.
///
/// An empty `ImageSet` is not produced by the dedup pipeline (every
/// candidate layer has `|M| ≥ 1`); for safety, the empty case is
/// rendered as `"layermeld: empty layer"` rather than panicking.
#[must_use]
pub fn created_by_for(membership: &ImageSet) -> String {
    let ids: Vec<InputImageId> = membership.iter().collect();
    match ids.as_slice() {
        [] => "layermeld: empty layer".to_string(),
        [single] => format!("layermeld: per-image layer for image-{}", single.0),
        many => {
            let joined = many.iter().map(|id| id.0.to_string()).collect::<Vec<_>>().join(",");
            format!("layermeld: shared layer for {{{joined}}}")
        }
    }
}

/// Format a 32-byte SHA-256 digest as the OCI `sha256:<hex>` string used
/// by `rootfs.diff_ids`. Pure pass-through of [`hex_encode`] with the
/// algorithm prefix prepended; centralised so the prefix spelling is
/// identical to whatever 09 §9.x manifest emission picks.
#[must_use]
pub fn diff_id_string(digest: &[u8; 32]) -> String {
    format!("sha256:{}", hex_encode(digest))
}

/// Rewrite an input image config into the squashed output config per
/// spec 08 §8.1.
///
/// `input` is the parsed input config (carry-over fields are read from
/// here). `stack` is the ordered list of output layers belonging to this
/// image, already sorted per spec 05 §5.3. `t0` is the run-wide
/// invocation timestamp.
///
/// # Errors
///
/// [`Error::Validation`] only if the underlying `oci-spec`
/// `ImageConfigurationBuilder` rejects the constructed value — in
/// practice this can only happen when the crate adds new required
/// fields in a future version that this code has not been updated for,
/// since both `architecture` and `os` are always populated and
/// `rootfs` is built from a complete [`RootFsBuilder`]. A
/// [`oci_spec::OciSpecError`] is wrapped verbatim into the message.
pub fn rewrite_image_config(input: &ImageConfiguration, stack: &[&EmittedLayer], t0: T0) -> Result<ImageConfiguration> {
    let created = t0.to_rfc3339();
    let diff_ids: Vec<String> = stack.iter().map(|l| diff_id_string(&l.digest)).collect();
    let history: Vec<oci_spec::image::History> = stack
        .iter()
        .map(|l| {
            HistoryBuilder::default()
                .created(created.clone())
                .created_by(created_by_for(&l.membership))
                .build()
                .map_err(|e| Error::Validation(format!("history entry build failed: {e}")))
        })
        .collect::<Result<_>>()?;

    let rootfs = RootFsBuilder::default()
        .typ("layers".to_string())
        .diff_ids(diff_ids)
        .build()
        .map_err(|e| Error::Validation(format!("rootfs build failed: {e}")))?;

    let mut builder = ImageConfigurationBuilder::default()
        .created(created)
        .architecture(input.architecture().clone())
        .os(input.os().clone())
        .rootfs(rootfs)
        .history(history);
    if let Some(v) = input.os_version() {
        builder = builder.os_version(v.clone());
    }
    if let Some(features) = input.os_features() {
        builder = builder.os_features(features.clone());
    }
    if let Some(variant) = input.variant() {
        builder = builder.variant(variant.clone());
    }
    if let Some(cfg) = input.config() {
        builder = builder.config(cfg.clone());
    }
    builder
        .build()
        .map_err(|e| Error::Validation(format!("image config build failed: {e}")))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use oci_spec::image::{Arch, ConfigBuilder, Os, RootFsBuilder};

    use super::*;
    use crate::squash::index::InputImageId;

    fn ids(xs: &[usize]) -> ImageSet {
        ImageSet::from_ids(xs.iter().copied().map(InputImageId))
    }

    fn emitted(membership: ImageSet, byte: u8) -> EmittedLayer {
        EmittedLayer {
            membership,
            digest: [byte; 32],
            size: 1024,
            path: PathBuf::from(format!("/tmp/blobs/{byte}")),
        }
    }

    fn minimal_input() -> ImageConfiguration {
        ImageConfigurationBuilder::default()
            .architecture(Arch::Amd64)
            .os(Os::Linux)
            .rootfs(
                RootFsBuilder::default()
                    .diff_ids(vec!["sha256:deadbeef".to_string()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    fn rich_input() -> ImageConfiguration {
        let cfg = ConfigBuilder::default()
            .user("alice".to_string())
            .env(vec!["PATH=/usr/bin".to_string()])
            .cmd(vec!["sh".to_string()])
            .working_dir("/home/alice".to_string())
            .build()
            .unwrap();
        ImageConfigurationBuilder::default()
            .created("1999-12-31T23:59:59Z".to_string())
            .author("someone-we-do-not-carry@example.com".to_string())
            .architecture(Arch::ARM64)
            .os(Os::Linux)
            .os_version("5.15.0".to_string())
            .os_features(vec!["foo".to_string()])
            .variant("v8".to_string())
            .config(cfg)
            .rootfs(
                RootFsBuilder::default()
                    .diff_ids(vec!["sha256:original-1".to_string(), "sha256:original-2".to_string()])
                    .build()
                    .unwrap(),
            )
            .history(vec![
                HistoryBuilder::default()
                    .created("1999-12-31T23:59:59Z".to_string())
                    .created_by("RUN echo hi".to_string())
                    .author("from-input".to_string())
                    .build()
                    .unwrap(),
            ])
            .build()
            .unwrap()
    }

    #[test]
    fn created_by_for_singleton_uses_per_image_form() {
        let s = created_by_for(&ImageSet::singleton(InputImageId(3)));
        assert_eq!(s, "layermeld: per-image layer for image-3");
    }

    #[test]
    fn created_by_for_shared_uses_braced_csv() {
        let s = created_by_for(&ids(&[2, 0, 1]));
        // ImageSet sorts internally — the output must reflect ascending order.
        assert_eq!(s, "layermeld: shared layer for {0,1,2}");
    }

    #[test]
    fn created_by_for_handles_empty_set_safely() {
        let s = created_by_for(&ImageSet::new());
        assert_eq!(s, "layermeld: empty layer");
    }

    #[test]
    fn diff_id_string_prefixes_sha256() {
        let d = [0xab; 32];
        let s = diff_id_string(&d);
        assert!(s.starts_with("sha256:"));
        assert_eq!(s.len(), "sha256:".len() + 64);
        assert_eq!(s, format!("sha256:{}", "ab".repeat(32)));
    }

    #[test]
    fn rewrite_sets_created_to_t0_rfc3339() {
        let input = minimal_input();
        let l0 = emitted(ImageSet::singleton(InputImageId(0)), 0xaa);
        let stack = [&l0];
        let out = rewrite_image_config(&input, &stack, T0::from_unix_seconds(1_700_000_000)).unwrap();
        assert_eq!(out.created().as_deref(), Some("2023-11-14T22:13:20Z"));
    }

    #[test]
    fn rewrite_carries_platform_fields_verbatim() {
        let input = rich_input();
        let l0 = emitted(ImageSet::singleton(InputImageId(0)), 0x11);
        let out = rewrite_image_config(&input, &[&l0], T0::from_unix_seconds(0)).unwrap();
        assert_eq!(out.architecture(), &Arch::ARM64);
        assert_eq!(out.os(), &Os::Linux);
        assert_eq!(out.os_version().as_deref(), Some("5.15.0"));
        assert_eq!(out.os_features().as_deref(), Some(&vec!["foo".to_string()][..]));
        assert_eq!(out.variant().as_deref(), Some("v8"));
    }

    #[test]
    fn rewrite_drops_top_level_author() {
        let input = rich_input();
        let l0 = emitted(ImageSet::singleton(InputImageId(0)), 0x11);
        let out = rewrite_image_config(&input, &[&l0], T0::from_unix_seconds(0)).unwrap();
        assert!(out.author().is_none(), "top-level author must be dropped");
    }

    #[test]
    fn rewrite_carries_inner_config_verbatim() {
        let input = rich_input();
        let l0 = emitted(ImageSet::singleton(InputImageId(0)), 0x11);
        let out = rewrite_image_config(&input, &[&l0], T0::from_unix_seconds(0)).unwrap();
        let cfg = out.config().as_ref().expect("inner config carries over");
        assert_eq!(cfg.user().as_deref(), Some("alice"));
        assert_eq!(cfg.env().as_deref(), Some(&vec!["PATH=/usr/bin".to_string()][..]));
        assert_eq!(cfg.cmd().as_deref(), Some(&vec!["sh".to_string()][..]));
        assert_eq!(cfg.working_dir().as_deref(), Some("/home/alice"));
    }

    #[test]
    fn rewrite_replaces_rootfs_with_layers_and_diff_ids() {
        let input = rich_input(); // had two unrelated input diff_ids
        let l0 = emitted(ids(&[0, 1]), 0x11);
        let l1 = emitted(ImageSet::singleton(InputImageId(0)), 0x22);
        let out = rewrite_image_config(&input, &[&l0, &l1], T0::from_unix_seconds(0)).unwrap();
        let rootfs = out.rootfs();
        assert_eq!(rootfs.typ(), "layers");
        assert_eq!(
            rootfs.diff_ids(),
            &vec![
                format!("sha256:{}", "11".repeat(32)),
                format!("sha256:{}", "22".repeat(32)),
            ]
        );
    }

    #[test]
    fn rewrite_history_has_one_entry_per_layer_in_stack_order() {
        let input = minimal_input();
        let layers = [
            emitted(ids(&[0, 1, 2]), 0x01),
            emitted(ids(&[0, 1]), 0x02),
            emitted(ImageSet::singleton(InputImageId(0)), 0x03),
        ];
        let stack = [&layers[0], &layers[1], &layers[2]];
        let out = rewrite_image_config(&input, &stack, T0::from_unix_seconds(0)).unwrap();
        let h = out.history();
        assert_eq!(h.len(), 3);
        assert_eq!(
            h[0].created_by().as_deref(),
            Some("layermeld: shared layer for {0,1,2}")
        );
        assert_eq!(
            h[1].created_by().as_deref(),
            Some("layermeld: shared layer for {0,1}")
        );
        assert_eq!(
            h[2].created_by().as_deref(),
            Some("layermeld: per-image layer for image-0")
        );
    }

    #[test]
    fn rewrite_history_entries_share_t0_and_omit_optional_fields() {
        let input = minimal_input();
        let l0 = emitted(ImageSet::singleton(InputImageId(0)), 0x11);
        let t0 = T0::from_unix_seconds(42);
        let out = rewrite_image_config(&input, &[&l0], t0).unwrap();
        let h = &out.history()[0];
        assert_eq!(h.created().as_deref(), Some(t0.to_rfc3339().as_str()));
        assert!(h.author().is_none());
        assert!(h.comment().is_none());
        assert!(h.empty_layer().is_none());
    }

    #[test]
    fn rewrite_with_empty_stack_yields_empty_diff_ids_and_history() {
        let input = minimal_input();
        let out = rewrite_image_config(&input, &[], T0::from_unix_seconds(0)).unwrap();
        assert!(out.rootfs().diff_ids().is_empty());
        assert!(out.history().is_empty());
        assert_eq!(out.rootfs().typ(), "layers");
    }

    #[test]
    fn rewrite_unset_optional_platform_fields_stay_unset() {
        let input = minimal_input();
        let l0 = emitted(ImageSet::singleton(InputImageId(0)), 0x11);
        let out = rewrite_image_config(&input, &[&l0], T0::from_unix_seconds(0)).unwrap();
        assert!(out.os_version().is_none());
        assert!(out.os_features().is_none());
        assert!(out.variant().is_none());
        assert!(out.config().is_none());
    }

    #[test]
    fn rewrite_diff_ids_count_matches_history_count() {
        // Spec §8.5 validation requires layer count == diff_ids count.
        // The rewrite is the producer; assert the invariant at the source.
        let input = minimal_input();
        let layers = [
            emitted(ids(&[0, 1]), 0x01),
            emitted(ids(&[0]), 0x02),
            emitted(ids(&[0]), 0x03),
        ];
        let stack = [&layers[0], &layers[1], &layers[2]];
        let out = rewrite_image_config(&input, &stack, T0::from_unix_seconds(0)).unwrap();
        assert_eq!(out.rootfs().diff_ids().len(), out.history().len());
        assert_eq!(out.rootfs().diff_ids().len(), stack.len());
    }

    #[test]
    fn rewrite_is_byte_deterministic_on_repeat_runs() {
        // Spec 11 §11.6: byte-identical output for the same input + T0.
        let input = rich_input();
        let layers = [
            emitted(ids(&[0, 1]), 0xaa),
            emitted(ImageSet::singleton(InputImageId(0)), 0xbb),
        ];
        let stack = [&layers[0], &layers[1]];
        let t0 = T0::from_unix_seconds(1_700_000_000);
        let a = rewrite_image_config(&input, &stack, t0).unwrap();
        let b = rewrite_image_config(&input, &stack, t0).unwrap();
        let a_json = a.to_string().unwrap();
        let b_json = b.to_string().unwrap();
        assert_eq!(a_json, b_json);
    }

    #[test]
    fn rewrite_does_not_carry_input_history() {
        // The input had a history entry with author="from-input" — none
        // of those fields should leak into the output.
        let input = rich_input();
        let l0 = emitted(ImageSet::singleton(InputImageId(0)), 0x11);
        let out = rewrite_image_config(&input, &[&l0], T0::from_unix_seconds(0)).unwrap();
        let h = &out.history()[0];
        assert!(h.author().is_none());
        assert_eq!(
            h.created_by().as_deref(),
            Some("layermeld: per-image layer for image-0")
        );
    }
}
