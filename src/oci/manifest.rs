//! Image manifest (spec 08 §8.2).
//!
//! After the assemble stage (spec 07) has produced the per-layer output
//! blobs and [`crate::oci::config::rewrite_image_config`] has produced
//! the rewritten image config, this module emits the OCI v1 image
//! manifest that ties the two together.
//!
//! ## What is set
//!
//! - `schemaVersion` = 2 (the only value spec §8.2 / OCI v1 allow).
//! - `mediaType` = `application/vnd.oci.image.manifest.v1+json`.
//! - `config` is a [`Descriptor`] over the rewritten image config blob:
//!   `mediaType` = `application/vnd.oci.image.config.v1+json`, `digest`
//!   spelled `sha256:<hex>`, `size` matching the on-disk blob byte count.
//! - `layers` is one descriptor per [`EmittedLayer`] in the
//!   caller-provided order — i.e. the spec 05 §5.3 stack order
//!   ([`crate::dedup::stack::stack_for_image`] produces it). Each is
//!   `mediaType` = `application/vnd.oci.image.layer.v1.tar` (uncompressed
//!   per spec 07 §7.3), with `digest` and `size` from the assemble pass.
//! - `annotations`:
//!   - `org.opencontainers.image.created` = `T0` formatted via
//!     [`T0::to_rfc3339`].
//!   - `org.opencontainers.image.ref.name` is set **only when exactly
//!     one repo tag is known** for the input image. Multiple repo tags
//!     are surfaced at the index level instead (one index entry per tag,
//!     all pointing at the same manifest digest — spec §8.2 last
//!     paragraph), so writing one of them onto the manifest in the
//!     multi-tag case would silently drop the rest. With zero tags
//!     (spec 09 §9.2 dir-transport case), the annotation is omitted
//!     altogether.
//!
//! ## What is dropped
//!
//! Every input-side annotation other than the one ref.name we forward
//! (spec §8.2: "All other input annotations are dropped"). Layer-level
//! annotations are never carried — the output's layer descriptors are
//! freshly minted and refer to freshly assembled blobs.
//!
//! ## Determinism (spec 11 §11.6)
//!
//! Every *value* the manifest carries is a pure function of inputs the
//! caller already pinned: digests are SHA-256s of the deterministic tar
//! bytes the assemble pass produced, descriptor field ordering is
//! whatever `oci-spec` emits (a function of the pinned crate version),
//! and `created` / `ref.name` are themselves deterministic strings.
//!
//! The byte form on disk is *not* yet canonical at this layer: the
//! `annotations` field on `oci-spec`'s `ImageManifest` is a
//! `HashMap<String, String>`, which serialises in a randomised iteration
//! order. Spec 09's output writer is responsible for canonicalising the
//! JSON (e.g. by re-serialising via a `BTreeMap`-backed `serde_json::Value`)
//! before the bytes are hashed and written under `blobs/sha256/<digest>`.
//! At this layer we guarantee the weaker invariant: two runs over the
//! same inputs produce structurally equal [`ImageManifest`] values.

use std::collections::HashMap;

use oci_spec::image::{
    ANNOTATION_CREATED, ANNOTATION_REF_NAME, Descriptor, DescriptorBuilder, Digest, ImageManifest,
    ImageManifestBuilder, MediaType,
};

use crate::Error;
use crate::Result;
use crate::assemble::digest::hex_encode;
use crate::assemble::emit::EmittedLayer;
use crate::timestamp::T0;

/// Build a fresh [`Descriptor`] over a SHA-256 blob with the given media
/// type and on-disk size.
///
/// Centralised so the `sha256:<hex>` spelling matches the rest of the
/// crate (see also [`crate::oci::config::diff_id_string`]) and so the
/// `oci-spec` builder error path is wrapped consistently as
/// [`Error::Validation`].
fn build_descriptor(media_type: MediaType, digest: &[u8; 32], size: u64) -> Result<Descriptor> {
    let digest_str = format!("sha256:{}", hex_encode(digest));
    let parsed = Digest::try_from(digest_str.as_str())
        .map_err(|e| Error::Validation(format!("invalid sha256 digest {digest_str}: {e}")))?;
    DescriptorBuilder::default()
        .media_type(media_type)
        .digest(parsed)
        .size(size)
        .build()
        .map_err(|e| Error::Validation(format!("descriptor build failed: {e}")))
}

/// Build the OCI v1 image manifest for one output image per spec 08 §8.2.
///
/// `config_digest` / `config_size` describe the rewritten image-config
/// blob (the one [`crate::oci::config::rewrite_image_config`] produced
/// and the caller has already serialised + written under
/// `blobs/sha256/<digest>`). `stack` is the per-image ordered slice of
/// emitted output layers — already sorted per spec 05 §5.3
/// (descending `|M|`, lex tiebreak, per-image layer last). `t0` is the
/// run-wide invocation timestamp. `repo_tags` is the input image's
/// repo-tag list as surfaced by [`crate::input::model::InputImage`].
///
/// # Errors
///
/// [`Error::Validation`] if the underlying `oci-spec` builders reject
/// the constructed value (in practice only on a future major bump that
/// adds new required fields), or if a digest somehow fails the
/// `oci-spec` `Digest` syntax check (impossible for the 32-byte arrays
/// produced by the assemble pass, but surfaced rather than panicking
/// out of paranoia).
pub fn build_manifest(
    config_digest: &[u8; 32],
    config_size: u64,
    stack: &[&EmittedLayer],
    t0: T0,
    repo_tags: &[String],
) -> Result<ImageManifest> {
    let config = build_descriptor(MediaType::ImageConfig, config_digest, config_size)?;
    let layers: Vec<Descriptor> = stack
        .iter()
        .map(|l| build_descriptor(MediaType::ImageLayer, &l.digest, l.size))
        .collect::<Result<_>>()?;

    let mut annotations: HashMap<String, String> = HashMap::new();
    annotations.insert(ANNOTATION_CREATED.to_string(), t0.to_rfc3339());
    if let [single] = repo_tags {
        annotations.insert(ANNOTATION_REF_NAME.to_string(), single.clone());
    }

    ImageManifestBuilder::default()
        .schema_version(2u32)
        .media_type(MediaType::ImageManifest)
        .config(config)
        .layers(layers)
        .annotations(annotations)
        .build()
        .map_err(|e| Error::Validation(format!("image manifest build failed: {e}")))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::dedup::membership::ImageSet;
    use crate::squash::index::InputImageId;

    fn ids(xs: &[usize]) -> ImageSet {
        ImageSet::from_ids(xs.iter().copied().map(InputImageId))
    }

    fn emitted(membership: ImageSet, byte: u8, size: u64) -> EmittedLayer {
        EmittedLayer {
            membership,
            digest: [byte; 32],
            size,
            path: PathBuf::from(format!("/tmp/blobs/{byte}")),
        }
    }

    #[test]
    fn schema_version_is_2() {
        let l = emitted(ImageSet::singleton(InputImageId(0)), 0x11, 1024);
        let m = build_manifest(&[0x22; 32], 512, &[&l], T0::from_unix_seconds(0), &[]).unwrap();
        assert_eq!(m.schema_version(), 2);
    }

    #[test]
    fn media_type_is_oci_image_manifest_v1() {
        let l = emitted(ImageSet::singleton(InputImageId(0)), 0x11, 1024);
        let m = build_manifest(&[0x22; 32], 512, &[&l], T0::from_unix_seconds(0), &[]).unwrap();
        assert_eq!(m.media_type().as_ref(), Some(&MediaType::ImageManifest));
    }

    #[test]
    fn config_descriptor_uses_image_config_media_type_and_sha256_digest() {
        let l = emitted(ImageSet::singleton(InputImageId(0)), 0x11, 1024);
        let cfg_digest = [0xab; 32];
        let m = build_manifest(&cfg_digest, 4096, &[&l], T0::from_unix_seconds(0), &[]).unwrap();
        let c = m.config();
        assert_eq!(c.media_type(), &MediaType::ImageConfig);
        assert_eq!(c.size(), 4096);
        assert_eq!(c.digest().to_string(), format!("sha256:{}", "ab".repeat(32)));
    }

    #[test]
    fn layer_descriptors_use_uncompressed_tar_media_type() {
        // Spec §8.2 / spec 07 §7.3: layers are emitted uncompressed; the
        // descriptor must reflect that, even if a registry would happily
        // accept gzipped layers in general.
        let layers = [
            emitted(ids(&[0, 1]), 0x01, 100),
            emitted(ImageSet::singleton(InputImageId(0)), 0x02, 200),
        ];
        let stack = [&layers[0], &layers[1]];
        let m = build_manifest(&[0; 32], 0, &stack, T0::from_unix_seconds(0), &[]).unwrap();
        for d in m.layers() {
            assert_eq!(d.media_type(), &MediaType::ImageLayer);
        }
    }

    #[test]
    fn layer_descriptors_preserve_stack_order_digest_and_size() {
        let layers = [
            emitted(ids(&[0, 1, 2]), 0x01, 11),
            emitted(ids(&[0, 1]), 0x02, 22),
            emitted(ImageSet::singleton(InputImageId(0)), 0x03, 33),
        ];
        let stack = [&layers[0], &layers[1], &layers[2]];
        let m = build_manifest(&[0; 32], 0, &stack, T0::from_unix_seconds(0), &[]).unwrap();
        let descs = m.layers();
        assert_eq!(descs.len(), 3);
        for (d, l) in descs.iter().zip(stack.iter()) {
            assert_eq!(d.size(), l.size);
            assert_eq!(d.digest().to_string(), format!("sha256:{}", hex_encode(&l.digest)));
        }
    }

    #[test]
    fn layers_count_matches_stack_len_including_empty() {
        let m = build_manifest(&[0xcd; 32], 8, &[], T0::from_unix_seconds(0), &[]).unwrap();
        assert!(m.layers().is_empty());
    }

    #[test]
    fn annotations_always_carry_image_created_in_rfc3339() {
        let l = emitted(ImageSet::singleton(InputImageId(0)), 0x11, 1024);
        let m = build_manifest(&[0; 32], 0, &[&l], T0::from_unix_seconds(1_700_000_000), &[]).unwrap();
        let ann = m.annotations().as_ref().expect("created annotation always set");
        assert_eq!(
            ann.get(ANNOTATION_CREATED).map(String::as_str),
            Some("2023-11-14T22:13:20Z")
        );
    }

    #[test]
    fn ref_name_set_for_exactly_one_repo_tag() {
        let l = emitted(ImageSet::singleton(InputImageId(0)), 0x11, 1024);
        let m = build_manifest(
            &[0; 32],
            0,
            &[&l],
            T0::from_unix_seconds(0),
            &["docker.io/library/alpine:3.19".to_string()],
        )
        .unwrap();
        let ann = m.annotations().as_ref().unwrap();
        assert_eq!(
            ann.get(ANNOTATION_REF_NAME).map(String::as_str),
            Some("docker.io/library/alpine:3.19"),
        );
    }

    #[test]
    fn ref_name_omitted_when_no_repo_tags() {
        // Spec 09 §9.2 dir-transport case: zero tags → no ref.name on
        // the manifest (and the index entry is untagged too).
        let l = emitted(ImageSet::singleton(InputImageId(0)), 0x11, 1024);
        let m = build_manifest(&[0; 32], 0, &[&l], T0::from_unix_seconds(0), &[]).unwrap();
        let ann = m.annotations().as_ref().unwrap();
        assert!(!ann.contains_key(ANNOTATION_REF_NAME));
    }

    #[test]
    fn ref_name_omitted_when_multiple_repo_tags() {
        // Multiple tags → multiple index entries, all pointing at the
        // same manifest digest. The manifest itself can only carry one
        // ref.name, so dropping it (rather than picking one and silently
        // losing the rest) is the only honest choice.
        let l = emitted(ImageSet::singleton(InputImageId(0)), 0x11, 1024);
        let m = build_manifest(
            &[0; 32],
            0,
            &[&l],
            T0::from_unix_seconds(0),
            &["a:1".to_string(), "a:2".to_string()],
        )
        .unwrap();
        let ann = m.annotations().as_ref().unwrap();
        assert!(!ann.contains_key(ANNOTATION_REF_NAME));
    }

    #[test]
    fn manifest_value_equality_on_repeat_runs() {
        // Spec 11 §11.6 wants byte-identical *output blobs* on a repeat
        // run. Annotations are an [`oci-spec`] `HashMap<String,String>`,
        // which serialises in randomised iteration order — so the
        // canonical-bytes guarantee is the responsibility of spec 09's
        // output writer (it must canonicalise the JSON before hashing,
        // e.g. by sorting keys). At this layer we verify the weaker but
        // still meaningful invariant: structurally, the same inputs
        // produce equal manifests, with no hidden non-determinism in the
        // values themselves (digests, sizes, annotation set, layer order).
        let layers = [
            emitted(ids(&[0, 1]), 0xaa, 17),
            emitted(ImageSet::singleton(InputImageId(0)), 0xbb, 23),
        ];
        let stack = [&layers[0], &layers[1]];
        let t0 = T0::from_unix_seconds(1_700_000_000);
        let tags = vec!["repo/example:tag".to_string()];
        let a = build_manifest(&[0xcd; 32], 5, &stack, t0, &tags).unwrap();
        let b = build_manifest(&[0xcd; 32], 5, &stack, t0, &tags).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn config_and_layer_digests_use_lowercase_hex() {
        let l = emitted(ImageSet::singleton(InputImageId(0)), 0xfe, 1);
        let m = build_manifest(&[0xfe; 32], 1, &[&l], T0::from_unix_seconds(0), &[]).unwrap();
        let c = m.config().digest().to_string();
        let l0 = m.layers()[0].digest().to_string();
        assert!(
            c.chars()
                .skip("sha256:".len())
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        );
        assert!(
            l0.chars()
                .skip("sha256:".len())
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        );
    }
}
