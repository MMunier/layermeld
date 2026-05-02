//! Image index (spec 09 §9.2).
//!
//! After the per-image manifest blobs have been emitted by
//! [`crate::oci::manifest::build_manifest`] + serialised under
//! `blobs/sha256/<digest>`, this module produces the single
//! `index.json` document that ties every output image (and its repo
//! tags) together into one OCI image layout (spec 09 §9.1).
//!
//! ## Per-entry shape
//!
//! Spec §9.2 dictates one [`Descriptor`] per **(output image, repo
//! tag)** pair:
//!
//! - `mediaType` = `application/vnd.oci.image.manifest.v1+json`.
//! - `digest`, `size` of the image manifest blob.
//! - `platform.architecture`, `platform.os` copied from the image
//!   config. `variant` / `os.version` / `os.features` are also forwarded
//!   when the input config carried them — strictly more than the spec
//!   requires, but the OCI [`Platform`] schema accepts them and they are
//!   useful information for any consumer that already inspects platform
//!   alternatives. They are still pure functions of the input config, so
//!   determinism (spec 11 §11.6) is unaffected.
//! - `annotations`:
//!   - `org.opencontainers.image.created` = `T0`, on every entry.
//!   - `org.opencontainers.image.ref.name` = the repo tag, on each
//!     tagged entry. An untagged image (spec §9.2 last paragraph,
//!     dir-transport included) still gets one entry, just without the
//!     `ref.name` annotation.
//!
//! ## Multiple tags per image
//!
//! Spec §9.2: "Inputs with multiple tags produce multiple index entries,
//! all pointing at the same manifest digest." Implemented literally: an
//! image with N tags expands into N entries with byte-identical
//! `digest`, `size`, and `platform` fields, differing only in their
//! `ref.name` annotation. The blob on disk is referenced once.
//!
//! ## Determinism
//!
//! Iteration order of `manifests[]` is `(input image order in argv,
//! then repo-tag order as supplied)`. Both come from the caller; this
//! module never reorders them. The annotation maps are
//! `HashMap<String, String>` (oci-spec's typed model), so canonical
//! byte form is the responsibility of spec 09's output writer (it must
//! re-serialise via a sorted-key map before hashing) — exactly the same
//! contract as [`crate::oci::manifest::build_manifest`].

use std::collections::HashMap;

use oci_spec::image::{
    ANNOTATION_CREATED, ANNOTATION_REF_NAME, Descriptor, DescriptorBuilder, Digest, ImageConfiguration, ImageIndex,
    ImageIndexBuilder, MediaType, Platform, PlatformBuilder,
};

use crate::Error;
use crate::Result;
use crate::assemble::digest::hex_encode;
use crate::timestamp::T0;

/// One output image's input to [`build_index`]: the manifest blob's
/// identity plus the source config (for platform fields) plus the
/// image's repo tags.
#[derive(Debug)]
pub struct IndexEntryInput<'a> {
    /// SHA-256 of the on-disk manifest blob produced by spec 09's
    /// output writer (which serialises the [`oci_spec::image::ImageManifest`]
    /// returned from [`crate::oci::manifest::build_manifest`]).
    pub manifest_digest: &'a [u8; 32],
    /// On-disk size of that manifest blob, in bytes.
    pub manifest_size: u64,
    /// Source image config — read for `architecture`, `os`, and (when
    /// present) `variant` / `os.version` / `os.features`.
    pub config: &'a ImageConfiguration,
    /// Repo tags from the input image. Empty for untagged inputs (e.g.
    /// dir-transport, spec 09 §9.2 last paragraph).
    pub repo_tags: &'a [String],
}

fn build_platform(config: &ImageConfiguration) -> Result<Platform> {
    let mut builder = PlatformBuilder::default()
        .architecture(config.architecture().clone())
        .os(config.os().clone());
    if let Some(v) = config.variant() {
        builder = builder.variant(v.clone());
    }
    if let Some(v) = config.os_version() {
        builder = builder.os_version(v.clone());
    }
    if let Some(features) = config.os_features() {
        builder = builder.os_features(features.clone());
    }
    builder
        .build()
        .map_err(|e| Error::Validation(format!("platform build failed: {e}")))
}

fn build_entry(input: &IndexEntryInput<'_>, t0: T0, ref_name: Option<&str>) -> Result<Descriptor> {
    let digest_str = format!("sha256:{}", hex_encode(input.manifest_digest));
    let parsed = Digest::try_from(digest_str.as_str())
        .map_err(|e| Error::Validation(format!("invalid sha256 digest {digest_str}: {e}")))?;
    let platform = build_platform(input.config)?;

    let mut annotations: HashMap<String, String> = HashMap::new();
    annotations.insert(ANNOTATION_CREATED.to_string(), t0.to_rfc3339());
    if let Some(tag) = ref_name {
        annotations.insert(ANNOTATION_REF_NAME.to_string(), tag.to_string());
    }

    DescriptorBuilder::default()
        .media_type(MediaType::ImageManifest)
        .digest(parsed)
        .size(input.manifest_size)
        .platform(platform)
        .annotations(annotations)
        .build()
        .map_err(|e| Error::Validation(format!("index entry build failed: {e}")))
}

/// Build the OCI image index for one output layout per spec 09 §9.2.
///
/// `images` lists every output image in the order they should appear in
/// `manifests[]` (typically argv order, established by [`crate::lib::run`]).
/// `t0` is the run-wide invocation timestamp.
///
/// # Errors
///
/// [`Error::Validation`] if the underlying `oci-spec` builders reject
/// any constructed value, or if a digest somehow fails the `Digest`
/// syntax check (impossible for the 32-byte arrays this crate produces,
/// but surfaced rather than panicking out of paranoia).
pub fn build_index(images: &[IndexEntryInput<'_>], t0: T0) -> Result<ImageIndex> {
    let mut manifests: Vec<Descriptor> = Vec::new();
    for img in images {
        if img.repo_tags.is_empty() {
            manifests.push(build_entry(img, t0, None)?);
        } else {
            for tag in img.repo_tags {
                manifests.push(build_entry(img, t0, Some(tag))?);
            }
        }
    }

    ImageIndexBuilder::default()
        .schema_version(2u32)
        .media_type(MediaType::ImageIndex)
        .manifests(manifests)
        .build()
        .map_err(|e| Error::Validation(format!("image index build failed: {e}")))
}

#[cfg(test)]
mod tests {
    use oci_spec::image::{Arch, ImageConfigurationBuilder, Os, RootFsBuilder};

    use super::*;

    fn cfg(arch: Arch, os: Os, variant: Option<&str>) -> ImageConfiguration {
        let mut b = ImageConfigurationBuilder::default().architecture(arch).os(os).rootfs(
            RootFsBuilder::default()
                .diff_ids(vec!["sha256:0".to_string()])
                .build()
                .unwrap(),
        );
        if let Some(v) = variant {
            b = b.variant(v.to_string());
        }
        b.build().unwrap()
    }

    fn entry<'a>(
        digest: &'a [u8; 32],
        size: u64,
        config: &'a ImageConfiguration,
        tags: &'a [String],
    ) -> IndexEntryInput<'a> {
        IndexEntryInput {
            manifest_digest: digest,
            manifest_size: size,
            config,
            repo_tags: tags,
        }
    }

    #[test]
    fn schema_version_is_2() {
        let c = cfg(Arch::Amd64, Os::Linux, None);
        let d = [0x11; 32];
        let idx = build_index(&[entry(&d, 100, &c, &[])], T0::from_unix_seconds(0)).unwrap();
        assert_eq!(idx.schema_version(), 2);
    }

    #[test]
    fn media_type_is_oci_image_index_v1() {
        let c = cfg(Arch::Amd64, Os::Linux, None);
        let d = [0x11; 32];
        let idx = build_index(&[entry(&d, 100, &c, &[])], T0::from_unix_seconds(0)).unwrap();
        assert_eq!(idx.media_type().as_ref(), Some(&MediaType::ImageIndex));
    }

    #[test]
    fn untagged_image_yields_one_entry_without_ref_name() {
        // Spec §9.2 last paragraph: untagged images still appear in the
        // index, just without ref.name. Dir-transport (spec 09 §9.2,
        // spec 01 §1.5) is the canonical case.
        let c = cfg(Arch::Amd64, Os::Linux, None);
        let d = [0x11; 32];
        let idx = build_index(&[entry(&d, 100, &c, &[])], T0::from_unix_seconds(0)).unwrap();
        assert_eq!(idx.manifests().len(), 1);
        let ann = idx.manifests()[0].annotations().as_ref().unwrap();
        assert!(!ann.contains_key(ANNOTATION_REF_NAME));
    }

    #[test]
    fn single_tag_yields_one_entry_with_ref_name() {
        let c = cfg(Arch::Amd64, Os::Linux, None);
        let d = [0x11; 32];
        let tags = ["docker.io/library/alpine:3.19".to_string()];
        let idx = build_index(&[entry(&d, 100, &c, &tags)], T0::from_unix_seconds(0)).unwrap();
        assert_eq!(idx.manifests().len(), 1);
        let ann = idx.manifests()[0].annotations().as_ref().unwrap();
        assert_eq!(
            ann.get(ANNOTATION_REF_NAME).map(String::as_str),
            Some("docker.io/library/alpine:3.19"),
        );
    }

    #[test]
    fn multiple_tags_expand_to_multiple_entries_sharing_digest() {
        // Spec §9.2: "Inputs with multiple tags produce multiple index
        // entries, all pointing at the same manifest digest." The blob
        // on disk is referenced once.
        let c = cfg(Arch::Amd64, Os::Linux, None);
        let d = [0xab; 32];
        let tags = [
            "repo:tag-a".to_string(),
            "repo:tag-b".to_string(),
            "repo:tag-c".to_string(),
        ];
        let idx = build_index(&[entry(&d, 1234, &c, &tags)], T0::from_unix_seconds(0)).unwrap();
        let descs = idx.manifests();
        assert_eq!(descs.len(), 3);
        let expected_digest = format!("sha256:{}", "ab".repeat(32));
        for d in descs {
            assert_eq!(d.digest().to_string(), expected_digest);
            assert_eq!(d.size(), 1234);
        }
        let names: Vec<_> = descs
            .iter()
            .map(|d| {
                d.annotations()
                    .as_ref()
                    .unwrap()
                    .get(ANNOTATION_REF_NAME)
                    .cloned()
                    .unwrap()
            })
            .collect();
        assert_eq!(names, vec!["repo:tag-a", "repo:tag-b", "repo:tag-c"]);
    }

    #[test]
    fn entry_media_type_is_image_manifest_v1() {
        let c = cfg(Arch::Amd64, Os::Linux, None);
        let d = [0x11; 32];
        let idx = build_index(&[entry(&d, 100, &c, &[])], T0::from_unix_seconds(0)).unwrap();
        assert_eq!(idx.manifests()[0].media_type(), &MediaType::ImageManifest);
    }

    #[test]
    fn platform_copied_from_image_config() {
        let c = cfg(Arch::ARM64, Os::Linux, Some("v8"));
        let d = [0x11; 32];
        let idx = build_index(&[entry(&d, 100, &c, &[])], T0::from_unix_seconds(0)).unwrap();
        let p = idx.manifests()[0].platform().as_ref().unwrap();
        assert_eq!(p.architecture(), &Arch::ARM64);
        assert_eq!(p.os(), &Os::Linux);
        assert_eq!(p.variant().as_deref(), Some("v8"));
    }

    #[test]
    fn platform_optional_fields_unset_when_absent() {
        let c = cfg(Arch::Amd64, Os::Linux, None);
        let d = [0x11; 32];
        let idx = build_index(&[entry(&d, 100, &c, &[])], T0::from_unix_seconds(0)).unwrap();
        let p = idx.manifests()[0].platform().as_ref().unwrap();
        assert!(p.variant().is_none());
        assert!(p.os_version().is_none());
        assert!(p.os_features().is_none());
    }

    #[test]
    fn created_annotation_present_on_every_entry_in_rfc3339() {
        let c = cfg(Arch::Amd64, Os::Linux, None);
        let d = [0x11; 32];
        let tags = ["a:1".to_string(), "a:2".to_string()];
        let t0 = T0::from_unix_seconds(1_700_000_000);
        let idx = build_index(&[entry(&d, 100, &c, &tags)], t0).unwrap();
        for desc in idx.manifests() {
            let ann = desc.annotations().as_ref().unwrap();
            assert_eq!(
                ann.get(ANNOTATION_CREATED).map(String::as_str),
                Some("2023-11-14T22:13:20Z"),
            );
        }
    }

    #[test]
    fn one_index_entry_per_image_when_each_has_one_tag() {
        // Two distinct output images, each with one tag → two entries.
        let c0 = cfg(Arch::Amd64, Os::Linux, None);
        let c1 = cfg(Arch::ARM64, Os::Linux, Some("v8"));
        let d0 = [0xaa; 32];
        let d1 = [0xbb; 32];
        let t0 = ["img-0:latest".to_string()];
        let t1 = ["img-1:latest".to_string()];
        let idx = build_index(
            &[entry(&d0, 10, &c0, &t0), entry(&d1, 20, &c1, &t1)],
            T0::from_unix_seconds(0),
        )
        .unwrap();
        assert_eq!(idx.manifests().len(), 2);
        assert_eq!(idx.manifests()[0].size(), 10);
        assert_eq!(idx.manifests()[1].size(), 20);
        assert_eq!(
            idx.manifests()[0].platform().as_ref().unwrap().architecture(),
            &Arch::Amd64
        );
        assert_eq!(
            idx.manifests()[1].platform().as_ref().unwrap().architecture(),
            &Arch::ARM64
        );
    }

    #[test]
    fn entry_order_follows_input_order_then_tag_order() {
        // image-0 has 2 tags, image-1 untagged, image-2 has 1 tag →
        // 4 entries in order: (0,t0a), (0,t0b), (1,—), (2,t2).
        let c = cfg(Arch::Amd64, Os::Linux, None);
        let d0 = [0x10; 32];
        let d1 = [0x20; 32];
        let d2 = [0x30; 32];
        let t0 = ["img0:a".to_string(), "img0:b".to_string()];
        let t1: [String; 0] = [];
        let t2 = ["img2:c".to_string()];
        let idx = build_index(
            &[entry(&d0, 1, &c, &t0), entry(&d1, 2, &c, &t1), entry(&d2, 3, &c, &t2)],
            T0::from_unix_seconds(0),
        )
        .unwrap();
        let descs = idx.manifests();
        assert_eq!(descs.len(), 4);
        let sizes: Vec<u64> = descs.iter().map(Descriptor::size).collect();
        assert_eq!(sizes, vec![1, 1, 2, 3]);
        let refs: Vec<Option<String>> = descs
            .iter()
            .map(|d| d.annotations().as_ref().unwrap().get(ANNOTATION_REF_NAME).cloned())
            .collect();
        assert_eq!(
            refs,
            vec![
                Some("img0:a".to_string()),
                Some("img0:b".to_string()),
                None,
                Some("img2:c".to_string()),
            ]
        );
    }

    #[test]
    fn empty_input_yields_index_with_no_manifests() {
        // Defensive: spec §9.2 doesn't exercise this case, but a
        // zero-image index is structurally valid and panicking would
        // be worse than emitting an empty list.
        let idx = build_index(&[], T0::from_unix_seconds(0)).unwrap();
        assert!(idx.manifests().is_empty());
    }

    #[test]
    fn digest_uses_lowercase_hex() {
        let c = cfg(Arch::Amd64, Os::Linux, None);
        let d = [0xfe; 32];
        let idx = build_index(&[entry(&d, 1, &c, &[])], T0::from_unix_seconds(0)).unwrap();
        let s = idx.manifests()[0].digest().to_string();
        assert!(s.starts_with("sha256:"));
        assert!(
            s.chars()
                .skip("sha256:".len())
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
        );
    }

    #[test]
    fn index_value_equality_on_repeat_runs() {
        // Spec 11 §11.6 byte-determinism is the output writer's job
        // (it must canonicalise the annotation HashMap before hashing).
        // At this layer we verify the structural-equality contract:
        // identical inputs produce equal index values.
        let c = cfg(Arch::Amd64, Os::Linux, None);
        let d = [0x11; 32];
        let tags = ["repo:tag".to_string()];
        let t0 = T0::from_unix_seconds(1_700_000_000);
        let a = build_index(&[entry(&d, 7, &c, &tags)], t0).unwrap();
        let b = build_index(&[entry(&d, 7, &c, &tags)], t0).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn os_version_and_features_forwarded_when_present() {
        let c = ImageConfigurationBuilder::default()
            .architecture(Arch::Amd64)
            .os(Os::Linux)
            .os_version("10.0.17763.1234".to_string())
            .os_features(vec!["win32k".to_string()])
            .rootfs(
                RootFsBuilder::default()
                    .diff_ids(vec!["sha256:0".to_string()])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let d = [0x11; 32];
        let idx = build_index(&[entry(&d, 1, &c, &[])], T0::from_unix_seconds(0)).unwrap();
        let p = idx.manifests()[0].platform().as_ref().unwrap();
        assert_eq!(p.os_version().as_deref(), Some("10.0.17763.1234"));
        assert_eq!(p.os_features().as_deref(), Some(&vec!["win32k".to_string()][..]));
    }
}
