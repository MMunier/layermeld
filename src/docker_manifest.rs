//! Docker-archive `manifest.json` generation (spec 09 §9.5).
//!
//! `podman load` only restores **multiple** images from a single tarball
//! when the archive carries a top-level Docker-style `manifest.json` —
//! the OCI image index alone (`index.json`) is enough for skopeo and
//! crane but `podman load` falls back to single-image semantics on it.
//! This module produces that compatibility document so a multi-image
//! squash output round-trips through `podman load -i`.
//!
//! The Docker manifest is emitted **in addition to** the OCI
//! `index.json` and `oci-layout` documents (spec 09 §9.1 / §9.2). All
//! three reference the same `blobs/sha256/<digest>` storage tree, so no
//! blob bytes are duplicated.
//!
//! ## Document shape
//!
//! The Docker schema is a JSON array, one object per output image:
//!
//! ```json
//! [
//!   {
//!     "Config": "blobs/sha256/<config-digest>",
//!     "RepoTags": ["repo:tag-a", "repo:tag-b"],
//!     "Layers": [
//!       "blobs/sha256/<layer-digest-1>",
//!       "blobs/sha256/<layer-digest-2>"
//!     ]
//!   },
//!   ...
//! ]
//! ```
//!
//! Field semantics:
//!
//! * `Config` — tar-relative path to the per-image OCI image config
//!   blob (spec 08 §8.1). The path uses the `blobs/sha256/<hex>`
//!   layout this crate's output already lives in; both modern `podman
//!   save` and `docker load` accept this hybrid form.
//! * `RepoTags` — every repo tag attached to the input image. **Unlike**
//!   the OCI index (spec 09 §9.2 — one entry per `(image, tag)` pair),
//!   the Docker schema collapses multiple tags into a single entry, so
//!   one input image always produces exactly one Docker manifest entry
//!   regardless of tag count. Empty list for untagged images.
//! * `Layers` — tar-relative paths to each output layer blob in the
//!   image's stack order (spec 05 §5.3). Layers are uncompressed PAX
//!   tars (spec 07 §7.3), which is what the Docker schema expects.
//!
//! ## Determinism (spec 11 §11.6)
//!
//! Field ordering inside each entry is whatever `serde_json` emits for
//! `#[derive(Serialize)]` — fixed by struct field declaration order,
//! not by `HashMap` iteration. Image order, tag order, and layer order
//! are taken verbatim from the caller; this module never reorders. The
//! resulting bytes are therefore a pure function of the inputs the
//! pipeline already pinned.

use std::collections::BTreeMap;

use oci_spec::image::MediaType;
use serde::{Deserialize, Serialize};

use crate::Result;
use crate::assemble::digest::hex_encode;

/// One entry in a Docker-archive `manifest.json`.
///
/// Field names use Docker's `PascalCase` serialisation so the JSON shape
/// matches what `docker load` / `podman load` expect. The struct
/// derives [`Deserialize`] purely so it could be re-parsed by tests or
/// future input-side adapters; the `serde(rename = ...)` annotations
/// pin both directions to the canonical wire names.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DockerManifestEntry {
    /// Tar-relative path to the per-image OCI image config blob, in the
    /// `blobs/sha256/<hex>` form this crate's output uses.
    #[serde(rename = "Config")]
    pub config: String,

    /// Repo tags attached to the input image, in the order the input
    /// supplied them. Empty for untagged images (spec 09 §9.2
    /// dir-transport case).
    #[serde(rename = "RepoTags")]
    pub repo_tags: Vec<String>,

    /// Tar-relative paths to each output layer blob in image stack
    /// order (spec 05 §5.3), in `blobs/sha256/<hex>` form.
    #[serde(rename = "Layers")]
    pub layers: Vec<String>,

    // The layerSources references within the image
    #[serde(rename = "LayerSources")]
    #[serde(default)]
    pub layer_sources: BTreeMap<String, DockerManifestLayerSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DockerManifestLayerSource {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct DockerManifestLayerSourceInput<'a> {
    pub media_type: &'static str,
    pub digest: &'a [u8; 32],
    pub size: u64,
}

/// One image's input to [`build_docker_manifest`].
///
/// Per-image rather than per-tag (the Docker schema collapses tags into
/// a single entry per image — spec 09 §9.5 docker-side, contrast with
/// the OCI index's per-tag fan-out in §9.2).
#[derive(Debug, Clone)]
pub struct DockerManifestInput<'a> {
    /// SHA-256 of the per-image OCI image config blob, as already
    /// written under `<scratch>/blobs/sha256/<hex>` by the run pipeline.
    pub config_digest: &'a [u8; 32],

    /// Stack-ordered SHA-256 of each output layer blob this image
    /// references (spec 05 §5.3 order).
    pub layer_digests: &'a [[u8; 32]],

    /// Repo tags from the input image — propagated verbatim into the
    /// `RepoTags` field. Empty slice for untagged inputs.
    pub repo_tags: &'a [String],

    /// Optional References for layer metadata, docker is fine without
    /// podman requires them
    pub layer_sources: &'a [DockerManifestLayerSourceInput<'a>],
}

/// Build the Docker-archive `manifest.json` document for the given
/// images.
///
/// Returns one [`DockerManifestEntry`] per input, in the input order.
/// Multi-tagged images stay as a single entry with their full tag list;
/// untagged images stay as a single entry with `RepoTags: []`.
///
/// # Errors
///
/// This function is currently total — it cannot fail — but returns
/// `Result` so future validation (e.g. tag string sanity-checking) can
/// be added without churning every caller.
pub fn build_docker_manifest(images: &[DockerManifestInput<'_>]) -> Result<Vec<DockerManifestEntry>> {
    let mut out: Vec<DockerManifestEntry> = Vec::with_capacity(images.len());
    for img in images {
        let config = blob_path(img.config_digest);
        let layers: Vec<String> = img.layer_digests.iter().map(blob_path).collect();

        let layer_sources = img
            .layer_sources
            .iter()
            .map(|source| {
                let prefixed_digest = digest_prefix(source.digest);
                let details = DockerManifestLayerSource {
                    media_type: MediaType::ImageLayer.to_string(),
                    digest: prefixed_digest.clone(),
                    size: source.size,
                };
                (prefixed_digest, details)
            })
            .collect();

        out.push(DockerManifestEntry {
            config,
            repo_tags: img.repo_tags.to_vec(),
            layers,
            layer_sources,
        });
    }
    Ok(out)
}

/// Format a SHA-256 digest as the tar-relative `blobs/sha256/<hex>`
/// path the rest of the layout uses. Centralised here so the Docker
/// manifest, the OCI manifest, and the index all agree on the spelling.
fn blob_path(digest: &[u8; 32]) -> String {
    format!("blobs/sha256/{}", hex_encode(digest))
}

/// Format a SHA-256 digest as 'sha256:<hex>'
fn digest_prefix(digest: &[u8; 32]) -> String {
    format!("sha256:{}", hex_encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn input<'a>(config: &'a [u8; 32], layers: &'a [[u8; 32]], tags: &'a [String]) -> DockerManifestInput<'a> {
        DockerManifestInput {
            config_digest: config,
            layer_digests: layers,
            repo_tags: tags,
            layer_sources: &[],
        }
    }

    #[test]
    fn single_image_single_tag_produces_one_entry() {
        let cfg = d(0xab);
        let layers = [d(0x01)];
        let tags = ["repo:tag".to_string()];
        let m = build_docker_manifest(&[input(&cfg, &layers, &tags)]).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].config, format!("blobs/sha256/{}", "ab".repeat(32)));
        assert_eq!(m[0].repo_tags, vec!["repo:tag"]);
        assert_eq!(m[0].layers, vec![format!("blobs/sha256/{}", "01".repeat(32))]);
    }

    #[test]
    fn multiple_tags_collapse_to_a_single_entry() {
        // Spec 09 §9.5 docker-side vs §9.2 oci-side: the OCI index
        // expands one image with N tags into N descriptors, but the
        // Docker schema encodes them as a single entry whose RepoTags
        // is an N-element array.
        let cfg = d(0xab);
        let layers = [d(0x01), d(0x02)];
        let tags = ["repo:a".to_string(), "repo:b".to_string(), "repo:c".to_string()];
        let m = build_docker_manifest(&[input(&cfg, &layers, &tags)]).unwrap();
        assert_eq!(m.len(), 1, "multi-tagged image must stay as one entry");
        assert_eq!(m[0].repo_tags, tags);
    }

    #[test]
    fn untagged_image_emits_empty_repo_tags_array() {
        let cfg = d(0xcd);
        let layers = [d(0xee)];
        let tags: [String; 0] = [];
        let m = build_docker_manifest(&[input(&cfg, &layers, &tags)]).unwrap();
        assert_eq!(m.len(), 1);
        assert!(m[0].repo_tags.is_empty());
    }

    #[test]
    fn layers_preserve_stack_order() {
        // Spec 05 §5.3 stack order is caller-pinned; this module never
        // reorders. Pass a deliberately non-sorted byte sequence to
        // catch any accidental sort.
        let cfg = d(0xab);
        let layers = [d(0x03), d(0x01), d(0x02)];
        let tags: [String; 0] = [];
        let m = build_docker_manifest(&[input(&cfg, &layers, &tags)]).unwrap();
        let want: Vec<String> = layers.iter().map(blob_path).collect();
        assert_eq!(m[0].layers, want);
    }

    #[test]
    fn multiple_images_keep_input_order() {
        let cfg_a = d(0xaa);
        let cfg_b = d(0xbb);
        let layers_a = [d(0x10)];
        let layers_b = [d(0x20)];
        let tags_a = ["a:1".to_string()];
        let tags_b = ["b:1".to_string()];
        let m = build_docker_manifest(&[input(&cfg_a, &layers_a, &tags_a), input(&cfg_b, &layers_b, &tags_b)]).unwrap();
        assert_eq!(m.len(), 2);
        assert!(m[0].config.ends_with(&"aa".repeat(32)));
        assert!(m[1].config.ends_with(&"bb".repeat(32)));
    }

    #[test]
    fn empty_input_yields_empty_array() {
        let m = build_docker_manifest(&[]).unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn paths_use_blobs_sha256_prefix_and_lowercase_hex() {
        let cfg = d(0xfe);
        let layers = [d(0xab)];
        let tags: [String; 0] = [];
        let m = build_docker_manifest(&[input(&cfg, &layers, &tags)]).unwrap();
        for s in std::iter::once(&m[0].config).chain(m[0].layers.iter()) {
            assert!(s.starts_with("blobs/sha256/"), "got: {s}");
            let hex = &s["blobs/sha256/".len()..];
            assert_eq!(hex.len(), 64);
            assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
    }

    #[test]
    fn json_serialisation_uses_pascal_case_keys() {
        let cfg = d(0xab);
        let layers = [d(0x01)];
        let tags = ["repo:tag".to_string()];
        let m = build_docker_manifest(&[input(&cfg, &layers, &tags)]).unwrap();
        let body = serde_json::to_string(&m).unwrap();
        // Docker's wire schema: the keys are PascalCase, never camelCase
        // or snake_case. `docker load` rejects the others outright.
        assert!(body.contains("\"Config\""), "body: {body}");
        assert!(body.contains("\"RepoTags\""), "body: {body}");
        assert!(body.contains("\"Layers\""), "body: {body}");
    }

    #[test]
    fn json_round_trip_preserves_entry_value() {
        let cfg = d(0x01);
        let layers = [d(0x02), d(0x03)];
        let tags = ["repo:tag".to_string()];
        let m = build_docker_manifest(&[input(&cfg, &layers, &tags)]).unwrap();
        let body = serde_json::to_vec(&m).unwrap();
        let back: Vec<DockerManifestEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn determinism_two_runs_produce_byte_equal_json() {
        // Spec 11 §11.6: same inputs produce byte-identical bytes. The
        // struct uses `Vec`s only — no HashMap source of iteration
        // randomness, so structural equality already implies byte
        // equality. Confirm by comparing serialised forms.
        let cfg = d(0xab);
        let layers = [d(0x01), d(0x02)];
        let tags = ["a:1".to_string(), "a:2".to_string()];
        let a = build_docker_manifest(&[input(&cfg, &layers, &tags)]).unwrap();
        let b = build_docker_manifest(&[input(&cfg, &layers, &tags)]).unwrap();
        assert_eq!(serde_json::to_vec(&a).unwrap(), serde_json::to_vec(&b).unwrap());
    }

    #[test]
    fn deserialises_a_real_docker_manifest_json_blob() {
        // Sanity: hand-write a `docker save` style document and confirm
        // it round-trips through our typed model. Catches accidental
        // future renames.
        let raw = br#"
            [
              {
                "Config": "blobs/sha256/cf",
                "RepoTags": ["repo:tag"],
                "Layers": ["blobs/sha256/aa", "blobs/sha256/bb"]
              }
            ]
        "#;
        let v: Vec<DockerManifestEntry> = serde_json::from_slice(raw).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].config, "blobs/sha256/cf");
        assert_eq!(v[0].repo_tags, vec!["repo:tag"]);
        assert_eq!(v[0].layers, vec!["blobs/sha256/aa", "blobs/sha256/bb"]);
    }
}
