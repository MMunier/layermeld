//! Post-assembly validation gate (spec 08 §8.5).
//!
//! Spec §8.5 requires every per-image manifest to be cross-checked
//! against the on-disk blob tree and the assembly records (spec 07 §7.7)
//! *before* the index is written, so that a malformed pipeline never
//! leaves an `index.json` pointing at digests that don't resolve. The
//! checks are:
//!
//! 1. Every digest the manifest references (its [`config`] descriptor and
//!    each of the [`layers`] descriptors) resolves to an actual file under
//!    `blobs/sha256/`.
//! 2. Every descriptor's `size` matches the on-disk byte count of the
//!    referenced blob.
//! 3. `manifest.layers.len()` equals `config.rootfs.diff_ids.len()`.
//! 4. Each `rootfs.diff_ids[i]` equals the `sha256:<hex>` of the
//!    [`EmittedLayer`] the assemble pass recorded at stack position `i`
//!    (spec 07 §7.7).
//!
//! On the first failure, [`validate`] returns [`Error::Validation`] and
//! the caller (the `lib::run` driver, spec 10) is expected to abort
//! before [`crate::oci::index::build_index`] is even called — let alone
//! before the index is serialised onto disk.
//!
//! [`config`]: ImageManifest::config
//! [`layers`]: ImageManifest::layers

use std::fs;
use std::path::Path;

use oci_spec::image::{Descriptor, ImageConfiguration, ImageManifest};

use crate::Error;
use crate::Result;
use crate::assemble::emit::EmittedLayer;
use crate::oci::config::diff_id_string;

/// Validation inputs for one output image.
///
/// `manifest` and `config` are the freshly-built typed values from
/// [`crate::oci::manifest::build_manifest`] /
/// [`crate::oci::config::rewrite_image_config`]. `stack` is the same
/// per-image ordered slice of [`EmittedLayer`]s those builders consumed —
/// passed through here so the `diff_id` cross-check (spec §8.5 last bullet)
/// can compare against the assemble pass's recorded digests rather than
/// re-hashing the blobs on disk.
#[derive(Debug)]
pub struct ImageValidationInput<'a> {
    /// Manifest under validation.
    pub manifest: &'a ImageManifest,
    /// The image config the manifest's `config` descriptor refers to.
    /// Read for `rootfs.diff_ids` only — the digest+size of the config
    /// blob itself comes from `manifest.config()`.
    pub config: &'a ImageConfiguration,
    /// Per-image ordered stack of emitted output layers (spec 05 §5.3
    /// order). Used for the `diff_id` cross-check; must be the same slice
    /// that was passed to the manifest / config builders.
    pub stack: &'a [&'a EmittedLayer],
}

/// Validate every output image per spec 08 §8.5.
///
/// `scratch_root` is the run's output root (the same directory the
/// assemble pass wrote `blobs/sha256/<digest>` under). `images` is one
/// entry per output image; iteration order does not matter — each image
/// is validated independently.
///
/// # Errors
///
/// [`Error::Validation`] on the first failing check, with a message
/// naming the offending image position, descriptor, and observed-vs-
/// expected values. Any one of:
///
/// * a referenced blob does not resolve (missing file, non-`sha256:` algo),
/// * a referenced blob's on-disk size disagrees with the descriptor,
/// * `manifest.layers.len()` ≠ `config.rootfs.diff_ids.len()`,
/// * `config.rootfs.diff_ids.len()` ≠ `stack.len()` (the assembly record
///   the caller is asserting matches the config),
/// * a `diff_id` text mismatches the corresponding [`EmittedLayer`] digest.
pub fn validate(scratch_root: &Path, images: &[ImageValidationInput<'_>]) -> Result<()> {
    let blobs_dir = scratch_root.join("blobs").join("sha256");
    for (i, img) in images.iter().enumerate() {
        validate_image(&blobs_dir, i, img)?;
    }
    Ok(())
}

fn validate_image(blobs_dir: &Path, image_idx: usize, img: &ImageValidationInput<'_>) -> Result<()> {
    // Spec §8.5 bullet 1+2: every referenced digest resolves and sizes match.
    check_descriptor(blobs_dir, image_idx, "config", img.manifest.config())?;
    for (i, desc) in img.manifest.layers().iter().enumerate() {
        check_descriptor(blobs_dir, image_idx, &format!("layers[{i}]"), desc)?;
    }

    // Spec §8.5 bullet 3: layer count == rootfs.diff_ids count.
    let layer_count = img.manifest.layers().len();
    let diff_ids = img.config.rootfs().diff_ids();
    if layer_count != diff_ids.len() {
        return Err(Error::Validation(format!(
            "image {image_idx}: manifest.layers count ({layer_count}) \
             does not match config.rootfs.diff_ids count ({})",
            diff_ids.len(),
        )));
    }

    // The caller-provided stack is the source of truth for the assembly
    // record; cross-checking it against the config catches the case where
    // the wrong stack was threaded in even though the config and manifest
    // happen to agree on layer count.
    if img.stack.len() != diff_ids.len() {
        return Err(Error::Validation(format!(
            "image {image_idx}: assembled stack length ({}) \
             does not match config.rootfs.diff_ids count ({})",
            img.stack.len(),
            diff_ids.len(),
        )));
    }

    // Spec §8.5 bullet 4: each diff_id matches the assembled layer.
    for (i, (diff_id, layer)) in diff_ids.iter().zip(img.stack.iter()).enumerate() {
        let expected = diff_id_string(&layer.digest);
        if diff_id != &expected {
            return Err(Error::Validation(format!(
                "image {image_idx}: rootfs.diff_ids[{i}] = {diff_id}, \
                 expected {expected} from assembly record",
            )));
        }
    }

    Ok(())
}

fn check_descriptor(blobs_dir: &Path, image_idx: usize, label: &str, desc: &Descriptor) -> Result<()> {
    let digest_str = desc.digest().to_string();
    let hex = digest_str.strip_prefix("sha256:").ok_or_else(|| {
        Error::Validation(format!(
            "image {image_idx}: {label} digest {digest_str} is not sha256-prefixed",
        ))
    })?;
    let path = blobs_dir.join(hex);
    let meta = fs::metadata(&path).map_err(|e| {
        Error::Validation(format!(
            "image {image_idx}: {label} blob {digest_str} missing at {}: {e}",
            path.display(),
        ))
    })?;
    let on_disk = meta.len();
    let declared = desc.size();
    if on_disk != declared {
        return Err(Error::Validation(format!(
            "image {image_idx}: {label} blob {digest_str} size mismatch: \
             descriptor says {declared}, on disk {on_disk}",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use oci_spec::image::{
        Arch, DescriptorBuilder, Digest, ImageConfigurationBuilder, ImageManifestBuilder, MediaType, Os, RootFsBuilder,
    };

    use super::*;
    use crate::assemble::digest::hex_encode;
    use crate::dedup::membership::ImageSet;
    use crate::squash::index::InputImageId;

    fn write_blob(scratch: &Path, digest: &[u8; 32], bytes: &[u8]) -> PathBuf {
        let dir = scratch.join("blobs").join("sha256");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(hex_encode(digest));
        fs::write(&path, bytes).unwrap();
        path
    }

    fn descriptor(media_type: MediaType, digest: &[u8; 32], size: u64) -> Descriptor {
        let s = format!("sha256:{}", hex_encode(digest));
        DescriptorBuilder::default()
            .media_type(media_type)
            .digest(Digest::try_from(s.as_str()).unwrap())
            .size(size)
            .build()
            .unwrap()
    }

    fn manifest_with(config: Descriptor, layers: Vec<Descriptor>) -> ImageManifest {
        ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .config(config)
            .layers(layers)
            .build()
            .unwrap()
    }

    fn config_with(diff_ids: Vec<String>) -> ImageConfiguration {
        ImageConfigurationBuilder::default()
            .architecture(Arch::Amd64)
            .os(Os::Linux)
            .rootfs(
                RootFsBuilder::default()
                    .typ("layers".to_string())
                    .diff_ids(diff_ids)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }

    fn emitted(membership: ImageSet, byte: u8, size: u64) -> EmittedLayer {
        EmittedLayer {
            membership,
            digest: [byte; 32],
            size,
            path: PathBuf::from("/dev/null"),
        }
    }

    /// Build a minimal but complete validation fixture: one image, one
    /// layer, one config, all blobs present on disk with matching sizes.
    fn happy_fixture(scratch: &Path) -> (ImageManifest, ImageConfiguration, EmittedLayer) {
        let cfg_digest = [0xab; 32];
        let cfg_bytes = b"config-bytes";
        write_blob(scratch, &cfg_digest, cfg_bytes);

        let layer_digest = [0xcd; 32];
        let layer_bytes = vec![0u8; 1024];
        write_blob(scratch, &layer_digest, &layer_bytes);

        let layer = emitted(ImageSet::singleton(InputImageId(0)), 0xcd, layer_bytes.len() as u64);
        let cfg = config_with(vec![format!("sha256:{}", "cd".repeat(32))]);
        let manifest = manifest_with(
            descriptor(MediaType::ImageConfig, &cfg_digest, cfg_bytes.len() as u64),
            vec![descriptor(
                MediaType::ImageLayer,
                &layer_digest,
                layer_bytes.len() as u64,
            )],
        );
        (manifest, cfg, layer)
    }

    #[test]
    fn happy_path_passes() {
        let scratch = tempfile::tempdir().unwrap();
        let (m, c, l) = happy_fixture(scratch.path());
        let stack = [&l];
        validate(
            scratch.path(),
            &[ImageValidationInput {
                manifest: &m,
                config: &c,
                stack: &stack,
            }],
        )
        .unwrap();
    }

    #[test]
    fn empty_image_list_passes() {
        // No images is structurally valid — the spec doesn't forbid an
        // empty index, and panicking on it would only mask other bugs.
        let scratch = tempfile::tempdir().unwrap();
        validate(scratch.path(), &[]).unwrap();
    }

    #[test]
    fn missing_config_blob_fails() {
        let scratch = tempfile::tempdir().unwrap();
        let (m, c, l) = happy_fixture(scratch.path());
        // Remove the config blob.
        let cfg_hex = hex_encode(&[0xab; 32]);
        fs::remove_file(scratch.path().join("blobs").join("sha256").join(&cfg_hex)).unwrap();
        let stack = [&l];
        let err = validate(
            scratch.path(),
            &[ImageValidationInput {
                manifest: &m,
                config: &c,
                stack: &stack,
            }],
        )
        .unwrap_err();
        match err {
            Error::Validation(msg) => {
                assert!(msg.contains("config"), "got: {msg}");
                assert!(msg.contains("missing"), "got: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn missing_layer_blob_fails() {
        let scratch = tempfile::tempdir().unwrap();
        let (m, c, l) = happy_fixture(scratch.path());
        let layer_hex = hex_encode(&[0xcd; 32]);
        fs::remove_file(scratch.path().join("blobs").join("sha256").join(&layer_hex)).unwrap();
        let stack = [&l];
        let err = validate(
            scratch.path(),
            &[ImageValidationInput {
                manifest: &m,
                config: &c,
                stack: &stack,
            }],
        )
        .unwrap_err();
        match err {
            Error::Validation(msg) => assert!(msg.contains("layers[0]"), "got: {msg}"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn config_size_mismatch_fails() {
        let scratch = tempfile::tempdir().unwrap();
        let (_, c, l) = happy_fixture(scratch.path());
        // Manifest claims the config is 999 bytes, but the on-disk
        // fixture is 12. Build a manifest with the wrong size.
        let cfg_digest = [0xab; 32];
        let layer_digest = [0xcd; 32];
        let manifest = manifest_with(
            descriptor(MediaType::ImageConfig, &cfg_digest, 999),
            vec![descriptor(MediaType::ImageLayer, &layer_digest, 1024)],
        );
        let stack = [&l];
        let err = validate(
            scratch.path(),
            &[ImageValidationInput {
                manifest: &manifest,
                config: &c,
                stack: &stack,
            }],
        )
        .unwrap_err();
        match err {
            Error::Validation(msg) => {
                assert!(msg.contains("size mismatch"), "got: {msg}");
                assert!(msg.contains("config"), "got: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn layer_size_mismatch_fails() {
        let scratch = tempfile::tempdir().unwrap();
        let (_, c, l) = happy_fixture(scratch.path());
        let cfg_digest = [0xab; 32];
        let layer_digest = [0xcd; 32];
        let manifest = manifest_with(
            descriptor(MediaType::ImageConfig, &cfg_digest, 12),
            vec![descriptor(MediaType::ImageLayer, &layer_digest, 7)],
        );
        let stack = [&l];
        let err = validate(
            scratch.path(),
            &[ImageValidationInput {
                manifest: &manifest,
                config: &c,
                stack: &stack,
            }],
        )
        .unwrap_err();
        match err {
            Error::Validation(msg) => {
                assert!(msg.contains("size mismatch"), "got: {msg}");
                assert!(msg.contains("layers[0]"), "got: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn layer_count_diff_id_count_mismatch_fails() {
        // Manifest has one layer descriptor; config claims two diff_ids.
        let scratch = tempfile::tempdir().unwrap();
        let (m, _, l) = happy_fixture(scratch.path());
        let cfg = config_with(vec![
            format!("sha256:{}", "cd".repeat(32)),
            format!("sha256:{}", "ef".repeat(32)),
        ]);
        let stack = [&l];
        let err = validate(
            scratch.path(),
            &[ImageValidationInput {
                manifest: &m,
                config: &cfg,
                stack: &stack,
            }],
        )
        .unwrap_err();
        match err {
            Error::Validation(msg) => {
                assert!(msg.contains("manifest.layers count"), "got: {msg}");
                assert!(msg.contains("diff_ids count"), "got: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn stack_length_mismatch_fails() {
        // Caller passed a stack that doesn't match the config — surface
        // it rather than silently zip-truncating.
        let scratch = tempfile::tempdir().unwrap();
        let (m, c, l) = happy_fixture(scratch.path());
        let extra = emitted(ImageSet::singleton(InputImageId(0)), 0xee, 1);
        let stack = [&l, &extra]; // length 2, config has 1 diff_id
        let err = validate(
            scratch.path(),
            &[ImageValidationInput {
                manifest: &m,
                config: &c,
                stack: &stack,
            }],
        )
        .unwrap_err();
        match err {
            Error::Validation(msg) => assert!(msg.contains("assembled stack length"), "got: {msg}"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn diff_id_text_mismatch_fails() {
        // Config carries a diff_id that doesn't match the EmittedLayer.
        let scratch = tempfile::tempdir().unwrap();
        let (m, _, l) = happy_fixture(scratch.path());
        let bogus = format!("sha256:{}", "ff".repeat(32));
        let cfg = config_with(vec![bogus.clone()]);
        let stack = [&l];
        let err = validate(
            scratch.path(),
            &[ImageValidationInput {
                manifest: &m,
                config: &cfg,
                stack: &stack,
            }],
        )
        .unwrap_err();
        match err {
            Error::Validation(msg) => {
                assert!(msg.contains("rootfs.diff_ids[0]"), "got: {msg}");
                assert!(msg.contains(&bogus), "got: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn multi_image_first_failure_wins_and_names_the_image() {
        // Image 0 is fine; image 1 has a missing layer blob. Error must
        // mention "image 1" so the user can grep the failure to a
        // specific manifest.
        let scratch = tempfile::tempdir().unwrap();
        let (m0, c0, l0) = happy_fixture(scratch.path());
        let stack0 = [&l0];

        // Image 1: build a separate fixture but omit the layer blob.
        let cfg1_digest = [0x12; 32];
        let cfg1_bytes = b"another-config";
        write_blob(scratch.path(), &cfg1_digest, cfg1_bytes);
        let layer1_digest = [0x34; 32];
        // Intentionally do NOT write the layer blob.
        let l1 = emitted(ImageSet::singleton(InputImageId(1)), 0x34, 99);
        let c1 = config_with(vec![format!("sha256:{}", "34".repeat(32))]);
        let m1 = manifest_with(
            descriptor(MediaType::ImageConfig, &cfg1_digest, cfg1_bytes.len() as u64),
            vec![descriptor(MediaType::ImageLayer, &layer1_digest, 99)],
        );
        let stack1 = [&l1];

        let err = validate(
            scratch.path(),
            &[
                ImageValidationInput {
                    manifest: &m0,
                    config: &c0,
                    stack: &stack0,
                },
                ImageValidationInput {
                    manifest: &m1,
                    config: &c1,
                    stack: &stack1,
                },
            ],
        )
        .unwrap_err();
        match err {
            Error::Validation(msg) => {
                assert!(msg.contains("image 1"), "got: {msg}");
                assert!(msg.contains("layers[0]"), "got: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn multi_layer_image_passes_when_all_diff_ids_match() {
        // Three layers, three diff_ids, all blobs present.
        let scratch = tempfile::tempdir().unwrap();
        let cfg_digest = [0xab; 32];
        write_blob(scratch.path(), &cfg_digest, b"cfg");

        let bytes = vec![0u8; 16];
        let l0 = emitted(ImageSet::singleton(InputImageId(0)), 0x01, bytes.len() as u64);
        let l1 = emitted(ImageSet::singleton(InputImageId(0)), 0x02, bytes.len() as u64);
        let l2 = emitted(ImageSet::singleton(InputImageId(0)), 0x03, bytes.len() as u64);
        for d in [&l0.digest, &l1.digest, &l2.digest] {
            write_blob(scratch.path(), d, &bytes);
        }

        let cfg = config_with(vec![
            format!("sha256:{}", "01".repeat(32)),
            format!("sha256:{}", "02".repeat(32)),
            format!("sha256:{}", "03".repeat(32)),
        ]);
        let manifest = manifest_with(
            descriptor(MediaType::ImageConfig, &cfg_digest, 3),
            vec![
                descriptor(MediaType::ImageLayer, &l0.digest, bytes.len() as u64),
                descriptor(MediaType::ImageLayer, &l1.digest, bytes.len() as u64),
                descriptor(MediaType::ImageLayer, &l2.digest, bytes.len() as u64),
            ],
        );

        let stack = [&l0, &l1, &l2];
        validate(
            scratch.path(),
            &[ImageValidationInput {
                manifest: &manifest,
                config: &cfg,
                stack: &stack,
            }],
        )
        .unwrap();
    }

    #[test]
    fn diff_id_mismatch_at_non_first_position_is_caught() {
        // Stack[1] disagrees with diff_ids[1] — the loop must keep going
        // past index 0 rather than short-circuiting.
        let scratch = tempfile::tempdir().unwrap();
        let cfg_digest = [0xab; 32];
        write_blob(scratch.path(), &cfg_digest, b"cfg");
        let l0 = emitted(ImageSet::singleton(InputImageId(0)), 0x01, 4);
        let l1 = emitted(ImageSet::singleton(InputImageId(0)), 0x02, 4);
        write_blob(scratch.path(), &l0.digest, &[0u8; 4]);
        write_blob(scratch.path(), &l1.digest, &[0u8; 4]);
        let cfg = config_with(vec![
            format!("sha256:{}", "01".repeat(32)),
            format!("sha256:{}", "ee".repeat(32)), // bogus
        ]);
        let manifest = manifest_with(
            descriptor(MediaType::ImageConfig, &cfg_digest, 3),
            vec![
                descriptor(MediaType::ImageLayer, &l0.digest, 4),
                descriptor(MediaType::ImageLayer, &l1.digest, 4),
            ],
        );
        let stack = [&l0, &l1];
        let err = validate(
            scratch.path(),
            &[ImageValidationInput {
                manifest: &manifest,
                config: &cfg,
                stack: &stack,
            }],
        )
        .unwrap_err();
        match err {
            Error::Validation(msg) => assert!(msg.contains("rootfs.diff_ids[1]"), "got: {msg}"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn empty_stack_with_empty_diff_ids_passes() {
        // A zero-layer image is structurally valid (diff_ids.len() == 0
        // == manifest.layers.len() == stack.len()). Spec §8.5 doesn't
        // forbid it; the only real-world way to hit it would be a
        // synthetic test fixture, but the gate must not false-positive.
        let scratch = tempfile::tempdir().unwrap();
        let cfg_digest = [0xab; 32];
        write_blob(scratch.path(), &cfg_digest, b"cfg-only");
        let cfg = config_with(vec![]);
        let manifest = manifest_with(descriptor(MediaType::ImageConfig, &cfg_digest, 8), vec![]);
        validate(
            scratch.path(),
            &[ImageValidationInput {
                manifest: &manifest,
                config: &cfg,
                stack: &[],
            }],
        )
        .unwrap();
    }
}
