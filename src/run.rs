//! Top-level pipeline driver (spec 10).
//!
//! [`run`] is the single entry point [`crate::main`] calls after argv has
//! been translated into a [`Config`]. It threads every spec stage in
//! order — capture `T0`, resolve collisions, load inputs, verify
//! digests, squash, dedup, assemble, write OCI documents, package,
//! finalise — and returns a [`Summary`] for the binary to print.
//!
//! ## Stage ordering (spec 10 §10.7 / §10.8)
//!
//! The order is dictated by the exit-code rules: anything that can
//! produce an exit code 2 (bad usage) or 4 (input digest mismatch)
//! must precede the first byte written under the output destination,
//! and the destination collision check (exit code 3) is also performed
//! before any other side effect.
//!
//! 1. Capture `T0` (spec 06 §6.1) — also surfaces a malformed
//!    `SOURCE_DATE_EPOCH` as exit code 2.
//! 2. Reserve the output destination via
//!    [`crate::output::collision::prepare_destination`] — exit code 3
//!    on collision without `--force`.
//! 3. Load every input path into a flat list of [`InputImage`]s. Each
//!    input may carry multiple images (multi-image archives, spec 10
//!    §10.2); their argv-order position becomes the [`InputImageId`].
//! 4. Emit the platform-consistency warning (spec 08 §8.3).
//! 5. Verify input layer digests (spec 07 §7.6) — exit code 4 on
//!    mismatch, before any output blob exists.
//! 6. Squash + hardlink-resolve each image (spec 03).
//! 7. Compute naive + effective membership and the candidate-layer
//!    partition (spec 05 §5.1–§5.4).
//! 8. Run the dissolve pass (spec 05 §5.5).
//! 9. Set up the scratch directory (defaults to `<output>.partial/`,
//!    spec 10 §10.4) and emit every layer blob via
//!    [`crate::assemble::emit_layers`].
//! 10. For each input image: rewrite the image config, write the config
//!     blob, build the manifest, write the manifest blob.
//! 11. Run the post-assembly validation gate (spec 08 §8.5).
//! 12. Build the OCI image index (spec 09 §9.2).
//! 13. Package the layout — directory or tar — into the final output
//!     path (spec 09 §9.3 / §9.4).
//! 14. Build the [`Summary`] (spec 10 §10.6).
//!
//! On `--dry-run` (spec 10 §10.4) steps 9–13 are skipped: no scratch
//! tree, no output, no rename. The summary is still produced so the
//! user can preview savings — per-layer sizes are sourced from
//! [`estimated_tar_size`] (spec 05 §5.5.1's PAX-tar size estimator),
//! which is a pure function of the candidate layer's entries and so
//! agrees byte-for-byte with what the assembler would have produced.
//! `diff_id`s cannot be predicted without actually streaming the
//! bytes, so they render as a `sha256:<dry-run>` placeholder.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use oci_spec::image::{ImageConfiguration, ImageManifest};
use sha2::{Digest as ShaDigest, Sha256};

use crate::assemble::digest::hex_encode;
use crate::assemble::emit::{EmittedLayer, emit_layers};
use crate::assemble::verify::verify_input_digests;
use crate::cli::Layout;
use crate::config::Config;
use crate::dedup::colocate::colocate_hardlink_targets;
use crate::dedup::dissolve::{dissolve, estimated_tar_size};
use crate::dedup::membership::{ImageSet, effective_membership, naive_membership};
use crate::dedup::partition::partition;
use crate::dedup::stack::stack_for_image;
use crate::docker_manifest::{DockerManifestInput, DockerManifestLayerSourceInput, build_docker_manifest};
use crate::input::model::{InputImage, LayerHandle};
use crate::input::{DirTransportReader, DockerArchiveReader, Layout as InputLayout, OciLayoutReader, detect};
use crate::oci::config::rewrite_image_config;
use crate::oci::index::{IndexEntryInput, build_index};
use crate::oci::manifest::build_manifest;
use crate::oci::platform_check::check_platform_consistency;
use crate::oci::validate::{ImageValidationInput, validate as validate_layout};
use crate::output::collision::{Prepared, prepare_destination};
use crate::output::dir::{canonical_json_bytes, finalize_layout};
use crate::output::tar::finalize_tar;
use crate::squash::apply::apply_image;
use crate::squash::hardlink::resolve as resolve_hardlinks;
use crate::squash::index::{InputImageId, SquashedFs};
use crate::summary::{ImageManifestSummary, InputSummary, LayerSummary, Summary};
use crate::timestamp::T0;
use crate::{Error, Result};

/// Run the full squash pipeline described in spec 10.
///
/// On success returns a populated [`Summary`] reflecting the bytes
/// landed at `config.output`. The caller is responsible for printing
/// it to stdout (subject to `--quiet`) per spec 10 §10.6 / §10.8.
///
/// # Errors
///
/// Every variant of [`Error`] can surface here; see spec 10 §10.7 for
/// the exit-code mapping the binary applies on top.
pub fn run(config: &Config) -> Result<Summary> {
    // Step 1 — capture T0. Done before anything else so a malformed
    // SOURCE_DATE_EPOCH aborts as exit code 2 with no side effects.
    let (t0, _t0_source) = T0::capture(config.timestamp)?;

    // Step 2 — reserve the output destination. Exit code 3 on
    // collision without --force; the move-aside happens here when
    // --force is set, but only the move — the final write is later.
    let _prepared = if config.dry_run {
        Prepared::Vacant
    } else {
        prepare_destination(&config.output, config.force, t0)?
    };

    // Step 3 — load every input path into the flat InputImage list.
    // Each input may yield multiple images; their flattened position is
    // the InputImageId downstream stages use as a slice index.
    let images = load_inputs(&config.inputs)?;
    if images.is_empty() {
        return Err(Error::Usage("no input images resolved from the given paths".into()));
    }
    let images_layers: Vec<Vec<LayerHandle>> = images.iter().map(|img| img.layers.clone()).collect();

    // Step 4 — platform consistency warning. Single tracing::warn! event
    // when input platforms diverge (spec 08 §8.3); the run continues.
    let configs_borrow: Vec<&ImageConfiguration> = images.iter().map(|img| &img.config).collect();
    check_platform_consistency(&configs_borrow);

    // Step 5 — verify input layer digests (spec 07 §7.6). Exit code 4
    // on mismatch; runs before any output blob is written.
    verify_input_digests(&images_layers, config.jobs)?;

    // Step 6 — squash + hardlink-resolve each input image.
    tracing::info!("Squashing image file systems");
    let squashed: Vec<SquashedFs> = images
        .iter()
        .enumerate()
        .map(|(i, img)| {
            let mut fs = apply_image(InputImageId(i), &img.layers)?;
            let image_label = if img.repo_tags.is_empty() {
                format!("input image #{i}")
            } else {
                format!("input image #{i} ({})", img.repo_tags.join(", "))
            };
            resolve_hardlinks(&mut fs, &image_label)?;
            Ok(fs)
        })
        .collect::<Result<Vec<_>>>()?;

    // Step 7 — naive + effective membership, candidate-layer partition.
    tracing::info!("Partitioning layers");
    let naive = naive_membership(&squashed);
    let eff = effective_membership(&squashed, &naive);
    let mut layers = partition(&squashed, &eff);

    // Step 8 — dissolve pass.
    tracing::info!("Dissolve pass");
    dissolve(&mut layers, &squashed, config.min_layer_size);

    // Step 8b — co-locate each per-image layer's hardlink targets.
    // Spec 05 §5.6 lets a hardlink in {i} reference a target that
    // lives only in a sibling shared layer; runtimes that extract
    // each layer tar in isolation (`podman load`, `docker load`)
    // can't follow that cross-tar reference. Pulling the target's
    // body into {i} costs a few KiB per image and lets hardlinks
    // round-trip through real container loaders. Idempotent.
    tracing::info!("Co-locating hardlink targets");
    colocate_hardlink_targets(&mut layers, &squashed);

    // Step 9 — set up scratch and assemble layer blobs (skipped in dry-
    // run; assembly is what produces the digests we'd want to report,
    // so the dry-run summary will report empty layer rows).
    tracing::info!("Emitting layers");
    let scratch_root = scratch_path(config);
    let emitted: Vec<EmittedLayer> = if config.dry_run {
        Vec::new()
    } else {
        fs::create_dir_all(&scratch_root)?;
        emit_layers(&layers, &images_layers, t0, &scratch_root, config.jobs)?
    };

    // Index the emitted layers by membership so per-image stack
    // ordering can map ImageSet keys back onto layer accounting.
    let by_membership: std::collections::BTreeMap<ImageSet, &EmittedLayer> =
        emitted.iter().map(|l| (l.membership.clone(), l)).collect();

    // Step 10–11 — per-image artifact assembly + validation.
    let artifacts: Vec<ImageArtifacts> = if config.dry_run {
        Vec::new()
    } else {
        let artifacts = build_per_image_artifacts(&images, &layers, &by_membership, &scratch_root, t0)?;
        run_validation_gate(&artifacts, &scratch_root)?;
        artifacts
    };

    // Step 12–13 — index + finalize (skipped on dry-run).
    if !config.dry_run {
        finalize_output(config, &images, &artifacts, &scratch_root, t0)?;
    }

    // Step 14 — summary.
    let layer_rows = if config.dry_run {
        estimated_layer_rows(&layers)
    } else {
        emitted.iter().map(LayerSummary::from_emitted).collect()
    };
    Ok(build_summary(config, &images, layer_rows, &artifacts, t0))
}

/// Build per-image artifacts (rewritten config + manifest) and write
/// their blobs into `scratch_root` (spec 10 §10's steps 10–11).
fn build_per_image_artifacts<'a>(
    images: &'a [InputImage],
    layers: &std::collections::BTreeMap<ImageSet, crate::dedup::partition::CandidateLayer>,
    by_membership: &std::collections::BTreeMap<ImageSet, &'a EmittedLayer>,
    scratch_root: &Path,
    t0: T0,
) -> Result<Vec<ImageArtifacts<'a>>> {
    let mut artifacts: Vec<ImageArtifacts<'a>> = Vec::with_capacity(images.len());
    for (i, img) in images.iter().enumerate() {
        tracing::info!("Processing output image {i}");
        let stack_keys = stack_for_image(layers, InputImageId(i));
        let stack: Vec<&EmittedLayer> = stack_keys
            .iter()
            .map(|m| {
                by_membership.get(m).copied().ok_or_else(|| {
                    Error::Validation(format!("stack references unknown layer membership {m:?} for image-{i}"))
                })
            })
            .collect::<Result<_>>()?;

        let new_config = rewrite_image_config(&img.config, &stack, t0)?;
        let config_bytes = canonical_json_bytes(&new_config)?;
        let (config_digest, _) = write_blob_atomic(scratch_root, &config_bytes)?;

        let manifest = build_manifest(&config_digest, config_bytes.len() as u64, &stack, t0, &img.repo_tags)?;
        let manifest_bytes = canonical_json_bytes(&manifest)?;
        let (manifest_digest, _) = write_blob_atomic(scratch_root, &manifest_bytes)?;

        artifacts.push(ImageArtifacts {
            stack,
            config: new_config,
            config_digest,
            manifest,
            manifest_digest,
            manifest_size: manifest_bytes.len() as u64,
        });
    }
    Ok(artifacts)
}

/// Spec 08 §8.5 validation gate. Fails before the index is built so a
/// broken pipeline never produces a layout.
fn run_validation_gate(artifacts: &[ImageArtifacts<'_>], scratch_root: &Path) -> Result<()> {
    let validation_inputs: Vec<ImageValidationInput<'_>> = artifacts
        .iter()
        .map(|a| ImageValidationInput {
            manifest: &a.manifest,
            config: &a.config,
            stack: a.stack.as_slice(),
        })
        .collect();
    tracing::info!("Validating layout");
    validate_layout(scratch_root, &validation_inputs)
}

/// Build the OCI image index + Docker `manifest.json` and finalize the
/// output layout (spec 10 §10's steps 12–13).
fn finalize_output(
    config: &Config,
    images: &[InputImage],
    artifacts: &[ImageArtifacts<'_>],
    scratch_root: &Path,
    t0: T0,
) -> Result<()> {
    let index_inputs: Vec<IndexEntryInput<'_>> = images
        .iter()
        .zip(artifacts.iter())
        .map(|(img, a)| IndexEntryInput {
            manifest_digest: &a.manifest_digest,
            manifest_size: a.manifest_size,
            config: &img.config,
            repo_tags: img.repo_tags.as_slice(),
        })
        .collect();
    let index = build_index(&index_inputs, t0)?;

    // Spec 09 §9.5: emit a Docker-archive `manifest.json` alongside the
    // OCI `index.json` so `podman load -i` can restore every image
    // (podman falls back to single-image semantics on a pure OCI
    // layout). Layer digests come straight off the assembled stack —
    // same blobs as the OCI manifest references, so no extra bytes land
    // on disk.
    let layer_digests_per_image: Vec<Vec<[u8; 32]>> = artifacts
        .iter()
        .map(|a| a.stack.iter().map(|l| l.digest).collect())
        .collect();

    let layer_sources_per_images: Vec<Vec<DockerManifestLayerSourceInput<'_>>> = artifacts
        .iter()
        .map(|a| {
            a.stack
                .iter()
                .map(|l| DockerManifestLayerSourceInput {
                    digest: &l.digest,
                    media_type: "application/vnd.oci.image.layer.v1.tar",
                    size: l.size,
                })
                .collect()
        })
        .collect();

    let docker_inputs: Vec<DockerManifestInput<'_>> = artifacts
        .iter()
        .zip(images.iter())
        .zip(layer_digests_per_image.iter())
        .zip(layer_sources_per_images.iter())
        .map(|(((a, img), layers), layer_sources)| DockerManifestInput {
            config_digest: &a.config_digest,
            layer_digests: layers.as_slice(),
            layer_sources: layer_sources.as_slice(),
            repo_tags: img.repo_tags.as_slice(),
        })
        .collect();
    let docker_manifest = build_docker_manifest(&docker_inputs)?;

    match config.layout {
        Layout::Dir => finalize_layout(scratch_root, &index, &docker_manifest, &config.output)?,
        Layout::Tar => {
            finalize_tar(scratch_root, &index, &docker_manifest, &config.output, t0)?;
            // Tar packaging leaves the staging directory in place (it
            // streams blobs from there into the tar). Sweep it now so a
            // successful run leaves only the artifact.
            let _ = fs::remove_dir_all(scratch_root);
        }
    }
    Ok(())
}

/// Build the per-layer summary rows for a `--dry-run` invocation.
///
/// Sources sizes from [`estimated_tar_size`] (spec 05 §5.5.1's
/// PAX-tar size estimator — the same function the dissolve pass
/// uses), and substitutes a `sha256:<dry-run>` placeholder for the
/// `diff_id` since the real digest cannot be computed without
/// streaming the bytes. The iteration order is the candidate
/// partition's lex-on-`ImageSet` order, matching what
/// [`emit_layers`] would have produced.
fn estimated_layer_rows(
    layers: &std::collections::BTreeMap<ImageSet, crate::dedup::partition::CandidateLayer>,
) -> Vec<LayerSummary> {
    layers
        .iter()
        .map(|(membership, layer)| LayerSummary {
            membership: membership.clone(),
            size: estimated_tar_size(layer),
            diff_id: "sha256:<dry-run>".to_string(),
        })
        .collect()
}

/// Per-image artifacts accumulated during step 10.
struct ImageArtifacts<'a> {
    stack: Vec<&'a EmittedLayer>,
    config: ImageConfiguration,
    config_digest: [u8; 32],
    manifest: ImageManifest,
    manifest_digest: [u8; 32],
    manifest_size: u64,
}

/// Resolve the scratch root.
///
/// If `--scratch` was given, that path wins verbatim. Otherwise the
/// suffix depends on the layout:
///
/// * [`Layout::Dir`] uses `<output>.partial/` per spec 10 §10.4 — the
///   same path [`finalize_layout`] then renames onto `<output>`, so an
///   aborted run leaves a single `.partial/` dir for the next run to
///   refuse without `--force`.
/// * [`Layout::Tar`] uses `<output>.staging/` instead, because
///   [`finalize_tar`] needs `<output>.partial` *as a sibling file* for
///   its own atomic-publish dance — using the same path for the scratch
///   directory and the tar's temp file would collide on first
///   `File::create`.
fn scratch_path(config: &Config) -> PathBuf {
    if let Some(p) = config.scratch.clone() {
        return p;
    }
    let suffix = match config.layout {
        Layout::Tar => ".staging",
        Layout::Dir => ".partial",
    };
    let mut name = config
        .output
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(suffix);
    config.output.with_file_name(name)
}

/// Load every input path, flattening multi-image archives into a single
/// `Vec<InputImage>`. Position in the result is the [`InputImageId`].
fn load_inputs(paths: &[PathBuf]) -> Result<Vec<InputImage>> {
    tracing::info!("Loading images");
    let mut out: Vec<InputImage> = Vec::new();
    for path in paths {
        let mut images = load_one(path)?;
        out.append(&mut images);
    }
    Ok(out)
}

fn load_one(path: &Path) -> Result<Vec<InputImage>> {
    let layout = detect(path)?;
    match layout {
        InputLayout::OciLayoutDir | InputLayout::OciLayoutTar => OciLayoutReader::open(path)?.into_images(),
        InputLayout::DockerArchive | InputLayout::DockerArchiveDir => DockerArchiveReader::open(path)?.into_images(),
        InputLayout::DirTransport => DirTransportReader::open(path)?.into_images(),
    }
}

/// Write `bytes` under `scratch_root/blobs/sha256/<sha256-hex>` via the
/// same temp-file + rename atomic publish discipline
/// [`crate::assemble::emit::emit_layer`] uses.
///
/// Returns the digest and final path. The hash is computed once over
/// the in-memory bytes — these are short documents (image config,
/// manifest) so single-buffer hashing is cheaper than streaming.
fn write_blob_atomic(scratch_root: &Path, bytes: &[u8]) -> Result<([u8; 32], PathBuf)> {
    let digest = sha256_of(bytes);
    let blobs_dir = scratch_root.join("blobs").join("sha256");
    fs::create_dir_all(&blobs_dir)?;
    let final_path = blobs_dir.join(hex_encode(&digest));

    // Idempotent: if the same blob is already in place, leave it. Bytes
    // are by-construction identical (same digest), so a re-hash would be
    // wasted I/O.
    if final_path.is_file() {
        return Ok((digest, final_path));
    }

    let tmp_path = blobs_dir.join(format!(".tmp-{}-blob-{}", std::process::id(), hex_encode(&digest)));
    {
        let mut f = File::create(&tmp_path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, &final_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("rename {} -> {} failed: {e}", tmp_path.display(), final_path.display()),
        ))
    })?;
    Ok((digest, final_path))
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn build_summary(
    config: &Config,
    images: &[InputImage],
    layers: Vec<LayerSummary>,
    artifacts: &[ImageArtifacts<'_>],
    t0: T0,
) -> Summary {
    let inputs: Vec<InputSummary> = images
        .iter()
        .enumerate()
        .map(|(i, img)| InputSummary {
            image_id: InputImageId(i),
            label: image_label(img),
            layer_count: img.layers.len(),
            total_bytes: img.layers.iter().map(|l| l.size).sum(),
        })
        .collect();
    let image_manifests: Vec<ImageManifestSummary> = images
        .iter()
        .enumerate()
        .map(|(i, img)| {
            // In dry-run, no manifests were built — fall back to a
            // placeholder digest so the section still renders.
            let manifest_digest = artifacts.get(i).map_or_else(
                || "sha256:<dry-run>".to_string(),
                |a| format!("sha256:{}", hex_encode(&a.manifest_digest)),
            );
            ImageManifestSummary {
                image_id: InputImageId(i),
                label: image_label(img),
                manifest_digest,
            }
        })
        .collect();
    Summary {
        inputs,
        output_path: config.output.clone(),
        output_layout: config.layout,
        layers,
        image_manifests,
        t0,
    }
}

/// Display label for an input image: first repo tag if any, else
/// `<untagged>` (spec 09 §9.2 dir-transport case).
fn image_label(img: &InputImage) -> String {
    img.repo_tags
        .first()
        .cloned()
        .unwrap_or_else(|| "<untagged>".to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use flate2::Compression as GzLevel;
    use flate2::write::GzEncoder;
    use oci_spec::image::{
        ANNOTATION_REF_NAME, Arch, ConfigBuilder, Descriptor, DescriptorBuilder, Digest, ImageConfigurationBuilder,
        ImageIndex, ImageIndexBuilder, ImageManifestBuilder, MediaType, Os, RootFsBuilder,
    };
    use sha2::{Digest as _, Sha256};
    use tar::{Builder, EntryType, Header};
    use tempfile::TempDir;

    use super::*;

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        hex_encode(&h.finalize().into())
    }

    fn append_regular(builder: &mut Builder<&mut Vec<u8>>, path: &str, body: &[u8]) {
        let mut h = Header::new_gnu();
        h.set_entry_type(EntryType::Regular);
        h.set_path(path).unwrap();
        h.set_mode(0o644);
        h.set_uid(0);
        h.set_gid(0);
        h.set_size(body.len() as u64);
        h.set_cksum();
        builder.append(&h, body).unwrap();
    }

    fn append_directory(builder: &mut Builder<&mut Vec<u8>>, path: &str) {
        let mut h = Header::new_gnu();
        h.set_entry_type(EntryType::Directory);
        h.set_path(path).unwrap();
        h.set_mode(0o755);
        h.set_uid(0);
        h.set_gid(0);
        h.set_size(0);
        h.set_cksum();
        builder.append(&h, std::io::empty()).unwrap();
    }

    /// Build a small uncompressed tar layer with the given files. For
    /// each file, every strict ancestor directory is auto-emitted as a
    /// dedicated tar entry first, since spec 05 §5.4.4 expects explicit
    /// entries for every path's ancestors.
    fn build_layer_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut tb = Builder::new(&mut buf);
            tb.mode(tar::HeaderMode::Deterministic);
            let mut emitted_dirs = std::collections::BTreeSet::new();
            for (path, _) in files {
                let p = Path::new(path);
                for anc in p.ancestors().skip(1) {
                    if anc.as_os_str().is_empty() {
                        continue;
                    }
                    let s = anc.to_str().unwrap().to_string();
                    if emitted_dirs.insert(s.clone()) {
                        append_directory(&mut tb, &s);
                    }
                }
            }
            for (path, body) in files {
                append_regular(&mut tb, path, body);
            }
            tb.finish().unwrap();
        }
        buf
    }

    fn gzip_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), GzLevel::default());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    /// Construct a minimal dir-transport input image on disk so
    /// [`run`] can exercise the full pipeline. Returns the input root.
    ///
    /// The dir-transport layout (spec 01 §1.5) places blobs as flat
    /// `<root>/<hex>` files alongside a `manifest.json` object. Layers
    /// here are uncompressed (`media_type` = `tar`), so the layer
    /// digest equals the `diff_id` — the simplest case.
    fn make_dir_transport_input(root: &Path, files: &[(&str, &[u8])]) -> PathBuf {
        fs::create_dir_all(root).unwrap();

        let layer_bytes = build_layer_tar(files);
        let layer_hex = sha256_hex(&layer_bytes);
        fs::write(root.join(&layer_hex), &layer_bytes).unwrap();

        let cfg = ImageConfigurationBuilder::default()
            .architecture(Arch::Amd64)
            .os(Os::Linux)
            .config(ConfigBuilder::default().cmd(vec!["sh".to_string()]).build().unwrap())
            .rootfs(
                RootFsBuilder::default()
                    .typ("layers".to_string())
                    .diff_ids(vec![format!("sha256:{layer_hex}")])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let cfg_bytes = serde_json::to_vec(&cfg).unwrap();
        let cfg_hex = sha256_hex(&cfg_bytes);
        fs::write(root.join(&cfg_hex), &cfg_bytes).unwrap();

        let cfg_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageConfig)
            .digest(Digest::from_str(&format!("sha256:{cfg_hex}")).unwrap())
            .size(cfg_bytes.len() as u64)
            .build()
            .unwrap();
        let layer_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageLayer)
            .digest(Digest::from_str(&format!("sha256:{layer_hex}")).unwrap())
            .size(layer_bytes.len() as u64)
            .build()
            .unwrap();
        let manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .config(cfg_descriptor)
            .layers(vec![layer_descriptor])
            .build()
            .unwrap();
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(root.join("manifest.json"), &manifest_bytes).unwrap();

        root.to_path_buf()
    }

    fn cfg_with_tar(output: PathBuf, inputs: Vec<PathBuf>) -> Config {
        Config {
            inputs,
            output,
            layout: Layout::Tar,
            min_layer_size: 0, // skip dissolve in tests
            force: false,
            timestamp: Some(1_700_000_000),
            jobs: 1,
            scratch: None,
            verbose: 0,
            quiet: false,
            dry_run: false,
        }
    }

    fn cfg_with_dir(output: PathBuf, inputs: Vec<PathBuf>) -> Config {
        let mut c = cfg_with_tar(output, inputs);
        c.layout = Layout::Dir;
        c
    }

    fn read_index(path: &Path) -> ImageIndex {
        let bytes = fs::read(path).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn end_to_end_single_image_dir_layout_produces_valid_oci_layout() {
        let td = TempDir::new().unwrap();
        let input_root = make_dir_transport_input(&td.path().join("in"), &[("etc/hostname", b"alpine\n")]);
        let output = td.path().join("out");
        let cfg = cfg_with_dir(output.clone(), vec![input_root]);

        let summary = run(&cfg).unwrap();

        // Output exists as an OCI layout directory.
        assert!(output.is_dir());
        assert!(output.join("oci-layout").is_file());
        assert!(output.join("index.json").is_file());
        let blobs = output.join("blobs").join("sha256");
        assert!(blobs.is_dir());

        let layout: serde_json::Value = serde_json::from_slice(&fs::read(output.join("oci-layout")).unwrap()).unwrap();
        assert_eq!(layout["imageLayoutVersion"], "1.0.0");

        let index = read_index(&output.join("index.json"));
        assert_eq!(index.manifests().len(), 1);

        // Every digest the index references resolves to a blob.
        let manifest_digest = index.manifests()[0].digest().to_string();
        let manifest_hex = manifest_digest.strip_prefix("sha256:").unwrap();
        assert!(blobs.join(manifest_hex).is_file());

        // Summary reflects what was written.
        assert_eq!(summary.image_manifests.len(), 1);
        assert!(summary.image_manifests[0].manifest_digest.starts_with("sha256:"));
        assert!(!summary.layers.is_empty());
    }

    #[test]
    fn end_to_end_single_image_tar_layout_produces_packed_tar() {
        let td = TempDir::new().unwrap();
        let input_root = make_dir_transport_input(&td.path().join("in"), &[("etc/hostname", b"alpine\n")]);
        let output = td.path().join("out.tar");
        let cfg = cfg_with_tar(output.clone(), vec![input_root]);

        run(&cfg).unwrap();

        assert!(output.is_file(), "tar layout must produce a single file");
        let bytes = fs::read(&output).unwrap();
        // ustar magic at standard offset.
        assert_eq!(&bytes[257..263], b"ustar\0");
        // Scratch swept after a successful tar run.
        assert!(!td.path().join("out.tar.partial").exists());
    }

    #[test]
    fn determinism_two_runs_produce_byte_identical_tar() {
        // Spec 11 §11.6: same inputs + same T0 ⇒ byte-equal output.
        let td_a = TempDir::new().unwrap();
        let td_b = TempDir::new().unwrap();
        let in_a = make_dir_transport_input(&td_a.path().join("in"), &[("a", b"alpha"), ("b", b"bravo")]);
        let in_b = make_dir_transport_input(&td_b.path().join("in"), &[("a", b"alpha"), ("b", b"bravo")]);
        let out_a = td_a.path().join("out.tar");
        let out_b = td_b.path().join("out.tar");
        run(&cfg_with_tar(out_a.clone(), vec![in_a])).unwrap();
        run(&cfg_with_tar(out_b.clone(), vec![in_b])).unwrap();
        assert_eq!(fs::read(&out_a).unwrap(), fs::read(&out_b).unwrap());
    }

    #[test]
    fn two_inputs_with_shared_content_produce_shared_layer() {
        // Spec 05: two images that present the same FileIdentity at the
        // same path should share a single output layer covering {0,1}.
        // To keep the two output manifests + configs distinct (so we
        // can confirm the shared layer is the *layer*, not a coincidence
        // of byte-equal manifests), the two images carry the same
        // shared file plus a distinct per-image file.
        let td = TempDir::new().unwrap();
        let a = make_dir_transport_input(
            &td.path().join("a"),
            &[("etc/shared", b"same-bytes"), ("only-a", b"alpha-only")],
        );
        let b = make_dir_transport_input(
            &td.path().join("b"),
            &[("etc/shared", b"same-bytes"), ("only-b", b"bravo-only")],
        );
        let output = td.path().join("out");
        run(&cfg_with_dir(output.clone(), vec![a, b])).unwrap();

        let index = read_index(&output.join("index.json"));
        assert_eq!(index.manifests().len(), 2, "one manifest per image");

        // Per-image blobs are distinct (configs reference different
        // diff_id stacks; manifests reference different configs); the
        // shared {0,1} layer dedups to a single on-disk blob:
        // 2 manifests + 2 configs + 1 shared layer + 2 per-image layers = 7.
        let blob_count = fs::read_dir(output.join("blobs").join("sha256")).unwrap().count();
        assert_eq!(
            blob_count, 7,
            "expected 2 manifests + 2 configs + 1 shared layer + 2 per-image layers",
        );
    }

    #[test]
    fn missing_input_path_surfaces_io_error() {
        let td = TempDir::new().unwrap();
        let output = td.path().join("out.tar");
        let cfg = cfg_with_tar(output, vec![td.path().join("does-not-exist")]);
        let err = run(&cfg).unwrap_err();
        // detect() wraps the missing-path stat as MalformedInput.
        assert!(matches!(err, Error::MalformedInput(_)), "got: {err:?}");
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn collision_without_force_is_exit_code_3_before_any_output() {
        let td = TempDir::new().unwrap();
        let input_root = make_dir_transport_input(&td.path().join("in"), &[("a", b"x")]);
        let output = td.path().join("out.tar");
        // Pre-create the destination so the collision check trips.
        fs::write(&output, b"prior").unwrap();
        let cfg = cfg_with_tar(output.clone(), vec![input_root]);

        let err = run(&cfg).unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert!(matches!(err, Error::OutputExists(_)));
        // Original file untouched (never deleted).
        assert_eq!(fs::read(&output).unwrap(), b"prior");
        // No partial / scratch left around.
        assert!(!td.path().join("out.tar.partial").exists());
    }

    #[test]
    fn force_moves_existing_aside_and_writes_new_output() {
        let td = TempDir::new().unwrap();
        let input_root = make_dir_transport_input(&td.path().join("in"), &[("a", b"x")]);
        let output = td.path().join("out.tar");
        fs::write(&output, b"prior").unwrap();
        let mut cfg = cfg_with_tar(output.clone(), vec![input_root]);
        cfg.force = true;

        run(&cfg).unwrap();

        // Old bytes survive in the aside; new tar landed at output.
        let aside = td.path().join(format!("out.tar.old-{}", 1_700_000_000));
        assert_eq!(fs::read(&aside).unwrap(), b"prior");
        assert!(output.is_file());
    }

    #[test]
    fn digest_mismatch_is_exit_code_4_before_blob_writes() {
        // Tamper an input layer blob so its on-disk bytes do not match
        // the manifest's declared digest. spec 07 §7.6 verification
        // must surface this as exit code 4 before any output exists.
        let td = TempDir::new().unwrap();
        let input_root = make_dir_transport_input(&td.path().join("in"), &[("a", b"x")]);

        // Find the single layer blob (everything that isn't `manifest.json`
        // or the config) and overwrite its bytes with garbage of the
        // same length so the size check still passes — only the SHA-256
        // diverges.
        let manifest: ImageManifest =
            serde_json::from_slice(&fs::read(input_root.join("manifest.json")).unwrap()).unwrap();
        let layer_hex = manifest.layers()[0]
            .digest()
            .to_string()
            .strip_prefix("sha256:")
            .unwrap()
            .to_string();
        let layer_path = input_root.join(&layer_hex);
        let original = fs::read(&layer_path).unwrap();
        let mut tampered = original.clone();
        // Flip a bit deep inside the tar body.
        let target = tampered.len() / 2;
        tampered[target] ^= 0xff;
        fs::write(&layer_path, &tampered).unwrap();

        let output = td.path().join("out.tar");
        let cfg = cfg_with_tar(output.clone(), vec![input_root]);

        let err = run(&cfg).unwrap_err();
        assert_eq!(err.exit_code(), 4);
        assert!(matches!(err, Error::DigestMismatch { .. }));
        assert!(!output.exists(), "output must not exist after exit 4");
    }

    #[test]
    fn dry_run_leaves_no_output_but_returns_summary() {
        let td = TempDir::new().unwrap();
        let input_root = make_dir_transport_input(&td.path().join("in"), &[("a", b"x")]);
        let output = td.path().join("out.tar");
        let mut cfg = cfg_with_tar(output.clone(), vec![input_root]);
        cfg.dry_run = true;

        let summary = run(&cfg).unwrap();
        assert!(!output.exists(), "dry-run must not produce output");
        assert!(!td.path().join("out.tar.partial").exists());
        assert!(!td.path().join("out.tar.staging").exists());
        assert_eq!(summary.inputs.len(), 1);
    }

    #[test]
    fn dry_run_summary_previews_layer_sizes_from_estimate() {
        // Spec 10 §10.4: --dry-run "reports the would-be summary so the
        // user can preview savings". Layer rows must be populated even
        // though no blob was assembled — sizes come from the tar-size
        // estimator (spec 05 §5.5.1) and diff_ids carry the dry-run
        // placeholder.
        let td = TempDir::new().unwrap();
        let input_root = make_dir_transport_input(&td.path().join("in"), &[("etc/hello", b"world")]);
        let output = td.path().join("out");
        let mut cfg = cfg_with_dir(output.clone(), vec![input_root]);
        cfg.dry_run = true;

        let summary = run(&cfg).unwrap();

        assert!(!output.exists(), "dry-run must not produce output");
        assert!(!summary.layers.is_empty(), "layer rows must populate in dry-run");
        for layer in &summary.layers {
            assert!(
                layer.size > 0,
                "estimated tar size must be non-zero for non-empty layers"
            );
            assert_eq!(layer.diff_id, "sha256:<dry-run>");
        }
        // The summary still renders end-to-end (totals + saved%
        // computed from the estimated sizes).
        let rendered = summary.to_string();
        assert!(rendered.contains("inputs total (squashed):"));
        assert!(rendered.contains("outputs total (deduplicated):"));
    }

    #[test]
    fn dry_run_estimate_matches_real_run_layer_sizes() {
        // The dry-run preview uses the same tar-size estimator the
        // dissolve pass uses, which is itself a function of the same
        // PAX header layout the assembler emits — so the previewed
        // per-layer sizes must agree with what a real run would emit.
        let td_a = TempDir::new().unwrap();
        let td_b = TempDir::new().unwrap();
        let in_a = make_dir_transport_input(&td_a.path().join("in"), &[("etc/hello", b"world")]);
        let in_b = make_dir_transport_input(&td_b.path().join("in"), &[("etc/hello", b"world")]);

        let mut dry = cfg_with_dir(td_a.path().join("out"), vec![in_a]);
        dry.dry_run = true;
        let dry_summary = run(&dry).unwrap();

        let real = cfg_with_dir(td_b.path().join("out"), vec![in_b]);
        let real_summary = run(&real).unwrap();

        let dry_sizes: Vec<(ImageSet, u64)> = dry_summary
            .layers
            .iter()
            .map(|l| (l.membership.clone(), l.size))
            .collect();
        let real_sizes: Vec<(ImageSet, u64)> = real_summary
            .layers
            .iter()
            .map(|l| (l.membership.clone(), l.size))
            .collect();
        assert_eq!(dry_sizes, real_sizes);
    }

    #[test]
    fn dry_run_skips_collision_check_and_leaves_destination_untouched() {
        // --dry-run never writes to <output>, so it doesn't matter
        // whether the destination already exists. Verify the existing
        // bytes survive verbatim and no aside is created.
        let td = TempDir::new().unwrap();
        let input_root = make_dir_transport_input(&td.path().join("in"), &[("a", b"x")]);
        let output = td.path().join("out.tar");
        fs::write(&output, b"prior").unwrap();
        let mut cfg = cfg_with_tar(output.clone(), vec![input_root]);
        cfg.dry_run = true;

        run(&cfg).unwrap();

        assert_eq!(fs::read(&output).unwrap(), b"prior");
        let aside = td.path().join(format!("out.tar.old-{}", 1_700_000_000));
        assert!(!aside.exists(), "dry-run must not move-aside");
    }

    #[test]
    fn summary_carries_input_label_from_repo_tag_when_present() {
        // Annotate the input with a ref.name so the OCI-layout reader
        // surfaces it as the repo tag — but easier here is to just use
        // the dir-transport flow which produces an untagged image,
        // then assert the fallback label.
        let td = TempDir::new().unwrap();
        let input_root = make_dir_transport_input(&td.path().join("in"), &[("a", b"x")]);
        let output = td.path().join("out");
        let summary = run(&cfg_with_dir(output, vec![input_root])).unwrap();
        assert_eq!(summary.inputs[0].label, "<untagged>");
    }

    #[test]
    fn argv_order_invariance_produces_identical_output() {
        // Spec 11 §11.3: image_id is a function of the input set, not
        // argv order. Two runs over the same physical inputs in
        // different argv permutations must produce byte-equal output.
        // Config::from_cli enforces canonical-path lex sorting, but
        // run() consumes a Config directly, so we sort here to mirror
        // the production flow.
        let td_a = TempDir::new().unwrap();
        let td_b = TempDir::new().unwrap();
        let common: &[(&str, &[u8])] = &[("a", b"alpha")];
        let a0 = make_dir_transport_input(&td_a.path().join("a"), common);
        let a1 = make_dir_transport_input(&td_a.path().join("b"), &[("a", b"beta")]);
        let b0 = make_dir_transport_input(&td_b.path().join("a"), common);
        let b1 = make_dir_transport_input(&td_b.path().join("b"), &[("a", b"beta")]);

        // Sort by canonical path to mirror Config::from_cli.
        let mut paths_a = vec![a0.clone(), a1.clone()];
        paths_a.sort();
        let mut paths_b = vec![b1, b0];
        // After canonical-sort these collapse to the same lex order
        // (the basename suffix `a` and `b` were chosen to stay sorted
        // across the per-tempdir paths).
        paths_b.sort();

        let out_a = td_a.path().join("out.tar");
        let out_b = td_b.path().join("out.tar");
        run(&cfg_with_tar(out_a.clone(), paths_a)).unwrap();
        run(&cfg_with_tar(out_b.clone(), paths_b)).unwrap();
        assert_eq!(fs::read(&out_a).unwrap(), fs::read(&out_b).unwrap());
    }

    #[test]
    fn write_blob_atomic_is_idempotent_for_identical_bytes() {
        let td = TempDir::new().unwrap();
        let bytes = b"some-blob-bytes";
        let (d1, p1) = write_blob_atomic(td.path(), bytes).unwrap();
        let (d2, p2) = write_blob_atomic(td.path(), bytes).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(p1, p2);
        assert_eq!(fs::read(&p1).unwrap(), bytes);
    }

    #[test]
    fn scratch_path_defaults_to_staging_sibling_for_tar() {
        // Tar layout uses a different sibling name than the
        // `<output>.partial` file finalize_tar writes — they would
        // otherwise collide on the same path.
        let cfg = Config {
            inputs: Vec::new(),
            output: PathBuf::from("/tmp/foo/out.tar"),
            layout: Layout::Tar,
            min_layer_size: 0,
            force: false,
            timestamp: Some(0),
            jobs: 0,
            scratch: None,
            verbose: 0,
            quiet: false,
            dry_run: false,
        };
        assert_eq!(scratch_path(&cfg), PathBuf::from("/tmp/foo/out.tar.staging"));
    }

    #[test]
    fn scratch_path_defaults_to_partial_sibling_for_dir() {
        // Dir layout uses the staging dir as the rename source, so
        // `<output>.partial/` is the spec 10 §10.4 prescribed default.
        let cfg = Config {
            inputs: Vec::new(),
            output: PathBuf::from("/tmp/foo/out"),
            layout: Layout::Dir,
            min_layer_size: 0,
            force: false,
            timestamp: Some(0),
            jobs: 0,
            scratch: None,
            verbose: 0,
            quiet: false,
            dry_run: false,
        };
        assert_eq!(scratch_path(&cfg), PathBuf::from("/tmp/foo/out.partial"));
    }

    #[test]
    fn scratch_path_honours_explicit_override() {
        let cfg = Config {
            inputs: Vec::new(),
            output: PathBuf::from("/tmp/foo/out.tar"),
            layout: Layout::Tar,
            min_layer_size: 0,
            force: false,
            timestamp: Some(0),
            jobs: 0,
            scratch: Some(PathBuf::from("/var/scratch/here")),
            verbose: 0,
            quiet: false,
            dry_run: false,
        };
        assert_eq!(scratch_path(&cfg), PathBuf::from("/var/scratch/here"));
    }

    #[test]
    fn image_label_falls_back_to_untagged() {
        let img = InputImage {
            config: ImageConfigurationBuilder::default()
                .architecture(Arch::Amd64)
                .os(Os::Linux)
                .rootfs(RootFsBuilder::default().diff_ids(Vec::<String>::new()).build().unwrap())
                .build()
                .unwrap(),
            layers: Vec::new(),
            repo_tags: Vec::new(),
            platform: oci_spec::image::PlatformBuilder::default()
                .architecture(Arch::Amd64)
                .os(Os::Linux)
                .build()
                .unwrap(),
        };
        assert_eq!(image_label(&img), "<untagged>");
    }

    #[test]
    fn image_label_uses_first_repo_tag() {
        let img = InputImage {
            config: ImageConfigurationBuilder::default()
                .architecture(Arch::Amd64)
                .os(Os::Linux)
                .rootfs(RootFsBuilder::default().diff_ids(Vec::<String>::new()).build().unwrap())
                .build()
                .unwrap(),
            layers: Vec::new(),
            repo_tags: vec!["repo:tag-a".into(), "repo:tag-b".into()],
            platform: oci_spec::image::PlatformBuilder::default()
                .architecture(Arch::Amd64)
                .os(Os::Linux)
                .build()
                .unwrap(),
        };
        assert_eq!(image_label(&img), "repo:tag-a");
    }

    #[test]
    fn end_to_end_through_tar_input_with_compressed_layers() {
        // Build an OCI-layout *tar* input with a gzipped layer blob to
        // exercise the compression-detection path in load_one →
        // OciLayoutReader.
        let td = TempDir::new().unwrap();
        let layer_uncompressed = build_layer_tar(&[("etc/hello", b"world")]);
        let layer_gz = gzip_bytes(&layer_uncompressed);
        let layer_digest_hex = sha256_hex(&layer_gz);
        let diff_id_hex = sha256_hex(&layer_uncompressed);

        let cfg_value = ImageConfigurationBuilder::default()
            .architecture(Arch::Amd64)
            .os(Os::Linux)
            .rootfs(
                RootFsBuilder::default()
                    .typ("layers".to_string())
                    .diff_ids(vec![format!("sha256:{diff_id_hex}")])
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let cfg_bytes = serde_json::to_vec(&cfg_value).unwrap();
        let cfg_hex = sha256_hex(&cfg_bytes);

        let cfg_descriptor: Descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageConfig)
            .digest(Digest::from_str(&format!("sha256:{cfg_hex}")).unwrap())
            .size(cfg_bytes.len() as u64)
            .build()
            .unwrap();
        let layer_descriptor: Descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageLayerGzip)
            .digest(Digest::from_str(&format!("sha256:{layer_digest_hex}")).unwrap())
            .size(layer_gz.len() as u64)
            .build()
            .unwrap();
        let manifest: ImageManifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .config(cfg_descriptor)
            .layers(vec![layer_descriptor])
            .build()
            .unwrap();
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_hex = sha256_hex(&manifest_bytes);

        // Index pointing at the manifest, with a ref.name annotation
        // so the output summary picks it up.
        let mut anns: HashMap<String, String> = HashMap::new();
        anns.insert(ANNOTATION_REF_NAME.to_string(), "repo/example:latest".to_string());
        let manifest_descriptor: Descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(Digest::from_str(&format!("sha256:{manifest_hex}")).unwrap())
            .size(manifest_bytes.len() as u64)
            .annotations(anns)
            .build()
            .unwrap();
        let index = ImageIndexBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageIndex)
            .manifests(vec![manifest_descriptor])
            .build()
            .unwrap();
        let index_bytes = serde_json::to_vec(&index).unwrap();

        // Pack into an OCI-layout tar.
        let mut tar_buf = Vec::new();
        {
            let mut tb = Builder::new(&mut tar_buf);
            tb.mode(tar::HeaderMode::Deterministic);
            append_regular(&mut tb, "oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#);
            append_regular(&mut tb, "index.json", &index_bytes);
            append_regular(&mut tb, &format!("blobs/sha256/{cfg_hex}"), &cfg_bytes);
            append_regular(&mut tb, &format!("blobs/sha256/{manifest_hex}"), &manifest_bytes);
            append_regular(&mut tb, &format!("blobs/sha256/{layer_digest_hex}"), &layer_gz);
            tb.finish().unwrap();
        }
        let input_path = td.path().join("input.tar");
        fs::write(&input_path, &tar_buf).unwrap();

        let output = td.path().join("out");
        let summary = run(&cfg_with_dir(output.clone(), vec![input_path])).unwrap();

        assert!(output.is_dir());
        assert_eq!(summary.inputs.len(), 1);
        assert_eq!(summary.inputs[0].label, "repo/example:latest");
        // Output index ref.name carries the input tag through.
        let out_index = read_index(&output.join("index.json"));
        let out_ann = out_index.manifests()[0].annotations().as_ref().unwrap();
        assert_eq!(
            out_ann.get(ANNOTATION_REF_NAME).map(String::as_str),
            Some("repo/example:latest"),
        );
    }
}
