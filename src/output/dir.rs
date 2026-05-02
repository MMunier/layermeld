//! OCI-layout dir packaging (spec 09 §9.3, §9.4).
//!
//! Finalises a populated staging directory into the user-visible output
//! path: writes the `oci-layout` and `index.json` documents on top of the
//! already-populated `blobs/sha256/` tree, fsyncs the new files, then
//! `rename(2)`'s the staging directory onto the output path. Layer,
//! config, and manifest blobs are expected to be in place before this
//! function is called — [`crate::assemble::emit::emit_layers`] writes the
//! layer blobs, and the config/manifest blob writers (built on top of
//! [`canonical_json_bytes`]) cover the rest.
//!
//! ## Atomicity (spec 09 §9.4)
//!
//! The staging directory must be a same-filesystem sibling of the output
//! path so that `rename(2)` is atomic — typically `<output>.partial/`,
//! the convention spec §9.4 prescribes. A run that aborts before the
//! final rename leaves only `<output>.partial/`, which the next run will
//! refuse to overwrite unless `--force` is given (collision handling is
//! a separate task per spec §9.4 last paragraph).
//!
//! ## Determinism (spec 11 §11.6)
//!
//! `oci-layout` and `index.json` are emitted via [`canonical_json_bytes`],
//! which round-trips through [`serde_json::Value`] — `serde_json::Map`
//! is `BTreeMap`-backed by default, so every JSON object's keys land in
//! sorted order regardless of how the source struct's `HashMap` happened
//! to iterate. Two runs over identical inputs therefore produce
//! byte-identical layout files.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use oci_spec::image::ImageIndex;
use serde::Serialize;

use crate::{Error, Result};

/// Bytes of the `oci-layout` marker file (spec 09 §9.1) in canonical
/// JSON form: a single object with one key. Shared with
/// [`super::tar`] so both packagers emit byte-identical layout markers.
pub(super) const OCI_LAYOUT_BODY: &[u8] = b"{\"imageLayoutVersion\":\"1.0.0\"}";

/// Finalise a staging directory into the user-visible output path.
///
/// Writes the `oci-layout` marker and the `index.json` document into
/// `staging`, fsyncs the new files plus the staging directory itself,
/// and atomically renames `staging` onto `output`.
///
/// # Preconditions
///
/// * `staging` exists and contains a `blobs/sha256/` tree populated with
///   every blob the index references (layers, configs, manifests).
/// * `staging` and `output` are on the same filesystem — `rename(2)`
///   across mounts fails with `EXDEV`.
/// * `output` does not already exist. Collision handling (`--force`,
///   move-aside) is a separate concern per spec 09 §9.4.
///
/// # Errors
///
/// * [`Error::Io`] for any filesystem failure (`create`, `write`,
///   `sync_all`, `rename`).
/// * [`Error::Validation`] if the in-memory index fails JSON encoding —
///   in practice unreachable for values produced by
///   [`crate::oci::index::build_index`], but surfaced rather than
///   panicking.
pub fn finalize_layout(staging: &Path, index: &ImageIndex, output: &Path) -> Result<()> {
    write_file_synced(&staging.join("oci-layout"), OCI_LAYOUT_BODY)?;
    let index_bytes = canonical_json_bytes(index)?;
    write_file_synced(&staging.join("index.json"), &index_bytes)?;
    sync_dir_best_effort(staging);
    fs::rename(staging, output).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("rename {} -> {} failed: {e}", staging.display(), output.display()),
        ))
    })?;
    if let Some(parent) = output.parent() {
        sync_dir_best_effort(parent);
    }
    Ok(())
}

/// Encode `value` as canonical JSON bytes — every object's keys appear
/// in lex order (the spec 11 §11.6 / spec 09 byte-determinism contract
/// for OCI documents that carry `HashMap`-backed annotation maps).
///
/// Routing through [`serde_json::Value`] performs the canonicalisation:
/// `serde_json::Map` is `BTreeMap`-backed unless the `preserve_order`
/// feature is enabled (it is not, in this crate's `Cargo.toml`), so the
/// `Map::insert` calls in `serde_json::value::Serializer` land entries
/// sorted regardless of the source `HashMap` iteration order.
///
/// # Errors
///
/// [`Error::Validation`] if `value` fails to encode. For OCI-spec types
/// produced by the rest of this crate, encoding is total.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let v: serde_json::Value =
        serde_json::to_value(value).map_err(|e| Error::Validation(format!("json encode failed: {e}")))?;
    serde_json::to_vec(&v).map_err(|e| Error::Validation(format!("json serialise failed: {e}")))
}

fn write_file_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// `fsync` a directory entry on Unix-like systems so the contents land
/// durably before `rename(2)`. Non-fatal: rename is still atomic without
/// it; only post-crash durability weakens.
pub(super) fn sync_dir_best_effort(dir: &Path) {
    if let Ok(f) = File::open(dir) {
        let _ = f.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use oci_spec::image::{
        ANNOTATION_CREATED, ANNOTATION_REF_NAME, Arch, Descriptor, DescriptorBuilder, Digest, ImageIndexBuilder,
        MediaType, Os, PlatformBuilder,
    };

    use super::*;

    fn dummy_descriptor(digest_hex: &str, size: u64, ann: &[(&str, &str)]) -> Descriptor {
        let digest = Digest::from_str(&format!("sha256:{digest_hex}")).unwrap();
        let platform = PlatformBuilder::default()
            .architecture(Arch::Amd64)
            .os(Os::Linux)
            .build()
            .unwrap();
        let mut annotations: HashMap<String, String> = HashMap::new();
        for (k, v) in ann {
            annotations.insert((*k).to_string(), (*v).to_string());
        }
        DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(digest)
            .size(size)
            .platform(platform)
            .annotations(annotations)
            .build()
            .unwrap()
    }

    fn dummy_index() -> ImageIndex {
        ImageIndexBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageIndex)
            .manifests(vec![dummy_descriptor(
                &"ab".repeat(32),
                100,
                &[
                    (ANNOTATION_REF_NAME, "repo:tag"),
                    (ANNOTATION_CREATED, "2023-11-14T22:13:20Z"),
                ],
            )])
            .build()
            .unwrap()
    }

    fn make_staging(parent: &Path) -> std::path::PathBuf {
        let staging = parent.join("out.partial");
        fs::create_dir_all(staging.join("blobs").join("sha256")).unwrap();
        // Drop a placeholder blob so `blobs/sha256/` is non-empty —
        // the staging contract is "all referenced blobs already there".
        fs::write(staging.join("blobs").join("sha256").join("dummy"), b"x").unwrap();
        staging
    }

    #[test]
    fn writes_oci_layout_marker_with_canonical_body() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path());
        let output = tmp.path().join("out");

        finalize_layout(&staging, &dummy_index(), &output).unwrap();

        let body = fs::read(output.join("oci-layout")).unwrap();
        assert_eq!(body, OCI_LAYOUT_BODY);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["imageLayoutVersion"], "1.0.0");
    }

    #[test]
    fn writes_index_json_at_top_of_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path());
        let output = tmp.path().join("out");

        finalize_layout(&staging, &dummy_index(), &output).unwrap();

        let body = fs::read(output.join("index.json")).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["schemaVersion"], 2);
        assert_eq!(v["mediaType"], "application/vnd.oci.image.index.v1+json");
        assert_eq!(v["manifests"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn rename_moves_staging_onto_output() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path());
        let output = tmp.path().join("out");

        finalize_layout(&staging, &dummy_index(), &output).unwrap();

        assert!(!staging.exists(), "staging must be gone after rename");
        assert!(output.is_dir(), "output must exist after rename");
        assert!(output.join("oci-layout").is_file());
        assert!(output.join("index.json").is_file());
        // The blob tree must have moved verbatim.
        assert!(output.join("blobs").join("sha256").join("dummy").is_file());
    }

    #[test]
    fn rename_fails_when_output_already_exists_as_nonempty_dir() {
        // Spec 09 §9.4: collision handling is the caller's concern.
        // finalize_layout itself surfaces the OS error via Error::Io.
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path());
        let output = tmp.path().join("out");
        fs::create_dir_all(&output).unwrap();
        fs::write(output.join("squatter"), b"x").unwrap();

        let err = finalize_layout(&staging, &dummy_index(), &output).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "got: {err:?}");
        // Staging is left in place so the caller can retry / clean up.
        assert!(staging.exists());
    }

    #[test]
    fn index_json_has_sorted_object_keys() {
        // Spec 11 §11.6: the annotation HashMap on each descriptor must
        // emit in canonical (lex) order, regardless of HashMap iteration
        // order. Construct a descriptor with deliberately reverse-sorted
        // annotations and confirm the encoded bytes carry them sorted.
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path());
        let output = tmp.path().join("out");

        // Two annotations whose lex order is `created < ref.name`.
        let descriptor = dummy_descriptor(
            &"cd".repeat(32),
            42,
            &[
                (ANNOTATION_REF_NAME, "z:tag"),
                (ANNOTATION_CREATED, "2024-01-01T00:00:00Z"),
            ],
        );
        let idx = ImageIndexBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageIndex)
            .manifests(vec![descriptor])
            .build()
            .unwrap();

        finalize_layout(&staging, &idx, &output).unwrap();
        let raw = fs::read_to_string(output.join("index.json")).unwrap();
        let created_at = raw.find("org.opencontainers.image.created").unwrap();
        let ref_name_at = raw.find("org.opencontainers.image.ref.name").unwrap();
        assert!(
            created_at < ref_name_at,
            "annotations not lex-sorted in canonical output: {raw}",
        );
    }

    #[test]
    fn determinism_two_runs_produce_identical_files() {
        // Spec 11 §11.6: the layout's two top-level documents are pure
        // functions of the in-memory index value.
        let tmp_a = tempfile::tempdir().unwrap();
        let tmp_b = tempfile::tempdir().unwrap();
        let staging_a = make_staging(tmp_a.path());
        let staging_b = make_staging(tmp_b.path());
        let out_a = tmp_a.path().join("out");
        let out_b = tmp_b.path().join("out");

        finalize_layout(&staging_a, &dummy_index(), &out_a).unwrap();
        finalize_layout(&staging_b, &dummy_index(), &out_b).unwrap();

        assert_eq!(
            fs::read(out_a.join("oci-layout")).unwrap(),
            fs::read(out_b.join("oci-layout")).unwrap(),
        );
        assert_eq!(
            fs::read(out_a.join("index.json")).unwrap(),
            fs::read(out_b.join("index.json")).unwrap(),
        );
    }

    #[test]
    fn canonical_json_bytes_sorts_hashmap_keys() {
        // Direct test of the canonicalisation primitive: a HashMap with
        // non-sorted iteration must emit keys in lex order.
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert("zulu".to_string(), "z".to_string());
        m.insert("alpha".to_string(), "a".to_string());
        m.insert("mike".to_string(), "m".to_string());
        let bytes = canonical_json_bytes(&m).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        let alpha_at = s.find("alpha").unwrap();
        let mike_at = s.find("mike").unwrap();
        let zulu_at = s.find("zulu").unwrap();
        assert!(alpha_at < mike_at && mike_at < zulu_at, "got: {s}");
    }

    #[test]
    fn canonical_json_bytes_round_trips_simple_values() {
        let v = serde_json::json!({"imageLayoutVersion": "1.0.0"});
        let bytes = canonical_json_bytes(&v).unwrap();
        let back: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn finalize_layout_preserves_existing_blob_tree_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = tmp.path().join("out.partial");
        let blobs = staging.join("blobs").join("sha256");
        fs::create_dir_all(&blobs).unwrap();
        // Three "blobs" with content that includes embedded NULs and
        // non-UTF-8 bytes — confirm the rename moves them byte-for-byte.
        fs::write(blobs.join("aa"), b"\x00\x01\x02").unwrap();
        fs::write(blobs.join("bb"), b"\xff\xfe\xfd").unwrap();
        fs::write(blobs.join("cc"), b"normal").unwrap();

        let output = tmp.path().join("out");
        finalize_layout(&staging, &dummy_index(), &output).unwrap();

        let out_blobs = output.join("blobs").join("sha256");
        assert_eq!(fs::read(out_blobs.join("aa")).unwrap(), b"\x00\x01\x02");
        assert_eq!(fs::read(out_blobs.join("bb")).unwrap(), b"\xff\xfe\xfd");
        assert_eq!(fs::read(out_blobs.join("cc")).unwrap(), b"normal");
    }

    #[test]
    fn missing_staging_dir_surfaces_io_error() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = tmp.path().join("does-not-exist");
        let output = tmp.path().join("out");
        let err = finalize_layout(&staging, &dummy_index(), &output).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "got: {err:?}");
    }
}
