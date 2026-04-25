//! Input format detection and parsing (spec 01).
//!
//! [`detect`] (spec 01 §1.6) inspects a filesystem path and dispatches to
//! one of the transport-specific readers. Detection is **content-driven**:
//! filename and extension are never load-bearing per spec 01 §1.0
//! ("auto-detected from the path's content, not from its extension").
//!
//! The transport-specific submodules each normalise their findings into
//! the shared `InputImage` model — those readers are not implemented yet
//! (this module only handles the dispatch step).

pub mod dir_transport;
pub mod docker_archive;
pub mod oci_layout;

use std::fs;
use std::io::Read;
use std::path::Path;

use crate::{Error, Result};

/// Identified on-disk layout of an input image reference.
///
/// Values mirror spec 01 §§1.1–1.5 one-to-one. The variants carry no
/// payload — callers already hold the path and route on the variant alone
/// to the matching transport reader (`oci_layout`, `docker_archive`,
/// `dir_transport`).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Layout {
    /// OCI image layout, directory form (spec 01 §1.1).
    OciLayoutDir,
    /// OCI image layout, packaged as a tar file (spec 01 §1.2).
    OciLayoutTar,
    /// `docker save` archive (tar form, spec 01 §1.3).
    DockerArchive,
    /// `docker save` archive extracted into a directory (spec 01 §1.4).
    DockerArchiveDir,
    /// Podman/Docker `dir` transport: flat digest-named blobs alongside
    /// `manifest.json` (spec 01 §1.5).
    DirTransport,
}

/// Inspect `path` and classify it as one of the supported input layouts.
///
/// The dispatch rules follow spec 01:
///
/// * Directories with an `oci-layout` marker → [`Layout::OciLayoutDir`]
///   (spec 01 §1.1). If a top-level `manifest.json` is also present, OCI
///   wins per the ambiguity rule in §1.6 and a `tracing::warn!` event is
///   emitted.
/// * Tar files containing an `oci-layout` entry → [`Layout::OciLayoutTar`]
///   (spec 01 §1.2). The same ambiguity rule applies.
/// * Tar files with only a top-level `manifest.json` → [`Layout::DockerArchive`]
///   (spec 01 §1.3).
/// * Directories with a top-level `manifest.json` (no `oci-layout`):
///     * JSON top-level array → [`Layout::DockerArchiveDir`] (spec 01 §1.4),
///       since a `docker save` `manifest.json` is the array form.
///     * JSON top-level object → [`Layout::DirTransport`] (spec 01 §1.5),
///       since `dir` transport carries a single OCI/Docker manifest object
///       alongside flat digest-named blobs.
///
/// Anything else is rejected with [`Error::MalformedInput`] naming the
/// markers that were searched for, per spec 01 §1.6.
///
/// # Errors
///
/// * [`Error::MalformedInput`] if no layout marker matches, if the path
///   exists but is neither a regular file nor a directory, or if a
///   candidate `manifest.json` cannot be parsed as JSON.
/// * [`Error::Io`] for read failures while inspecting the path.
pub fn detect(path: &Path) -> Result<Layout> {
    let meta = fs::metadata(path)
        .map_err(|e| Error::MalformedInput(format!("cannot stat input path {}: {e}", path.display())))?;

    if meta.is_dir() {
        detect_dir(path)
    } else if meta.is_file() {
        detect_tar_file(path)
    } else {
        Err(Error::MalformedInput(format!(
            "input is neither a regular file nor a directory: {}",
            path.display(),
        )))
    }
}

/// Classify a directory input.
///
/// Implements the dir-side of spec 01 §§1.1, 1.4, 1.5, 1.6.
fn detect_dir(path: &Path) -> Result<Layout> {
    let has_oci_layout = path.join("oci-layout").is_file();
    let has_manifest = path.join("manifest.json").is_file();

    if has_oci_layout {
        if has_manifest {
            // Spec 01 §1.6: OCI wins, but emit a warning so users can
            // catch confused exports (e.g. `docker save` output dropped
            // into an OCI layout dir).
            tracing::warn!(
                path = %path.display(),
                "ambiguous input: both `oci-layout` and `manifest.json` present in directory; treating as OCI layout per spec 01 §1.6",
            );
        }
        return Ok(Layout::OciLayoutDir);
    }

    if has_manifest {
        return classify_dir_manifest(path);
    }

    Err(Error::MalformedInput(format!(
        "no input layout markers in directory {} (looked for `oci-layout` and `manifest.json`)",
        path.display(),
    )))
}

/// Distinguish [`Layout::DockerArchiveDir`] from [`Layout::DirTransport`].
///
/// Both layouts surface as a directory carrying `manifest.json`. They are
/// disambiguated by the JSON top-level shape: `docker save` produces an
/// array of per-image manifests (spec 01 §1.3, also §1.4 for the
/// extracted form), while the `dir` transport carries a single
/// OCI- or Docker-schema manifest as an object (spec 01 §1.5).
fn classify_dir_manifest(path: &Path) -> Result<Layout> {
    let manifest_path = path.join("manifest.json");
    let bytes = fs::read(&manifest_path)
        .map_err(|e| Error::MalformedInput(format!("cannot read {}: {e}", manifest_path.display())))?;

    match json_top_level(&bytes)? {
        TopLevel::Array => Ok(Layout::DockerArchiveDir),
        TopLevel::Object => Ok(Layout::DirTransport),
    }
}

/// Classify a tar file. Spec 01 §§1.2, 1.3, 1.6.
///
/// We scan top-level entries (paths with no `/`) for the `oci-layout` and
/// `manifest.json` markers. Subdirectory entries are ignored — both shapes
/// place their markers at the archive root. As soon as both markers are
/// observed the scan exits early after warning, since OCI wins per §1.6.
fn detect_tar_file(path: &Path) -> Result<Layout> {
    let file = fs::File::open(path)
        .map_err(|e| Error::MalformedInput(format!("cannot open input tar {}: {e}", path.display())))?;
    let (has_oci_layout, has_manifest) = scan_tar_top_level(file)?;

    match (has_oci_layout, has_manifest) {
        (true, true) => {
            tracing::warn!(
                path = %path.display(),
                "ambiguous input: both `oci-layout` and `manifest.json` present in tar; treating as OCI layout per spec 01 §1.6",
            );
            Ok(Layout::OciLayoutTar)
        }
        (true, false) => Ok(Layout::OciLayoutTar),
        (false, true) => Ok(Layout::DockerArchive),
        (false, false) => Err(Error::MalformedInput(format!(
            "no input layout markers at the top level of tar {} (looked for `oci-layout` and `manifest.json`)",
            path.display(),
        ))),
    }
}

/// Scan the top-level of a tar archive for the two layout markers.
///
/// Bodies are not read — only the entry headers are inspected. The scan
/// short-circuits as soon as both markers are confirmed.
fn scan_tar_top_level<R: Read>(reader: R) -> Result<(bool, bool)> {
    let mut archive = tar::Archive::new(reader);
    let mut has_oci_layout = false;
    let mut has_manifest = false;

    for entry in archive.entries()? {
        let entry = entry?;
        let path = entry.path()?;
        // Top-level entries have exactly one path component. `manifest.json`
        // and `oci-layout` are both single-component file names.
        if path.components().count() != 1 {
            continue;
        }
        match path.as_os_str().to_str() {
            Some("oci-layout") => has_oci_layout = true,
            Some("manifest.json") => has_manifest = true,
            _ => {}
        }
        if has_oci_layout && has_manifest {
            break;
        }
    }

    Ok((has_oci_layout, has_manifest))
}

#[derive(Debug, Eq, PartialEq)]
enum TopLevel {
    Array,
    Object,
}

/// Determine whether the JSON document in `bytes` has an array or object
/// top level. Whitespace per RFC 8259 (`\t`, `\n`, `\r`, ` `) is skipped;
/// any other leading byte is rejected with a parse error.
///
/// We do not run a full JSON parse here — only the shape of the top-level
/// value matters for layout classification, and the downstream readers
/// will validate the document with `oci-spec` regardless (spec 01 §1.7a).
fn json_top_level(bytes: &[u8]) -> Result<TopLevel> {
    for &b in bytes {
        match b {
            b' ' | b'\t' | b'\n' | b'\r' => {}
            b'[' => return Ok(TopLevel::Array),
            b'{' => return Ok(TopLevel::Object),
            other => {
                return Err(Error::MalformedInput(format!(
                    "manifest.json: expected JSON array or object at top level, found byte 0x{other:02x}",
                )));
            }
        }
    }
    Err(Error::MalformedInput(
        "manifest.json: empty or whitespace-only document".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;

    use tar::{Builder, EntryType, Header};
    use tempfile::tempdir;

    use super::*;

    fn write_file(path: &Path, contents: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = fs::File::create(path).unwrap();
        f.write_all(contents).unwrap();
    }

    fn append_file(builder: &mut Builder<&mut Vec<u8>>, path: &str, body: &[u8]) {
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

    #[test]
    fn detects_oci_layout_dir() {
        let tmp = tempdir().unwrap();
        write_file(&tmp.path().join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#);
        write_file(&tmp.path().join("index.json"), b"{}");
        assert_eq!(detect(tmp.path()).unwrap(), Layout::OciLayoutDir);
    }

    #[test]
    fn detects_oci_layout_dir_when_manifest_also_present() {
        // Ambiguity: spec 01 §1.6 says OCI wins. We don't (yet) test the
        // tracing warning is emitted; the resolution itself is the
        // load-bearing behaviour.
        let tmp = tempdir().unwrap();
        write_file(&tmp.path().join("oci-layout"), b"{}");
        write_file(&tmp.path().join("manifest.json"), b"[]");
        assert_eq!(detect(tmp.path()).unwrap(), Layout::OciLayoutDir);
    }

    #[test]
    fn detects_docker_archive_dir_via_array_manifest() {
        let tmp = tempdir().unwrap();
        write_file(
            &tmp.path().join("manifest.json"),
            br#"[{"Config":"abc.json","Layers":["abc/layer.tar"]}]"#,
        );
        assert_eq!(detect(tmp.path()).unwrap(), Layout::DockerArchiveDir);
    }

    #[test]
    fn detects_dir_transport_via_object_manifest() {
        let tmp = tempdir().unwrap();
        write_file(
            &tmp.path().join("manifest.json"),
            br#"{"schemaVersion":2,"config":{"digest":"sha256:abc"},"layers":[]}"#,
        );
        assert_eq!(detect(tmp.path()).unwrap(), Layout::DirTransport);
    }

    #[test]
    fn directory_with_no_markers_is_rejected() {
        let tmp = tempdir().unwrap();
        write_file(&tmp.path().join("random.txt"), b"hello");
        let err = detect(tmp.path()).unwrap_err();
        match err {
            Error::MalformedInput(msg) => {
                assert!(msg.contains("no input layout markers"), "msg: {msg}");
                assert!(msg.contains("oci-layout"), "msg: {msg}");
                assert!(msg.contains("manifest.json"), "msg: {msg}");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn manifest_with_invalid_json_top_level_errors() {
        let tmp = tempdir().unwrap();
        // Leading non-whitespace, non-`{`/non-`[` byte.
        write_file(&tmp.path().join("manifest.json"), b"\"oops\"");
        let err = detect(tmp.path()).unwrap_err();
        match err {
            Error::MalformedInput(msg) => assert!(msg.contains("expected JSON array or object")),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn manifest_empty_file_errors() {
        let tmp = tempdir().unwrap();
        write_file(&tmp.path().join("manifest.json"), b"   \t\n");
        let err = detect(tmp.path()).unwrap_err();
        match err {
            Error::MalformedInput(msg) => assert!(msg.contains("empty or whitespace-only")),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn manifest_tolerates_leading_whitespace() {
        let tmp = tempdir().unwrap();
        write_file(&tmp.path().join("manifest.json"), b"\n\t  [ ]");
        assert_eq!(detect(tmp.path()).unwrap(), Layout::DockerArchiveDir);
    }

    fn build_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut tb = Builder::new(&mut buf);
            tb.mode(tar::HeaderMode::Deterministic);
            for (path, body) in entries {
                append_file(&mut tb, path, body);
            }
            tb.finish().unwrap();
        }
        buf
    }

    #[test]
    fn detects_oci_layout_tar() {
        let tmp = tempdir().unwrap();
        let tar_path = tmp.path().join("image.tar");
        let bytes = build_tar(&[
            ("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#),
            ("index.json", b"{}"),
            ("blobs/sha256/deadbeef", b"layer-bytes"),
        ]);
        write_file(&tar_path, &bytes);
        assert_eq!(detect(&tar_path).unwrap(), Layout::OciLayoutTar);
    }

    #[test]
    fn detects_docker_archive_tar() {
        let tmp = tempdir().unwrap();
        let tar_path = tmp.path().join("image.tar");
        let bytes = build_tar(&[
            ("manifest.json", b"[]"),
            ("abc.json", b"{}"),
            ("abc/layer.tar", b"inner-tar-bytes"),
        ]);
        write_file(&tar_path, &bytes);
        assert_eq!(detect(&tar_path).unwrap(), Layout::DockerArchive);
    }

    #[test]
    fn ambiguous_tar_resolves_to_oci_layout_tar() {
        let tmp = tempdir().unwrap();
        let tar_path = tmp.path().join("image.tar");
        let bytes = build_tar(&[
            ("manifest.json", b"[]"),
            ("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#),
            ("index.json", b"{}"),
        ]);
        write_file(&tar_path, &bytes);
        assert_eq!(detect(&tar_path).unwrap(), Layout::OciLayoutTar);
    }

    #[test]
    fn tar_without_markers_is_rejected() {
        let tmp = tempdir().unwrap();
        let tar_path = tmp.path().join("image.tar");
        let bytes = build_tar(&[("README", b"not a container image")]);
        write_file(&tar_path, &bytes);
        let err = detect(&tar_path).unwrap_err();
        assert!(matches!(err, Error::MalformedInput(_)));
    }

    #[test]
    fn tar_ignores_nested_marker_names() {
        // A `manifest.json` *inside a subdirectory* must not promote the
        // tar to a docker-archive — markers are top-level only.
        let tmp = tempdir().unwrap();
        let tar_path = tmp.path().join("image.tar");
        let bytes = build_tar(&[("nested/manifest.json", b"[]"), ("nested/oci-layout", b"{}")]);
        write_file(&tar_path, &bytes);
        let err = detect(&tar_path).unwrap_err();
        assert!(matches!(err, Error::MalformedInput(_)));
    }

    #[test]
    fn nonexistent_path_is_malformed_input() {
        let tmp = tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        let err = detect(&missing).unwrap_err();
        match err {
            Error::MalformedInput(msg) => assert!(msg.contains("cannot stat")),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn json_top_level_classifies_obvious_inputs() {
        assert_eq!(json_top_level(b"{}").unwrap(), TopLevel::Object);
        assert_eq!(json_top_level(b"[]").unwrap(), TopLevel::Array);
        assert_eq!(json_top_level(b"  \n\r\t[1,2,3]").unwrap(), TopLevel::Array);
    }
}
