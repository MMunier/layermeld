//! Docker `save` archive reader (spec 01 §1.3, §1.4).
//!
//! Opens a `docker save` / `podman image save --format docker-archive`
//! output in either tar (§1.3) or extracted-directory (§1.4) form.
//! Parses the top-level `manifest.json` (the small Docker-archive
//! shape) and exposes:
//!
//! * the per-image manifest entries (one input image each, per spec
//!   01 §1.3 last sentence);
//! * a [`DockerArchiveReader::open_blob`] API that returns a fresh
//!   `Read` for any tar-relative path (the per-image config json or a
//!   `layer.tar`);
//! * a [`DockerArchiveReader::read_config`] convenience that resolves
//!   an entry's `Config` field via `oci-spec`'s typed
//!   [`ImageConfiguration`] (per spec 01 §1.7a).
//!
//! Layer tarballs are *never* re-packed (spec 01 §1.4 last sentence) —
//! the dir form opens the on-disk file directly and the tar form
//! reopens the outer archive and seeks to the layer body's offset
//! recorded during the initial scan. Each `open_blob` call returns an
//! independent reader so callers can interleave reads (the basis of
//! spec 02 §2.3's two-pass design).

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use oci_spec::image::ImageConfiguration;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// One entry in a Docker-archive `manifest.json`.
///
/// The schema is the small adapter shape called out by spec 01 §1.7a
/// — `oci-spec` does not model it directly, so we deserialise it with
/// `serde` and feed the referenced blobs (config, layers) into typed
/// `oci-spec` models on demand. Field names mirror the JSON exactly
/// (`TitleCase`, as emitted by `docker save` / `podman image save`).
#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct DockerManifest {
    /// Tar-relative path to the per-image config JSON (e.g. `abc.json`).
    /// Always present in a `docker save` archive.
    #[serde(rename = "Config")]
    pub config: String,

    /// Repository tags this image was saved under (`name:tag`). Empty
    /// for untagged images. Carried through to the output index per
    /// spec 09 §9.2.
    #[serde(rename = "RepoTags", default)]
    pub repo_tags: Vec<String>,

    /// Tar-relative paths to each layer tarball, bottom-up. Either
    /// `<id>/layer.tar` (legacy docker layout) or `<id>.tar` (newer
    /// podman layout) per spec 01 §1.3.
    #[serde(rename = "Layers", default)]
    pub layers: Vec<String>,
}

/// Reader for a Docker-archive image input.
///
/// Construct with [`DockerArchiveReader::open`]; the constructor
/// probes the path to decide between the directory (§1.4) and tar
/// (§1.3) shapes, parses `manifest.json`, and (for the tar form)
/// scans the archive once to record the body offset of every entry
/// referenced by any manifest. Subsequent [`Self::open_blob`] calls
/// reopen the file and seek directly to the body — no re-scan.
pub struct DockerArchiveReader {
    manifests: Vec<DockerManifest>,
    blobs: BlobSource,
}

/// Where the blob bytes live for a given input shape.
enum BlobSource {
    /// Extracted directory layout (§1.4): blobs are files under `root`,
    /// addressed by their tar-relative path verbatim.
    Dir { root: PathBuf },
    /// Tar layout (§1.3): every blob's body lives at a known offset
    /// inside `path`, recorded by tar-relative path in `offsets`.
    Tar {
        path: PathBuf,
        offsets: HashMap<String, BlobLoc>,
    },
}

/// Body location for an entry inside a tar archive.
#[derive(Debug, Clone, Copy)]
struct BlobLoc {
    offset: u64,
    size: u64,
}

impl DockerArchiveReader {
    /// Open the Docker archive rooted at `path`.
    ///
    /// Directory and tar shapes are distinguished by `fs::metadata`
    /// (matching the convention of [`crate::input::oci_layout`]). Both
    /// shapes are valid inputs per spec 01 §§1.3–1.4; the choice does
    /// not change the rest of the reader's surface.
    ///
    /// # Errors
    ///
    /// * [`Error::MalformedInput`] if `manifest.json` is missing,
    ///   unparseable, or (for the tar form) if a referenced blob has
    ///   no entry in the outer archive.
    /// * [`Error::Io`] for filesystem failures while inspecting the
    ///   input.
    pub fn open(path: &Path) -> Result<Self> {
        let meta = fs::metadata(path)
            .map_err(|e| Error::MalformedInput(format!("cannot stat docker archive at {}: {e}", path.display())))?;
        if meta.is_dir() {
            Self::open_dir(path)
        } else if meta.is_file() {
            Self::open_tar(path)
        } else {
            Err(Error::MalformedInput(format!(
                "docker archive path is neither a regular file nor a directory: {}",
                path.display()
            )))
        }
    }

    fn open_dir(path: &Path) -> Result<Self> {
        let manifest_path = path.join("manifest.json");
        let bytes = fs::read(&manifest_path)
            .map_err(|e| Error::MalformedInput(format!("cannot read {}: {e}", manifest_path.display())))?;
        let manifests = parse_manifest(&bytes)?;
        Ok(Self {
            manifests,
            blobs: BlobSource::Dir {
                root: path.to_path_buf(),
            },
        })
    }

    fn open_tar(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .map_err(|e| Error::MalformedInput(format!("cannot open docker archive tar {}: {e}", path.display())))?;
        let mut archive = tar::Archive::new(file);
        let mut manifest_bytes: Option<Vec<u8>> = None;
        let mut offsets: HashMap<String, BlobLoc> = HashMap::new();

        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_path = entry.path()?.into_owned();
            let Some(rel) = entry_path.to_str() else {
                continue;
            };
            // Record body offset *before* reading: reading advances the
            // underlying stream position past the body.
            let offset = entry.raw_file_position();
            let size = entry.size();

            // Directory entries (size 0, trailing-slash names) are
            // recorded too — they're harmless and the offset map is
            // keyed by exact path string anyway. Filtering them out
            // would just complicate matching without changing
            // correctness.
            offsets.insert(rel.to_string(), BlobLoc { offset, size });

            if rel == "manifest.json" {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf)?;
                manifest_bytes = Some(buf);
            }
        }

        let bytes = manifest_bytes.ok_or_else(|| {
            Error::MalformedInput(format!(
                "manifest.json missing from docker archive tar {}",
                path.display(),
            ))
        })?;
        let manifests = parse_manifest(&bytes)?;

        // Cross-check: every blob each manifest entry names must exist
        // in the outer archive. We catch this here so downstream
        // pipeline stages can assume `open_blob` succeeds for any path
        // the manifest references.
        for (idx, m) in manifests.iter().enumerate() {
            if !offsets.contains_key(&m.config) {
                return Err(Error::MalformedInput(format!(
                    "manifest entry {idx}: config {} not present in tar {}",
                    m.config,
                    path.display(),
                )));
            }
            for layer in &m.layers {
                if !offsets.contains_key(layer) {
                    return Err(Error::MalformedInput(format!(
                        "manifest entry {idx}: layer {layer} not present in tar {}",
                        path.display(),
                    )));
                }
            }
        }

        Ok(Self {
            manifests,
            blobs: BlobSource::Tar {
                path: path.to_path_buf(),
                offsets,
            },
        })
    }

    /// Borrow the parsed `manifest.json`. Each entry is one input
    /// image per spec 01 §1.3 last sentence.
    #[must_use]
    pub fn manifests(&self) -> &[DockerManifest] {
        &self.manifests
    }

    /// Open a fresh reader positioned at the start of the body for
    /// the entry named by `rel` (a tar-relative path, exactly as it
    /// appears in `manifest.json`'s `Config` or `Layers` fields).
    ///
    /// The `'static` bound matches what
    /// [`crate::tar_io::compression::open`] requires, so callers can
    /// pipe the returned reader straight into compression handling.
    ///
    /// # Errors
    ///
    /// * [`Error::MalformedInput`] if `rel` is not present in the
    ///   archive (dir form: file missing; tar form: not in the offset
    ///   map).
    /// * [`Error::Io`] for filesystem failures opening or seeking the
    ///   underlying file.
    pub fn open_blob(&self, rel: &str) -> Result<Box<dyn Read + Send + 'static>> {
        match &self.blobs {
            BlobSource::Dir { root } => {
                let blob_path = root.join(rel);
                let file = File::open(&blob_path)
                    .map_err(|e| Error::MalformedInput(format!("cannot open blob {}: {e}", blob_path.display())))?;
                Ok(Box::new(file))
            }
            BlobSource::Tar { path, offsets } => {
                let loc = offsets.get(rel).ok_or_else(|| {
                    Error::MalformedInput(format!("blob {rel} missing from docker archive tar {}", path.display()))
                })?;
                let mut file = File::open(path).map_err(|e| {
                    Error::MalformedInput(format!("cannot reopen docker archive tar {}: {e}", path.display()))
                })?;
                file.seek(SeekFrom::Start(loc.offset))?;
                Ok(Box::new(file.take(loc.size)))
            }
        }
    }

    /// Read a blob fully into memory. Convenience for small JSON
    /// blobs (config) — never call this for layer tarballs.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::open_blob`] returns, plus [`Error::Io`] on a
    /// short read.
    pub fn read_blob_to_end(&self, rel: &str) -> Result<Vec<u8>> {
        let mut reader = self.open_blob(rel)?;
        let mut out = Vec::new();
        reader.read_to_end(&mut out)?;
        Ok(out)
    }

    /// Resolve a manifest entry's `Config` blob and parse it as an
    /// OCI [`ImageConfiguration`]. Docker `save` writes its config in
    /// the OCI image-config schema, so `oci-spec` deserialises it
    /// without an adapter (per spec 01 §1.7a).
    ///
    /// # Errors
    ///
    /// * [`Error::MalformedInput`] if the config blob is missing or
    ///   does not parse as an OCI image config.
    pub fn read_config(&self, entry: &DockerManifest) -> Result<ImageConfiguration> {
        let bytes = self.read_blob_to_end(&entry.config)?;
        ImageConfiguration::from_reader(&*bytes)
            .map_err(|e| Error::MalformedInput(format!("cannot parse image config {}: {e}", entry.config)))
    }
}

/// Parse a Docker-archive `manifest.json` body. A non-empty array is
/// required (spec 01 §1.3 — at least one image per archive).
fn parse_manifest(bytes: &[u8]) -> Result<Vec<DockerManifest>> {
    let manifests: Vec<DockerManifest> = serde_json::from_slice(bytes)
        .map_err(|e| Error::MalformedInput(format!("cannot parse docker archive manifest.json: {e}")))?;
    if manifests.is_empty() {
        return Err(Error::MalformedInput(
            "docker archive manifest.json: empty manifest array".to_string(),
        ));
    }
    Ok(manifests)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tar::{Builder, EntryType, Header};
    use tempfile::tempdir;

    use super::*;

    fn write_file(path: &Path, contents: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = File::create(path).unwrap();
        f.write_all(contents).unwrap();
    }

    /// Minimal but valid OCI image config — accepted by
    /// `ImageConfiguration::from_reader`. The pipeline only cares
    /// about a few fields downstream; here we just need it to parse.
    fn sample_config_json() -> &'static [u8] {
        br#"{
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": ["sha256:0000000000000000000000000000000000000000000000000000000000000000"]},
            "history": []
        }"#
    }

    /// Two-image manifest exercising both the legacy `<id>/layer.tar`
    /// path shape and the newer `<id>.tar` shape from spec 01 §1.3.
    /// Two images so `manifests().len() == 2` is observable.
    fn sample_manifest_json() -> Vec<u8> {
        br#"[
            {
                "Config": "img1.json",
                "RepoTags": ["example.com/img:1"],
                "Layers": ["layer-a/layer.tar", "layer-b.tar"]
            },
            {
                "Config": "img2.json",
                "RepoTags": [],
                "Layers": ["layer-b.tar"]
            }
        ]"#
        .to_vec()
    }

    /// Materialise a synthetic Docker-archive directory with the two
    /// images above; returns the directory plus the layer payloads
    /// keyed by their tar-relative paths so tests can assert
    /// round-trip equality.
    struct DirFixture {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        layer_a: Vec<u8>,
        layer_b: Vec<u8>,
    }

    fn build_dir_fixture() -> DirFixture {
        let tmp = tempdir().unwrap();
        let root = tmp.path().to_path_buf();

        let layer_a = b"layer-a-tar-bytes".to_vec();
        let layer_b = b"layer-b-tar-bytes-distinct".to_vec();

        write_file(&root.join("manifest.json"), &sample_manifest_json());
        write_file(&root.join("img1.json"), sample_config_json());
        write_file(&root.join("img2.json"), sample_config_json());
        write_file(&root.join("layer-a/layer.tar"), &layer_a);
        write_file(&root.join("layer-b.tar"), &layer_b);

        DirFixture {
            _tmp: tmp,
            root,
            layer_a,
            layer_b,
        }
    }

    /// Pack the directory fixture into a single docker-archive tar.
    fn pack_dir_to_tar(dir: &Path, out: &Path) {
        let f = File::create(out).unwrap();
        let mut tb = Builder::new(f);
        tb.mode(tar::HeaderMode::Deterministic);

        // Walk in fixed order so the body offsets are reproducible.
        let mut paths: Vec<PathBuf> = walk_files(dir);
        paths.sort();
        for full in paths {
            let rel = full.strip_prefix(dir).unwrap();
            let body = fs::read(&full).unwrap();
            let mut h = Header::new_gnu();
            h.set_entry_type(EntryType::Regular);
            h.set_path(rel).unwrap();
            h.set_mode(0o644);
            h.set_uid(0);
            h.set_gid(0);
            h.set_size(body.len() as u64);
            h.set_cksum();
            tb.append(&h, &*body).unwrap();
        }
        tb.finish().unwrap();
    }

    fn walk_files(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(p) = stack.pop() {
            for entry in fs::read_dir(&p).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let ft = entry.file_type().unwrap();
                if ft.is_dir() {
                    stack.push(path);
                } else if ft.is_file() {
                    out.push(path);
                }
            }
        }
        out
    }

    #[test]
    fn dir_form_parses_manifest() {
        let fx = build_dir_fixture();
        let reader = DockerArchiveReader::open(&fx.root).unwrap();
        let m = reader.manifests();
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].config, "img1.json");
        assert_eq!(m[0].repo_tags, vec!["example.com/img:1".to_string()]);
        assert_eq!(m[0].layers, vec!["layer-a/layer.tar", "layer-b.tar"]);
        assert!(m[1].repo_tags.is_empty());
    }

    #[test]
    fn dir_form_open_blob_returns_layer_bytes_for_both_path_shapes() {
        // Spec 01 §1.3 calls out both `<id>/layer.tar` (legacy) and
        // `<id>.tar` (newer) layouts — both must round-trip.
        let fx = build_dir_fixture();
        let reader = DockerArchiveReader::open(&fx.root).unwrap();

        let mut a = Vec::new();
        reader
            .open_blob("layer-a/layer.tar")
            .unwrap()
            .read_to_end(&mut a)
            .unwrap();
        assert_eq!(a, fx.layer_a);

        let mut b = Vec::new();
        reader.open_blob("layer-b.tar").unwrap().read_to_end(&mut b).unwrap();
        assert_eq!(b, fx.layer_b);
    }

    #[test]
    fn dir_form_read_config_parses_via_oci_spec() {
        let fx = build_dir_fixture();
        let reader = DockerArchiveReader::open(&fx.root).unwrap();
        let cfg = reader.read_config(&reader.manifests()[0]).unwrap();
        assert_eq!(cfg.architecture().to_string(), "amd64");
        assert_eq!(cfg.os().to_string(), "linux");
    }

    #[test]
    fn dir_form_missing_blob_is_malformed_input() {
        let fx = build_dir_fixture();
        let reader = DockerArchiveReader::open(&fx.root).unwrap();
        match reader.open_blob("does-not-exist.tar") {
            Ok(_) => panic!("expected missing-blob error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("cannot open blob"), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn dir_form_missing_manifest_is_malformed_input() {
        let tmp = tempdir().unwrap();
        // Empty directory — manifest.json absent.
        match DockerArchiveReader::open(tmp.path()) {
            Ok(_) => panic!("expected missing-manifest error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("manifest.json"), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn dir_form_unparseable_manifest_is_malformed_input() {
        let tmp = tempdir().unwrap();
        write_file(&tmp.path().join("manifest.json"), b"{not json");
        match DockerArchiveReader::open(tmp.path()) {
            Ok(_) => panic!("expected parse error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("manifest.json"), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn empty_manifest_array_is_rejected() {
        let tmp = tempdir().unwrap();
        write_file(&tmp.path().join("manifest.json"), b"[]");
        match DockerArchiveReader::open(tmp.path()) {
            Ok(_) => panic!("expected empty-manifest error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("empty manifest array"), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn tar_form_parses_manifest_and_resolves_layers() {
        let fx = build_dir_fixture();
        let tmp = tempdir().unwrap();
        let tar_path = tmp.path().join("image.tar");
        pack_dir_to_tar(&fx.root, &tar_path);

        let reader = DockerArchiveReader::open(&tar_path).unwrap();
        assert_eq!(reader.manifests().len(), 2);

        // Layer bodies must round-trip through the seek-on-demand
        // reader (spec 01 §1.4 last sentence: layers consumed
        // directly, never re-packed).
        let mut a = Vec::new();
        reader
            .open_blob("layer-a/layer.tar")
            .unwrap()
            .read_to_end(&mut a)
            .unwrap();
        assert_eq!(a, fx.layer_a);

        let mut b = Vec::new();
        reader.open_blob("layer-b.tar").unwrap().read_to_end(&mut b).unwrap();
        assert_eq!(b, fx.layer_b);
    }

    #[test]
    fn tar_form_open_blob_is_repeatable_across_calls() {
        // Each open_blob must produce an independent reader so the
        // squash + assemble passes can interleave reads (spec 02 §2.3).
        let fx = build_dir_fixture();
        let tmp = tempdir().unwrap();
        let tar_path = tmp.path().join("image.tar");
        pack_dir_to_tar(&fx.root, &tar_path);
        let reader = DockerArchiveReader::open(&tar_path).unwrap();

        let mut a1 = reader.open_blob("layer-a/layer.tar").unwrap();
        let mut a2 = reader.open_blob("layer-a/layer.tar").unwrap();
        let mut va1 = Vec::new();
        let mut va2 = Vec::new();
        a1.read_to_end(&mut va1).unwrap();
        a2.read_to_end(&mut va2).unwrap();
        assert_eq!(va1, fx.layer_a);
        assert_eq!(va2, fx.layer_a);
    }

    #[test]
    fn tar_form_read_config_parses_via_oci_spec() {
        let fx = build_dir_fixture();
        let tmp = tempdir().unwrap();
        let tar_path = tmp.path().join("image.tar");
        pack_dir_to_tar(&fx.root, &tar_path);
        let reader = DockerArchiveReader::open(&tar_path).unwrap();

        let cfg = reader.read_config(&reader.manifests()[1]).unwrap();
        assert_eq!(cfg.architecture().to_string(), "amd64");
    }

    #[test]
    fn tar_form_missing_manifest_is_malformed_input() {
        let tmp = tempdir().unwrap();
        let tar_path = tmp.path().join("image.tar");
        let f = File::create(&tar_path).unwrap();
        let mut tb = Builder::new(f);
        tb.mode(tar::HeaderMode::Deterministic);
        // Has a layer, but no manifest.json — the marker check should
        // fire before any body parsing.
        let body = b"placeholder";
        let mut h = Header::new_gnu();
        h.set_entry_type(EntryType::Regular);
        h.set_path("layer.tar").unwrap();
        h.set_mode(0o644);
        h.set_size(body.len() as u64);
        h.set_cksum();
        tb.append(&h, &body[..]).unwrap();
        tb.finish().unwrap();
        drop(tb);

        match DockerArchiveReader::open(&tar_path) {
            Ok(_) => panic!("expected missing-manifest error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("manifest.json missing"), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn tar_form_manifest_referencing_missing_layer_is_rejected_at_open() {
        // The cross-check in `open_tar` exists so downstream callers
        // don't have to re-validate per blob; surface the failure
        // eagerly with a clear message.
        let tmp = tempdir().unwrap();
        let tar_path = tmp.path().join("image.tar");
        let f = File::create(&tar_path).unwrap();
        let mut tb = Builder::new(f);
        tb.mode(tar::HeaderMode::Deterministic);

        let manifest = br#"[{"Config":"cfg.json","RepoTags":[],"Layers":["missing/layer.tar"]}]"#;
        let cfg = sample_config_json();
        for (name, body) in [("manifest.json", &manifest[..]), ("cfg.json", cfg)] {
            let mut h = Header::new_gnu();
            h.set_entry_type(EntryType::Regular);
            h.set_path(name).unwrap();
            h.set_mode(0o644);
            h.set_size(body.len() as u64);
            h.set_cksum();
            tb.append(&h, body).unwrap();
        }
        tb.finish().unwrap();
        drop(tb);

        match DockerArchiveReader::open(&tar_path) {
            Ok(_) => panic!("expected missing-layer error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("missing/layer.tar"), "msg: {msg}");
                assert!(msg.contains("not present in tar"), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn tar_form_missing_blob_is_malformed_input() {
        let fx = build_dir_fixture();
        let tmp = tempdir().unwrap();
        let tar_path = tmp.path().join("image.tar");
        pack_dir_to_tar(&fx.root, &tar_path);
        let reader = DockerArchiveReader::open(&tar_path).unwrap();

        match reader.open_blob("phantom.tar") {
            Ok(_) => panic!("expected missing-blob error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("missing from docker archive tar"), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn nonexistent_path_is_malformed_input() {
        let tmp = tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        match DockerArchiveReader::open(&missing) {
            Ok(_) => panic!("expected stat failure"),
            Err(Error::MalformedInput(msg)) => assert!(msg.contains("cannot stat"), "msg: {msg}"),
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }
}
