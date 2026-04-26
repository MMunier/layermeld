//! Podman/Docker `dir` transport reader (spec 01 §1.5).
//!
//! Opens a directory produced by `podman image save --format docker-dir`
//! (or `--format oci-dir` without the `blobs/sha256/` layout prefix).
//! The directory holds a single `manifest.json` (OCI image manifest or
//! Docker schema 2 manifest schema — both are deserialised through
//! `oci-spec`'s typed [`ImageManifest`] per spec 01 §1.7a) and a flat
//! set of blob files named by the hex part of their digest, exactly as
//! `containers/image`'s `dir:` transport writes them
//! (`<root>/<hex>` — no algorithm prefix, no `blobs/sha256/`
//! subdirectory).
//!
//! The reader exposes:
//!
//! * the parsed [`ImageManifest`] (one input image per spec 01 §1.5);
//! * a [`DirTransportReader::open_blob`] API that yields a fresh `Read`
//!   positioned at the start of the named blob's body;
//! * a [`DirTransportReader::read_config`] convenience that resolves
//!   the manifest's config descriptor to a typed
//!   [`ImageConfiguration`].
//!
//! Blob bodies are read straight off disk — there is no archive to
//! seek through, so each `open_blob` call is just an `open(2)`. Repo
//! tags are *not* recovered here: the `dir` transport stores none
//! (unlike the OCI layout's `index.json` annotations or the Docker
//! archive's `RepoTags` field), so callers downstream must treat
//! dir-transport images as untagged for the purposes of spec 09 §9.2.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use oci_spec::image::{Digest, ImageConfiguration, ImageManifest};

use crate::input::model::{InputImage, LayerHandle, platform_from_config};
use crate::{Error, Result};

/// Reader for a `dir`-transport image input.
///
/// Construct with [`DirTransportReader::open`]; the constructor checks
/// the path is a directory, parses `manifest.json` via `oci-spec`, and
/// cross-checks that every digest the manifest references resolves to
/// a sibling file on disk. That eager check means downstream pipeline
/// stages can assume `open_blob` succeeds for any digest the manifest
/// names.
pub struct DirTransportReader {
    root: PathBuf,
    manifest: ImageManifest,
}

impl DirTransportReader {
    /// Open the dir-transport image rooted at `path`.
    ///
    /// # Errors
    ///
    /// * [`Error::MalformedInput`] if `path` is not a directory, if
    ///   `manifest.json` is missing or unparseable, or if any blob
    ///   the manifest references is absent from the directory.
    /// * [`Error::Io`] for filesystem failures while inspecting the
    ///   input.
    pub fn open(path: &Path) -> Result<Self> {
        let meta = fs::metadata(path).map_err(|e| {
            Error::MalformedInput(format!("cannot stat dir-transport input at {}: {e}", path.display()))
        })?;
        if !meta.is_dir() {
            return Err(Error::MalformedInput(format!(
                "dir-transport input is not a directory: {}",
                path.display(),
            )));
        }

        let manifest_path = path.join("manifest.json");
        let bytes = fs::read(&manifest_path)
            .map_err(|e| Error::MalformedInput(format!("cannot read {}: {e}", manifest_path.display())))?;
        let manifest = ImageManifest::from_reader(&*bytes).map_err(|e| {
            Error::MalformedInput(format!(
                "cannot parse {} as image manifest: {e}",
                manifest_path.display(),
            ))
        })?;

        let reader = Self {
            root: path.to_path_buf(),
            manifest,
        };
        reader.verify_blobs_present()?;
        Ok(reader)
    }

    /// Eager cross-check: every digest the manifest names must resolve
    /// to a sibling file. Mirrors the cross-check the docker-archive
    /// reader runs at open-time, so downstream callers don't have to
    /// re-validate per blob.
    fn verify_blobs_present(&self) -> Result<()> {
        let cfg_path = self.blob_path(self.manifest.config().digest());
        if !cfg_path.is_file() {
            return Err(Error::MalformedInput(format!(
                "config blob {} not present in dir-transport input {}",
                self.manifest.config().digest(),
                self.root.display(),
            )));
        }
        for layer in self.manifest.layers() {
            let p = self.blob_path(layer.digest());
            if !p.is_file() {
                return Err(Error::MalformedInput(format!(
                    "layer blob {} not present in dir-transport input {}",
                    layer.digest(),
                    self.root.display(),
                )));
            }
        }
        Ok(())
    }

    /// Resolve a digest to its on-disk path. The `dir:` transport
    /// stores blobs as `<root>/<hex>` (just the hex part, no algorithm
    /// prefix); `Digest::digest` returns exactly that hex.
    fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.root.join(digest.digest())
    }

    /// Borrow the parsed `manifest.json`. A dir-transport directory
    /// carries exactly one image (spec 01 §1.5).
    #[must_use]
    pub fn manifest(&self) -> &ImageManifest {
        &self.manifest
    }

    /// Open a fresh reader positioned at the start of the body for the
    /// blob identified by `digest`.
    ///
    /// The `'static` bound matches what
    /// [`crate::tar_io::compression::open`] requires, so callers can
    /// pipe the returned reader straight into compression handling.
    /// Each call returns an independent `File` — there is no shared
    /// stream position to coordinate, which keeps the two-pass
    /// assembly contract from spec 02 §2.3 trivially satisfied.
    ///
    /// # Errors
    ///
    /// * [`Error::MalformedInput`] if the blob file cannot be opened
    ///   (missing or unreadable).
    pub fn open_blob(&self, digest: &Digest) -> Result<Box<dyn Read + Send + 'static>> {
        let p = self.blob_path(digest);
        let f = File::open(&p).map_err(|e| Error::MalformedInput(format!("cannot open blob {}: {e}", p.display())))?;
        Ok(Box::new(f))
    }

    /// Read a blob fully into memory. Convenience for small JSON blobs
    /// (config) — never call this for layer tarballs.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::open_blob`] returns, plus [`Error::Io`] on a
    /// short read.
    pub fn read_blob_to_end(&self, digest: &Digest) -> Result<Vec<u8>> {
        let mut reader = self.open_blob(digest)?;
        let mut out = Vec::new();
        reader.read_to_end(&mut out)?;
        Ok(out)
    }

    /// Resolve the manifest's config descriptor to a typed
    /// [`ImageConfiguration`] via `oci-spec` (per spec 01 §1.7a).
    ///
    /// # Errors
    ///
    /// * [`Error::MalformedInput`] if the config blob is missing or
    ///   does not parse as an OCI image config.
    pub fn read_config(&self) -> Result<ImageConfiguration> {
        let bytes = self.read_blob_to_end(self.manifest.config().digest())?;
        ImageConfiguration::from_reader(&*bytes)
            .map_err(|e| Error::MalformedInput(format!("cannot parse image config: {e}")))
    }

    /// Normalise this directory into the shared [`InputImage`] model.
    /// Returned as a `Vec` for parity with the other transports even
    /// though spec 01 §1.5 says a `dir`-transport directory carries
    /// exactly one image.
    ///
    /// `repo_tags` is always empty: the `dir:` transport stores no
    /// tags (spec 01 §1.5). Spec 09 §9.2 then surfaces the image as
    /// untagged in the output index.
    ///
    /// # Errors
    ///
    /// * [`Error::MalformedInput`] if the config blob is missing or
    ///   unparseable, or if `rootfs.diff_ids` length does not match
    ///   the manifest's layer count.
    pub fn into_images(self) -> Result<Vec<InputImage>> {
        let config = self.read_config()?;
        let manifest = self.manifest.clone();
        let reader = Arc::new(self);

        let diff_ids = config.rootfs().diff_ids();
        let layer_descriptors = manifest.layers();
        if diff_ids.len() != layer_descriptors.len() {
            return Err(Error::MalformedInput(format!(
                "dir-transport config diff_ids ({}) do not align with manifest layers ({})",
                diff_ids.len(),
                layer_descriptors.len(),
            )));
        }

        let layers: Vec<LayerHandle> = layer_descriptors
            .iter()
            .zip(diff_ids)
            .map(|(desc, diff_id_str)| {
                let diff_id = Digest::from_str(diff_id_str).map_err(|e| {
                    Error::MalformedInput(format!("invalid diff_id `{diff_id_str}` in dir-transport config: {e}"))
                })?;
                let layer_digest = desc.digest().clone();
                let media_type = desc.media_type().to_string();
                let size = desc.size();
                let reader = reader.clone();
                let opener_digest = layer_digest.clone();
                LayerHandle::new(layer_digest, diff_id, size, media_type, move || {
                    reader.open_blob(&opener_digest)
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let platform = platform_from_config(&config);
        Ok(vec![InputImage {
            config,
            layers,
            repo_tags: Vec::new(),
            platform,
        }])
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::str::FromStr;

    use sha2::{Digest as _, Sha256};
    use tempfile::tempdir;

    use super::*;

    fn write_file(path: &Path, contents: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = File::create(path).unwrap();
        f.write_all(contents).unwrap();
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(&mut s, "{b:02x}").unwrap();
        }
        s
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        hex(&h.finalize())
    }

    fn sha256_digest(hex: &str) -> Digest {
        Digest::from_str(&format!("sha256:{hex}")).unwrap()
    }

    /// Synthetic dir-transport fixture: a single OCI image manifest
    /// pointing to one config + two layers, with each blob written as
    /// a sibling file named by its hex digest.
    struct Fixture {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        config_digest: String,
        layer1_digest: String,
        layer2_digest: String,
        layer1_body: Vec<u8>,
        layer2_body: Vec<u8>,
    }

    fn build_fixture() -> Fixture {
        let tmp = tempdir().unwrap();
        let root = tmp.path().to_path_buf();

        let layer1_body = b"layer-one-bytes".to_vec();
        let layer2_body = b"second-layer-distinct-bytes".to_vec();
        let layer1_digest = sha256_hex(&layer1_body);
        let layer2_digest = sha256_hex(&layer2_body);

        let config_body = br#"{
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": ["sha256:0000000000000000000000000000000000000000000000000000000000000000"]},
            "history": []
        }"#
        .to_vec();
        let config_digest = sha256_hex(&config_body);

        let manifest_body = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {{
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": "sha256:{config_digest}",
                    "size": {config_size}
                }},
                "layers": [
                    {{
                        "mediaType": "application/vnd.oci.image.layer.v1.tar",
                        "digest": "sha256:{layer1_digest}",
                        "size": {layer1_size}
                    }},
                    {{
                        "mediaType": "application/vnd.oci.image.layer.v1.tar",
                        "digest": "sha256:{layer2_digest}",
                        "size": {layer2_size}
                    }}
                ]
            }}"#,
            config_size = config_body.len(),
            layer1_size = layer1_body.len(),
            layer2_size = layer2_body.len(),
        )
        .into_bytes();

        // Spec 01 §1.5: blob files are flat siblings of manifest.json,
        // named by their (hex) digest — no `blobs/sha256/` prefix.
        write_file(&root.join("manifest.json"), &manifest_body);
        write_file(&root.join(&config_digest), &config_body);
        write_file(&root.join(&layer1_digest), &layer1_body);
        write_file(&root.join(&layer2_digest), &layer2_body);

        Fixture {
            _tmp: tmp,
            root,
            config_digest,
            layer1_digest,
            layer2_digest,
            layer1_body,
            layer2_body,
        }
    }

    #[test]
    fn open_parses_manifest_and_exposes_layers() {
        let fx = build_fixture();
        let reader = DirTransportReader::open(&fx.root).unwrap();
        let m = reader.manifest();
        assert_eq!(m.layers().len(), 2);
        assert_eq!(m.config().digest().digest(), fx.config_digest);
        assert_eq!(m.layers()[0].digest().digest(), fx.layer1_digest);
        assert_eq!(m.layers()[1].digest().digest(), fx.layer2_digest);
    }

    #[test]
    fn open_blob_returns_layer_bytes_for_each_layer() {
        let fx = build_fixture();
        let reader = DirTransportReader::open(&fx.root).unwrap();

        let mut a = Vec::new();
        reader
            .open_blob(&sha256_digest(&fx.layer1_digest))
            .unwrap()
            .read_to_end(&mut a)
            .unwrap();
        assert_eq!(a, fx.layer1_body);

        let mut b = Vec::new();
        reader
            .open_blob(&sha256_digest(&fx.layer2_digest))
            .unwrap()
            .read_to_end(&mut b)
            .unwrap();
        assert_eq!(b, fx.layer2_body);
    }

    #[test]
    fn open_blob_is_repeatable_across_calls() {
        // Each open_blob must produce an independent reader so the
        // two-pass assembly (spec 02 §2.3) can interleave reads.
        let fx = build_fixture();
        let reader = DirTransportReader::open(&fx.root).unwrap();
        let d = sha256_digest(&fx.layer1_digest);

        let mut r1 = reader.open_blob(&d).unwrap();
        let mut r2 = reader.open_blob(&d).unwrap();
        let mut v1 = Vec::new();
        let mut v2 = Vec::new();
        r1.read_to_end(&mut v1).unwrap();
        r2.read_to_end(&mut v2).unwrap();
        assert_eq!(v1, fx.layer1_body);
        assert_eq!(v2, fx.layer1_body);
    }

    #[test]
    fn read_config_parses_via_oci_spec() {
        let fx = build_fixture();
        let reader = DirTransportReader::open(&fx.root).unwrap();
        let cfg = reader.read_config().unwrap();
        assert_eq!(cfg.architecture().to_string(), "amd64");
        assert_eq!(cfg.os().to_string(), "linux");
    }

    #[test]
    fn missing_manifest_is_malformed_input() {
        // Empty directory — manifest.json absent.
        let tmp = tempdir().unwrap();
        match DirTransportReader::open(tmp.path()) {
            Ok(_) => panic!("expected missing-manifest error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("manifest.json"), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn unparseable_manifest_is_malformed_input() {
        let tmp = tempdir().unwrap();
        write_file(&tmp.path().join("manifest.json"), b"{not json");
        match DirTransportReader::open(tmp.path()) {
            Ok(_) => panic!("expected parse error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("image manifest"), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn missing_config_blob_is_rejected_at_open() {
        // The cross-check should fire before the caller ever calls
        // `open_blob`, so downstream stages don't have to re-validate.
        let fx = build_fixture();
        fs::remove_file(fx.root.join(&fx.config_digest)).unwrap();
        match DirTransportReader::open(&fx.root) {
            Ok(_) => panic!("expected missing-config error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("config blob"), "msg: {msg}");
                assert!(msg.contains("not present"), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn missing_layer_blob_is_rejected_at_open() {
        let fx = build_fixture();
        fs::remove_file(fx.root.join(&fx.layer2_digest)).unwrap();
        match DirTransportReader::open(&fx.root) {
            Ok(_) => panic!("expected missing-layer error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("layer blob"), "msg: {msg}");
                assert!(msg.contains(&fx.layer2_digest), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn nonexistent_path_is_malformed_input() {
        let tmp = tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        match DirTransportReader::open(&missing) {
            Ok(_) => panic!("expected stat failure"),
            Err(Error::MalformedInput(msg)) => assert!(msg.contains("cannot stat"), "msg: {msg}"),
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn file_path_is_rejected() {
        // dir-transport is directory-only by definition (spec 01 §1.5).
        let tmp = tempdir().unwrap();
        let f = tmp.path().join("not-a-dir");
        write_file(&f, b"hi");
        match DirTransportReader::open(&f) {
            Ok(_) => panic!("expected not-a-dir error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("not a directory"), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    /// Like `build_fixture` but with `diff_ids` matched 1:1 to layers,
    /// so `into_images` accepts the input.
    struct AlignedFixture {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        layer1_digest: String,
        layer2_digest: String,
        layer1_body: Vec<u8>,
        layer2_body: Vec<u8>,
    }

    fn build_aligned_fixture() -> AlignedFixture {
        let tmp = tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let layer1_body = b"layer-one-bytes".to_vec();
        let layer2_body = b"second-layer-distinct-bytes".to_vec();
        let layer1_digest = sha256_hex(&layer1_body);
        let layer2_digest = sha256_hex(&layer2_body);

        // Two diff_ids to align with the two manifest layers. The
        // values are arbitrary — `into_images` only checks alignment,
        // not that diff_id matches the layer body.
        let config_body = br#"{
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": [
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "sha256:2222222222222222222222222222222222222222222222222222222222222222"
            ]},
            "history": []
        }"#
        .to_vec();
        let config_digest = sha256_hex(&config_body);

        let manifest_body = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {{
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": "sha256:{config_digest}",
                    "size": {cs}
                }},
                "layers": [
                    {{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:{layer1_digest}","size":{l1s}}},
                    {{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:{layer2_digest}","size":{l2s}}}
                ]
            }}"#,
            cs = config_body.len(),
            l1s = layer1_body.len(),
            l2s = layer2_body.len(),
        )
        .into_bytes();

        write_file(&root.join("manifest.json"), &manifest_body);
        write_file(&root.join(&config_digest), &config_body);
        write_file(&root.join(&layer1_digest), &layer1_body);
        write_file(&root.join(&layer2_digest), &layer2_body);

        AlignedFixture {
            _tmp: tmp,
            root,
            layer1_digest,
            layer2_digest,
            layer1_body,
            layer2_body,
        }
    }

    #[test]
    fn into_images_yields_one_untagged_image() {
        let fx = build_aligned_fixture();
        let reader = DirTransportReader::open(&fx.root).unwrap();
        let images = reader.into_images().unwrap();
        assert_eq!(images.len(), 1);
        let img = &images[0];
        // Spec 01 §1.5: dir-transport carries no tags.
        assert!(img.repo_tags.is_empty());
        assert_eq!(img.layers.len(), 2);
        assert_eq!(img.layers[0].digest.digest(), fx.layer1_digest);
        assert_eq!(img.layers[1].digest.digest(), fx.layer2_digest);
        assert_eq!(img.platform.architecture().to_string(), "amd64");
        assert_eq!(img.platform.os().to_string(), "linux");
    }

    #[test]
    fn into_images_layer_open_round_trips_uncompressed_layer_bytes() {
        let fx = build_aligned_fixture();
        let reader = DirTransportReader::open(&fx.root).unwrap();
        let images = reader.into_images().unwrap();
        let layers = &images[0].layers;

        let mut a = Vec::new();
        layers[0].open().unwrap().read_to_end(&mut a).unwrap();
        assert_eq!(a, fx.layer1_body);
        let mut b = Vec::new();
        layers[1].open().unwrap().read_to_end(&mut b).unwrap();
        assert_eq!(b, fx.layer2_body);
    }

    #[test]
    fn into_images_rejects_diff_id_layer_count_mismatch() {
        // The original `build_fixture` config has only one diff_id but
        // its manifest names two layers — exactly the misalignment we
        // want surfaced.
        let fx = build_fixture();
        let reader = DirTransportReader::open(&fx.root).unwrap();
        match reader.into_images() {
            Ok(_) => panic!("expected diff_id alignment error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("diff_ids"), "msg: {msg}");
                assert!(msg.contains("manifest layers"), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }
}
