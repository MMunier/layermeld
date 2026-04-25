//! OCI image layout reader (spec 01 §1.1, §1.2).
//!
//! Opens an OCI image layout in either directory (§1.1) or tar (§1.2)
//! form, parses the `oci-layout` marker and `index.json` via the
//! `oci-spec` typed models (per spec 01 §1.7a), and exposes a
//! [`OciLayoutReader::open_blob`] API that yields a fresh `Read`
//! positioned at the start of the named blob's body.
//!
//! Layer blobs are never extracted to disk: the tar form keeps the
//! original `.tar` path on hand and reopens it for each blob request,
//! seeking to the body offset recorded during the initial scan; the
//! directory form opens the per-blob file directly. Each call returns
//! an independent reader, which is what spec 02 §2.3's two-pass
//! assembly relies on.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use oci_spec::image::{Descriptor, Digest, ImageIndex, ImageManifest, OciLayout};

use crate::{Error, Result};

/// Reader for an on-disk OCI image layout.
///
/// Construct with [`OciLayoutReader::open`]; the constructor probes the
/// path to decide between the directory (§1.1) and tar (§1.2) shapes,
/// parses `oci-layout` and `index.json`, and (for the tar form) builds
/// an offset map of every blob entry so subsequent reads can seek to a
/// blob in O(1).
pub struct OciLayoutReader {
    layout_version: String,
    index: ImageIndex,
    blobs: BlobSource,
}

/// Where the blob bytes live for a given layout. Holds enough state to
/// produce a fresh body reader on each [`OciLayoutReader::open_blob`]
/// call without re-parsing the layout.
enum BlobSource {
    /// Directory layout (§1.1): blobs are at `<root>/blobs/<algo>/<hex>`.
    Dir { root: PathBuf },
    /// Tar layout (§1.2): every blob's body lives at a known offset
    /// inside `path`, recorded by digest in `offsets`.
    Tar {
        path: PathBuf,
        offsets: HashMap<DigestKey, BlobLoc>,
    },
}

/// Body location for a blob inside a tar archive.
#[derive(Debug, Clone, Copy)]
struct BlobLoc {
    /// Absolute byte offset into the tar file where the body starts
    /// (i.e. just past the entry header). Suitable for `seek`.
    offset: u64,
    /// Body length in bytes; used to bound the returned reader so it
    /// stops at end-of-body rather than running into the next header.
    size: u64,
}

/// Owned key representing a digest as `(algorithm, hex)`. Used for the
/// blob-offset map so we never depend on a particular [`Digest`]
/// borrow lasting through the lookup.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct DigestKey {
    algo: String,
    hex: String,
}

impl DigestKey {
    fn from_digest(d: &Digest) -> Self {
        Self {
            algo: d.algorithm().as_ref().to_string(),
            hex: d.digest().to_string(),
        }
    }

    /// Build a key from a tar entry path of the form `blobs/<algo>/<hex>`.
    /// Returns `None` for any other path shape.
    fn from_blob_path(rel: &str) -> Option<Self> {
        let rest = rel.strip_prefix("blobs/")?;
        let (algo, hex) = rest.split_once('/')?;
        if algo.is_empty() || hex.is_empty() || hex.contains('/') {
            return None;
        }
        Some(Self {
            algo: algo.to_string(),
            hex: hex.to_string(),
        })
    }
}

impl OciLayoutReader {
    /// Open the layout rooted at `path`.
    ///
    /// Directory and tar shapes are distinguished by `fs::metadata`;
    /// callers that already ran [`crate::input::detect`] may pass either
    /// shape's path verbatim — the reader does its own probing rather
    /// than taking a [`crate::input::Layout`] hint, so it stays usable
    /// in isolation (e.g. tests).
    ///
    /// # Errors
    ///
    /// * [`Error::MalformedInput`] if `oci-layout` or `index.json` are
    ///   missing, unparseable, or (for the tar form) the archive
    ///   contains no `oci-layout` entry.
    /// * [`Error::Io`] for read failures while scanning the input.
    pub fn open(path: &Path) -> Result<Self> {
        let meta = fs::metadata(path)
            .map_err(|e| Error::MalformedInput(format!("cannot stat OCI layout at {}: {e}", path.display())))?;
        if meta.is_dir() {
            Self::open_dir(path)
        } else if meta.is_file() {
            Self::open_tar(path)
        } else {
            Err(Error::MalformedInput(format!(
                "OCI layout path is neither a regular file nor a directory: {}",
                path.display(),
            )))
        }
    }

    fn open_dir(path: &Path) -> Result<Self> {
        let layout = OciLayout::from_file(path.join("oci-layout"))
            .map_err(|e| Error::MalformedInput(format!("cannot parse oci-layout in {}: {e}", path.display())))?;
        let index = ImageIndex::from_file(path.join("index.json"))
            .map_err(|e| Error::MalformedInput(format!("cannot parse index.json in {}: {e}", path.display())))?;
        Ok(Self {
            layout_version: layout.image_layout_version().clone(),
            index,
            blobs: BlobSource::Dir {
                root: path.to_path_buf(),
            },
        })
    }

    fn open_tar(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .map_err(|e| Error::MalformedInput(format!("cannot open OCI layout tar {}: {e}", path.display())))?;
        let mut archive = tar::Archive::new(file);
        let mut layout: Option<OciLayout> = None;
        let mut index: Option<ImageIndex> = None;
        let mut offsets = HashMap::new();

        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_path = entry.path()?.into_owned();
            let Some(rel) = entry_path.to_str() else {
                continue;
            };
            // Body offset is recorded *before* we read the body, since
            // reading advances the underlying reader's position.
            let offset = entry.raw_file_position();
            let size = entry.size();

            match rel {
                "oci-layout" => {
                    let mut buf = Vec::new();
                    entry.read_to_end(&mut buf)?;
                    layout = Some(OciLayout::from_reader(&*buf).map_err(|e| {
                        Error::MalformedInput(format!("cannot parse oci-layout in tar {}: {e}", path.display()))
                    })?);
                }
                "index.json" => {
                    let mut buf = Vec::new();
                    entry.read_to_end(&mut buf)?;
                    index = Some(ImageIndex::from_reader(&*buf).map_err(|e| {
                        Error::MalformedInput(format!("cannot parse index.json in tar {}: {e}", path.display()))
                    })?);
                }
                other => {
                    if let Some(key) = DigestKey::from_blob_path(other) {
                        offsets.insert(key, BlobLoc { offset, size });
                    }
                    // Other entries (e.g. `blobs/`/directory headers,
                    // unrelated metadata) are silently ignored — the
                    // index plus the recorded blob offsets are the only
                    // state the reader needs.
                }
            }
        }

        let layout = layout
            .ok_or_else(|| Error::MalformedInput(format!("oci-layout marker missing from tar {}", path.display())))?;
        let index =
            index.ok_or_else(|| Error::MalformedInput(format!("index.json missing from tar {}", path.display())))?;

        Ok(Self {
            layout_version: layout.image_layout_version().clone(),
            index,
            blobs: BlobSource::Tar {
                path: path.to_path_buf(),
                offsets,
            },
        })
    }

    /// Image-layout schema version from the `oci-layout` marker (§1.1).
    #[must_use]
    pub fn image_layout_version(&self) -> &str {
        &self.layout_version
    }

    /// Borrow the parsed `index.json`. Each entry in `index.manifests()`
    /// is one input image per spec 01 §1.1.
    #[must_use]
    pub fn index(&self) -> &ImageIndex {
        &self.index
    }

    /// Open a fresh reader positioned at the start of the body for the
    /// blob identified by `digest`.
    ///
    /// For the directory shape, this opens `blobs/<algo>/<hex>` directly.
    /// For the tar shape, this reopens the original tar file and seeks
    /// to the body offset recorded during the initial scan, returning a
    /// `Take` adapter so reads stop at the end of the body.
    ///
    /// The `'static` bound matches what [`crate::tar_io::compression::open`]
    /// requires for its layered decoders, so callers can forward the
    /// returned reader straight into compression handling.
    ///
    /// # Errors
    ///
    /// * [`Error::MalformedInput`] if the digest is not present in the
    ///   layout (dir form: file missing; tar form: not in the offset
    ///   map).
    /// * [`Error::Io`] for filesystem failures opening or seeking the
    ///   underlying file.
    pub fn open_blob(&self, digest: &Digest) -> Result<Box<dyn Read + Send + 'static>> {
        match &self.blobs {
            BlobSource::Dir { root } => {
                let blob_path = root
                    .join("blobs")
                    .join(digest.algorithm().as_ref())
                    .join(digest.digest());
                let file = File::open(&blob_path)
                    .map_err(|e| Error::MalformedInput(format!("cannot open blob {}: {e}", blob_path.display())))?;
                Ok(Box::new(file))
            }
            BlobSource::Tar { path, offsets } => {
                let key = DigestKey::from_digest(digest);
                let loc = offsets.get(&key).ok_or_else(|| {
                    Error::MalformedInput(format!(
                        "blob {}:{} missing from tar {}",
                        key.algo,
                        key.hex,
                        path.display(),
                    ))
                })?;
                let mut file = File::open(path).map_err(|e| {
                    Error::MalformedInput(format!("cannot reopen OCI layout tar {}: {e}", path.display()))
                })?;
                file.seek(SeekFrom::Start(loc.offset))?;
                Ok(Box::new(file.take(loc.size)))
            }
        }
    }

    /// Read a blob fully into memory. Convenience for small JSON blobs
    /// (manifest, config) — never call this for layer blobs.
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

    /// Resolve `descriptor` to an [`ImageManifest`] by reading the blob
    /// it points at and parsing it via `oci-spec`.
    ///
    /// # Errors
    ///
    /// * [`Error::MalformedInput`] if the blob is missing or its bytes
    ///   do not parse as an OCI image manifest.
    pub fn read_manifest(&self, descriptor: &Descriptor) -> Result<ImageManifest> {
        let bytes = self.read_blob_to_end(descriptor.digest())?;
        ImageManifest::from_reader(&*bytes)
            .map_err(|e| Error::MalformedInput(format!("cannot parse image manifest {}: {e}", descriptor.digest())))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::str::FromStr;

    use sha2::{Digest as _, Sha256};
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

    /// Hex-encode bytes; used to derive blob filenames and digest values
    /// in the test fixtures.
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

    /// Build a synthetic OCI layout (directory form) with one image
    /// manifest pointing to one config and one (uncompressed) layer.
    /// Returns the directory plus the digests of the manifest, config,
    /// and layer in that order.
    struct LayoutFixture {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        manifest_digest: String,
        config_digest: String,
        layer_digest: String,
        layer_body: Vec<u8>,
    }

    fn build_layout_fixture() -> LayoutFixture {
        let tmp = tempdir().unwrap();
        let root = tmp.path().to_path_buf();

        // Layer blob: just some bytes — the reader doesn't try to parse
        // it, so its tar-validity is irrelevant for these tests.
        let layer_body = b"layer-bytes-payload".to_vec();
        let layer_digest = sha256_hex(&layer_body);

        // Config blob: minimal but valid OCI image config.
        let config_body = br#"{
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": ["sha256:0000000000000000000000000000000000000000000000000000000000000000"]}
        }"#
        .to_vec();
        let config_digest = sha256_hex(&config_body);

        // Manifest blob: refers to the config + layer above by digest.
        let manifest_body = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {{
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": "sha256:{config_digest}",
                    "size": {config_size}
                }},
                "layers": [{{
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": "sha256:{layer_digest}",
                    "size": {layer_size}
                }}]
            }}"#,
            config_size = config_body.len(),
            layer_size = layer_body.len(),
        )
        .into_bytes();
        let manifest_digest = sha256_hex(&manifest_body);

        // Index references the manifest.
        let index_body = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [{{
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:{manifest_digest}",
                    "size": {manifest_size}
                }}]
            }}"#,
            manifest_size = manifest_body.len(),
        )
        .into_bytes();

        write_file(&root.join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#);
        write_file(&root.join("index.json"), &index_body);
        write_file(&root.join(format!("blobs/sha256/{manifest_digest}")), &manifest_body);
        write_file(&root.join(format!("blobs/sha256/{config_digest}")), &config_body);
        write_file(&root.join(format!("blobs/sha256/{layer_digest}")), &layer_body);

        LayoutFixture {
            _tmp: tmp,
            root,
            manifest_digest,
            config_digest,
            layer_digest,
            layer_body,
        }
    }

    /// Pack a directory-form layout into a single tar at `out`. The
    /// caller passes the directory built by [`build_layout_fixture`].
    fn pack_layout_to_tar(dir: &Path, out: &Path) {
        let f = File::create(out).unwrap();
        let mut tb = Builder::new(f);
        tb.mode(tar::HeaderMode::Deterministic);

        // Walk in a fixed order so the body offsets are reproducible.
        let mut paths = Vec::new();
        for entry in walkdir(dir) {
            paths.push(entry);
        }
        paths.sort();

        for full_path in paths {
            let rel = full_path.strip_prefix(dir).unwrap();
            if rel.as_os_str().is_empty() {
                continue;
            }
            let body = fs::read(&full_path).unwrap();
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

    /// Tiny non-recursive walker: returns every regular-file path under
    /// `dir`, depth-first. Avoids pulling `walkdir` as a dev-dep just
    /// for a couple of tests.
    fn walkdir(dir: &Path) -> Vec<PathBuf> {
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

    fn sha256_digest(hex: &str) -> Digest {
        Digest::from_str(&format!("sha256:{hex}")).unwrap()
    }

    #[test]
    fn dir_form_parses_layout_and_index() {
        let fx = build_layout_fixture();
        let reader = OciLayoutReader::open(&fx.root).unwrap();
        assert_eq!(reader.image_layout_version(), "1.0.0");
        assert_eq!(reader.index().manifests().len(), 1);
    }

    #[test]
    fn dir_form_open_blob_returns_layer_bytes() {
        let fx = build_layout_fixture();
        let reader = OciLayoutReader::open(&fx.root).unwrap();
        let mut body = Vec::new();
        reader
            .open_blob(&sha256_digest(&fx.layer_digest))
            .unwrap()
            .read_to_end(&mut body)
            .unwrap();
        assert_eq!(body, fx.layer_body);
    }

    #[test]
    fn dir_form_read_manifest_resolves_via_descriptor() {
        let fx = build_layout_fixture();
        let reader = OciLayoutReader::open(&fx.root).unwrap();
        let descriptor = &reader.index().manifests()[0];
        let manifest = reader.read_manifest(descriptor).unwrap();
        assert_eq!(manifest.layers().len(), 1);
        assert_eq!(manifest.config().digest().digest(), fx.config_digest);
        assert_eq!(manifest.layers()[0].digest().digest(), fx.layer_digest);
    }

    #[test]
    fn dir_form_missing_blob_is_malformed_input() {
        let fx = build_layout_fixture();
        let reader = OciLayoutReader::open(&fx.root).unwrap();
        let bogus = sha256_digest(&"a".repeat(64));
        // `Box<dyn Read>` is not `Debug`, so unwrap_err can't be used —
        // pattern-match the result directly instead.
        match reader.open_blob(&bogus) {
            Ok(_) => panic!("expected missing-blob error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("cannot open blob"), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn dir_form_missing_oci_layout_marker_is_error() {
        let tmp = tempdir().unwrap();
        write_file(&tmp.path().join("index.json"), b"{}");
        match OciLayoutReader::open(tmp.path()) {
            Ok(_) => panic!("expected missing-marker error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("oci-layout"), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn tar_form_parses_layout_and_resolves_manifest_and_layer() {
        let fx = build_layout_fixture();
        let tmp = tempdir().unwrap();
        let tar_path = tmp.path().join("layout.tar");
        pack_layout_to_tar(&fx.root, &tar_path);

        let reader = OciLayoutReader::open(&tar_path).unwrap();
        assert_eq!(reader.image_layout_version(), "1.0.0");

        // Manifest resolves and points at the same config + layer
        // digests as the directory form.
        let descriptor = &reader.index().manifests()[0];
        assert_eq!(descriptor.digest().digest(), fx.manifest_digest);
        let manifest = reader.read_manifest(descriptor).unwrap();
        assert_eq!(manifest.config().digest().digest(), fx.config_digest);

        // Layer body must round-trip byte-for-byte through the seek-on-
        // demand reader. Spec 02 §2.3: bodies never spool to disk.
        let mut body = Vec::new();
        reader
            .open_blob(&sha256_digest(&fx.layer_digest))
            .unwrap()
            .read_to_end(&mut body)
            .unwrap();
        assert_eq!(body, fx.layer_body);
    }

    #[test]
    fn tar_form_open_blob_is_repeatable_across_calls() {
        // Each open_blob call must produce an independent reader so
        // assembly's two-pass strategy (hash, then body-copy) stays
        // legal even when the calls interleave.
        let fx = build_layout_fixture();
        let tmp = tempdir().unwrap();
        let tar_path = tmp.path().join("layout.tar");
        pack_layout_to_tar(&fx.root, &tar_path);
        let reader = OciLayoutReader::open(&tar_path).unwrap();

        let digest = sha256_digest(&fx.layer_digest);
        let mut a = reader.open_blob(&digest).unwrap();
        let mut b = reader.open_blob(&digest).unwrap();
        let mut va = Vec::new();
        let mut vb = Vec::new();
        a.read_to_end(&mut va).unwrap();
        b.read_to_end(&mut vb).unwrap();
        assert_eq!(va, fx.layer_body);
        assert_eq!(vb, fx.layer_body);
    }

    #[test]
    fn tar_form_missing_blob_is_malformed_input() {
        let fx = build_layout_fixture();
        let tmp = tempdir().unwrap();
        let tar_path = tmp.path().join("layout.tar");
        pack_layout_to_tar(&fx.root, &tar_path);
        let reader = OciLayoutReader::open(&tar_path).unwrap();

        let bogus = sha256_digest(&"f".repeat(64));
        match reader.open_blob(&bogus) {
            Ok(_) => panic!("expected missing-blob error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("missing from tar"), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn tar_form_missing_oci_layout_marker_is_error() {
        let tmp = tempdir().unwrap();
        let tar_path = tmp.path().join("layout.tar");
        let f = File::create(&tar_path).unwrap();
        let mut tb = Builder::new(f);
        tb.mode(tar::HeaderMode::Deterministic);
        // index.json present (valid OCI shape) but oci-layout absent —
        // we want the marker check to fire, not a JSON parse failure.
        let body = br#"{"schemaVersion":2,"manifests":[]}"#;
        let mut h = Header::new_gnu();
        h.set_entry_type(EntryType::Regular);
        h.set_path("index.json").unwrap();
        h.set_mode(0o644);
        h.set_size(body.len() as u64);
        h.set_cksum();
        tb.append(&h, &body[..]).unwrap();
        tb.finish().unwrap();
        drop(tb);

        match OciLayoutReader::open(&tar_path) {
            Ok(_) => panic!("expected missing-marker error"),
            Err(Error::MalformedInput(msg)) => {
                assert!(msg.contains("oci-layout marker missing"), "msg: {msg}");
            }
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn nonexistent_path_is_malformed_input() {
        let tmp = tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        match OciLayoutReader::open(&missing) {
            Ok(_) => panic!("expected stat failure"),
            Err(Error::MalformedInput(msg)) => assert!(msg.contains("cannot stat"), "msg: {msg}"),
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn digest_key_from_blob_path_rejects_unexpected_shapes() {
        // Sanity: only `blobs/<algo>/<hex>` keys feed the offset map.
        // Three-segment, missing-segment, and non-`blobs` prefixes all
        // produce `None` so the map stays clean.
        assert!(DigestKey::from_blob_path("manifest.json").is_none());
        assert!(DigestKey::from_blob_path("blobs/sha256/").is_none());
        assert!(DigestKey::from_blob_path("blobs//abc").is_none());
        assert!(DigestKey::from_blob_path("blobs/sha256/abc/extra").is_none());
        assert_eq!(
            DigestKey::from_blob_path("blobs/sha256/abc"),
            Some(DigestKey {
                algo: "sha256".into(),
                hex: "abc".into(),
            }),
        );
    }
}
