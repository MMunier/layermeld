//! Shared input model (spec 01).
//!
//! All transport-specific readers in [`crate::input`] normalise their
//! findings into the same [`InputImage`] / [`LayerHandle`] pair so the
//! rest of the pipeline (squash, dedup, assemble) can treat OCI layouts,
//! Docker archives, and `dir`-transport directories interchangeably.
//!
//! Layer bodies are exposed only as fresh streaming readers — no body
//! ever lives in memory or on disk between passes, in line with spec
//! 02 §2.1. [`LayerHandle`] holds an opener closure rather than an open
//! file, so the spec 02 §2.3 two-pass discipline (open, walk, drop;
//! reopen, body-copy) can run twice without coordinating shared state.
//!
//! The opener is wrapped in an [`Arc`] so a [`LayerHandle`] is `Send`
//! and `Clone`, which is what the rayon-driven assembly stage (spec 07
//! §7.4) will need to dispatch one assembler per output layer.

use std::io::Read;
use std::sync::Arc;

use oci_spec::image::{Digest, ImageConfiguration, Platform, PlatformBuilder};

use crate::Result;
use crate::tar_io::compression::{self, Compression};

/// One input image as the rest of the pipeline consumes it.
///
/// Every [`crate::input`] reader normalises into this shape so squash,
/// dedup, and assemble never branch on the source transport.
///
/// `repo_tags` is empty for transports that don't carry tags (notably
/// [`crate::input::DirTransportReader`] per spec 01 §1.5); spec 09 §9.2
/// then surfaces those images as untagged in the output index.
pub struct InputImage {
    /// Parsed image configuration (`oci-spec` typed model per spec 01 §1.7a).
    /// Carried verbatim into the output via spec 08 §8.1 except for the
    /// fields the rewrite pass replaces (`created`, `rootfs.diff_ids`,
    /// `history`).
    pub config: ImageConfiguration,
    /// Layers in **bottom-up** order, matching the on-disk manifest's
    /// `layers[]` and the config's `rootfs.diff_ids[]`. Spec 03 §3.2's
    /// squash walks them in this order.
    pub layers: Vec<LayerHandle>,
    /// Repo tags (e.g. `example.com/img:1`) carried over to the output
    /// index. OCI layouts surface them via the manifest descriptor's
    /// `org.opencontainers.image.ref.name` annotation; Docker archives
    /// pull them from `manifest.json`'s `RepoTags`. Empty for untagged
    /// inputs.
    pub repo_tags: Vec<String>,
    /// Platform (architecture + os, plus optional variant / os.version)
    /// derived from the image config. The pipeline uses this for the
    /// per-image output-index entry (spec 09 §9.2) and the platform
    /// consistency warning (spec 08 §8.3).
    pub platform: Platform,
}

/// Handle to one layer blob, capable of producing positioned tar
/// streams on demand (spec 02 §2.3).
///
/// The handle does **not** own an open file — instead it holds a
/// closure that opens a fresh reader each time, so the squash and
/// assemble passes can each obtain an independent stream without
/// coordinating seek state. Cloning a handle is cheap (the closure
/// lives behind an [`Arc`]), so the same layer can be dispatched to
/// multiple rayon tasks if needed.
#[derive(Clone)]
pub struct LayerHandle {
    /// Manifest descriptor digest (the *compressed* digest of the
    /// blob bytes on disk). Used for input-digest verification per
    /// spec 07 §7.6.
    pub digest: Digest,
    /// `diff_id` from the image config — the digest of the
    /// **uncompressed** tar bytes. Spec 08 §8.1 carries this verbatim
    /// into the output config when the layer is reused as-is.
    pub diff_id: Digest,
    /// On-disk (compressed) size in bytes, from the manifest descriptor.
    pub size: u64,
    /// Raw layer media type. Kept alongside [`Self::compression`] for
    /// diagnostics (the magic-byte cross-check in
    /// [`crate::tar_io::compression::open`] reports the declared type
    /// in error messages).
    pub media_type: String,
    /// Compression algorithm derived from `media_type` per spec 01 §1.8.
    /// Cached so callers don't re-parse the media type on every
    /// [`Self::open`].
    pub compression: Compression,
    /// Opener closure: returns a fresh raw (still compressed, if
    /// applicable) blob reader each call. Behind an `Arc` so the handle
    /// stays `Clone + Send + Sync`.
    opener: Arc<dyn Fn() -> Result<Box<dyn Read + Send + 'static>> + Send + Sync>,
}

impl LayerHandle {
    /// Construct a handle from the manifest + config metadata and a
    /// raw-blob opener. Used by each transport reader's
    /// `into_images` implementation; tests in this module also use it
    /// directly with an in-memory opener.
    ///
    /// # Errors
    ///
    /// * [`crate::Error::MalformedInput`] if `media_type` does not
    ///   resolve to a recognised layer compression
    ///   (see [`Compression::from_media_type`]).
    pub fn new<F>(digest: Digest, diff_id: Digest, size: u64, media_type: String, opener: F) -> Result<Self>
    where
        F: Fn() -> Result<Box<dyn Read + Send + 'static>> + Send + Sync + 'static,
    {
        let compression = Compression::from_media_type(&media_type)?;
        Ok(Self {
            digest,
            diff_id,
            size,
            media_type,
            compression,
            opener: Arc::new(opener),
        })
    }

    /// Open a fresh **decompressed** tar stream for this layer.
    ///
    /// Each call returns an independent reader — the underlying
    /// transport reader produced an independent raw stream (a fresh
    /// `File` for dir/dir-transport inputs, a reopened-and-seeked
    /// `File` for tar inputs), and the compression decoder is
    /// instantiated per call.
    ///
    /// # Errors
    ///
    /// Whatever the underlying opener and compression layer return:
    /// [`crate::Error::MalformedInput`] for missing blobs or magic-byte
    /// mismatches; [`crate::Error::Io`] for filesystem failures or
    /// decoder initialisation errors.
    pub fn open(&self) -> Result<Box<dyn Read>> {
        let raw = (self.opener)()?;
        compression::open(self.compression, raw)
    }

    /// Open a fresh **raw** (still compressed, if applicable) blob
    /// reader. The squash pass uses this when it computes the
    /// compressed-digest for input verification (spec 07 §7.6).
    ///
    /// # Errors
    ///
    /// Whatever the underlying opener returns.
    pub fn open_compressed(&self) -> Result<Box<dyn Read + Send + 'static>> {
        (self.opener)()
    }
}

impl std::fmt::Debug for LayerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The opener closure isn't `Debug`; the rest of the surface is
        // what diagnostic logs care about (digest + diff_id + size).
        f.debug_struct("LayerHandle")
            .field("digest", &format_args!("{}", self.digest))
            .field("diff_id", &format_args!("{}", self.diff_id))
            .field("size", &self.size)
            .field("media_type", &self.media_type)
            .field("compression", &self.compression)
            .finish_non_exhaustive()
    }
}

/// Build a [`Platform`] from the image config's platform fields per
/// spec 08 §8.1. The required pair (`architecture`, `os`) is mandatory
/// in the image config; the optional `variant` and `os.version` are
/// surfaced when present so the output index entry is faithful.
///
/// # Panics
///
/// Panics if `oci-spec` introduces new required `Platform` fields in a
/// future release — this would be a build-time dependency mismatch
/// rather than runtime user input, so it is reported as a panic.
#[must_use]
pub fn platform_from_config(cfg: &ImageConfiguration) -> Platform {
    let mut builder = PlatformBuilder::default()
        .architecture(cfg.architecture().clone())
        .os(cfg.os().clone());
    if let Some(variant) = cfg.variant() {
        builder = builder.variant(variant.clone());
    }
    if let Some(version) = cfg.os_version() {
        builder = builder.os_version(version.clone());
    }
    // Both required fields are always populated above, so the build
    // can only fail if `oci-spec` adds new required fields in a future
    // release — surface that as a panic rather than a runtime error,
    // since it would be a build-time dependency mismatch, not user input.
    builder
        .build()
        .expect("Platform requires only architecture+os, both supplied")
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::str::FromStr;

    use oci_spec::image::{Arch, ImageConfigurationBuilder, Os, RootFsBuilder};

    use super::*;
    use crate::Error;

    fn sha256_digest(hex: &str) -> Digest {
        Digest::from_str(&format!("sha256:{hex}")).unwrap()
    }

    fn config_with(arch: Arch, os: Os, variant: Option<&str>, os_version: Option<&str>) -> ImageConfiguration {
        let mut b = ImageConfigurationBuilder::default()
            .architecture(arch)
            .os(os)
            .rootfs(RootFsBuilder::default().diff_ids(Vec::<String>::new()).build().unwrap());
        if let Some(v) = variant {
            b = b.variant(v.to_string());
        }
        if let Some(v) = os_version {
            b = b.os_version(v.to_string());
        }
        b.build().unwrap()
    }

    #[test]
    fn platform_from_config_carries_required_and_optional_fields() {
        let cfg = config_with(Arch::Amd64, Os::Linux, Some("v2"), Some("10.0.14393.1066"));
        let p = platform_from_config(&cfg);
        assert_eq!(p.architecture(), &Arch::Amd64);
        assert_eq!(p.os(), &Os::Linux);
        assert_eq!(p.variant().as_deref(), Some("v2"));
        assert_eq!(p.os_version().as_deref(), Some("10.0.14393.1066"));
    }

    #[test]
    fn platform_from_config_drops_unset_optional_fields() {
        let cfg = config_with(Arch::ARM64, Os::Linux, None, None);
        let p = platform_from_config(&cfg);
        assert_eq!(p.architecture(), &Arch::ARM64);
        assert_eq!(p.os(), &Os::Linux);
        assert!(p.variant().is_none());
        assert!(p.os_version().is_none());
    }

    #[test]
    fn layer_handle_open_decompresses_per_media_type() {
        // Plain (uncompressed) tar passes through; the opener returns
        // some bytes and `open()` should yield them verbatim.
        let body = b"plain-tar-payload".to_vec();
        let body_clone = body.clone();
        let handle = LayerHandle::new(
            sha256_digest(&"a".repeat(64)),
            sha256_digest(&"b".repeat(64)),
            body.len() as u64,
            "application/vnd.oci.image.layer.v1.tar".into(),
            move || Ok(Box::new(Cursor::new(body_clone.clone())) as Box<dyn Read + Send + 'static>),
        )
        .unwrap();

        let mut out = Vec::new();
        handle.open().unwrap().read_to_end(&mut out).unwrap();
        assert_eq!(out, body);
        assert_eq!(handle.compression, Compression::None);
    }

    #[test]
    fn layer_handle_open_is_repeatable() {
        // Each open() call must produce an independent reader so the
        // squash and assemble passes can interleave (spec 02 §2.3).
        let body = b"twice-readable".to_vec();
        let body_clone = body.clone();
        let handle = LayerHandle::new(
            sha256_digest(&"c".repeat(64)),
            sha256_digest(&"d".repeat(64)),
            body.len() as u64,
            "application/vnd.oci.image.layer.v1.tar".into(),
            move || Ok(Box::new(Cursor::new(body_clone.clone())) as Box<dyn Read + Send + 'static>),
        )
        .unwrap();

        let mut a = Vec::new();
        let mut b = Vec::new();
        handle.open().unwrap().read_to_end(&mut a).unwrap();
        handle.open().unwrap().read_to_end(&mut b).unwrap();
        assert_eq!(a, body);
        assert_eq!(b, body);
    }

    #[test]
    fn layer_handle_open_compressed_returns_raw_bytes() {
        // For input-digest verification the squash pass needs the raw
        // (still-compressed-if-applicable) bytes — `open_compressed`
        // bypasses the decoder.
        use flate2::Compression as GzLevel;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut enc = GzEncoder::new(Vec::new(), GzLevel::default());
        enc.write_all(b"payload-payload-payload").unwrap();
        let gzipped = enc.finish().unwrap();
        let gzipped_clone = gzipped.clone();

        let handle = LayerHandle::new(
            sha256_digest(&"e".repeat(64)),
            sha256_digest(&"f".repeat(64)),
            gzipped.len() as u64,
            "application/vnd.oci.image.layer.v1.tar+gzip".into(),
            move || Ok(Box::new(Cursor::new(gzipped_clone.clone())) as Box<dyn Read + Send + 'static>),
        )
        .unwrap();

        let mut raw = Vec::new();
        handle.open_compressed().unwrap().read_to_end(&mut raw).unwrap();
        assert_eq!(raw, gzipped);
        // And the decompressed form round-trips.
        let mut decoded = Vec::new();
        handle.open().unwrap().read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, b"payload-payload-payload");
        assert_eq!(handle.compression, Compression::Gzip);
    }

    #[test]
    fn layer_handle_rejects_unrecognised_media_type() {
        let err = LayerHandle::new(
            sha256_digest(&"a".repeat(64)),
            sha256_digest(&"b".repeat(64)),
            0,
            "application/json".into(),
            || Ok(Box::new(Cursor::new(Vec::new())) as Box<dyn Read + Send + 'static>),
        )
        .unwrap_err();
        match err {
            Error::MalformedInput(msg) => assert!(msg.contains("unrecognised layer media type"), "msg: {msg}"),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn layer_handle_clone_shares_opener_state() {
        // Cloning must share the underlying Arc-wrapped opener so the
        // pipeline can hand out the same layer to multiple rayon tasks
        // without re-parsing the manifest.
        let body = b"shared-bytes".to_vec();
        let body_clone = body.clone();
        let handle = LayerHandle::new(
            sha256_digest(&"a".repeat(64)),
            sha256_digest(&"b".repeat(64)),
            body.len() as u64,
            "application/vnd.oci.image.layer.v1.tar".into(),
            move || Ok(Box::new(Cursor::new(body_clone.clone())) as Box<dyn Read + Send + 'static>),
        )
        .unwrap();

        let cloned = handle.clone();
        let mut from_orig = Vec::new();
        let mut from_clone = Vec::new();
        handle.open().unwrap().read_to_end(&mut from_orig).unwrap();
        cloned.open().unwrap().read_to_end(&mut from_clone).unwrap();
        assert_eq!(from_orig, body);
        assert_eq!(from_clone, body);
    }

    #[test]
    fn layer_handle_propagates_opener_failure() {
        let handle = LayerHandle::new(
            sha256_digest(&"a".repeat(64)),
            sha256_digest(&"b".repeat(64)),
            0,
            "application/vnd.oci.image.layer.v1.tar".into(),
            || Err(Error::MalformedInput("blob missing".into())),
        )
        .unwrap();
        match handle.open() {
            Ok(_) => panic!("expected opener failure"),
            Err(Error::MalformedInput(msg)) => assert_eq!(msg, "blob missing"),
            Err(other) => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn layer_handle_debug_redacts_opener() {
        // Sanity: Debug never tries to print the closure (which doesn't
        // implement Debug). Just confirm the format is callable and
        // contains the salient fields.
        let handle = LayerHandle::new(
            sha256_digest(&"a".repeat(64)),
            sha256_digest(&"b".repeat(64)),
            42,
            "application/vnd.oci.image.layer.v1.tar".into(),
            || Ok(Box::new(Cursor::new(Vec::new())) as Box<dyn Read + Send + 'static>),
        )
        .unwrap();
        let s = format!("{handle:?}");
        assert!(s.contains("LayerHandle"));
        assert!(s.contains("size: 42"));
        assert!(s.contains("compression"));
    }
}
