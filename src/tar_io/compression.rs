//! Compression detection and decoding for input layers (spec 01 §1.8,
//! spec 02 §02.2).
//!
//! Layer blobs may be plain tar, gzip, or zstd. Per spec 01 §1.8 the
//! manifest media type is **authoritative**; the leading magic bytes
//! are observed only as a consistency check. A disagreement aborts
//! the run rather than silently trusting either side.
//!
//! No bytes are spooled — the wrapper is a thin streaming decoder
//! layered over the caller-supplied [`Read`].

use std::io::{self, Cursor, Read};

use flate2::read::GzDecoder;
use zstd::stream::read::Decoder as ZstdDecoder;

use crate::{Error, Result};

/// Compression algorithm carried by an input layer blob.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Compression {
    /// Plain tar — no decoder layered.
    None,
    /// gzip (RFC 1952). Magic: `1f 8b`.
    Gzip,
    /// zstd (RFC 8478). Magic: `28 b5 2f fd`.
    Zstd,
}

impl Compression {
    /// Resolve a layer media type to a compression algorithm per spec 01 §1.8.
    ///
    /// Recognises the OCI v1 layer media types (including the
    /// `nondistributable.v1` variants kept for legacy interop) and the
    /// Docker `rootfs.diff` variants. Unknown media types are rejected
    /// rather than guessed at.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedInput`] if the media type is not a
    /// recognised layer type.
    pub fn from_media_type(media_type: &str) -> Result<Self> {
        // OCI uses a `+<algo>` suffix on a fixed base type. Splitting on
        // the last `+` lets us treat the algo independently from the
        // (possibly non-distributable) base.
        if let Some((base, suffix)) = media_type.rsplit_once('+')
            && is_oci_layer_base(base)
        {
            return match suffix {
                "gzip" => Ok(Compression::Gzip),
                "zstd" => Ok(Compression::Zstd),
                _ => Err(Error::MalformedInput(format!(
                    "unsupported layer compression suffix in media type: {media_type}"
                ))),
            };
        }

        match media_type {
            "application/vnd.oci.image.layer.v1.tar"
            | "application/vnd.oci.image.layer.nondistributable.v1.tar"
            | "application/vnd.docker.image.rootfs.diff.tar" => Ok(Compression::None),

            // Docker historic gzip variants. The uncompressed Docker
            // form falls into the `None` arm above; only the `.gzip`
            // suffixed types exist in the wild for compressed layers.
            "application/vnd.docker.image.rootfs.diff.tar.gzip"
            | "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip" => Ok(Compression::Gzip),

            other => Err(Error::MalformedInput(format!("unrecognised layer media type: {other}"))),
        }
    }

    /// Compression implied by the bytes at the start of a stream, or
    /// [`Compression::None`] if no known signature matches. Used only as
    /// a cross-check against the declared media type.
    fn from_magic(magic: &[u8]) -> Self {
        if magic.starts_with(&[0x1f, 0x8b]) {
            Compression::Gzip
        } else if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            Compression::Zstd
        } else {
            Compression::None
        }
    }
}

fn is_oci_layer_base(base: &str) -> bool {
    matches!(
        base,
        "application/vnd.oci.image.layer.v1.tar" | "application/vnd.oci.image.layer.nondistributable.v1.tar"
    )
}

/// Open a layer blob: peek the leading magic bytes, cross-check against
/// the declared compression (spec 01 §1.8), and return a stream that
/// yields decompressed tar bytes.
///
/// The four-byte peek is unread and chained back in front of the
/// underlying reader, so this works on non-seekable streams.
///
/// # Errors
///
/// * [`Error::MalformedInput`] if the magic bytes contradict the
///   declared compression.
/// * [`Error::Io`] for read failures during the magic-byte peek or
///   while initialising the zstd decoder.
pub fn open<R: Read + 'static>(declared: Compression, mut reader: R) -> Result<Box<dyn Read>> {
    let mut magic = [0u8; 4];
    let n = read_up_to(&mut reader, &mut magic)?;
    let observed = Compression::from_magic(&magic[..n]);

    if observed != declared {
        return Err(Error::MalformedInput(format!(
            "layer compression mismatch: media type implies {declared:?} but magic bytes look like {observed:?}"
        )));
    }

    // Splice the peeked bytes back in front of the live stream.
    let chained = Cursor::new(magic[..n].to_vec()).chain(reader);
    match declared {
        Compression::None => Ok(Box::new(chained)),
        Compression::Gzip => Ok(Box::new(GzDecoder::new(chained))),
        Compression::Zstd => Ok(Box::new(ZstdDecoder::new(chained)?)),
    }
}

/// Read up to `buf.len()` bytes; returns the number actually read.
///
/// Tolerates an early EOF (returning a short count) and retries on
/// `Interrupted`. Differs from [`Read::read_exact`] in that EOF is
/// not an error — the caller decides whether a short read is fatal.
fn read_up_to<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use flate2::Compression as GzLevel;
    use flate2::write::GzEncoder;

    use super::*;

    #[test]
    fn media_types_oci_uncompressed() {
        assert_eq!(
            Compression::from_media_type("application/vnd.oci.image.layer.v1.tar").unwrap(),
            Compression::None,
        );
        assert_eq!(
            Compression::from_media_type("application/vnd.oci.image.layer.nondistributable.v1.tar").unwrap(),
            Compression::None,
        );
    }

    #[test]
    fn media_types_oci_gzip_zstd_via_suffix() {
        assert_eq!(
            Compression::from_media_type("application/vnd.oci.image.layer.v1.tar+gzip").unwrap(),
            Compression::Gzip,
        );
        assert_eq!(
            Compression::from_media_type("application/vnd.oci.image.layer.v1.tar+zstd").unwrap(),
            Compression::Zstd,
        );
        assert_eq!(
            Compression::from_media_type("application/vnd.oci.image.layer.nondistributable.v1.tar+gzip").unwrap(),
            Compression::Gzip,
        );
    }

    #[test]
    fn media_types_docker_variants() {
        assert_eq!(
            Compression::from_media_type("application/vnd.docker.image.rootfs.diff.tar").unwrap(),
            Compression::None,
        );
        assert_eq!(
            Compression::from_media_type("application/vnd.docker.image.rootfs.diff.tar.gzip").unwrap(),
            Compression::Gzip,
        );
        assert_eq!(
            Compression::from_media_type("application/vnd.docker.image.rootfs.foreign.diff.tar.gzip").unwrap(),
            Compression::Gzip,
        );
    }

    #[test]
    fn media_type_unknown_suffix_on_oci_base_is_error() {
        let err = Compression::from_media_type("application/vnd.oci.image.layer.v1.tar+xz")
            .expect_err("xz suffix is not supported");
        match err {
            Error::MalformedInput(msg) => assert!(msg.contains("compression suffix")),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn media_type_completely_unknown_is_error() {
        let err = Compression::from_media_type("application/json").expect_err("non-layer media types are rejected");
        assert!(matches!(err, Error::MalformedInput(_)));
    }

    fn gzip(payload: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), GzLevel::default());
        enc.write_all(payload).unwrap();
        enc.finish().unwrap()
    }

    fn zstd_bytes(payload: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(Cursor::new(payload), 0).unwrap()
    }

    #[test]
    fn open_passthrough_returns_input_unchanged() {
        let payload = b"plain tar bytes, not really tar";
        let mut out = Vec::new();
        open(Compression::None, Cursor::new(payload.to_vec()))
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn open_gzip_decodes_to_original() {
        let payload = b"hello world payload that gets gzipped";
        let encoded = gzip(payload);
        let mut out = Vec::new();
        open(Compression::Gzip, Cursor::new(encoded))
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn open_zstd_decodes_to_original() {
        let payload = b"hello world payload that gets zstandardised";
        let encoded = zstd_bytes(payload);
        let mut out = Vec::new();
        open(Compression::Zstd, Cursor::new(encoded))
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, payload);
    }

    /// Helper: assert that opening with `declared` over `body` fails with
    /// a malformed-input error. `Box<dyn Read>` is not `Debug`, so we
    /// can't use the more idiomatic `expect_err` directly.
    fn assert_mismatch(declared: Compression, body: Vec<u8>) {
        match open(declared, Cursor::new(body)) {
            Ok(_) => panic!("expected magic-byte cross-check to reject {declared:?}"),
            Err(Error::MalformedInput(_)) => {}
            Err(other) => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn open_rejects_declared_gzip_with_plain_body() {
        assert_mismatch(Compression::Gzip, b"not gzipped at all".to_vec());
    }

    #[test]
    fn open_rejects_declared_none_with_gzip_body() {
        assert_mismatch(Compression::None, gzip(b"surprise"));
    }

    #[test]
    fn open_rejects_declared_zstd_with_gzip_body() {
        assert_mismatch(Compression::Zstd, gzip(b"surprise"));
    }

    #[test]
    fn open_short_stream_with_declared_none_succeeds() {
        // Two-byte stream; can't be gzip (different bytes) or zstd
        // (insufficient length). `None` declaration should succeed and
        // surface the bytes verbatim.
        let body = vec![b'h', b'i'];
        let mut out = Vec::new();
        open(Compression::None, Cursor::new(body.clone()))
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, body);
    }

    #[test]
    fn open_empty_stream_with_declared_gzip_is_mismatch() {
        assert_mismatch(Compression::Gzip, Vec::new());
    }

    #[test]
    fn from_magic_classifies_known_signatures() {
        assert_eq!(Compression::from_magic(&[0x1f, 0x8b, 0, 0]), Compression::Gzip);
        assert_eq!(Compression::from_magic(&[0x28, 0xb5, 0x2f, 0xfd]), Compression::Zstd,);
        assert_eq!(Compression::from_magic(&[0; 4]), Compression::None);
        // Truncated gzip magic — only one byte — is not a match.
        assert_eq!(Compression::from_magic(&[0x1f]), Compression::None);
    }
}
