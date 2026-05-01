//! Streaming SHA-256 digesting of tar bytes (spec 07 §7.2).
//!
//! [`HashingWriter`] is a `Write` adapter that forwards every byte to an
//! inner sink while streaming a running SHA-256 over the same bytes.
//! Spec 07 §7.2 requires the output blob's digest to be the SHA-256 of
//! the tar bytes "as they land on disk", computed in a single streaming
//! pass with no intermediate file. Wrapping the on-disk file writer in
//! this adapter is the implementation of that contract: the tar writer
//! sees an ordinary `Write`, the file sees the bytes verbatim, and the
//! digest is available the moment the tar trailer is flushed.

use std::io::{self, Write};

use sha2::{Digest, Sha256};

/// Pass-through `Write` adapter that hashes every byte forwarded to its
/// inner sink.
///
/// The hasher is updated only with bytes the inner sink reports as
/// successfully written, so a partial write does not pollute the digest
/// with bytes the file system rejected.
pub struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    bytes_written: u64,
}

impl<W: Write> HashingWriter<W> {
    /// Wrap any [`Write`] sink.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes_written: 0,
        }
    }

    /// Total bytes successfully written through this adapter so far.
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Borrow the inner sink. Useful for callers that need to call
    /// `flush()` on the underlying file once the tar writer has been
    /// dropped.
    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Consume the writer, returning the inner sink, the SHA-256 of the
    /// bytes forwarded, and the byte count.
    pub fn finalize(self) -> (W, [u8; 32], u64) {
        let digest: [u8; 32] = self.hasher.finalize().into();
        (self.inner, digest, self.bytes_written)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
            self.bytes_written += n as u64;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Lowercase hex-encode a 32-byte SHA-256 digest.
///
/// # Panics
///
/// Never panics in practice — every output byte is from the ASCII hex
/// alphabet, so the `from_utf8` round-trip is infallible. The `expect`
/// is present only to surface a corruption bug if the alphabet table
/// were ever broken.
#[must_use]
pub fn hex_encode(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = vec![0u8; 64];
    for (i, b) in digest.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    // SAFETY: every byte written is from the ASCII `HEX` table.
    String::from_utf8(out).expect("hex_encode emits ASCII")
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use sha2::{Digest, Sha256};

    use super::*;

    fn sha256_of(bytes: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }

    #[test]
    fn empty_input_produces_empty_sha256() {
        let mut buf = Vec::new();
        let hw = HashingWriter::new(&mut buf);
        let (_inner, digest, n) = hw.finalize();
        assert_eq!(n, 0);
        assert_eq!(digest, sha256_of(b""));
    }

    #[test]
    fn forwards_bytes_verbatim_to_inner() {
        let mut buf = Vec::new();
        {
            let mut hw = HashingWriter::new(&mut buf);
            hw.write_all(b"abcdef").unwrap();
        }
        assert_eq!(buf, b"abcdef");
    }

    #[test]
    fn digest_matches_concatenated_input() {
        let mut buf = Vec::new();
        let mut hw = HashingWriter::new(&mut buf);
        hw.write_all(b"hello ").unwrap();
        hw.write_all(b"world").unwrap();
        let (_inner, digest, n) = hw.finalize();
        assert_eq!(n, 11);
        assert_eq!(digest, sha256_of(b"hello world"));
    }

    #[test]
    fn bytes_written_tracks_running_total() {
        let mut buf = Vec::new();
        let mut hw = HashingWriter::new(&mut buf);
        hw.write_all(&[0u8; 100]).unwrap();
        assert_eq!(hw.bytes_written(), 100);
        hw.write_all(&[0u8; 23]).unwrap();
        assert_eq!(hw.bytes_written(), 123);
    }

    #[test]
    fn flush_propagates_to_inner() {
        // Sanity: the adapter forwards flush — important when wrapping
        // a BufWriter underneath.
        struct FlushCounter {
            flushes: u32,
            buf: Vec<u8>,
        }
        impl Write for FlushCounter {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.buf.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.flushes += 1;
                Ok(())
            }
        }
        let mut hw = HashingWriter::new(FlushCounter {
            flushes: 0,
            buf: Vec::new(),
        });
        hw.write_all(b"x").unwrap();
        hw.flush().unwrap();
        hw.flush().unwrap();
        let (inner, _, _) = hw.finalize();
        assert_eq!(inner.flushes, 2);
    }

    #[test]
    fn partial_write_only_hashes_accepted_bytes() {
        // A sink that always accepts only one byte at a time. The hasher
        // must be updated with exactly the prefix that was forwarded,
        // not the whole buffer the caller supplied.
        struct OneByte(Vec<u8>);
        impl Write for OneByte {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                if b.is_empty() {
                    return Ok(0);
                }
                self.0.push(b[0]);
                Ok(1)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut hw = HashingWriter::new(OneByte(Vec::new()));
        hw.write_all(b"abc").unwrap();
        let (inner, digest, n) = hw.finalize();
        assert_eq!(inner.0, b"abc");
        assert_eq!(n, 3);
        assert_eq!(digest, sha256_of(b"abc"));
    }

    #[test]
    fn hex_encode_known_vectors() {
        // sha256("") and sha256("abc") — well-known vectors.
        let empty = sha256_of(b"");
        assert_eq!(
            hex_encode(&empty),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let abc = sha256_of(b"abc");
        assert_eq!(
            hex_encode(&abc),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hex_encode_is_lowercase_and_64_chars() {
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        let s = hex_encode(&d);
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
