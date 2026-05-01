//! Input layer digest verification (spec 07 §7.6).
//!
//! Before any output blob is finalized, the tool re-reads every input
//! layer's raw (still-compressed-if-applicable) bytes and confirms they
//! hash to the digest declared in the source manifest descriptor. A
//! mismatch surfaces as [`Error::DigestMismatch`] (exit code 4 per
//! spec 10 §10.7) so the run aborts before the assembler can write a
//! blob derived from corrupted input.
//!
//! Verification is parallelised with the same `--jobs` bound the
//! assembler uses (spec 07 §7.5). Each task streams its layer through a
//! private hasher; readers are never shared across threads, mirroring
//! [`emit_layers`](super::emit::emit_layers).

use std::io::{self, Read};

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sha2::{Digest as ShaDigest, Sha256};

use crate::input::model::LayerHandle;
use crate::{Error, Result};

use super::digest::hex_encode;

/// Verify that every input layer's raw bytes hash to the digest declared
/// in its manifest descriptor.
///
/// `images_layers` is the same per-image layer slice the assembler
/// consumes (indexed by [`InputImageId::0`](crate::squash::index::InputImageId)).
///
/// `jobs` follows the spec 10 `--jobs` convention: `0` requests rayon's
/// default (logical CPU count), other values are forwarded verbatim.
///
/// # Errors
///
/// * [`Error::DigestMismatch`] (exit code 4) on the first layer whose
///   observed digest disagrees with the declared one. The error reports
///   both digests in `algorithm:hex` form so the user can correlate
///   against the manifest.
/// * [`Error::MalformedInput`] if a layer declares an algorithm other
///   than `sha256` — the rest of the pipeline writes only `sha256`
///   blobs (spec 07 §7.2 / spec 09's `blobs/sha256/` layout), so a
///   mixed-algorithm input would surface elsewhere as a confusing
///   downstream failure if waved through here.
/// * [`Error::Io`] on any read failure or thread-pool construction
///   error.
pub fn verify_input_digests(images_layers: &[Vec<LayerHandle>], jobs: usize) -> Result<()> {
    let handles: Vec<&LayerHandle> = images_layers.iter().flat_map(|img| img.iter()).collect();
    if handles.is_empty() {
        return Ok(());
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build()
        .map_err(|e| Error::Io(io::Error::other(format!("rayon thread pool build failed: {e}"))))?;
    pool.install(|| handles.par_iter().try_for_each(|h| verify_one(h)))
}

/// Stream one layer's raw bytes through a SHA-256 hasher and compare to
/// the declared descriptor digest.
fn verify_one(handle: &LayerHandle) -> Result<()> {
    let algo = handle.digest.algorithm().as_ref().to_string();
    if algo != "sha256" {
        return Err(Error::MalformedInput(format!(
            "unsupported layer digest algorithm {algo:?}: only sha256 is supported"
        )));
    }
    let mut reader = handle.open_compressed()?;
    let observed = sha256_stream(&mut reader)?;
    let observed_hex = hex_encode(&observed);
    let expected_hex = handle.digest.digest();
    if observed_hex != expected_hex {
        return Err(Error::DigestMismatch {
            expected: format!("sha256:{expected_hex}"),
            observed: format!("sha256:{observed_hex}"),
        });
    }
    Ok(())
}

/// Hash a [`Read`] stream end-to-end with SHA-256, in fixed-size chunks
/// so memory usage is constant regardless of layer size.
fn sha256_stream(r: &mut dyn Read) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024].into_boxed_slice();
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use oci_spec::image::Digest;
    use sha2::{Digest as ShaDigest, Sha256};

    use super::*;

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        hex_encode(&h.finalize().into())
    }

    fn make_handle_with_digest(bytes: Vec<u8>, declared_hex: &str) -> LayerHandle {
        let arc = Arc::new(bytes);
        let arc_for_open = arc.clone();
        LayerHandle::new(
            Digest::from_str(&format!("sha256:{declared_hex}")).unwrap(),
            Digest::from_str(&format!("sha256:{}", "b".repeat(64))).unwrap(),
            arc.len() as u64,
            "application/vnd.oci.image.layer.v1.tar".into(),
            move || {
                let cursor = Cursor::new((*arc_for_open).clone());
                Ok(Box::new(cursor) as Box<dyn Read + Send + 'static>)
            },
        )
        .unwrap()
    }

    fn make_handle(bytes: Vec<u8>) -> LayerHandle {
        let hex = sha256_hex(&bytes);
        make_handle_with_digest(bytes, &hex)
    }

    #[test]
    fn empty_input_is_ok() {
        verify_input_digests(&[], 1).unwrap();
        verify_input_digests(&[vec![], vec![]], 1).unwrap();
    }

    #[test]
    fn matching_digests_pass() {
        let h1 = make_handle(b"alpha-bytes".to_vec());
        let h2 = make_handle(b"bravo-bytes".to_vec());
        verify_input_digests(&[vec![h1, h2]], 1).unwrap();
    }

    #[test]
    fn matching_digests_pass_across_images() {
        let h1 = make_handle(b"image-zero-layer".to_vec());
        let h2 = make_handle(b"image-one-layer-a".to_vec());
        let h3 = make_handle(b"image-one-layer-b".to_vec());
        verify_input_digests(&[vec![h1], vec![h2, h3]], 2).unwrap();
    }

    #[test]
    fn mismatch_returns_digest_mismatch() {
        // Declare a wrong digest; the bytes hash to something else.
        let bogus = "0".repeat(64);
        let h = make_handle_with_digest(b"alpha-bytes".to_vec(), &bogus);
        let err = verify_input_digests(&[vec![h]], 1).unwrap_err();
        match err {
            Error::DigestMismatch { expected, observed } => {
                assert_eq!(expected, format!("sha256:{bogus}"));
                assert!(observed.starts_with("sha256:"));
                assert_ne!(observed, expected);
            }
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }

    #[test]
    fn mismatch_exit_code_is_four() {
        let bogus = "f".repeat(64);
        let h = make_handle_with_digest(b"x".to_vec(), &bogus);
        let err = verify_input_digests(&[vec![h]], 1).unwrap_err();
        assert_eq!(err.exit_code(), 4);
    }

    #[test]
    fn first_layer_in_set_can_be_bad() {
        // Even if later layers match, a single bad one trips the check.
        let bogus = "1".repeat(64);
        let bad = make_handle_with_digest(b"first".to_vec(), &bogus);
        let good = make_handle(b"second".to_vec());
        let err = verify_input_digests(&[vec![bad, good]], 1).unwrap_err();
        matches!(err, Error::DigestMismatch { .. });
    }

    #[test]
    fn opener_io_error_propagates() {
        // An opener returning an error must surface as Io / MalformedInput
        // rather than masquerading as a digest mismatch.
        let h = LayerHandle::new(
            Digest::from_str(&format!("sha256:{}", "a".repeat(64))).unwrap(),
            Digest::from_str(&format!("sha256:{}", "b".repeat(64))).unwrap(),
            0,
            "application/vnd.oci.image.layer.v1.tar".into(),
            || Err(Error::MalformedInput("blob missing".into())),
        )
        .unwrap();
        let err = verify_input_digests(&[vec![h]], 1).unwrap_err();
        match err {
            Error::MalformedInput(msg) => assert_eq!(msg, "blob missing"),
            other => panic!("expected MalformedInput, got {other:?}"),
        }
    }

    #[test]
    fn gzip_layer_verifies_against_compressed_digest() {
        // For OCI gzipped layers the manifest digest is over the
        // compressed bytes (spec 01 §1.8). open_compressed gives us
        // those bytes verbatim, so the verify pass hashes the right
        // thing without redecompressing.
        use flate2::Compression as GzLevel;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let mut enc = GzEncoder::new(Vec::new(), GzLevel::default());
        enc.write_all(b"interior-tar-bytes").unwrap();
        let gzipped = enc.finish().unwrap();
        let declared = sha256_hex(&gzipped);
        let gz_clone = gzipped.clone();

        let h = LayerHandle::new(
            Digest::from_str(&format!("sha256:{declared}")).unwrap(),
            Digest::from_str(&format!("sha256:{}", "b".repeat(64))).unwrap(),
            gzipped.len() as u64,
            "application/vnd.oci.image.layer.v1.tar+gzip".into(),
            move || Ok(Box::new(Cursor::new(gz_clone.clone())) as Box<dyn Read + Send + 'static>),
        )
        .unwrap();
        verify_input_digests(&[vec![h]], 1).unwrap();
    }

    #[test]
    fn jobs_zero_falls_back_to_default() {
        let h = make_handle(b"defaults".to_vec());
        verify_input_digests(&[vec![h]], 0).unwrap();
    }

    #[test]
    fn parallel_run_visits_every_layer() {
        // Build N layers that count opener invocations; verify every
        // one was hashed exactly once even with a parallel pool.
        let n = 8;
        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for i in 0..n {
            let body = format!("layer-{i}").into_bytes();
            let declared = sha256_hex(&body);
            let arc = Arc::new(body);
            let arc_for_open = arc.clone();
            let counter_for_open = counter.clone();
            let h = LayerHandle::new(
                Digest::from_str(&format!("sha256:{declared}")).unwrap(),
                Digest::from_str(&format!("sha256:{}", "b".repeat(64))).unwrap(),
                arc.len() as u64,
                "application/vnd.oci.image.layer.v1.tar".into(),
                move || {
                    counter_for_open.fetch_add(1, Ordering::Relaxed);
                    Ok(Box::new(Cursor::new((*arc_for_open).clone())) as Box<dyn Read + Send + 'static>)
                },
            )
            .unwrap();
            handles.push(h);
        }
        verify_input_digests(&[handles], 4).unwrap();
        assert_eq!(counter.load(Ordering::Relaxed), n);
    }

    #[test]
    fn observed_hex_in_error_matches_actual_sha256() {
        // The error must report the *real* observed digest so the user
        // can grep the manifest for which side disagrees.
        let bogus = "2".repeat(64);
        let body = b"some-real-bytes".to_vec();
        let actual = sha256_hex(&body);
        let h = make_handle_with_digest(body, &bogus);
        let err = verify_input_digests(&[vec![h]], 1).unwrap_err();
        match err {
            Error::DigestMismatch { observed, .. } => assert_eq!(observed, format!("sha256:{actual}")),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn sha256_stream_chunks_large_inputs() {
        // The internal buffer is 64KiB; feed a stream that exceeds it
        // to confirm chunking accumulates correctly.
        let body = vec![0xabu8; 200 * 1024];
        let expected_hex = sha256_hex(&body);
        let mut cursor = Cursor::new(body);
        let observed = sha256_stream(&mut cursor).unwrap();
        assert_eq!(hex_encode(&observed), expected_hex);
    }
}
