//! Crate-wide error type.
//!
//! Variants are grouped by the exit-code classes defined in spec 10 §10.7.
//! `main.rs` is the only place that maps these onto process exit codes;
//! library callers should pattern-match on the variant directly.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level error returned by every fallible API in the crate.
///
/// The shape mirrors spec 10 §10.7:
///
/// * `0` — success (no variant; absence of an error).
/// * `1` — [`Error::Io`], [`Error::MalformedInput`], [`Error::Validation`].
/// * `2` — [`Error::Usage`].
/// * `3` — [`Error::OutputExists`].
/// * `4` — [`Error::DigestMismatch`].
#[derive(Debug, Error)]
pub enum Error {
    /// Bad CLI usage. Maps to exit code 2; spec 10 §10.7 requires that
    /// no file is written or moved before this is returned.
    #[error("bad usage: {0}")]
    Usage(String),

    /// The output destination exists and `--force` was not given.
    /// Maps to exit code 3 (spec 09 §9.6 / spec 10 §10.7).
    #[error("output already exists: {0} (use --force to overwrite)")]
    OutputExists(PathBuf),

    /// An input layer's observed digest did not match its manifest
    /// descriptor. Maps to exit code 4 (spec 07 §7.6).
    #[error("input digest mismatch: expected {expected}, observed {observed}")]
    DigestMismatch {
        /// Digest as recorded in the input manifest descriptor.
        expected: String,
        /// Digest computed while streaming the layer body.
        observed: String,
    },

    /// Underlying I/O failure. Maps to exit code 1.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    /// Input image, tar, or OCI document is malformed. Maps to exit code 1.
    #[error("malformed input: {0}")]
    MalformedInput(String),

    /// Internal post-assembly validation failed (8.5). Maps to exit code 1.
    #[error("validation failed: {0}")]
    Validation(String),
}

impl Error {
    /// Process exit code per spec 10 §10.7.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Usage(_) => 2,
            Error::OutputExists(_) => 3,
            Error::DigestMismatch { .. } => 4,
            Error::Io(_) | Error::MalformedInput(_) | Error::Validation(_) => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_spec_10_7() {
        assert_eq!(Error::Usage("x".into()).exit_code(), 2);
        assert_eq!(Error::OutputExists(PathBuf::from("/tmp/x")).exit_code(), 3);
        assert_eq!(
            Error::DigestMismatch {
                expected: "sha256:a".into(),
                observed: "sha256:b".into(),
            }
            .exit_code(),
            4
        );
        assert_eq!(Error::MalformedInput("x".into()).exit_code(), 1);
        assert_eq!(Error::Validation("x".into()).exit_code(), 1);
        assert_eq!(Error::Io(io::Error::other("x")).exit_code(), 1);
    }
}
