//! Force / collision handling for the output destination (spec 09 §9.4).
//!
//! Spec contract: if `<output>` already exists when the tool starts, the
//! run is refused with [`Error::OutputExists`] (exit code 3) unless
//! `--force` is given. Under `--force`, the existing destination is
//! moved aside to `<output>.old-<T0>` so the new output can land in its
//! place; the aside copy is left for the user to delete. This keeps the
//! "never silently destroy user data" invariant the spec mandates and
//! is symmetric across both packaging modes (tar and dir).
//!
//! Called once by the run driver up-front, before any blob is written —
//! exit-code-3 collisions must not have produced output (spec 10 §10.7).
//!
//! ## Aside-name collision
//!
//! If `<output>.old-<T0>` itself already exists (e.g. the user re-ran
//! with the same `--timestamp`), the rename is *not* performed: doing so
//! would either silently overwrite a regular-file aside (`rename(2)`
//! over a file is destructive on POSIX) or fail noisily on a directory
//! one. Both outcomes violate the "never delete the aside copy" rule, so
//! the tool refuses with [`Error::OutputExists`] pointing at the
//! conflicting aside path. The user can rename the prior aside out of
//! the way, or pick a different `--timestamp`, and retry.

use std::fs;
use std::path::{Path, PathBuf};

use crate::timestamp::T0;
use crate::{Error, Result};

/// Outcome of [`prepare_destination`] — what, if anything, was moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prepared {
    /// `<output>` did not exist; nothing to do.
    Vacant,
    /// `<output>` existed and was renamed to the contained path.
    MovedAside(PathBuf),
}

/// Resolve the destination collision rule for `<output>`.
///
/// * If `output` does not exist, returns [`Prepared::Vacant`].
/// * If `output` exists and `force` is false, returns
///   [`Error::OutputExists`].
/// * If `output` exists and `force` is true, renames it to
///   `<output>.old-<T0>` and returns [`Prepared::MovedAside`] with the
///   aside path. The `<T0>` token is `t0`'s integer Unix-seconds value
///   in decimal (negative values keep the leading `-`).
///
/// # Errors
///
/// * [`Error::OutputExists`] when `output` exists and either `force` is
///   false, or the aside path itself already exists (the move would
///   destroy the prior aside, which spec 09 §9.4 forbids).
/// * [`Error::Io`] when the `rename(2)` itself fails (a different mount
///   point, permission denied, etc.).
pub fn prepare_destination(output: &Path, force: bool, t0: T0) -> Result<Prepared> {
    if !output.try_exists()? {
        return Ok(Prepared::Vacant);
    }
    if !force {
        return Err(Error::OutputExists(output.to_path_buf()));
    }
    let aside = aside_path(output, t0);
    if aside.try_exists()? {
        return Err(Error::OutputExists(aside));
    }
    fs::rename(output, &aside).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("move aside {} -> {} failed: {e}", output.display(), aside.display()),
        ))
    })?;
    Ok(Prepared::MovedAside(aside))
}

/// Build the move-aside path for `output` given the run's `t0`.
///
/// Format: `<output>.old-<unix-seconds>`. Sibling of `output` so the
/// rename is same-filesystem and therefore atomic. Lives outside
/// [`prepare_destination`] so callers can pre-compute the aside path
/// for messaging without performing the move.
#[must_use]
pub fn aside_path(output: &Path, t0: T0) -> PathBuf {
    let file_name = output
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    let mut name = file_name;
    name.push(format!(".old-{}", t0.as_unix_seconds()));
    output.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> T0 {
        T0::from_unix_seconds(1_700_000_000)
    }

    #[test]
    fn vacant_when_output_does_not_exist() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out.tar");
        let prepared = prepare_destination(&out, false, t0()).unwrap();
        assert_eq!(prepared, Prepared::Vacant);
        // Nothing should have been created.
        assert!(!out.exists());
    }

    #[test]
    fn vacant_under_force_does_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out.tar");
        let prepared = prepare_destination(&out, true, t0()).unwrap();
        assert_eq!(prepared, Prepared::Vacant);
        assert!(!out.exists());
        // No spurious aside left behind.
        assert!(!aside_path(&out, t0()).exists());
    }

    #[test]
    fn refuses_when_output_exists_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out.tar");
        fs::write(&out, b"existing").unwrap();

        let err = prepare_destination(&out, false, t0()).unwrap_err();
        match err {
            Error::OutputExists(p) => assert_eq!(p, out),
            other => panic!("got: {other:?}"),
        }
        // The existing destination is untouched (never deleted).
        assert_eq!(fs::read(&out).unwrap(), b"existing");
    }

    #[test]
    fn refuses_existing_directory_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir_all(out.join("blobs").join("sha256")).unwrap();
        fs::write(out.join("oci-layout"), b"x").unwrap();

        let err = prepare_destination(&out, false, t0()).unwrap_err();
        assert!(matches!(err, Error::OutputExists(ref p) if *p == out), "got: {err:?}");
        // Directory tree intact.
        assert!(out.join("oci-layout").is_file());
    }

    #[test]
    fn force_moves_existing_file_aside() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out.tar");
        fs::write(&out, b"prior").unwrap();

        let prepared = prepare_destination(&out, true, t0()).unwrap();
        let aside = aside_path(&out, t0());
        assert_eq!(prepared, Prepared::MovedAside(aside.clone()));
        // Output path is now vacant; the aside carries the old bytes.
        assert!(!out.exists(), "output path must be free for the new write");
        assert_eq!(fs::read(&aside).unwrap(), b"prior");
    }

    #[test]
    fn force_moves_existing_directory_aside() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out");
        fs::create_dir_all(out.join("blobs").join("sha256")).unwrap();
        fs::write(out.join("oci-layout"), b"x").unwrap();

        let prepared = prepare_destination(&out, true, t0()).unwrap();
        let aside = aside_path(&out, t0());
        assert_eq!(prepared, Prepared::MovedAside(aside.clone()));
        assert!(!out.exists());
        assert!(aside.is_dir());
        assert!(aside.join("oci-layout").is_file());
    }

    #[test]
    fn aside_name_is_sibling_of_output() {
        // `rename(2)` must be same-filesystem; spec §9.4 implies the
        // aside lives next to the output. Confirm the path layout.
        let p = aside_path(Path::new("/tmp/foo/out.tar"), T0::from_unix_seconds(1_700_000_000));
        assert_eq!(p, PathBuf::from("/tmp/foo/out.tar.old-1700000000"));

        let p = aside_path(Path::new("/tmp/out"), T0::from_unix_seconds(0));
        assert_eq!(p, PathBuf::from("/tmp/out.old-0"));
    }

    #[test]
    fn aside_name_carries_negative_t0_verbatim() {
        // Spec 06 §6.6: negative T0 sentinels are preserved unmodified.
        // The aside name must reflect whatever value the run captured —
        // a leading `-` in the suffix is fine for filesystems.
        let p = aside_path(Path::new("/tmp/out.tar"), T0::from_unix_seconds(-1));
        assert_eq!(p, PathBuf::from("/tmp/out.tar.old--1"));
    }

    #[test]
    fn refuses_when_aside_path_already_exists() {
        // Re-running with `--force` *and* the same `--timestamp` would
        // collide on the aside name. Renaming over the prior aside
        // would either silently overwrite a regular file or fail on a
        // directory — both destroy or surface unhelpfully. The tool
        // refuses up-front with OutputExists pointing at the aside.
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out.tar");
        fs::write(&out, b"current").unwrap();
        let aside = aside_path(&out, t0());
        fs::write(&aside, b"prior-aside").unwrap();

        let err = prepare_destination(&out, true, t0()).unwrap_err();
        match err {
            Error::OutputExists(p) => assert_eq!(p, aside),
            other => panic!("got: {other:?}"),
        }
        // Both files survive — no destruction took place.
        assert_eq!(fs::read(&out).unwrap(), b"current");
        assert_eq!(fs::read(&aside).unwrap(), b"prior-aside");
    }

    #[test]
    fn aside_under_different_t0_does_not_collide() {
        // Two runs with different timestamps each get their own aside
        // path. The second --force run produces aside.old-<T0_2>
        // alongside the surviving aside.old-<T0_1>.
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out.tar");
        fs::write(&out, b"first").unwrap();

        let t0_a = T0::from_unix_seconds(1);
        prepare_destination(&out, true, t0_a).unwrap();
        let aside_a = aside_path(&out, t0_a);
        assert_eq!(fs::read(&aside_a).unwrap(), b"first");

        // Caller drops a fresh output, then re-runs with a later T0.
        fs::write(&out, b"second").unwrap();
        let t0_b = T0::from_unix_seconds(2);
        prepare_destination(&out, true, t0_b).unwrap();
        let aside_b = aside_path(&out, t0_b);
        assert_eq!(fs::read(&aside_b).unwrap(), b"second");
        // The first aside is untouched.
        assert_eq!(fs::read(&aside_a).unwrap(), b"first");
    }

    #[test]
    fn force_returns_aside_path_for_caller_to_log() {
        // Spec §9.4: "The aside copy is left for the user to delete."
        // The caller (CLI summary, future task) needs the aside path
        // to mention it in the human-readable run summary. The Prepared
        // outcome carries the path so callers don't have to recompute.
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out.tar");
        fs::write(&out, b"x").unwrap();

        let prepared = prepare_destination(&out, true, t0()).unwrap();
        match prepared {
            Prepared::MovedAside(p) => {
                assert!(p.exists());
                assert_eq!(p, aside_path(&out, t0()));
            }
            Prepared::Vacant => panic!("expected MovedAside, got Vacant"),
        }
    }

    #[test]
    fn aside_is_not_deleted_by_subsequent_call() {
        // A follow-up run that finds a vacant output (the prior --force
        // already moved the live copy aside) must not touch the aside.
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out.tar");
        fs::write(&out, b"first").unwrap();
        prepare_destination(&out, true, t0()).unwrap();
        let aside = aside_path(&out, t0());
        assert!(aside.exists());

        // Output now vacant — second prepare with same T0 should be a
        // no-op. The aside must still be there afterwards (the spec's
        // "never delete the aside copy" invariant).
        let prepared = prepare_destination(&out, true, t0()).unwrap();
        assert_eq!(prepared, Prepared::Vacant);
        assert!(aside.exists(), "previous aside copy must survive");
        assert_eq!(fs::read(&aside).unwrap(), b"first");
    }

    #[test]
    fn output_exists_error_carries_exit_code_3() {
        // Spec 10 §10.7: collision → exit 3. Sanity-check that the
        // error variant we return maps to the right code.
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out.tar");
        fs::write(&out, b"x").unwrap();

        let err = prepare_destination(&out, false, t0()).unwrap_err();
        assert_eq!(err.exit_code(), 3);
    }
}
