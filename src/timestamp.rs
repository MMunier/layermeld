//! Timestamp normalisation: `T0` capture + propagation (spec 06).
//!
//! Every time-bearing field the tool emits — tar entry `mtime`, OCI
//! image config `created`, `history[].created`, the
//! `org.opencontainers.image.created` annotation on output manifests
//! and the index — is collapsed onto a single value, the **invocation
//! timestamp** [`T0`]. Spec 06 §6.1 requires that `T0` be captured
//! once at the start of the run, before any output is written, and
//! threaded through every downstream stage. This module owns the
//! capture; downstream stages take an owned [`T0`] by value (it is
//! `Copy`) and must never re-read the wall clock or environment
//! themselves.
//!
//! ## Resolution precedence (spec 06 §6.1)
//!
//! [`T0::capture`] resolves the value in this order, first match wins:
//!
//! 1. The `--timestamp <unix-seconds>` CLI flag, passed in as
//!    `cli_override`. Driven by [`crate::cli`] / [`crate::config`].
//! 2. The `SOURCE_DATE_EPOCH` environment variable, the de-facto
//!    standard for reproducible-build tooling. Parsed as a signed
//!    integer number of Unix seconds.
//! 3. The system wall clock, truncated to whole seconds (spec 06
//!    §6.4 — no sub-second precision in output).
//!
//! Sources 1 and 2 are not validated against any range: spec 06 §6.6
//! says far-past / far-future values are baked in unconditionally.
//! Only a fundamentally unparseable `SOURCE_DATE_EPOCH` is rejected,
//! and as a CLI usage error (exit code 2) since it came from the
//! invocation environment.
//!
//! ## Why `i64`
//!
//! Unix seconds are signed in POSIX; pre-1970 sentinels surface as
//! negative values. `i64` covers ±292 billion years either way, which
//! is enough for the §6.6 "absurdly large" cases plus the negative
//! sentinels without overflow. The narrowing to a tar `u64` mtime
//! happens at the writer (`tar_io::writer::set_mtime`) and is the
//! caller's concern — this module does not pre-clip.

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Error, Result};

/// Name of the reproducible-build env var consulted by [`T0::capture`].
const SOURCE_DATE_EPOCH: &str = "SOURCE_DATE_EPOCH";

/// The run's invocation timestamp — Unix seconds, UTC, second precision.
///
/// Constructed once via [`T0::capture`] and threaded down the pipeline.
/// `Copy` so it can be passed by value through stage boundaries without
/// re-reading any source. See spec 06 for the field-by-field
/// propagation contract.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct T0(i64);

/// How a particular [`T0`] was resolved. Reported in the run summary
/// so the user always knows what was baked into the output (spec 06
/// §6.1 last paragraph).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum T0Source {
    /// Resolved from the `--timestamp` CLI flag.
    CliFlag,
    /// Resolved from the `SOURCE_DATE_EPOCH` environment variable.
    SourceDateEpoch,
    /// Resolved from the system wall clock.
    WallClock,
}

impl T0 {
    /// Resolve `T0` per spec 06 §6.1 precedence: `cli_override` >
    /// `SOURCE_DATE_EPOCH` env > wall clock.
    ///
    /// `cli_override` is the value parsed off `--timestamp`; pass
    /// `None` when the flag was not given. The wall-clock branch
    /// truncates to whole seconds (spec 06 §6.4).
    ///
    /// # Errors
    ///
    /// * [`Error::Usage`] if `SOURCE_DATE_EPOCH` is set but does not
    ///   parse as a signed integer. The variable comes from the
    ///   invocation environment, so a bad value is a usage problem
    ///   (exit code 2 per spec 10 §10.7); the run aborts before any
    ///   output is touched.
    /// * [`Error::Io`] if the system clock reports a moment before
    ///   the Unix epoch (vanishingly rare; wrapping `SystemTimeError`).
    pub fn capture(cli_override: Option<i64>) -> Result<(Self, T0Source)> {
        if let Some(v) = cli_override {
            return Ok((T0(v), T0Source::CliFlag));
        }
        match env::var(SOURCE_DATE_EPOCH) {
            Ok(s) => {
                let v = s
                    .trim()
                    .parse::<i64>()
                    .map_err(|e| Error::Usage(format!("invalid {SOURCE_DATE_EPOCH}={s:?}: {e}")))?;
                Ok((T0(v), T0Source::SourceDateEpoch))
            }
            Err(env::VarError::NotPresent) => {
                let secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| Error::Io(std::io::Error::other(format!("system clock before unix epoch: {e}"))))?
                    .as_secs();
                // `as_secs` returns u64; cast to i64. Saturating cast is
                // unnecessary in practice (would overflow at year ~292
                // billion AD) but spelled out so the intent is explicit.
                let signed = i64::try_from(secs).unwrap_or(i64::MAX);
                Ok((T0(signed), T0Source::WallClock))
            }
            Err(env::VarError::NotUnicode(raw)) => Err(Error::Usage(format!(
                "{SOURCE_DATE_EPOCH} contains non-UTF-8 bytes: {}",
                raw.to_string_lossy()
            ))),
        }
    }

    /// Construct a `T0` directly from a Unix-seconds value. Useful in
    /// tests and for downstream library callers that have already
    /// resolved the value externally.
    #[must_use]
    pub const fn from_unix_seconds(secs: i64) -> Self {
        T0(secs)
    }

    /// Unix-seconds value, signed. Suitable for OCI `created`
    /// formatting and for tar `mtime` after the caller's own clamp.
    #[must_use]
    pub const fn as_unix_seconds(self) -> i64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// `std::env` is process-global; serialise tests that mutate
    /// `SOURCE_DATE_EPOCH` so a parallel runner doesn't race.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard that restores the prior value of an env var on drop.
    struct EnvGuard {
        key: &'static str,
        prior: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prior = env::var_os(key);
            // SAFETY: tests serialise on `ENV_LOCK`; no other thread
            // observes the temporary state.
            unsafe { env::set_var(key, value) };
            Self { key, prior }
        }

        fn unset(key: &'static str) -> Self {
            let prior = env::var_os(key);
            // SAFETY: see `set`.
            unsafe { env::remove_var(key) };
            Self { key, prior }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: see `set`.
            unsafe {
                match &self.prior {
                    Some(v) => env::set_var(self.key, v),
                    None => env::remove_var(self.key),
                }
            }
        }
    }

    #[test]
    fn cli_override_wins_over_env_and_clock() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set(SOURCE_DATE_EPOCH, "12345");
        let (t0, src) = T0::capture(Some(7)).unwrap();
        assert_eq!(t0.as_unix_seconds(), 7);
        assert_eq!(src, T0Source::CliFlag);
    }

    #[test]
    fn cli_override_accepts_negative_values() {
        // Spec 06 §6.6: pre-1970 sentinels are baked in verbatim.
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::unset(SOURCE_DATE_EPOCH);
        let (t0, src) = T0::capture(Some(-1)).unwrap();
        assert_eq!(t0.as_unix_seconds(), -1);
        assert_eq!(src, T0Source::CliFlag);
    }

    #[test]
    fn cli_override_accepts_far_future() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::unset(SOURCE_DATE_EPOCH);
        let (t0, src) = T0::capture(Some(i64::MAX)).unwrap();
        assert_eq!(t0.as_unix_seconds(), i64::MAX);
        assert_eq!(src, T0Source::CliFlag);
    }

    #[test]
    fn source_date_epoch_used_when_no_cli_override() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set(SOURCE_DATE_EPOCH, "1700000000");
        let (t0, src) = T0::capture(None).unwrap();
        assert_eq!(t0.as_unix_seconds(), 1_700_000_000);
        assert_eq!(src, T0Source::SourceDateEpoch);
    }

    #[test]
    fn source_date_epoch_accepts_negative() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set(SOURCE_DATE_EPOCH, "-42");
        let (t0, src) = T0::capture(None).unwrap();
        assert_eq!(t0.as_unix_seconds(), -42);
        assert_eq!(src, T0Source::SourceDateEpoch);
    }

    #[test]
    fn source_date_epoch_trims_whitespace() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set(SOURCE_DATE_EPOCH, "  100\n");
        let (t0, src) = T0::capture(None).unwrap();
        assert_eq!(t0.as_unix_seconds(), 100);
        assert_eq!(src, T0Source::SourceDateEpoch);
    }

    #[test]
    fn source_date_epoch_unparseable_is_usage_error() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set(SOURCE_DATE_EPOCH, "not-a-number");
        let err = T0::capture(None).unwrap_err();
        match err {
            Error::Usage(msg) => assert!(msg.contains(SOURCE_DATE_EPOCH)),
            other => panic!("expected Error::Usage, got {other:?}"),
        }
    }

    #[test]
    fn source_date_epoch_empty_is_usage_error() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::set(SOURCE_DATE_EPOCH, "");
        let err = T0::capture(None).unwrap_err();
        assert!(matches!(err, Error::Usage(_)));
    }

    #[test]
    fn wall_clock_used_when_neither_source_set() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _g = EnvGuard::unset(SOURCE_DATE_EPOCH);
        let before = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();
        let (t0, src) = T0::capture(None).unwrap();
        let after = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();
        assert_eq!(src, T0Source::WallClock);
        assert!(
            t0.as_unix_seconds() >= before && t0.as_unix_seconds() <= after,
            "wall-clock T0 {} not in [{before}, {after}]",
            t0.as_unix_seconds()
        );
    }

    #[test]
    fn from_unix_seconds_round_trip() {
        let t0 = T0::from_unix_seconds(1_234_567_890);
        assert_eq!(t0.as_unix_seconds(), 1_234_567_890);
    }

    #[test]
    fn t0_is_copy_and_eq() {
        let a = T0::from_unix_seconds(42);
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a, T0::from_unix_seconds(42));
        assert_ne!(a, T0::from_unix_seconds(43));
    }

    #[test]
    fn t0_orders_by_seconds() {
        assert!(T0::from_unix_seconds(1) < T0::from_unix_seconds(2));
        assert!(T0::from_unix_seconds(-5) < T0::from_unix_seconds(0));
    }
}
