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

    /// Format `T0` as an RFC 3339 / ISO 8601 timestamp in UTC.
    ///
    /// The output shape is fixed: `YYYY-MM-DDTHH:MM:SSZ`, four-digit
    /// year, second precision, literal `Z` zone designator. This is
    /// the format the OCI image-spec mandates for the `created` field
    /// on image configs / history entries (spec 08 §8.1) and for the
    /// `org.opencontainers.image.created` annotation on manifests and
    /// the index (spec 08 §8.2, 8.4). All callers in the pipeline go
    /// through this helper so the same `T0` lands byte-identically in
    /// every emitted document — that is the spec 11 §11.6
    /// reproducibility contract.
    ///
    /// # Range clamping
    ///
    /// RFC 3339 requires a four-digit year, which restricts the
    /// representable range to `0001-01-01T00:00:00Z` ..=
    /// `9999-12-31T23:59:59Z`. A `T0` outside that range is clamped
    /// to the nearest endpoint rather than producing ill-formed
    /// output. Spec 06 §6.6 treats absurdly far-past / far-future
    /// timestamps as baked in unconditionally; the only adjustment
    /// this layer makes is the format-grammar clamp, which preserves
    /// the second-precision contract of §6.4.
    ///
    /// No external crate is consulted: civil-date conversion uses
    /// Howard Hinnant's `civil_from_days` algorithm, which is exact
    /// over the proleptic Gregorian calendar for the entire `i64`
    /// range. The `chrono` and `time` crates are intentionally not
    /// dependencies of this project.
    #[must_use]
    pub fn to_rfc3339(self) -> String {
        let secs = self.0.clamp(MIN_RFC3339_UNIX, MAX_RFC3339_UNIX);
        let (y, mo, d, h, mi, s) = civil_from_unix(secs);
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
    }
}

/// `0001-01-01T00:00:00Z` in Unix seconds — the lower RFC 3339 bound
/// for [`T0::to_rfc3339`].
const MIN_RFC3339_UNIX: i64 = -62_135_596_800;

/// `9999-12-31T23:59:59Z` in Unix seconds — the upper RFC 3339 bound
/// for [`T0::to_rfc3339`].
const MAX_RFC3339_UNIX: i64 = 253_402_300_799;

/// Convert Unix seconds to a broken-down UTC `(year, month, day, hour,
/// minute, second)` tuple. Pure arithmetic; no allocation, no calendar
/// crate.
///
/// `month` and `day` are 1-based. `hour` is 0..=23, `minute` and
/// `second` are 0..=59 (no leap seconds — Unix time itself doesn't
/// represent them).
fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    const SECS_PER_DAY: i64 = 86_400;
    // Floor-division so negative `secs` (pre-1970) round toward
    // -infinity, which is what the civil-day algorithm expects.
    let days = secs.div_euclid(SECS_PER_DAY);
    // `rem_euclid` for a positive divisor is in `0..SECS_PER_DAY`, so
    // it always fits in u32.
    let sod = u32::try_from(secs.rem_euclid(SECS_PER_DAY)).expect("rem_euclid by 86_400 is in 0..86_400");
    let h = sod / 3600;
    let mi = (sod % 3600) / 60;
    let s = sod % 60;
    let (y, mo, d) = civil_from_days(days);
    (y, mo, d, h, mi, s)
}

/// Howard Hinnant's `civil_from_days`: days-since-1970-01-01 to
/// `(year, month, day)` in the proleptic Gregorian calendar. Exact
/// for any `i64` day count well past the bounds [`T0::to_rfc3339`]
/// will ever pass in.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    // Shift epoch from 1970-03-01 (March-based to dodge leap-day
    // arithmetic) by 719468 days. Hinnant's original uses a manual
    // floor-divide trick because C++ `/` truncates toward zero; in
    // Rust, `div_euclid` is already floor-division for a positive
    // divisor, so the trick collapses to a direct call.
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    // `era * 146_097` is the largest multiple of 146 097 not exceeding
    // `z` (floor-div property), so `z - era * 146_097` is in
    // `0..146_097` and fits comfortably in u32.
    let doe = u32::try_from(z - era * 146_097).expect("day-of-era is in 0..146_097");
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // 0..=399
    let y = i64::from(yoe) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // 0..=365
    let mp = (5 * doy + 2) / 153; // 0..=11
    let d = doy - (153 * mp + 2) / 5 + 1; // 1..=31
    let mo = if mp < 10 { mp + 3 } else { mp - 9 }; // 1..=12
    let year = if mo <= 2 { y + 1 } else { y };
    (year, mo, d)
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

    #[test]
    fn rfc3339_unix_epoch() {
        let s = T0::from_unix_seconds(0).to_rfc3339();
        assert_eq!(s, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn rfc3339_one_second_before_epoch() {
        // Confirms the floor-division branch handles negative seconds
        // correctly — naive truncation would emit
        // "1970-01-01T-1:..." or similar nonsense.
        let s = T0::from_unix_seconds(-1).to_rfc3339();
        assert_eq!(s, "1969-12-31T23:59:59Z");
    }

    #[test]
    fn rfc3339_known_recent_value() {
        // 1700000000 unix = 2023-11-14T22:13:20Z.
        let s = T0::from_unix_seconds(1_700_000_000).to_rfc3339();
        assert_eq!(s, "2023-11-14T22:13:20Z");
    }

    #[test]
    fn rfc3339_another_known_value() {
        // 1234567890 unix = 2009-02-13T23:31:30Z (a popular sanity
        // check for unix-time conversions).
        let s = T0::from_unix_seconds(1_234_567_890).to_rfc3339();
        assert_eq!(s, "2009-02-13T23:31:30Z");
    }

    #[test]
    fn rfc3339_leap_day_2000() {
        // 951_782_400 = 2000-02-29T00:00:00Z. Year 2000 is a leap
        // year (divisible by 400) — exercises the era arithmetic.
        let s = T0::from_unix_seconds(951_782_400).to_rfc3339();
        assert_eq!(s, "2000-02-29T00:00:00Z");
    }

    #[test]
    fn rfc3339_non_leap_century_1900() {
        // 1900-03-01T00:00:00Z = -2_203_891_200. 1900 is divisible
        // by 100 but not 400, so it is *not* a leap year — March 1
        // immediately follows February 28.
        let s = T0::from_unix_seconds(-2_203_891_200).to_rfc3339();
        assert_eq!(s, "1900-03-01T00:00:00Z");
        let prev = T0::from_unix_seconds(-2_203_891_200 - 86_400).to_rfc3339();
        assert_eq!(prev, "1900-02-28T00:00:00Z");
    }

    #[test]
    fn rfc3339_day_boundary() {
        let s = T0::from_unix_seconds(86_399).to_rfc3339();
        assert_eq!(s, "1970-01-01T23:59:59Z");
        let s = T0::from_unix_seconds(86_400).to_rfc3339();
        assert_eq!(s, "1970-01-02T00:00:00Z");
    }

    #[test]
    fn rfc3339_zero_pads_year() {
        // 0001-01-01T00:00:00Z is the lower clamp; format must
        // surface "0001", not "1".
        let s = T0::from_unix_seconds(MIN_RFC3339_UNIX).to_rfc3339();
        assert_eq!(s, "0001-01-01T00:00:00Z");
    }

    #[test]
    fn rfc3339_clamps_far_past() {
        // Anything before year 1 saturates to the lower bound.
        let s = T0::from_unix_seconds(i64::MIN).to_rfc3339();
        assert_eq!(s, "0001-01-01T00:00:00Z");
        let s = T0::from_unix_seconds(MIN_RFC3339_UNIX - 1).to_rfc3339();
        assert_eq!(s, "0001-01-01T00:00:00Z");
    }

    #[test]
    fn rfc3339_clamps_far_future() {
        // i64::MAX would otherwise overflow the four-digit year
        // grammar; saturate to 9999-12-31T23:59:59Z.
        let s = T0::from_unix_seconds(i64::MAX).to_rfc3339();
        assert_eq!(s, "9999-12-31T23:59:59Z");
        let s = T0::from_unix_seconds(MAX_RFC3339_UNIX + 1).to_rfc3339();
        assert_eq!(s, "9999-12-31T23:59:59Z");
    }

    #[test]
    fn rfc3339_max_bound_is_last_second_of_9999() {
        let s = T0::from_unix_seconds(MAX_RFC3339_UNIX).to_rfc3339();
        assert_eq!(s, "9999-12-31T23:59:59Z");
    }

    #[test]
    fn rfc3339_fixed_width_grammar() {
        // Format must always be 20 chars: 4+1+2+1+2+1+2+1+2+1+2+1.
        let s = T0::from_unix_seconds(1).to_rfc3339();
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z'));
        assert_eq!(s.as_bytes()[4], b'-');
        assert_eq!(s.as_bytes()[7], b'-');
        assert_eq!(s.as_bytes()[10], b'T');
        assert_eq!(s.as_bytes()[13], b':');
        assert_eq!(s.as_bytes()[16], b':');
    }

    #[test]
    fn rfc3339_minute_and_hour_rollover() {
        // 3599 = 00:59:59, 3600 = 01:00:00.
        assert_eq!(T0::from_unix_seconds(3599).to_rfc3339(), "1970-01-01T00:59:59Z");
        assert_eq!(T0::from_unix_seconds(3600).to_rfc3339(), "1970-01-01T01:00:00Z");
    }

    #[test]
    fn rfc3339_negative_seconds_within_day() {
        // -86_400 = 1969-12-31T00:00:00Z. Confirms day rollover
        // through the floor-division boundary.
        assert_eq!(T0::from_unix_seconds(-86_400).to_rfc3339(), "1969-12-31T00:00:00Z");
        assert_eq!(T0::from_unix_seconds(-86_401).to_rfc3339(), "1969-12-30T23:59:59Z");
    }

    #[test]
    fn rfc3339_year_2038_boundary() {
        // 2_147_483_647 = 2038-01-19T03:14:07Z (i32 unix-time
        // overflow). The tool uses i64 throughout, so this is just
        // an ordinary timestamp.
        let s = T0::from_unix_seconds(2_147_483_647).to_rfc3339();
        assert_eq!(s, "2038-01-19T03:14:07Z");
    }
}
