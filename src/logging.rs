//! Logging setup (spec 10 §10.4–10.5).
//!
//! `tracing-subscriber` is wired to **stderr** (spec 10 §10.8 — stdout
//! is reserved for the run summary). The default filter level comes
//! from the `-v` / `-q` CLI flags; setting `RUST_LOG` overrides that
//! default per spec 10 §10.5 ("CLI flags set the default; `RUST_LOG`
//! overrides it"). Quiet mode also suppresses the run summary on
//! stdout — that part is enforced by the summary emitter, not here.
//!
//! The `(verbose, quiet)` → directive mapping is pulled out as a pure
//! helper so the test suite can pin it without installing a global
//! subscriber (which `tracing` only allows once per process).

use tracing_subscriber::EnvFilter;

/// `EnvFilter` directive that the `-v`/`-q` flags resolve to when
/// `RUST_LOG` is unset.
///
/// | flag combination          | directive |
/// |---------------------------|-----------|
/// | `--quiet`                 | `error`   |
/// | (default, no flags)       | `warn`    |
/// | `-v`                      | `info`    |
/// | `-vv` and above           | `trace`   |
///
/// Spec 10 §10.4 calls `-vv` "per-entry tracing — high volume,
/// intended for debugging", which lines up with `trace` rather than
/// `debug`. Higher repeat counts saturate at `trace` rather than
/// inventing new levels.
fn default_directive(verbose: u8, quiet: bool) -> &'static str {
    if quiet {
        "error"
    } else {
        match verbose {
            0 => "warn",
            1 => "info",
            _ => "trace",
        }
    }
}

/// Build the [`EnvFilter`] to install, given an explicit `RUST_LOG`
/// value (typically `std::env::var("RUST_LOG").ok()`).
///
/// `rust_log` takes precedence over `(verbose, quiet)` per spec 10
/// §10.5 — but only when it is `Some`, non-empty after trimming, and
/// parses as a valid `EnvFilter` directive. An unparseable or
/// blank-but-set `RUST_LOG` falls back to the CLI-derived default
/// rather than crashing the binary at startup.
fn make_filter_from_env(rust_log: Option<&str>, verbose: u8, quiet: bool) -> EnvFilter {
    if let Some(s) = rust_log {
        let trimmed = s.trim();
        if !trimmed.is_empty()
            && let Ok(filter) = EnvFilter::try_new(trimmed)
        {
            return filter;
        }
    }
    EnvFilter::new(default_directive(verbose, quiet))
}

/// Build the [`EnvFilter`] backing the global subscriber, reading
/// `RUST_LOG` from the process environment.
///
/// Exposed for callers that want to install a custom subscriber
/// (e.g. an integration test capturing log output) while still
/// honouring the CLI flag mapping.
#[must_use]
pub fn make_filter(verbose: u8, quiet: bool) -> EnvFilter {
    make_filter_from_env(std::env::var("RUST_LOG").ok().as_deref(), verbose, quiet)
}

/// Install the global `tracing` subscriber for the binary entry
/// point.
///
/// Writes formatted events to stderr and gates them through
/// [`make_filter`]. Intended to be called exactly once, early in
/// `main`, before any pipeline work.
///
/// # Errors
///
/// Returns the error from
/// [`tracing::subscriber::set_global_default`] when a subscriber is
/// already installed. The binary entry point calls this once; tests
/// that need to install their own subscriber should rely on
/// [`make_filter`] / `tracing::subscriber::with_default` instead of
/// invoking this function.
pub fn init(verbose: u8, quiet: bool) -> Result<(), tracing::subscriber::SetGlobalDefaultError> {
    let subscriber = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(make_filter(verbose, quiet))
        .finish();
    tracing::subscriber::set_global_default(subscriber)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_floors_to_error() {
        // Spec 10 §10.4: `--quiet` suppresses non-error output. The
        // verbose count is meaningless in this branch (clap rejects
        // `-v -q` as ArgumentConflict, but the helper is still
        // total over the input domain).
        assert_eq!(default_directive(0, true), "error");
        assert_eq!(default_directive(1, true), "error");
        assert_eq!(default_directive(2, true), "error");
        assert_eq!(default_directive(u8::MAX, true), "error");
    }

    #[test]
    fn verbose_levels_map_through() {
        assert_eq!(default_directive(0, false), "warn");
        assert_eq!(default_directive(1, false), "info");
        // `-vv` and beyond saturate at `trace` — there is no level
        // above `trace` in `tracing`, and spec 10 §10.4 explicitly
        // calls per-entry tracing "high volume, intended for
        // debugging" which is the `trace` level by convention.
        assert_eq!(default_directive(2, false), "trace");
        assert_eq!(default_directive(3, false), "trace");
        assert_eq!(default_directive(u8::MAX, false), "trace");
    }

    #[test]
    fn rust_log_overrides_default_when_set() {
        // Spec 10 §10.5: `RUST_LOG` overrides the `-v`/`-q`-derived
        // default. `verbose=0` would default to `warn`, but
        // `RUST_LOG=debug` wins.
        let f = make_filter_from_env(Some("debug"), 0, false);
        assert_eq!(format!("{f}"), "debug");
    }

    #[test]
    fn rust_log_overrides_quiet() {
        // The override applies to `--quiet` too — a user setting
        // `RUST_LOG=trace` while passing `-q` is asking for tracing
        // output, and gets it.
        let f = make_filter_from_env(Some("trace"), 0, true);
        assert_eq!(format!("{f}"), "trace");
    }

    #[test]
    fn empty_rust_log_falls_back_to_default() {
        // An exported but empty `RUST_LOG` (common in shells where
        // `export RUST_LOG=` is used to clear it) should not be
        // treated as a directive — fall back to the CLI default.
        let f = make_filter_from_env(Some(""), 1, false);
        assert_eq!(format!("{f}"), "info");
    }

    #[test]
    fn whitespace_rust_log_falls_back_to_default() {
        let f = make_filter_from_env(Some("   "), 0, false);
        assert_eq!(format!("{f}"), "warn");
    }

    #[test]
    fn none_rust_log_uses_cli_default() {
        // Verbose=0 default: warn.
        let f = make_filter_from_env(None, 0, false);
        assert_eq!(format!("{f}"), "warn");
        // Verbose=1: info.
        let f = make_filter_from_env(None, 1, false);
        assert_eq!(format!("{f}"), "info");
        // Quiet: error.
        let f = make_filter_from_env(None, 0, true);
        assert_eq!(format!("{f}"), "error");
        // Verbose>=2: trace.
        let f = make_filter_from_env(None, 2, false);
        assert_eq!(format!("{f}"), "trace");
    }

    #[test]
    fn rust_log_targeted_directives_pass_through() {
        // EnvFilter accepts per-target directives — verify we hand
        // them off verbatim rather than re-parsing into a single
        // level.
        let f = make_filter_from_env(Some("container_squash=debug,tar=warn"), 0, false);
        let display = format!("{f}");
        assert!(display.contains("container_squash=debug"), "got: {display}");
        assert!(display.contains("tar=warn"), "got: {display}");
    }
}
