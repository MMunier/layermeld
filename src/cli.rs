//! `clap` derive structs for the binary entry point (spec 10).
//!
//! This module owns the argv-shape only. It performs no I/O, no path
//! canonicalisation, and does not touch the environment beyond what
//! `clap` itself does for `--help`/`--version`. The argv-to-`Config`
//! translation that spec 10 §10.7's "exit code 2 must not have written
//! or moved any file" rule depends on lives in [`crate::config`]
//! (built on top of these structs) and the binary entry in
//! [`crate::main`] — keeping all CLI-shape decisions in one place
//! means the library tests can construct `Config` directly without
//! re-deriving clap state.

use std::path::PathBuf;

use clap::{ArgAction, Parser, ValueEnum};

use crate::dedup::dissolve::DEFAULT_MIN_LAYER_SIZE;

/// Parsed command-line arguments for the `container-squash` binary.
///
/// Field semantics are described in spec 10 §10.2–10.4. The struct is
/// intentionally a faithful reflection of argv: defaults are filled in
/// here so that downstream code can treat every field as resolved, but
/// nothing is canonicalised or validated against the filesystem at
/// this layer.
#[derive(Debug, Parser)]
#[command(
    name = "container-squash",
    about = "Deterministic OCI/Docker image squasher with cross-image deduplication.",
    version,
    // Spec 10 §10.6 calls the summary out as the success-path stdout
    // contract. Hide clap's auto-generated `--help` short alias in
    // long-help only so it doesn't compete with `-h` for a future
    // human-readable flag — keeping `-h` reserved follows GNU/clap
    // conventions and doesn't cost us anything today.
    disable_help_flag = false,
)]
pub struct Cli {
    /// Input image paths. One or more local paths; see spec 01 for the
    /// accepted layouts (OCI dir/tar, docker-archive dir/tar, dir
    /// transport). Order is significant only as a deterministic
    /// tiebreaker (spec 11).
    #[arg(required = true, num_args = 1.., value_name = "INPUT")]
    pub inputs: Vec<PathBuf>,

    /// Output destination. By default a tar file containing an OCI
    /// image layout; with `--layout dir`, a directory tree instead.
    #[arg(short = 'o', long, value_name = "PATH")]
    pub output: PathBuf,

    /// Output packaging shape (spec 09 §9.3).
    #[arg(long, value_enum, default_value_t = Layout::Tar, value_name = "SHAPE")]
    pub layout: Layout,

    /// Minimum estimated tar size for a shared subset layer to survive
    /// the dissolve pass (spec 05 §5.5). Layers below this are
    /// dissolved and their files cascaded into smaller subset layers.
    /// Accepts power-of-two suffixes (`k`/`K`, `M`, `G`, `T`); `0`
    /// disables the pass entirely.
    #[arg(
        long,
        value_name = "BYTES",
        value_parser = parse_size,
        default_value_t = DEFAULT_MIN_LAYER_SIZE,
    )]
    pub min_layer_size: u64,

    /// Overwrite an existing destination by moving it aside to
    /// `<output>.old-<T0>` (spec 09 §9.4). Without this flag, an
    /// existing destination aborts the run with exit code 3.
    #[arg(long)]
    pub force: bool,

    /// Pin `T0` to the given Unix-seconds value (spec 06 §6.1).
    /// Overrides `SOURCE_DATE_EPOCH`. Negative values are accepted
    /// verbatim (spec 06 §6.6).
    #[arg(long, value_name = "UNIX-SECONDS", allow_hyphen_values = true)]
    pub timestamp: Option<i64>,

    /// Bound on concurrent layer assembly tasks (spec 07 §7.5). `0`
    /// (the default) lets `rayon` pick the logical CPU count.
    #[arg(long, value_name = "N", default_value_t = 0)]
    pub jobs: usize,

    /// Scratch directory for temporary files. Defaults to
    /// `<output>.partial/` next to the output destination.
    #[arg(long, value_name = "PATH")]
    pub scratch: Option<PathBuf>,

    /// Increase progress-logging verbosity on stderr. Repeatable:
    /// `-v` enables info-level logging, `-vv` enables per-entry
    /// tracing (high volume; debug only).
    #[arg(short, long, action = ArgAction::Count, conflicts_with = "quiet")]
    pub verbose: u8,

    /// Suppress all non-error output, including the run summary
    /// (spec 10 §10.6). Mutually exclusive with `--verbose`.
    #[arg(short, long)]
    pub quiet: bool,

    /// Perform every step except the final blob/index/oci-layout
    /// writes. Reports the would-be summary so the user can preview
    /// savings (spec 10 §10.4).
    #[arg(long)]
    pub dry_run: bool,
}

/// Output packaging shape (spec 09 §9.3). Selected via `--layout`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Layout {
    /// Pack the OCI layout into a single PAX tar (the default).
    Tar,
    /// Emit the OCI layout as a directory tree.
    Dir,
}

/// Parse a byte count with optional power-of-two suffix.
///
/// Accepted shapes: `<digits>` (raw bytes), `<digits><suffix>` where
/// suffix is one of `k`/`K` (×1024), `m`/`M` (×1024²), `g`/`G`
/// (×1024³), `t`/`T` (×1024⁴). Whitespace between the number and
/// suffix is rejected — this keeps the parser unambiguous and avoids
/// accidental shell-quoting surprises like `--min-layer-size "16 k"`.
///
/// Returns the parsed `u64` byte count. Used by `--min-layer-size`
/// (spec 10 §10.4); `0` is a valid result and disables the dissolve
/// pass per spec 05 §5.5.5.
///
/// # Errors
///
/// Returns an `Err(String)` (clap's value-parser error type) when:
/// * the input is empty or pure whitespace,
/// * the digit portion fails `u64::from_str`,
/// * the multiplied value would overflow `u64`,
/// * a non-recognised trailing alphabetic byte appears.
fn parse_size(input: &str) -> std::result::Result<u64, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("expected a byte count, got an empty value".into());
    }

    let (digits, multiplier) = split_suffix(s)?;
    if digits.is_empty() {
        return Err(format!("missing number in size value {input:?}"));
    }

    let n: u64 = digits
        .parse()
        .map_err(|e: std::num::ParseIntError| format!("invalid number in size value {input:?}: {e}"))?;
    n.checked_mul(multiplier)
        .ok_or_else(|| format!("size value {input:?} overflows u64"))
}

/// Split `s` into `(digit_portion, multiplier)`. The trailing byte —
/// if any — is consumed only when it matches a known suffix; an
/// unrecognised alphabetic byte is rejected so typos like `--min-
/// layer-size 16x` fail loudly rather than silently parsing as `16`.
fn split_suffix(s: &str) -> std::result::Result<(&str, u64), String> {
    let bytes = s.as_bytes();
    let last = *bytes
        .last()
        .ok_or_else(|| format!("size value {s:?}: unrecognized suffix (empty)"))?;

    let mut suffix_len = 1;
    let multiplier: Option<u64> = match last {
        b'k' | b'K' => Some(1024),
        b'm' | b'M' => Some(1024 * 1024),
        b'g' | b'G' => Some(1024 * 1024 * 1024),
        b't' | b'T' => Some(1024_u64.pow(4)),
        b'i' | b'I' => {
            let second_last = *bytes
                .get(bytes.len() - 2)
                .ok_or_else(|| format!("size value {s:?}: unrecognized suffix (i)"))?;
            let multiplier: Option<u64> = match second_last {
                b'k' | b'K' => Some(1024),
                b'm' | b'M' => Some(1024 * 1024),
                b'g' | b'G' => Some(1024 * 1024 * 1024),
                b't' | b'T' => Some(1024_u64.pow(4)),
                _ => {
                    return Err(format!(
                        "size value {s:?}: unrecognised suffix {:?}{:?} (expected k/M/G/T(i) or none)",
                        second_last as char, last as char
                    ));
                }
            };
            suffix_len += 1;
            multiplier
        }
        b'0'..=b'9' => None,
        _ => {
            return Err(format!(
                "size value {s:?}: unrecognised suffix {:?} (expected k/M/G/T(i) or none)",
                last as char
            ));
        }
    };

    Ok(match multiplier {
        Some(m) => (&s[..s.len().saturating_sub(suffix_len)], m),
        None => (s, 1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> std::result::Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("container-squash").chain(args.iter().copied()))
    }

    #[test]
    fn debug_assert_clap_definition() {
        // Catches programmer errors in the derive (duplicate short
        // flags, conflicting required/default, ...) at test time.
        Cli::command().debug_assert();
    }

    #[test]
    fn minimal_invocation() {
        let cli = parse(&["-o", "out.tar", "in1"]).unwrap();
        assert_eq!(cli.inputs, vec![PathBuf::from("in1")]);
        assert_eq!(cli.output, PathBuf::from("out.tar"));
        assert_eq!(cli.layout, Layout::Tar);
        assert_eq!(cli.min_layer_size, DEFAULT_MIN_LAYER_SIZE);
        assert!(!cli.force);
        assert_eq!(cli.timestamp, None);
        assert_eq!(cli.jobs, 0);
        assert_eq!(cli.scratch, None);
        assert_eq!(cli.verbose, 0);
        assert!(!cli.quiet);
        assert!(!cli.dry_run);
    }

    #[test]
    fn multiple_inputs_preserved_in_order() {
        let cli = parse(&["-o", "out.tar", "a", "b", "c"]).unwrap();
        assert_eq!(
            cli.inputs,
            vec![PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c")]
        );
    }

    #[test]
    fn long_output_flag_works() {
        let cli = parse(&["--output", "out.tar", "in"]).unwrap();
        assert_eq!(cli.output, PathBuf::from("out.tar"));
    }

    #[test]
    fn missing_output_is_usage_error() {
        let err = parse(&["in"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn missing_inputs_is_usage_error() {
        let err = parse(&["-o", "out.tar"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn layout_dir_parses() {
        let cli = parse(&["-o", "out", "--layout", "dir", "in"]).unwrap();
        assert_eq!(cli.layout, Layout::Dir);
    }

    #[test]
    fn layout_tar_parses() {
        let cli = parse(&["-o", "out", "--layout", "tar", "in"]).unwrap();
        assert_eq!(cli.layout, Layout::Tar);
    }

    #[test]
    fn layout_unknown_value_rejected() {
        let err = parse(&["-o", "out", "--layout", "ext4", "in"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
    }

    #[test]
    fn min_layer_size_plain_bytes() {
        let cli = parse(&["-o", "out", "--min-layer-size", "4096", "in"]).unwrap();
        assert_eq!(cli.min_layer_size, 4096);
    }

    #[test]
    fn min_layer_size_zero_disables() {
        // Spec 05 §5.5.5: `--min-layer-size 0` disables the dissolve
        // pass. Must round-trip exactly, not be rejected as "empty".
        let cli = parse(&["-o", "out", "--min-layer-size", "0", "in"]).unwrap();
        assert_eq!(cli.min_layer_size, 0);
    }

    #[test]
    fn min_layer_size_kilobyte_suffix() {
        for arg in ["16k", "16K"] {
            let cli = parse(&["-o", "out", "--min-layer-size", arg, "in"]).unwrap();
            assert_eq!(cli.min_layer_size, 16 * 1024, "input {arg}");
        }
    }

    #[test]
    fn min_layer_size_megabyte_suffix() {
        for arg in ["1M", "1m"] {
            let cli = parse(&["-o", "out", "--min-layer-size", arg, "in"]).unwrap();
            assert_eq!(cli.min_layer_size, 1024 * 1024, "input {arg}");
        }
    }

    #[test]
    fn min_layer_size_gigabyte_suffix() {
        let cli = parse(&["-o", "out", "--min-layer-size", "2G", "in"]).unwrap();
        assert_eq!(cli.min_layer_size, 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn min_layer_size_terabyte_suffix() {
        let cli = parse(&["-o", "out", "--min-layer-size", "3T", "in"]).unwrap();
        assert_eq!(cli.min_layer_size, 3 * 1024_u64.pow(4));
    }

    #[test]
    fn min_layer_size_default_matches_dissolve_constant() {
        let cli = parse(&["-o", "out", "in"]).unwrap();
        assert_eq!(cli.min_layer_size, DEFAULT_MIN_LAYER_SIZE);
    }

    #[test]
    fn min_layer_size_unknown_suffix_rejected() {
        let err = parse(&["-o", "out", "--min-layer-size", "16x", "in"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn min_layer_size_empty_rejected() {
        let err = parse(&["-o", "out", "--min-layer-size", "", "in"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn min_layer_size_suffix_only_rejected() {
        let err = parse(&["-o", "out", "--min-layer-size", "k", "in"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn min_layer_size_overflow_rejected() {
        // 9 EiB (= 9 * 2^60) overflows u64 by a factor of ~16. The
        // raw u64 max is ~16 EiB but `9T` is ~9 * 2^40, which is fine,
        // so we exercise the overflow path with a value past T-scale.
        let err = parse(&["-o", "out", "--min-layer-size", "18446744073709551615T", "in"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn min_layer_size_internal_whitespace_rejected() {
        let err = parse(&["-o", "out", "--min-layer-size", "16 k", "in"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn force_flag() {
        let cli = parse(&["-o", "out", "--force", "in"]).unwrap();
        assert!(cli.force);
    }

    #[test]
    fn timestamp_positive() {
        let cli = parse(&["-o", "out", "--timestamp", "1700000000", "in"]).unwrap();
        assert_eq!(cli.timestamp, Some(1_700_000_000));
    }

    #[test]
    fn timestamp_negative() {
        // Spec 06 §6.6: pre-1970 sentinels survive verbatim. `clap`
        // would normally treat a hyphen as a flag introducer; we
        // override with `allow_hyphen_values`.
        let cli = parse(&["-o", "out", "--timestamp", "-1", "in"]).unwrap();
        assert_eq!(cli.timestamp, Some(-1));
    }

    #[test]
    fn timestamp_unparseable_rejected() {
        let err = parse(&["-o", "out", "--timestamp", "yesterday", "in"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn jobs_explicit() {
        let cli = parse(&["-o", "out", "--jobs", "4", "in"]).unwrap();
        assert_eq!(cli.jobs, 4);
    }

    #[test]
    fn jobs_zero_means_auto() {
        // `0` is forwarded verbatim; the assemble pipeline maps it
        // onto rayon's logical-CPU default (spec 07 §7.5).
        let cli = parse(&["-o", "out", "--jobs", "0", "in"]).unwrap();
        assert_eq!(cli.jobs, 0);
    }

    #[test]
    fn scratch_path() {
        let cli = parse(&["-o", "out", "--scratch", "/tmp/cs", "in"]).unwrap();
        assert_eq!(cli.scratch, Some(PathBuf::from("/tmp/cs")));
    }

    #[test]
    fn verbose_count() {
        let cli = parse(&["-o", "out", "-v", "in"]).unwrap();
        assert_eq!(cli.verbose, 1);
        let cli = parse(&["-o", "out", "-vv", "in"]).unwrap();
        assert_eq!(cli.verbose, 2);
        let cli = parse(&["-o", "out", "-vvv", "in"]).unwrap();
        assert_eq!(cli.verbose, 3);
    }

    #[test]
    fn quiet_flag() {
        let cli = parse(&["-o", "out", "-q", "in"]).unwrap();
        assert!(cli.quiet);
    }

    #[test]
    fn verbose_and_quiet_conflict() {
        // Spec 10 §10.4: `-v` and `-q` are mutually exclusive — clap
        // surfaces this as `ArgumentConflict`, which `main.rs` will
        // map onto exit code 2 per spec 10 §10.7.
        let err = parse(&["-o", "out", "-v", "-q", "in"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn dry_run_flag() {
        let cli = parse(&["-o", "out", "--dry-run", "in"]).unwrap();
        assert!(cli.dry_run);
    }

    #[test]
    fn unknown_flag_rejected() {
        let err = parse(&["-o", "out", "--no-such-flag", "in"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn version_flag_emits_version() {
        // `--version` is a clap-builtin "successful" exit; the kind
        // distinguishes it from a true error.
        let err = parse(&["--version"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn help_flag_emits_help() {
        let err = parse(&["--help"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn parse_size_accepts_zero_with_suffix() {
        assert_eq!(parse_size("0k").unwrap(), 0);
    }

    #[test]
    fn parse_size_rejects_pure_whitespace() {
        assert!(parse_size("   ").is_err());
    }
}
