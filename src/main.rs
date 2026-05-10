//! Thin CLI shell. Parses argv into a [`Config`], calls [`run`], prints
//! the summary, maps errors to exit codes per spec 10 §10.7.
//!
//! Pipeline logic lives in the library crate; this file deliberately
//! contains no behaviour beyond argv-to-Config translation, exit-code
//! mapping, and stdout/stderr discipline (spec 10 §10.8):
//!
//! * Stdout — the run summary on success, nothing on failure.
//! * Stderr — log events from `tracing-subscriber` and the final error
//!   message on failure.
//!
//! Exit codes (spec 10 §10.7):
//!
//! | code | meaning                                                   |
//! |------|-----------------------------------------------------------|
//! | 0    | success                                                   |
//! | 1    | generic failure ([`Error::Io`] / [`Error::MalformedInput`] / [`Error::Validation`]) |
//! | 2    | bad CLI usage ([`Error::Usage`]) — clap also exits 2 on argv-shape errors before this binary runs any pipeline code |
//! | 3    | output destination already exists ([`Error::OutputExists`]) |
//! | 4    | input digest verification failed ([`Error::DigestMismatch`]) |
//!
//! The exit-code-2 contract — "no file written or moved" — is upheld by
//! the order of operations in [`run`]: argv-shape errors come out of
//! clap before any filesystem touch; [`Config::from_cli`] only reads
//! input paths (it does not create the output, scratch, or move-aside
//! locations); the destination collision check that produces exit 3
//! and the digest verification that produces exit 4 both run before
//! the first byte is written under the output destination.

use std::process::ExitCode;

use clap::Parser;

use layermeld::cli::Cli;
use layermeld::config::Config;
use layermeld::{Error, logging, run};

fn main() -> ExitCode {
    // clap handles `--help` / `--version` (exits 0) and argv-shape
    // errors (exits 2) itself, before we touch anything. Both match
    // spec 10 §10.7.
    let cli = Cli::parse();
    let verbose = cli.verbose;
    let quiet = cli.quiet;

    // Logging subscribes to stderr (spec 10 §10.8). A failure here only
    // means a subscriber was already installed in this process, which
    // cannot happen in the binary entry point — but treating it as
    // fatal would be hostile, so we ignore the error and continue.
    let _ = logging::init(verbose, quiet);

    let config = match Config::from_cli(cli) {
        Ok(c) => c,
        Err(e) => return report_error(&e),
    };

    let summary = match run(&config) {
        Ok(s) => s,
        Err(e) => return report_error(&e),
    };

    // Spec 10 §10.6 / §10.8: summary on stdout post-rename, suppressed
    // by `--quiet`.
    if !quiet {
        println!("{summary}");
    }
    ExitCode::SUCCESS
}

fn report_error(err: &Error) -> ExitCode {
    eprintln!("error: {err}");
    // exit_code() returns one of 1/2/3/4, all in u8 range.
    ExitCode::from(u8::try_from(err.exit_code()).unwrap_or(1))
}
