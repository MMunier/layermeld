//! Thin CLI shell. Parses argv into a `Config`, calls `lib::run`, prints
//! the summary, maps errors to exit codes per spec 10 §10.7.
//!
//! Pipeline logic lives in the library crate; this file deliberately
//! contains no behaviour beyond argv-to-Config translation, exit-code
//! mapping, and stdout/stderr discipline (10 §10.8).

fn main() {
    // Stage skeleton — wired up in spec 10 implementation. Until then,
    // the binary is intentionally a no-op so that the project builds.
}
