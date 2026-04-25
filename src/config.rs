//! Typed configuration consumed by [`crate::run`].
//!
//! `main.rs` is the only place that builds a [`Config`] from argv;
//! library tests construct it directly. See spec 10 for the source CLI
//! and spec 11 §11.3 for the canonicalize-and-dedupe rule on input paths.
