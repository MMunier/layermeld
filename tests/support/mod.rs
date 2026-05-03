//! Shared test helpers. Each top-level integration test file pulls this
//! in via `mod support;` (Cargo treats subdirectories under `tests/` as
//! module trees rather than separate test binaries).
//!
//! The `dead_code` allow is necessary because each integration test
//! binary only references a subset of these helpers — Cargo compiles
//! one binary per file under `tests/` and runs dead-code analysis per
//! binary, so anything not used by a particular consumer warns.

#![allow(dead_code)]

pub mod fs_verify;
pub mod synthetic;
