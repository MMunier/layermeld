//! Shared test helpers. Each top-level integration test file pulls this
//! in via `mod support;` (Cargo treats subdirectories under `tests/` as
//! module trees rather than separate test binaries).

pub mod synthetic;
