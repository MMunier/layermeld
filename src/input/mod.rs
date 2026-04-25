//! Input format detection and parsing (spec 01).
//!
//! `detect()` (1.6) inspects a path and dispatches to one of the
//! transport-specific readers. Every reader normalises its findings
//! into the shared `InputImage` model.

pub mod dir_transport;
pub mod docker_archive;
pub mod oci_layout;
