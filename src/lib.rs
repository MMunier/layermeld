//! `container-squash` — deterministic OCI/Docker image squasher with
//! cross-image deduplication.
//!
//! The library exposes a single top-level entry point, [`run`], which
//! the `main.rs` shell drives after parsing CLI arguments. Every
//! pipeline stage lives in its own module; see `specs/00-project-structure.md`
//! for the module-to-spec mapping.

pub mod assemble;
pub mod cli;
pub mod config;
pub mod dedup;
pub mod error;
pub mod identity;
pub mod input;
pub mod logging;
pub mod oci;
pub mod output;
pub mod run;
pub mod squash;
pub mod summary;
pub mod tar_io;
pub mod timestamp;

pub use error::{Error, Result};
pub use run::run;
