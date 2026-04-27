//! Squashing pass (spec 03).
//!
//! Pipeline order, per spec 03:
//! 1. [`apply`]   — fold the input image's layer stack into a
//!    [`index::SquashedFs`], decoding whiteouts / opaque-dir markers
//!    via the index's subtree primitives (spec 03 §3.2).
//! 2. [`hardlink`] — resolve every surviving `Hardlink` entry,
//!    demoting links whose target was whited out to regular files
//!    pointing at the originating layer's body bytes (spec 03 §3.3).

pub mod apply;
pub mod hardlink;
pub mod index;
