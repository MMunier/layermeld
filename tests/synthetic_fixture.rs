//! Smoke tests for the synthetic fixture builder used by the
//! round-trip + determinism test families (spec 11 §11.6.2).
//!
//! These tests pin two contracts the future round-trip / determinism
//! corpora rely on:
//!
//! 1. The fixture covers every entry kind the writer can emit.
//! 2. The dir-transport materialisation is parseable end-to-end —
//!    the `layermeld` binary can squash it without erroring.

mod support;

use std::collections::HashSet;
use std::process::Command;

use layermeld::tar_io::reader::{EntryKind, Reader};

use support::synthetic::SyntheticImage;
use tempfile::TempDir;

/// Round-trip the canonical fixture's tar bytes through the reader and
/// assert every entry kind from spec 11 §11.6.2 surfaces.
#[test]
fn canonical_fixture_covers_every_entry_kind() {
    let img = SyntheticImage::canonical();
    let bytes = img.layer_tar();

    let mut reader = Reader::new(std::io::Cursor::new(bytes));
    let mut kinds: HashSet<EntryKind> = HashSet::new();
    let mut entries = reader.entries().unwrap();
    for entry in entries.by_ref() {
        let entry = entry.unwrap();
        kinds.insert(entry.meta().kind);
    }

    for required in [
        EntryKind::Regular,
        EntryKind::Directory,
        EntryKind::Symlink,
        EntryKind::Hardlink,
        EntryKind::CharDevice,
        EntryKind::BlockDevice,
        EntryKind::Fifo,
    ] {
        assert!(kinds.contains(&required), "missing entry kind: {required:?}");
    }
}

/// Setuid, sticky, non-zero ownership, and xattrs all survive a tar
/// round trip — these are the "metadata corners" spec 11 §11.5
/// requires the round-trip test to verify.
#[test]
fn canonical_fixture_carries_metadata_corners() {
    let img = SyntheticImage::canonical();
    let bytes = img.layer_tar();

    let mut reader = Reader::new(std::io::Cursor::new(bytes));
    let mut entries = reader.entries().unwrap();

    let mut saw_setuid = false;
    let mut saw_sticky = false;
    let mut saw_nonzero_owner = false;
    let mut saw_xattr = false;

    for entry in entries.by_ref() {
        let entry = entry.unwrap();
        let m = entry.meta();
        if m.mode & 0o4000 != 0 {
            saw_setuid = true;
        }
        if m.mode & 0o1000 != 0 {
            saw_sticky = true;
        }
        if m.uid != 0 || m.gid != 0 {
            saw_nonzero_owner = true;
        }
        if !m.xattrs.is_empty() {
            saw_xattr = true;
        }
    }

    assert!(saw_setuid, "fixture is missing a setuid entry");
    assert!(saw_sticky, "fixture is missing a sticky-bit entry");
    assert!(saw_nonzero_owner, "fixture is missing a non-zero uid/gid entry");
    assert!(saw_xattr, "fixture is missing an xattr-bearing entry");
}

/// The dir-transport materialisation produces the three artefacts the
/// `dir:` transport reader expects and the binary can consume them
/// end-to-end without erroring.
#[test]
fn dir_transport_image_is_squashable_end_to_end() {
    let td = TempDir::new().unwrap();
    let input_root = td.path().join("in");
    let artifact = SyntheticImage::canonical().write_dir_transport(&input_root).unwrap();

    assert!(artifact.root.join("manifest.json").is_file());
    assert!(artifact.root.join(&artifact.layer_hex).is_file());
    assert!(artifact.root.join(&artifact.config_hex).is_file());

    let output = td.path().join("out.tar");
    let status = Command::new(env!("CARGO_BIN_EXE_layermeld"))
        .args([
            "--output",
            output.to_str().unwrap(),
            "--timestamp",
            "1700000000",
            input_root.to_str().unwrap(),
        ])
        .output()
        .expect("spawn layermeld");

    assert_eq!(
        status.status.code(),
        Some(0),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&status.stderr),
        String::from_utf8_lossy(&status.stdout),
    );
    assert!(output.is_file(), "tool did not produce the output tar");
}
