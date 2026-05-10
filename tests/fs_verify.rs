//! Tests for the in-memory FS verifier (`tests/support/fs_verify.rs`).
//!
//! These pin the verifier itself before the round-trip / determinism
//! corpora rely on it. The verifier is the only place in the
//! repository that "unpacks" layers — a bug here would silently
//! invalidate every round-trip assertion downstream.

mod support;

use std::collections::BTreeSet;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use layermeld::tar_io::reader::EntryKind;
use sha2::{Digest as _, Sha256};
use tar::{Builder, EntryType, Header};

use support::fs_verify::{InMemoryFs, diff};
use support::synthetic::SyntheticImage;

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

struct TarEntry<'a> {
    path: &'a str,
    entry_type: EntryType,
    mode: u32,
    body: &'a [u8],
    link_target: Option<&'a str>,
}

fn file<'a>(path: &'a str, body: &'a [u8]) -> TarEntry<'a> {
    TarEntry {
        path,
        entry_type: EntryType::Regular,
        mode: 0o644,
        body,
        link_target: None,
    }
}

fn dir(path: &str) -> TarEntry<'_> {
    TarEntry {
        path,
        entry_type: EntryType::Directory,
        mode: 0o755,
        body: &[],
        link_target: None,
    }
}

fn whiteout(path: &str) -> TarEntry<'_> {
    TarEntry {
        path,
        entry_type: EntryType::Regular,
        mode: 0o000,
        body: &[],
        link_target: None,
    }
}

fn symlink<'a>(path: &'a str, target: &'a str) -> TarEntry<'a> {
    TarEntry {
        path,
        entry_type: EntryType::Symlink,
        mode: 0o777,
        body: &[],
        link_target: Some(target),
    }
}

fn hardlink<'a>(path: &'a str, target: &'a str) -> TarEntry<'a> {
    TarEntry {
        path,
        entry_type: EntryType::Link,
        mode: 0o644,
        body: &[],
        link_target: Some(target),
    }
}

fn build_tar(entries: &[TarEntry]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut tb = Builder::new(&mut buf);
        tb.mode(tar::HeaderMode::Deterministic);
        for e in entries {
            let mut h = Header::new_gnu();
            h.set_entry_type(e.entry_type);
            h.set_path(e.path).unwrap();
            if let Some(t) = e.link_target {
                h.set_link_name(t).unwrap();
            }
            h.set_mode(e.mode);
            h.set_uid(0);
            h.set_gid(0);
            h.set_size(e.body.len() as u64);
            h.set_cksum();
            tb.append(&h, e.body).unwrap();
        }
        tb.finish().unwrap();
    }
    buf
}

#[test]
fn single_layer_populates_paths_with_metadata_and_hashes() {
    let bytes = build_tar(&[
        dir("etc/"),
        file("etc/hostname", b"node\n"),
        symlink("etc/hostname.link", "hostname"),
    ]);
    let fs = InMemoryFs::apply_layers([Cursor::new(bytes)]).unwrap();

    assert_eq!(fs.nodes.len(), 3);
    let host = fs.nodes.get(Path::new("etc/hostname")).unwrap();
    assert_eq!(host.kind, EntryKind::Regular);
    assert_eq!(host.size, b"node\n".len() as u64);
    assert_eq!(host.content_hash, Some(sha256_of(b"node\n")));

    let link = fs.nodes.get(Path::new("etc/hostname.link")).unwrap();
    assert_eq!(link.kind, EntryKind::Symlink);
    assert_eq!(link.link_target.as_deref(), Some(Path::new("hostname")));
    assert!(link.content_hash.is_none());

    assert!(fs.hardlink_groups.is_empty(), "no hardlinks in this fixture");
}

#[test]
fn upper_layer_overwrites_lower_layer_metadata_and_body() {
    let lower = build_tar(&[file("etc/hostname", b"old\n")]);
    let upper = build_tar(&[file("etc/hostname", b"new-bytes\n")]);
    let fs = InMemoryFs::apply_layers([Cursor::new(lower), Cursor::new(upper)]).unwrap();

    let host = fs.nodes.get(Path::new("etc/hostname")).unwrap();
    assert_eq!(host.size, b"new-bytes\n".len() as u64);
    assert_eq!(host.content_hash, Some(sha256_of(b"new-bytes\n")));
}

#[test]
fn whiteouts_drop_target_and_marker_does_not_appear() {
    let lower = build_tar(&[dir("etc/"), file("etc/hostname", b"x"), file("etc/hosts", b"y")]);
    let upper = build_tar(&[whiteout("etc/.wh.hostname")]);
    let fs = InMemoryFs::apply_layers([Cursor::new(lower), Cursor::new(upper)]).unwrap();

    assert!(!fs.nodes.contains_key(Path::new("etc/hostname")));
    assert!(fs.nodes.contains_key(Path::new("etc/hosts")));
    assert!(!fs.nodes.contains_key(Path::new("etc/.wh.hostname")));
}

#[test]
fn whiteout_on_directory_drops_subtree() {
    let lower = build_tar(&[
        dir("var/"),
        dir("var/log/"),
        file("var/log/syslog", b"line1\n"),
        file("var/log/messages", b"line2\n"),
        file("var/run.pid", b"42"),
    ]);
    let upper = build_tar(&[whiteout("var/.wh.log")]);
    let fs = InMemoryFs::apply_layers([Cursor::new(lower), Cursor::new(upper)]).unwrap();

    assert!(fs.nodes.contains_key(Path::new("var")));
    assert!(!fs.nodes.contains_key(Path::new("var/log")));
    assert!(!fs.nodes.contains_key(Path::new("var/log/syslog")));
    assert!(!fs.nodes.contains_key(Path::new("var/log/messages")));
    assert!(fs.nodes.contains_key(Path::new("var/run.pid")));
}

#[test]
fn opaque_dir_clears_descendants_but_keeps_directory() {
    let lower = build_tar(&[
        dir("var/"),
        dir("var/cache/"),
        file("var/cache/a", b"a"),
        file("var/cache/b", b"b"),
    ]);
    let upper = build_tar(&[whiteout("var/cache/.wh..wh..opq")]);
    let fs = InMemoryFs::apply_layers([Cursor::new(lower), Cursor::new(upper)]).unwrap();

    assert!(fs.nodes.contains_key(Path::new("var/cache")));
    assert!(!fs.nodes.contains_key(Path::new("var/cache/a")));
    assert!(!fs.nodes.contains_key(Path::new("var/cache/b")));
    assert!(!fs.nodes.contains_key(Path::new("var/cache/.wh..wh..opq")));
}

#[test]
fn hardlinks_form_groups_and_inherit_terminal_metadata() {
    let bytes = build_tar(&[
        file("etc/hostname", b"node\n"),
        hardlink("etc/hostname.alias", "etc/hostname"),
        hardlink("etc/hostname.alias2", "etc/hostname.alias"),
    ]);
    let fs = InMemoryFs::apply_layers([Cursor::new(bytes)]).unwrap();

    // All three paths share an inode.
    assert_eq!(fs.hardlink_groups.len(), 1);
    let group = fs.hardlink_groups.iter().next().unwrap();
    let expected: BTreeSet<PathBuf> = [
        PathBuf::from("etc/hostname"),
        PathBuf::from("etc/hostname.alias"),
        PathBuf::from("etc/hostname.alias2"),
    ]
    .into_iter()
    .collect();
    assert_eq!(group, &expected);

    // Aliases inherited the regular's content hash.
    let want = sha256_of(b"node\n");
    for p in ["etc/hostname", "etc/hostname.alias", "etc/hostname.alias2"] {
        let node = fs.nodes.get(Path::new(p)).unwrap();
        assert_eq!(node.kind, EntryKind::Regular);
        assert_eq!(node.content_hash, Some(want));
        assert!(node.link_target.is_none(), "alias {p} should not retain link_target");
    }
}

#[test]
fn diff_accepts_two_independent_runs_of_the_canonical_fixture() {
    // Building the same fixture twice and applying it must produce
    // byte-equal `InMemoryFs` values — `mtime` is dropped at the
    // verifier level, so the two should compare equal even though the
    // tar bytes are themselves identical.
    let img = SyntheticImage::canonical();
    let bytes = img.layer_tar();
    let a = InMemoryFs::apply_layers([Cursor::new(bytes.clone())]).unwrap();
    let b = InMemoryFs::apply_layers([Cursor::new(bytes)]).unwrap();
    diff(&a, &b).expect("identical inputs must diff clean");
}

#[test]
fn diff_reports_path_set_differences() {
    let left = InMemoryFs::apply_layers([Cursor::new(build_tar(&[file("a", b"1"), file("b", b"2")]))]).unwrap();
    let right = InMemoryFs::apply_layers([Cursor::new(build_tar(&[file("a", b"1"), file("c", b"3")]))]).unwrap();
    let err = diff(&left, &right).unwrap_err();
    assert!(err.contains("only in left:  b"), "got: {err}");
    assert!(err.contains("only in right: c"), "got: {err}");
}

#[test]
fn diff_reports_per_path_metadata_differences() {
    let left = InMemoryFs::apply_layers([Cursor::new(build_tar(&[file("etc/hostname", b"a")]))]).unwrap();
    let right = InMemoryFs::apply_layers([Cursor::new(build_tar(&[file("etc/hostname", b"b")]))]).unwrap();
    let err = diff(&left, &right).unwrap_err();
    assert!(err.contains("etc/hostname differs"), "got: {err}");
}

#[test]
fn diff_reports_hardlink_topology_differences() {
    // Same path set + per-path metadata, but the right side has a
    // hardlink between them and the left does not.
    let left = build_tar(&[file("etc/a", b"x"), file("etc/b", b"x")]);
    let right = build_tar(&[file("etc/a", b"x"), hardlink("etc/b", "etc/a")]);
    let lf = InMemoryFs::apply_layers([Cursor::new(left)]).unwrap();
    let rf = InMemoryFs::apply_layers([Cursor::new(right)]).unwrap();
    let err = diff(&lf, &rf).unwrap_err();
    assert!(err.contains("hardlink topology differs"), "got: {err}");
}

#[test]
fn dot_slash_prefix_and_trailing_slash_are_normalised() {
    // Whiteout written as `./etc/.wh.foo` must drop the lower layer's
    // `etc/foo`; a directory written as `etc/` must key as `etc`.
    let lower = build_tar(&[dir("etc/"), file("etc/foo", b"old")]);
    let upper = build_tar(&[whiteout("./etc/.wh.foo")]);
    let fs = InMemoryFs::apply_layers([Cursor::new(lower), Cursor::new(upper)]).unwrap();
    assert!(fs.nodes.contains_key(Path::new("etc")));
    assert!(!fs.nodes.contains_key(Path::new("etc/foo")));
}

#[test]
fn missing_hardlink_target_surfaces_invalid_data_error() {
    // A hardlink whose target was never created in any layer is
    // self-inconsistent input; the verifier rejects it rather than
    // silently producing a partial FS.
    let bytes = build_tar(&[hardlink("etc/alias", "etc/never_existed")]);
    let err = InMemoryFs::apply_layers([Cursor::new(bytes)]).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("missing path"), "got: {err}");
}

#[test]
fn canonical_fixture_round_trips_through_the_verifier() {
    // The fixture covers every entry kind the writer can emit. Pin
    // that the verifier surfaces each expected path with the right
    // kind and the right content hash.
    let img = SyntheticImage::canonical();
    let fs = InMemoryFs::apply_layers([Cursor::new(img.layer_tar())]).unwrap();

    let kinds: BTreeSet<EntryKind> = fs.nodes.values().map(|n| n.kind).collect();
    for required in [
        EntryKind::Regular,
        EntryKind::Directory,
        EntryKind::Symlink,
        EntryKind::CharDevice,
        EntryKind::BlockDevice,
        EntryKind::Fifo,
    ] {
        assert!(kinds.contains(&required), "missing kind {required:?}");
    }

    // The hardlink in the canonical fixture (`etc/hostname.alias` →
    // `etc/hostname`) collapses to a Regular at unpack time, so the
    // alias should not appear with kind Hardlink.
    assert!(!kinds.contains(&EntryKind::Hardlink));
    assert_eq!(fs.hardlink_groups.len(), 1);
    let group = fs.hardlink_groups.iter().next().unwrap();
    assert!(group.contains(Path::new("etc/hostname")));
    assert!(group.contains(Path::new("etc/hostname.alias")));

    // Setuid bin survives.
    let setuid = fs.nodes.get(Path::new("bin/setuid-bin")).unwrap();
    assert_eq!(setuid.mode & 0o4000, 0o4000);
}
