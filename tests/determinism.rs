//! Determinism regression test (spec 11 §11.6.1).
//!
//! Runs the binary twice on a pinned input set with a pinned `T0` and
//! asserts the outputs are byte-identical:
//!
//! * For `--layout tar` (the default): the outer tar bytes — and
//!   therefore every blob, `index.json`, and `oci-layout` packed inside
//!   it — must match.
//! * For `--layout dir`: every file in the staged output tree
//!   (`blobs/sha256/*`, `index.json`, `oci-layout`) must have identical
//!   bytes between runs.
//!
//! Both shapes share the same byte-level pipeline (spec 11 §11.1), but
//! exercising both pins regressions in the packagers (`output::tar` /
//! `output::dir`) too — the dir packager uses lex-sorted directory
//! traversal while the tar packager re-emits via `tar_io::writer`, and
//! either could leak nondeterminism without the other noticing.
//!
//! When `hack/images/` is populated (per the spec 00 §0.6 prepare
//! script), each subdirectory under it is also exercised; absent or
//! empty `hack/images/` is silently skipped per spec 00 §0.6 — we don't
//! require ad-hoc fixtures to be present in CI.

mod support;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use support::synthetic::SyntheticImage;
use tempfile::TempDir;

const PINNED_T0: &str = "1700000000";

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_container-squash"))
}

/// Run the binary on `inputs` with the given `--layout`, return the
/// status output. Panics on spawn failure.
fn run_tool(inputs: &[&Path], output: &Path, layout: &str) -> std::process::Output {
    let mut cmd = bin();
    cmd.args(["--layout", layout, "--timestamp", PINNED_T0, "--output"]);
    cmd.arg(output);
    for p in inputs {
        cmd.arg(p);
    }
    cmd.output().expect("spawn container-squash")
}

/// Walk a directory tree and collect `(relative path -> bytes)` for
/// every regular file. Path keys go through a `BTreeMap` so iteration
/// order is lex and the pretty-printed diff (if any) is stable.
fn collect_dir_bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries: Vec<_> = fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
            .map(|e| e.unwrap())
            .collect();
        // Sort for a stable walk — read_dir's order is filesystem-
        // dependent and would make any failure message non-reproducible.
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let ft = entry.file_type().unwrap();
            if ft.is_dir() {
                walk(root, &path, out);
            } else if ft.is_file() {
                let rel = path.strip_prefix(root).unwrap().to_path_buf();
                let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                out.insert(rel, bytes);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// Assert two runs of the tool on the same inputs produce byte-identical
/// tar output. Used by both the synthetic and the optional
/// `hack/images/` corpora.
fn assert_tar_run_is_deterministic(inputs: &[&Path]) {
    let td = TempDir::new().unwrap();
    let out_a = td.path().join("a.tar");
    let out_b = td.path().join("b.tar");

    let r_a = run_tool(inputs, &out_a, "tar");
    assert_eq!(
        r_a.status.code(),
        Some(0),
        "first run failed: stderr={}",
        String::from_utf8_lossy(&r_a.stderr)
    );
    let r_b = run_tool(inputs, &out_b, "tar");
    assert_eq!(
        r_b.status.code(),
        Some(0),
        "second run failed: stderr={}",
        String::from_utf8_lossy(&r_b.stderr)
    );

    let bytes_a = fs::read(&out_a).expect("read first tar");
    let bytes_b = fs::read(&out_b).expect("read second tar");
    assert_eq!(
        bytes_a.len(),
        bytes_b.len(),
        "tar size diverged: {} vs {}",
        bytes_a.len(),
        bytes_b.len()
    );
    assert!(
        bytes_a == bytes_b,
        "outer tar bytes diverged between runs (size {})",
        bytes_a.len()
    );
}

fn assert_dir_run_is_deterministic(inputs: &[&Path]) {
    let td = TempDir::new().unwrap();
    let out_a = td.path().join("a");
    let out_b = td.path().join("b");

    let r_a = run_tool(inputs, &out_a, "dir");
    assert_eq!(
        r_a.status.code(),
        Some(0),
        "first run failed: stderr={}",
        String::from_utf8_lossy(&r_a.stderr)
    );
    let r_b = run_tool(inputs, &out_b, "dir");
    assert_eq!(
        r_b.status.code(),
        Some(0),
        "second run failed: stderr={}",
        String::from_utf8_lossy(&r_b.stderr)
    );

    let map_a = collect_dir_bytes(&out_a);
    let map_b = collect_dir_bytes(&out_b);

    let keys_a: Vec<_> = map_a.keys().collect();
    let keys_b: Vec<_> = map_b.keys().collect();
    assert_eq!(keys_a, keys_b, "set of files in dir layout diverged");

    for (path, bytes_a) in &map_a {
        let bytes_b = &map_b[path];
        assert!(
            bytes_a == bytes_b,
            "bytes diverged between runs for {} (size {} vs {})",
            path.display(),
            bytes_a.len(),
            bytes_b.len()
        );
    }
}

/// Synthetic single-image fixture, tar layout (the default).
#[test]
fn synthetic_single_image_tar_layout_is_deterministic() {
    let td = TempDir::new().unwrap();
    let input = td.path().join("in");
    SyntheticImage::canonical().write_dir_transport(&input).unwrap();

    assert_tar_run_is_deterministic(&[&input]);
}

/// Synthetic single-image fixture, dir layout. Exercises the
/// `output::dir` packager's canonical-bytes path independently of the
/// tar packager.
#[test]
fn synthetic_single_image_dir_layout_is_deterministic() {
    let td = TempDir::new().unwrap();
    let input = td.path().join("in");
    SyntheticImage::canonical().write_dir_transport(&input).unwrap();

    assert_dir_run_is_deterministic(&[&input]);
}

/// Two synthetic inputs in argv order `[A, B]` vs `[B, A]` must produce
/// byte-identical output — spec 11 §11.3 canonicalises argv order by
/// lex-sorting absolute paths before assigning `image_id`s.
#[test]
fn argv_order_invariant_tar_layout() {
    let td = TempDir::new().unwrap();
    let in_a = td.path().join("a-input");
    let in_b = td.path().join("b-input");
    SyntheticImage::canonical().write_dir_transport(&in_a).unwrap();
    SyntheticImage::canonical().write_dir_transport(&in_b).unwrap();

    let out_forward = td.path().join("forward.tar");
    let out_reverse = td.path().join("reverse.tar");

    let r1 = run_tool(&[&in_a, &in_b], &out_forward, "tar");
    assert_eq!(
        r1.status.code(),
        Some(0),
        "forward run failed: stderr={}",
        String::from_utf8_lossy(&r1.stderr)
    );
    let r2 = run_tool(&[&in_b, &in_a], &out_reverse, "tar");
    assert_eq!(
        r2.status.code(),
        Some(0),
        "reverse run failed: stderr={}",
        String::from_utf8_lossy(&r2.stderr)
    );

    let bytes_forward = fs::read(&out_forward).unwrap();
    let bytes_reverse = fs::read(&out_reverse).unwrap();
    assert!(
        bytes_forward == bytes_reverse,
        "argv order leaked into output bytes (size {} vs {})",
        bytes_forward.len(),
        bytes_reverse.len()
    );
}

/// Walk every subdirectory of `hack/images/` (if present) and run the
/// determinism check against each one. Skips silently — with a clear
/// `eprintln!` — when the corpus isn't materialised, per spec 00 §0.6
/// fixture-skip behaviour. This is the optional "real images" arm of
/// spec 11 §11.6.1; the synthetic tests above are the always-on arm.
#[test]
fn hack_images_corpus_is_deterministic() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("hack/images");
    if !corpus.is_dir() {
        eprintln!(
            "skipping hack/images determinism test: {} is absent (run hack/prepare_images.sh to populate)",
            corpus.display()
        );
        return;
    }

    let mut subdirs: Vec<PathBuf> = fs::read_dir(&corpus)
        .expect("read hack/images")
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|ft| ft.is_dir()))
        .map(|e| e.path())
        .collect();
    subdirs.sort();

    if subdirs.is_empty() {
        eprintln!(
            "skipping hack/images determinism test: {} contains no fixture subdirectories",
            corpus.display()
        );
        return;
    }

    for fixture in &subdirs {
        eprintln!("determinism check: {}", fixture.display());
        assert_tar_run_is_deterministic(&[fixture.as_path()]);
    }
}
