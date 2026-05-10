//! Round-trip correctness regression test (spec 11 §11.5 / §11.6.2).
//!
//! For every input image, build `FS(i)` from the input layer stack and
//! `FS'(i)` from the squashed output's layer stack, then assert
//! [`fs_verify::diff`] reports no differences. The permitted exceptions
//! from spec 11 §11.5 (mtime / `uname` / `gname`) are absent from
//! [`fs_verify::FsNode`] entirely, so any other discrepancy — kind,
//! mode, uid/gid, body bytes, xattrs, hardlink topology — surfaces as a
//! hard failure here.
//!
//! Two always-on cases exercise the synthetic fixture (single-image and
//! two-image-with-shared-layer); a third case sweeps `hack/images/` when
//! present, skipping silently per spec 00 §0.6 when the corpus has not
//! been materialised.

mod support;

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;

use layermeld::input::{self, DirTransportReader, DockerArchiveReader, InputImage, Layout, OciLayoutReader};
use support::fs_verify::{InMemoryFs, diff};
use support::synthetic::SyntheticImage;
use tempfile::TempDir;

const PINNED_T0: &str = "1700000000";

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_layermeld"))
}

/// Run the binary with `--layout dir` so we can read the output back via
/// [`OciLayoutReader`] without first having to unpack a tar.
///
/// The child's stdout/stderr are tee'd live to the test process's own
/// stdout/stderr (visible under `cargo test -- --nocapture`) while also
/// being captured into the returned [`Output`], so a slow run is
/// observable in real time without losing the buffered text the
/// assertions later use for failure messages.
fn run_tool_dir(inputs: &[&Path], output: &Path) -> Output {
    let mut cmd = bin();
    cmd.args(["--layout", "dir", "--timestamp", PINNED_T0, "--output"]);
    cmd.arg(output);
    for p in inputs {
        cmd.arg(p);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn layermeld");

    let child_stdout = child.stdout.take().expect("stdout piped");
    let child_stderr = child.stderr.take().expect("stderr piped");

    let stdout_thread = thread::spawn(move || tee_to(child_stdout, std::io::stdout()));
    let stderr_thread = thread::spawn(move || tee_to(child_stderr, std::io::stderr()));

    let status = child.wait().expect("wait layermeld");
    let stdout = stdout_thread.join().expect("stdout tee thread");
    let stderr = stderr_thread.join().expect("stderr tee thread");

    Output { status, stdout, stderr }
}

/// Drain `src` to EOF, mirroring every chunk to `sink` (flushed eagerly
/// so the user sees output as it arrives) while accumulating the full
/// stream into a `Vec<u8>` for the caller to retain.
fn tee_to<R: Read, W: Write>(mut src: R, mut sink: W) -> Vec<u8> {
    let mut captured = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match src.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                captured.extend_from_slice(&buf[..n]);
                let _ = sink.write_all(&buf[..n]);
                let _ = sink.flush();
            }
        }
    }
    captured
}

/// Open `path` through the same detection + reader path the production
/// pipeline uses, so the round-trip exercises the real input ingest
/// rather than a parallel test-only parser.
fn load_images(path: &Path) -> Vec<InputImage> {
    let layout = input::detect(path).unwrap_or_else(|e| panic!("detect {}: {e}", path.display()));
    match layout {
        Layout::OciLayoutDir | Layout::OciLayoutTar => OciLayoutReader::open(path)
            .unwrap_or_else(|e| panic!("open OCI layout {}: {e}", path.display()))
            .into_images()
            .unwrap_or_else(|e| panic!("normalise OCI layout {}: {e}", path.display())),
        Layout::DirTransport => DirTransportReader::open(path)
            .unwrap_or_else(|e| panic!("open dir-transport {}: {e}", path.display()))
            .into_images()
            .unwrap_or_else(|e| panic!("normalise dir-transport {}: {e}", path.display())),
        Layout::DockerArchive | Layout::DockerArchiveDir => DockerArchiveReader::open(path)
            .unwrap_or_else(|e| panic!("open docker-archive {}: {e}", path.display()))
            .into_images()
            .unwrap_or_else(|e| panic!("normalise docker-archive {}: {e}", path.display())),
    }
}

/// Apply an image's layer stack into an in-memory filesystem.
///
/// Each [`LayerHandle::open`] returns a fresh decompressed tar stream;
/// they are collected into a `Vec<Box<dyn Read>>` and handed to
/// [`InMemoryFs::apply_layers`] in bottom-up order (the order
/// [`InputImage::layers`] is documented to carry).
fn build_fs(image: &InputImage) -> InMemoryFs {
    let mut layers: Vec<Box<dyn Read>> = Vec::with_capacity(image.layers.len());
    for handle in &image.layers {
        layers.push(handle.open().expect("open layer"));
    }
    InMemoryFs::apply_layers(layers).expect("apply layers")
}

/// Output OCI layouts may contain one index entry per (image,
/// `repo_tag`), so an N-tag input becomes N identical entries pointing
/// at the same manifest digest. For round-trip purposes only the unique
/// manifests matter — collapse duplicates while preserving
/// first-occurrence order so the result still aligns with input-image
/// order.
fn dedupe_by_layer_digests(images: Vec<InputImage>) -> Vec<InputImage> {
    let mut seen: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut out = Vec::with_capacity(images.len());
    for img in images {
        let key: Vec<String> = img.layers.iter().map(|h| h.digest.to_string()).collect();
        if seen.insert(key) {
            out.push(img);
        }
    }
    out
}

/// Run the tool on `input` and assert every input image's filesystem
/// round-trips through the squashed output unchanged (spec 11 §11.5).
fn assert_round_trip(input: &Path) {
    let td = TempDir::new().unwrap();
    let output = td.path().join("out");
    let result = run_tool_dir(&[input], &output);
    assert_eq!(
        result.status.code(),
        Some(0),
        "tool failed for {}: stderr={}",
        input.display(),
        String::from_utf8_lossy(&result.stderr),
    );

    let inputs = load_images(input);
    let outputs = dedupe_by_layer_digests(load_images(&output));

    assert_eq!(
        inputs.len(),
        outputs.len(),
        "input/output image count mismatch for {} ({} input vs {} unique-manifest output)",
        input.display(),
        inputs.len(),
        outputs.len(),
    );

    for (i, (lhs, rhs)) in inputs.iter().zip(outputs.iter()).enumerate() {
        let fs_in = build_fs(lhs);
        let fs_out = build_fs(rhs);
        if let Err(msg) = diff(&fs_in, &fs_out) {
            panic!("round-trip diverged for image {i} of {}:\n{msg}", input.display());
        }
    }
}

/// Single-image synthetic fixture covering every entry kind plus xattrs,
/// setuid, sticky, and non-zero uid/gid (spec 11 §11.6.2). The
/// always-on canary that fails loudly on any ownership / mode / xattr /
/// hardlink-topology regression.
#[test]
fn synthetic_single_image_round_trip() {
    let td = TempDir::new().unwrap();
    let input = td.path().join("in");
    SyntheticImage::canonical().write_dir_transport(&input).unwrap();

    assert_round_trip(&input);
}

/// Two distinct inputs that happen to carry byte-identical layers: the
/// dedup pass collapses the shared content into one `L({0,1})`, which
/// then dissolves below the default `--min-layer-size` into per-image
/// `L({i})` fallbacks. Round-trip still has to reproduce the original
/// FS for each image — exercises the shared-layer placement + dissolve
/// migration (spec 05 §5.3 / §5.4 / §5.5) end-to-end, and pins the
/// leaf-directory regression where `tmp` used to vanish from the
/// dissolved output.
#[test]
fn synthetic_two_image_shared_layer_round_trip() {
    let td = TempDir::new().unwrap();
    let in_a = td.path().join("a");
    let in_b = td.path().join("b");
    SyntheticImage::canonical().write_dir_transport(&in_a).unwrap();
    SyntheticImage::canonical().write_dir_transport(&in_b).unwrap();

    let output = td.path().join("out");
    let result = run_tool_dir(&[&in_a, &in_b], &output);
    assert_eq!(
        result.status.code(),
        Some(0),
        "tool failed: stderr={}",
        String::from_utf8_lossy(&result.stderr),
    );

    let in_imgs = {
        let mut v = load_images(&in_a);
        v.extend(load_images(&in_b));
        v
    };
    // Both inputs are untagged dir-transport images, so the output
    // index carries exactly one descriptor per input image (spec 09
    // §9.2). When the two inputs happen to be byte-identical the dedup
    // pass collapses them onto a single shared layer and both output
    // descriptors point at the same manifest digest — that is fine,
    // the per-image stack at runtime is still `[L({0,1})]` for each,
    // so applying it must reproduce the input FS for both. No
    // deduplication on the output side here.
    let out_imgs = load_images(&output);

    assert_eq!(in_imgs.len(), 2, "two inputs expected");
    assert_eq!(
        out_imgs.len(),
        2,
        "expected one output index entry per untagged input image",
    );

    for (i, (lhs, rhs)) in in_imgs.iter().zip(out_imgs.iter()).enumerate() {
        let fs_in = build_fs(lhs);
        let fs_out = build_fs(rhs);
        if let Err(msg) = diff(&fs_in, &fs_out) {
            panic!("round-trip diverged for image {i}:\n{msg}");
        }
    }
}

/// Walk every subdirectory of `hack/images/` (if present) and run the
/// round-trip check against each one. Skips silently — with a clear
/// `eprintln!` — when the corpus isn't materialised, per spec 00 §0.6
/// fixture-skip behaviour.
#[test]
fn hack_images_corpus_round_trip() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("hack/images");
    if !corpus.is_dir() {
        eprintln!(
            "skipping hack/images round-trip test: {} is absent (run hack/prepare_images.sh to populate)",
            corpus.display(),
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
            "skipping hack/images round-trip test: {} contains no fixture subdirectories",
            corpus.display(),
        );
        return;
    }

    for fixture in &subdirs {
        eprintln!("round-trip check: {}", fixture.display());
        assert_round_trip(fixture);
    }
}
