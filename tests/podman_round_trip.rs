//! End-to-end round-trip through a real container runtime (podman).
//!
//! Mirrors `round_trip.rs`, but instead of unpacking the squashed
//! output back into an [`InMemoryFs`] via the in-tree tar reader, the
//! squashed layout is `podman load`-ed and the rootfs is recovered
//! with `podman create` + `podman export`. The verifier then asserts
//! that, for each input image, the tar produced by `podman export` of
//! the *original* image matches the tar produced by `podman export` of
//! the corresponding image in the merged squashed output, modulo the
//! spec 11 §11.5 axes (mtime / uname / gname).
//!
//! Pulling two real postgres images is required and slow, so the test
//! skips cleanly when podman is missing or `podman pull` fails (no
//! network, registry outage, etc.) — same skip-when-fixture-absent
//! pattern the rest of the integration suite uses.
//!
//! Cleanup: every podman image and container created here is named
//! with a per-process suffix and dropped by a [`PodmanCleanup`] guard
//! in `Drop`, so a panicking test still leaves the user's podman
//! storage as it was.

mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use support::fs_verify::{InMemoryFs, diff};
use tempfile::TempDir;

const PINNED_T0: &str = "1700000000";
const TAG_A: &str = "17.9-trixie";
const TAG_B: &str = "18.3-trixie";

fn have(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn podman(args: &[&str]) -> Output {
    Command::new("podman").args(args).output().expect("spawn podman")
}

fn podman_must(args: &[&str]) -> String {
    let out = podman(args);
    assert!(
        out.status.success(),
        "podman {args:?} failed:\n  stdout: {}\n  stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Container/image names created by the test, dropped on `Drop` so a
/// panic mid-test still cleans up. `rmi -f` removes the image and any
/// containers that reference it; we additionally `rm -f` containers
/// individually since `podman export` of a container created from a
/// since-removed image works but the container row lingers.
struct PodmanCleanup {
    images: Vec<String>,
    containers: Vec<String>,
}

impl PodmanCleanup {
    fn new() -> Self {
        Self { images: Vec::new(), containers: Vec::new() }
    }
    fn track_image(&mut self, image: &str) {
        self.images.push(image.to_string());
    }
    fn track_container(&mut self, cid: &str) {
        self.containers.push(cid.to_string());
    }
}

impl Drop for PodmanCleanup {
    fn drop(&mut self) {
        for cid in &self.containers {
            let _ = podman(&["rm", "-f", cid]);
        }
        for img in &self.images {
            let _ = podman(&["rmi", "-f", img]);
        }
    }
}

/// `podman create` + `podman export` to `tar_path`. Records the
/// transient container with `cleanup` so it is removed even if a later
/// step panics.
fn export_rootfs(image_ref: &str, tar_path: &Path, cleanup: &mut PodmanCleanup) {
    let cid = podman_must(&["create", image_ref]);
    cleanup.track_container(&cid);

    let f = fs::File::create(tar_path)
        .unwrap_or_else(|e| panic!("create {}: {e}", tar_path.display()));
    let status = Command::new("podman")
        .args(["export", &cid])
        .stdout(f)
        .status()
        .expect("spawn podman export");
    assert!(status.success(), "podman export {cid} failed");
}

fn fs_from_tar(path: &Path) -> InMemoryFs {
    let f = fs::File::open(path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    InMemoryFs::apply_layers([f]).expect("apply rootfs tar")
}

fn run_squash(inputs: &[&Path], output: &Path) {
    let status = Command::new(env!("CARGO_BIN_EXE_container-squash"))
        .args(["--layout", "tar", "--timestamp", PINNED_T0, "--output"])
        .arg(output)
        .args(inputs)
        .status()
        .expect("spawn container-squash");
    assert!(status.success(), "container-squash failed for inputs {inputs:?}");
}

/// Pull the two postgres tags, save each as a separate docker-archive,
/// merge them with the tool, reload, and verify the per-tag rootfs
/// matches what podman produced for the originals.
#[test]
fn merged_postgres_images_match_originals_through_podman() {
    if !have("podman") {
        eprintln!("skipping podman_round_trip: podman not in PATH");
        return;
    }

    let pid = std::process::id();
    let cs_a = format!("localhost/cs-test-pg17:t{pid}");
    let cs_b = format!("localhost/cs-test-pg18:t{pid}");

    let mut cleanup = PodmanCleanup::new();
    cleanup.track_image(&cs_a);
    cleanup.track_image(&cs_b);

    let upstream_a = format!("docker.io/library/postgres:{TAG_A}");
    let upstream_b = format!("docker.io/library/postgres:{TAG_B}");
    if !podman(&["pull", "--quiet", &upstream_a]).status.success()
        || !podman(&["pull", "--quiet", &upstream_b]).status.success()
    {
        eprintln!("skipping podman_round_trip: podman pull failed (no network or registry?)");
        return;
    }

    // Retag onto unique test-only refs so concurrent or repeated runs
    // do not collide on the upstream tags. The originals stay in
    // storage but are irrelevant past this point.
    podman_must(&["tag", &upstream_a, &cs_a]);
    podman_must(&["tag", &upstream_b, &cs_b]);

    // Source images + two rootfs exports + merged.tar + two more
    // rootfs exports easily exceed a few GiB, which a typical tmpfs
    // `/tmp` will reject with EDQUOT. Stage under cargo's per-target
    // tmpdir so the test uses the same disk-backed area as the build
    // tree.
    let td = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let arch_a = td.path().join("pg17.tar");
    let arch_b = td.path().join("pg18.tar");
    podman_must(&[
        "save", "--quiet", "--format", "docker-archive", "-o",
        arch_a.to_str().unwrap(), &cs_a,
    ]);
    podman_must(&[
        "save", "--quiet", "--format", "docker-archive", "-o",
        arch_b.to_str().unwrap(), &cs_b,
    ]);

    let orig_fs_a = td.path().join("orig-pg17.tar");
    let orig_fs_b = td.path().join("orig-pg18.tar");
    export_rootfs(&cs_a, &orig_fs_a, &mut cleanup);
    export_rootfs(&cs_b, &orig_fs_b, &mut cleanup);

    // Drop the originals from podman storage so the merged load
    // reinstates each tag from the squashed bytes alone — otherwise
    // `podman load` would no-op on already-present manifests and the
    // re-export would tautologically match the originals.
    podman_must(&["rmi", "-f", &cs_a, &cs_b]);

    let merged = td.path().join("merged.tar");
    run_squash(&[arch_a.as_path(), arch_b.as_path()], &merged);

    podman_must(&["load", "-i", merged.to_str().unwrap()]);

    let merged_fs_a = td.path().join("merged-pg17.tar");
    let merged_fs_b = td.path().join("merged-pg18.tar");
    export_rootfs(&cs_a, &merged_fs_a, &mut cleanup);
    export_rootfs(&cs_b, &merged_fs_b, &mut cleanup);

    let pairs: [(&PathBuf, &PathBuf, &str); 2] = [
        (&orig_fs_a, &merged_fs_a, &cs_a),
        (&orig_fs_b, &merged_fs_b, &cs_b),
    ];
    for (orig, merged, label) in pairs {
        let lhs = fs_from_tar(orig);
        let rhs = fs_from_tar(merged);
        if let Err(msg) = diff(&lhs, &rhs) {
            panic!("podman round-trip diverged for {label}:\n{msg}");
        }
    }
}
