//! End-to-end round-trip through a real container runtime (podman/docker).
//!
//! Mirrors `round_trip.rs`, but instead of unpacking the squashed
//! output back into an [`InMemoryFs`] via the in-tree tar reader, the
//! squashed layout is `podman/docker load`-ed and the rootfs is recovered
//! with `podman/docker create` + `podman/docker export`. The verifier then asserts
//! that, for each input image, the tar produced by `podman/docker export` of
//! the *original* image matches the tar produced by `podman/docker export` of
//! the corresponding image in the merged squashed output, modulo the
//! spec 11 §11.5 axes (mtime / uname / gname).
//!
//! Pulling two real postgres images is required and slow, so the test
//! skips cleanly when the container manager is missing or `pull` fails (no
//! network, registry outage, etc.) — same skip-when-fixture-absent
//! pattern the rest of the integration suite uses.
//!
//! Cleanup: every container image and container created here is named
//! with a per-process suffix and dropped by a [`ContainerCleanup`] guard
//! in `Drop`, so a panicking test still leaves the user's container
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

/// Abstraction over container managers (podman, docker, etc.)
/// that handle pulling, saving, loading, and exporting images.
trait ContainerManager {
    /// The binary name (e.g. "podman", "docker")
    fn binary_name(&self) -> &'static str;

    /// Check if the binary is available on PATH
    fn is_available(&self) -> bool {
        Command::new(self.binary_name())
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Run the container manager command with given args, return Output
    fn run(&self, args: &[&str]) -> Output {
        Command::new(self.binary_name())
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", self.binary_name()))
    }

    /// Run command and assert success, returning trimmed stdout
    fn must(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "{} {args:?} failed:\n  stdout: {}\n  stderr: {}",
            self.binary_name(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Pull an image; returns true on success, false on failure
    fn pull(&self, image: &str) -> bool;

    /// Tag an image from source to target
    fn tag(&self, source: &str, target: &str) {
        self.must(&["tag", source, target]);
    }

    /// Save an image to a docker-archive format file
    fn save(&self, image: &str, output: &Path);

    /// Load an image from a file
    fn load(&self, input: &Path) {
        self.must(&["load", "-i", input.to_str().unwrap()]);
    }

    /// Remove an image forcefully
    fn rmi(&self, image: &str) {
        let _ = self.run(&["rmi", "-f", image]);
    }

    /// Create a container from an image, returning container ID
    fn create(&self, image: &str) -> String {
        self.must(&["create", image])
    }

    /// Export a container's rootfs to a tar file
    fn export(&self, container: &str, output: &Path);
}

/// Podman implementation of `ContainerManager`
struct Podman;

impl ContainerManager for Podman {
    fn binary_name(&self) -> &'static str {
        "podman"
    }

    fn pull(&self, image: &str) -> bool {
        self.run(&["pull", "--quiet", image]).status.success()
    }

    fn save(&self, image: &str, output: &Path) {
        self.must(&[
            "save",
            "--quiet",
            "--format",
            "docker-archive",
            "-o",
            output.to_str().unwrap(),
            image,
        ]);
    }

    fn export(&self, container: &str, output: &Path) {
        let f = fs::File::create(output).unwrap_or_else(|e| panic!("create {}: {e}", output.display()));
        let status = Command::new(self.binary_name())
            .args(["export", container])
            .stdout(f)
            .status()
            .expect("spawn podman export");
        assert!(status.success(), "podman export {container} failed");
    }
}

/// Docker implementation of `ContainerManager`
struct Docker;

impl ContainerManager for Docker {
    fn binary_name(&self) -> &'static str {
        "docker"
    }

    fn pull(&self, image: &str) -> bool {
        self.run(&["pull", image]).status.success()
    }

    fn save(&self, image: &str, output: &Path) {
        self.must(&["save", "-o", output.to_str().unwrap(), image]);
    }

    fn export(&self, container: &str, output: &Path) {
        let f = fs::File::create(output).unwrap_or_else(|e| panic!("create {}: {e}", output.display()));
        let status = Command::new(self.binary_name())
            .args(["export", container])
            .stdout(f)
            .status()
            .expect("spawn docker export");
        assert!(status.success(), "docker export {container} failed");
    }
}

/// Container/image names created by the test, dropped on `Drop` so a
/// panic mid-test still cleans up. `rmi -f` removes the image and any
/// containers that reference it; we additionally `rm -f` containers
/// individually since `export` of a container created from a
/// since-removed image works but the container row lingers.
struct ContainerCleanup<'a> {
    manager: &'a dyn ContainerManager,
    images: Vec<String>,
    containers: Vec<String>,
}

impl<'a> ContainerCleanup<'a> {
    fn new(manager: &'a dyn ContainerManager) -> Self {
        Self {
            manager,
            images: Vec::new(),
            containers: Vec::new(),
        }
    }
    fn track_image(&mut self, image: &str) {
        self.images.push(image.to_string());
    }
    fn track_container(&mut self, cid: &str) {
        self.containers.push(cid.to_string());
    }
}

impl Drop for ContainerCleanup<'_> {
    fn drop(&mut self) {
        for cid in &self.containers {
            let _ = self.manager.run(&["rm", "-f", cid]);
        }
        for img in &self.images {
            self.manager.rmi(img);
        }
    }
}

/// Create a container from an image and export its rootfs to `tar_path`.
/// Records the transient container with `cleanup` so it is removed even if a later
/// step panics.
fn export_rootfs(manager: &dyn ContainerManager, image_ref: &str, tar_path: &Path, cleanup: &mut ContainerCleanup) {
    let cid = manager.create(image_ref);
    cleanup.track_container(&cid);
    manager.export(&cid, tar_path);
}

fn fs_from_tar(path: &Path) -> InMemoryFs {
    let f = fs::File::open(path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    InMemoryFs::apply_layers([f]).expect("apply rootfs tar")
}

fn run_squash(inputs: &[&Path], output: &Path) {
    let status = Command::new(env!("CARGO_BIN_EXE_layermeld"))
        .args(["--layout", "tar", "--timestamp", PINNED_T0, "--output"])
        .arg(output)
        .args(inputs)
        .status()
        .expect("spawn layermeld");
    assert!(status.success(), "layermeld failed for inputs {inputs:?}");
}

/// Pull the two postgres tags, save each as a separate docker-archive,
/// merge them with the tool, reload, and verify the per-tag rootfs
/// matches what the container manager produced for the originals.
fn merged_postgres_images_match_originals<C: ContainerManager>(manager: &C) {
    if !manager.is_available() {
        eprintln!("skipping podman_round_trip: podman not in PATH");
        return;
    }

    let pid = std::process::id();
    let cs_a = format!("localhost/cs-test-pg17:t{pid}");
    let cs_b = format!("localhost/cs-test-pg18:t{pid}");

    let mut cleanup = ContainerCleanup::new(manager);
    cleanup.track_image(&cs_a);
    cleanup.track_image(&cs_b);

    let upstream_a = format!("docker.io/library/postgres:{TAG_A}");
    let upstream_b = format!("docker.io/library/postgres:{TAG_B}");
    if !manager.pull(&upstream_a) || !manager.pull(&upstream_b) {
        eprintln!("skipping podman_round_trip: podman pull failed (no network or registry?)");
        return;
    }

    // Retag onto unique test-only refs so concurrent or repeated runs
    // do not collide on the upstream tags. The originals stay in
    // storage but are irrelevant past this point.
    manager.tag(&upstream_a, &cs_a);
    manager.tag(&upstream_b, &cs_b);

    // Source images + two rootfs exports + merged.tar + two more
    // rootfs exports easily exceed a few GiB, which a typical tmpfs
    // `/tmp` will reject with EDQUOT. Stage under cargo's per-target
    // tmpdir so the test uses the same disk-backed area as the build
    // tree.
    let mut td = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    td.disable_cleanup(true);
    let arch_a = td.path().join("pg17.tar");
    let arch_b = td.path().join("pg18.tar");
    manager.save(&cs_a, &arch_a);
    manager.save(&cs_b, &arch_b);

    let orig_fs_a = td.path().join("orig-pg17.tar");
    let orig_fs_b = td.path().join("orig-pg18.tar");
    export_rootfs(manager, &cs_a, &orig_fs_a, &mut cleanup);
    export_rootfs(manager, &cs_b, &orig_fs_b, &mut cleanup);

    // Drop the originals from storage so the merged load
    // reinstates each tag from the squashed bytes alone — otherwise
    // `load` would no-op on already-present manifests and the
    // re-export would tautologically match the originals.
    manager.rmi(&cs_a);
    manager.rmi(&cs_b);

    let merged = td.path().join("merged.tar");
    run_squash(&[arch_a.as_path(), arch_b.as_path()], &merged);

    manager.load(&merged);

    let merged_fs_a = td.path().join("merged-pg17.tar");
    let merged_fs_b = td.path().join("merged-pg18.tar");
    export_rootfs(manager, &cs_a, &merged_fs_a, &mut cleanup);
    export_rootfs(manager, &cs_b, &merged_fs_b, &mut cleanup);

    let pairs: [(&PathBuf, &PathBuf, &str); 2] = [(&orig_fs_a, &merged_fs_a, &cs_a), (&orig_fs_b, &merged_fs_b, &cs_b)];
    for (orig, merged, label) in pairs {
        let lhs = fs_from_tar(orig);
        let rhs = fs_from_tar(merged);
        if let Err(msg) = diff(&lhs, &rhs) {
            panic!("podman round-trip diverged for {label}:\n{msg}");
        }
    }
}

#[test]
fn merged_postgres_images_match_originals_through_podman() {
    merged_postgres_images_match_originals(&Podman);
}

#[test]
fn merged_postgres_images_match_originals_through_docker() {
    merged_postgres_images_match_originals(&Docker);
}
