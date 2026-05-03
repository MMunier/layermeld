//! End-to-end check that the binary maps errors to the spec 10 §10.7
//! exit codes. The library-level [`Error::exit_code`] mapping is unit-
//! tested in `src/error.rs`; these tests verify that `main.rs` actually
//! plumbs that mapping through to the process's exit status, and that
//! the stdout/stderr discipline of spec 10 §10.8 is honoured (summary
//! on stdout for success, nothing for failures).
//!
//! Uses `std::process::Command` against `CARGO_BIN_EXE_container-squash`
//! rather than `assert_cmd` so no extra dev-dependency is needed.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::str::FromStr;

use oci_spec::image::{
    Arch, ConfigBuilder, DescriptorBuilder, Digest, ImageConfigurationBuilder, ImageManifestBuilder, MediaType, Os,
    RootFsBuilder,
};
use tempfile::TempDir;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_container-squash"))
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().expect("spawn container-squash")
}

/// Build a minimal one-layer dir-transport image at `root`. The image
/// has no special content; it only needs to be parseable so the
/// pipeline can run end-to-end on the success-path test.
fn make_dir_transport_input(root: &Path) {
    fs::create_dir_all(root).unwrap();

    // Single-entry tar carrying one regular file.
    let mut layer_buf = Vec::new();
    {
        let mut tb = tar::Builder::new(&mut layer_buf);
        tb.mode(tar::HeaderMode::Deterministic);
        let body = b"hello\n";
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_path("hello").unwrap();
        h.set_mode(0o644);
        h.set_uid(0);
        h.set_gid(0);
        h.set_size(body.len() as u64);
        h.set_cksum();
        tb.append(&h, &body[..]).unwrap();
        tb.finish().unwrap();
    }

    let layer_hex = sha256_hex(&layer_buf);
    fs::write(root.join(&layer_hex), &layer_buf).unwrap();

    // Image config / manifest go through `oci-spec` builders so the
    // JSON shape is guaranteed to match what the input readers expect.
    let cfg = ImageConfigurationBuilder::default()
        .architecture(Arch::Amd64)
        .os(Os::Linux)
        .config(ConfigBuilder::default().cmd(vec!["sh".to_string()]).build().unwrap())
        .rootfs(
            RootFsBuilder::default()
                .typ("layers".to_string())
                .diff_ids(vec![format!("sha256:{layer_hex}")])
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let cfg_bytes = serde_json::to_vec(&cfg).unwrap();
    let cfg_hex = sha256_hex(&cfg_bytes);
    fs::write(root.join(&cfg_hex), &cfg_bytes).unwrap();

    let cfg_descriptor = DescriptorBuilder::default()
        .media_type(MediaType::ImageConfig)
        .digest(Digest::from_str(&format!("sha256:{cfg_hex}")).unwrap())
        .size(cfg_bytes.len() as u64)
        .build()
        .unwrap();
    let layer_descriptor = DescriptorBuilder::default()
        .media_type(MediaType::ImageLayer)
        .digest(Digest::from_str(&format!("sha256:{layer_hex}")).unwrap())
        .size(layer_buf.len() as u64)
        .build()
        .unwrap();
    let manifest = ImageManifestBuilder::default()
        .schema_version(2u32)
        .media_type(MediaType::ImageManifest)
        .config(cfg_descriptor)
        .layers(vec![layer_descriptor])
        .build()
        .unwrap();
    fs::write(root.join("manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let out: [u8; 32] = h.finalize().into();
    let mut s = String::with_capacity(64);
    for b in out {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

#[test]
fn missing_required_argv_is_exit_code_2() {
    // No `--output`, no inputs: clap reports a usage error and exits 2
    // before any pipeline code runs.
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(2));
    // Spec 10 §10.8: nothing on stdout for failures.
    assert!(
        out.stdout.is_empty(),
        "stdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn unknown_flag_is_exit_code_2() {
    let out = run(&["--no-such-flag", "--output", "x", "y"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn help_exits_zero_and_writes_to_stdout() {
    let out = run(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    // clap routes `--help` to stdout; our success-path summary is the
    // *only* thing we send to stdout otherwise, so this overlap is
    // fine — it only happens when the user explicitly asked for help.
    assert!(!out.stdout.is_empty());
}

#[test]
fn missing_input_path_is_exit_code_1() {
    let td = TempDir::new().unwrap();
    let output = td.path().join("out.tar");
    let bogus = td.path().join("does-not-exist");
    let out = run(&[
        "--output",
        output.to_str().unwrap(),
        "--timestamp",
        "1700000000",
        bogus.to_str().unwrap(),
    ]);
    // Config::from_cli surfaces a missing input as Error::Io, exit 1.
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("error:"), "stderr: {stderr}");
    // No output file was created on the way to the error.
    assert!(!output.exists());
}

#[test]
fn output_collision_without_force_is_exit_code_3() {
    let td = TempDir::new().unwrap();
    let input_root = td.path().join("in");
    make_dir_transport_input(&input_root);

    let output = td.path().join("out.tar");
    fs::write(&output, b"prior").unwrap();

    let out = run(&[
        "--output",
        output.to_str().unwrap(),
        "--timestamp",
        "1700000000",
        input_root.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    // Original output untouched (spec 09 §9.4 — never delete).
    assert_eq!(fs::read(&output).unwrap(), b"prior");
}

#[test]
fn success_prints_summary_to_stdout_and_exits_zero() {
    let td = TempDir::new().unwrap();
    let input_root = td.path().join("in");
    make_dir_transport_input(&input_root);

    let output = td.path().join("out.tar");
    let out = run(&[
        "--output",
        output.to_str().unwrap(),
        "--timestamp",
        "1700000000",
        input_root.to_str().unwrap(),
    ]);

    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("container-squash run summary"), "stdout: {stdout}");
    assert!(output.is_file());
}

#[test]
fn quiet_suppresses_summary_on_success() {
    let td = TempDir::new().unwrap();
    let input_root = td.path().join("in");
    make_dir_transport_input(&input_root);

    let output = td.path().join("out.tar");
    let out = run(&[
        "--quiet",
        "--output",
        output.to_str().unwrap(),
        "--timestamp",
        "1700000000",
        input_root.to_str().unwrap(),
    ]);

    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.is_empty(),
        "--quiet must suppress the summary; got: {:?}",
        out.stdout
    );
    assert!(output.is_file());
}

#[test]
fn dry_run_prints_summary_but_writes_no_output() {
    let td = TempDir::new().unwrap();
    let input_root = td.path().join("in");
    make_dir_transport_input(&input_root);

    let output = td.path().join("out.tar");
    let out = run(&[
        "--dry-run",
        "--output",
        output.to_str().unwrap(),
        "--timestamp",
        "1700000000",
        input_root.to_str().unwrap(),
    ]);

    assert_eq!(out.status.code(), Some(0));
    assert!(!output.exists(), "--dry-run must not produce output");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("container-squash run summary"));
}
