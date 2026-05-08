//! Tar packaging (spec 09 §9.3, §9.4).
//!
//! The default packaging mode: bundle the OCI layout (the `oci-layout`
//! marker, `index.json`, and the populated `blobs/sha256/` tree) into a
//! single uncompressed PAX tar at `<output>`. Used when the user did
//! not pass `--layout dir`.
//!
//! ## Pipeline
//!
//! ```text
//! tar_io::Writer ─► BufWriter ─► File (<output>.partial)
//! ```
//!
//! Layer / config / manifest blobs already exist on disk under
//! `staging/blobs/sha256/` (deposited by [`crate::assemble::emit::emit_layers`]
//! and the future config / manifest blob writers). Their bodies are
//! piped straight from the staging files into the tar — no spool, no
//! re-hash. The three top-level documents (`oci-layout`, `index.json`,
//! and the Docker-archive `manifest.json`) are computed in-memory: the
//! marker is a constant ([`super::dir::OCI_LAYOUT_BODY`]), the index
//! and the docker manifest both go through
//! [`super::dir::canonical_json_bytes`] so their `HashMap`-backed
//! annotation maps emit in lex key order — the same canonicalisation
//! the dir packager uses, so a layout written either way carries
//! byte-identical top-level documents.
//!
//! ## Tar dialect (spec 09 §9.3 / spec 02 §2.4)
//!
//! Same PAX dialect as output layers: `ustar` headers + PAX extended
//! headers when a field overflows. Per spec §9.3:
//!
//! * `mtime` = `T0` (negative `T0` clamps to 0 because tar mtime is
//!   unsigned, mirroring [`crate::assemble::emit::emit_layer`]).
//! * `uid` / `gid` = `0`.
//! * Mode = `0o755` for directories, `0o644` for regular files.
//! * `uname` / `gname` = empty (forced by [`crate::tar_io::writer`]).
//!
//! ## Determinism (spec 11 §11.6)
//!
//! Entry order is fully deterministic. The five fixed paths emit in
//! lex order — `blobs/`, `blobs/sha256/`, then every blob, then
//! `index.json`, `manifest.json`, `oci-layout`. Blob filenames inside
//! `blobs/sha256/` are sorted before emission so the order of
//! `read_dir` (filesystem-dependent) cannot leak into the tar.
//!
//! ## Atomicity (spec 09 §9.4)
//!
//! The tar is first written to a sibling temp path
//! `<output>.partial` in the same directory, then `fsync`'d and
//! `rename(2)`'d onto `<output>`. Same-filesystem rename is atomic.
//! A run that aborts mid-write leaves only `<output>.partial`, which
//! the next run will refuse to overwrite unless `--force` is given
//! (collision handling is a separate task per spec §9.4 last
//! paragraph).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use oci_spec::image::ImageIndex;

use crate::docker_manifest::DockerManifestEntry;
use crate::tar_io::reader::{EntryKind, EntryMeta};
use crate::tar_io::writer::Writer;
use crate::timestamp::T0;
use crate::{Error, Result};

use super::dir::{OCI_LAYOUT_BODY, canonical_json_bytes, sync_dir_best_effort};

/// Pack a populated staging tree into a single PAX tar at `output`.
///
/// Writes the tar to `<output>.partial`, fsyncs it, then atomically
/// renames it onto `output`. The two top-level documents (`oci-layout`,
/// `index.json`) are produced in-memory; layer / config / manifest blobs
/// are streamed from `staging/blobs/sha256/<hex>`.
///
/// # Preconditions
///
/// * `staging/blobs/sha256/` exists and contains every blob the index
///   references. Missing files surface as [`Error::Io`].
/// * `output` does not already exist. Collision handling (`--force`,
///   move-aside) is the caller's concern per spec 09 §9.4.
/// * `output` has a file-name component (i.e. is not the filesystem
///   root) — required to derive the `<output>.partial` sibling.
///
/// # Errors
///
/// * [`Error::Io`] for any filesystem failure (`create`, `read`,
///   `write`, `sync_all`, `rename`).
/// * [`Error::Validation`] if `output` has no file-name component, or
///   if a blob filename under `staging/blobs/sha256/` is not valid
///   UTF-8 (every digest the rest of the pipeline emits is lower-case
///   hex, so non-UTF-8 here means the staging tree was tampered with).
pub fn finalize_tar(
    staging: &Path,
    index: &ImageIndex,
    docker_manifest: &[DockerManifestEntry],
    output: &Path,
    t0: T0,
) -> Result<()> {
    let partial = partial_path(output)?;
    let index_bytes = canonical_json_bytes(index)?;
    let docker_bytes = canonical_json_bytes(&docker_manifest.to_vec())?;
    let blobs_dir = staging.join("blobs").join("sha256");
    let blob_names = sorted_blob_names(&blobs_dir)?;

    let file = File::create(&partial)?;
    let mut buffered = BufWriter::new(file);
    {
        let mut writer = Writer::new(&mut buffered);
        let mtime = u64::try_from(t0.as_unix_seconds()).unwrap_or(0);

        // Emission order is the lex order of the top-level entry paths
        // — `blobs/` < `blobs/sha256/` < every `blobs/sha256/<hex>`
        // (hex digits sort below any single-quote-or-higher byte) <
        // `index.json` < `manifest.json` < `oci-layout`. Sorting
        // `blob_names` above pins the per-blob order; the remaining
        // five paths are listed in lex order by construction.
        write_dir(&mut writer, "blobs", mtime)?;
        write_dir(&mut writer, "blobs/sha256", mtime)?;
        for name in &blob_names {
            let blob_path = blobs_dir.join(name);
            let size = fs::metadata(&blob_path)?.len();
            let f = File::open(&blob_path)?;
            let path_str = format!(
                "blobs/sha256/{}",
                name.to_str().ok_or_else(|| Error::Validation(format!(
                    "non-UTF-8 blob filename in {}: {}",
                    blobs_dir.display(),
                    Path::new(name).display(),
                )))?
            );
            write_file(&mut writer, &path_str, size, f, mtime)?;
        }
        write_file_bytes(&mut writer, "index.json", &index_bytes, mtime)?;
        write_file_bytes(&mut writer, "manifest.json", &docker_bytes, mtime)?;
        write_file_bytes(&mut writer, "oci-layout", OCI_LAYOUT_BODY, mtime)?;
        writer.finish()?;
    }
    buffered.flush()?;
    let file = buffered
        .into_inner()
        .map_err(|e| Error::Io(io::Error::other(format!("BufWriter flush failed: {e}"))))?;
    file.sync_all()?;
    drop(file);

    fs::rename(&partial, output).map_err(|e| {
        let _ = fs::remove_file(&partial);
        Error::Io(io::Error::new(
            e.kind(),
            format!("rename {} -> {} failed: {e}", partial.display(), output.display()),
        ))
    })?;
    if let Some(parent) = output.parent() {
        sync_dir_best_effort(parent);
    }
    Ok(())
}

/// Compute `<output>.partial` — same parent directory, file name with
/// `.partial` appended. Required so `rename(2)` is same-filesystem and
/// therefore atomic.
fn partial_path(output: &Path) -> Result<PathBuf> {
    let file_name = output
        .file_name()
        .ok_or_else(|| Error::Validation(format!("output path {} has no file name", output.display())))?;
    let mut name = file_name.to_os_string();
    name.push(".partial");
    Ok(output.with_file_name(name))
}

/// List blob file names under `dir` in lex byte-order. Reading the
/// directory is the only place filesystem ordering could leak into
/// the output, so we sort exhaustively before returning.
fn sorted_blob_names(dir: &Path) -> Result<Vec<OsString>> {
    let mut names: Vec<OsString> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        names.push(entry.file_name());
    }
    // Lex byte-order on the raw OsStr bytes — matches the order tar
    // entry paths sort under, so the per-blob block in the output
    // tar is monotonic.
    names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    Ok(names)
}

fn write_dir<W: Write>(writer: &mut Writer<W>, path: &str, mtime: u64) -> Result<()> {
    let meta = EntryMeta {
        path: PathBuf::from(path),
        kind: EntryKind::Directory,
        size: 0,
        mode: 0o755,
        uid: 0,
        gid: 0,
        mtime,
        uname: None,
        gname: None,
        link_target: None,
        rdev: None,
        xattrs: BTreeMap::new(),
    };
    writer.append(&meta, io::empty())
}

fn write_file<W: Write>(writer: &mut Writer<W>, path: &str, size: u64, body: File, mtime: u64) -> Result<()> {
    let meta = EntryMeta {
        path: PathBuf::from(path),
        kind: EntryKind::Regular,
        size,
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime,
        uname: None,
        gname: None,
        link_target: None,
        rdev: None,
        xattrs: BTreeMap::new(),
    };
    writer.append(&meta, body)
}

fn write_file_bytes<W: Write>(writer: &mut Writer<W>, path: &str, body: &[u8], mtime: u64) -> Result<()> {
    let meta = EntryMeta {
        path: PathBuf::from(path),
        kind: EntryKind::Regular,
        size: body.len() as u64,
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime,
        uname: None,
        gname: None,
        link_target: None,
        rdev: None,
        xattrs: BTreeMap::new(),
    };
    writer.append(&meta, body)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::str::FromStr;

    use oci_spec::image::{
        ANNOTATION_CREATED, ANNOTATION_REF_NAME, Arch, Descriptor, DescriptorBuilder, Digest, ImageIndexBuilder,
        MediaType, Os, PlatformBuilder,
    };

    use super::*;
    use crate::tar_io::reader::Reader;

    fn dummy_descriptor(digest_hex: &str, size: u64, ann: &[(&str, &str)]) -> Descriptor {
        let digest = Digest::from_str(&format!("sha256:{digest_hex}")).unwrap();
        let platform = PlatformBuilder::default()
            .architecture(Arch::Amd64)
            .os(Os::Linux)
            .build()
            .unwrap();
        let mut annotations: HashMap<String, String> = HashMap::new();
        for (k, v) in ann {
            annotations.insert((*k).to_string(), (*v).to_string());
        }
        DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(digest)
            .size(size)
            .platform(platform)
            .annotations(annotations)
            .build()
            .unwrap()
    }

    fn dummy_index() -> ImageIndex {
        ImageIndexBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageIndex)
            .manifests(vec![dummy_descriptor(
                &"ab".repeat(32),
                100,
                &[
                    (ANNOTATION_REF_NAME, "repo:tag"),
                    (ANNOTATION_CREATED, "2023-11-14T22:13:20Z"),
                ],
            )])
            .build()
            .unwrap()
    }

    fn make_staging(parent: &Path, blobs: &[(&str, &[u8])]) -> PathBuf {
        let staging = parent.join("out.partial-staging");
        let blobs_dir = staging.join("blobs").join("sha256");
        fs::create_dir_all(&blobs_dir).unwrap();
        for (name, body) in blobs {
            fs::write(blobs_dir.join(name), body).unwrap();
        }
        staging
    }

    fn read_back(bytes: &[u8]) -> Vec<(EntryMeta, Vec<u8>)> {
        let mut reader = Reader::new(Cursor::new(bytes.to_vec()));
        let mut out = Vec::new();
        let mut entries = reader.entries().unwrap();
        for e in entries.by_ref() {
            let mut e = e.unwrap();
            let mut body = Vec::new();
            io::Read::read_to_end(&mut e, &mut body).unwrap();
            out.push((e.meta().clone(), body));
        }
        out
    }

    #[test]
    fn output_is_a_single_tar_file_at_target_path() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[("aa", b"alpha-blob")]);
        let output = tmp.path().join("out.tar");

        finalize_tar(&staging, &dummy_index(), &[], &output, T0::from_unix_seconds(0)).unwrap();

        assert!(output.is_file(), "output must be a single file");
        // Sanity: parses back as a tar.
        let bytes = fs::read(&output).unwrap();
        let entries = read_back(&bytes);
        assert!(!entries.is_empty(), "tar must have at least the layout entries");
    }

    #[test]
    fn partial_is_renamed_onto_output() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[("aa", b"x")]);
        let output = tmp.path().join("out.tar");
        let partial = tmp.path().join("out.tar.partial");

        finalize_tar(&staging, &dummy_index(), &[], &output, T0::from_unix_seconds(0)).unwrap();

        assert!(output.is_file());
        assert!(!partial.exists(), "partial must be gone after rename");
    }

    #[test]
    fn entry_set_includes_layout_and_every_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(
            tmp.path(),
            &[("aa", b"first-blob"), ("bb", b"second-blob"), ("cc", b"third-blob")],
        );
        let output = tmp.path().join("out.tar");

        finalize_tar(&staging, &dummy_index(), &[], &output, T0::from_unix_seconds(0)).unwrap();
        let entries = read_back(&fs::read(&output).unwrap());

        let paths: Vec<String> = entries
            .iter()
            .map(|(m, _)| m.path.to_str().unwrap().to_string())
            .collect();
        // Directories arrive with a trailing slash from the tar reader
        // (the writer emits `blobs/` for directory entries per spec
        // 02 §2.4 conventions; the reader passes the slash through).
        assert!(paths.contains(&"blobs/".to_string()));
        assert!(paths.contains(&"blobs/sha256/".to_string()));
        assert!(paths.contains(&"blobs/sha256/aa".to_string()));
        assert!(paths.contains(&"blobs/sha256/bb".to_string()));
        assert!(paths.contains(&"blobs/sha256/cc".to_string()));
        assert!(paths.contains(&"index.json".to_string()));
        assert!(paths.contains(&"oci-layout".to_string()));
    }

    #[test]
    fn entries_are_emitted_in_lex_order() {
        // Spec 11 §11.6: deterministic byte output. read_dir order is
        // filesystem-dependent — the writer must sort blobs before
        // emission. Drop blobs in non-lex order to make the test
        // sensitive to that.
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[("zz", b"z"), ("aa", b"a"), ("mm", b"m"), ("bb", b"b")]);
        let output = tmp.path().join("out.tar");

        finalize_tar(&staging, &dummy_index(), &[], &output, T0::from_unix_seconds(0)).unwrap();
        let entries = read_back(&fs::read(&output).unwrap());
        let paths: Vec<String> = entries
            .iter()
            .map(|(m, _)| m.path.to_str().unwrap().to_string())
            .collect();

        // Filter to actual blob entries — exclude the parent directory
        // `blobs/sha256/` entry that the reader yields with a trailing
        // slash.
        let blob_paths: Vec<&String> = paths
            .iter()
            .filter(|p| p.starts_with("blobs/sha256/") && !p.ends_with('/'))
            .collect();
        assert_eq!(
            blob_paths,
            vec![
                &"blobs/sha256/aa".to_string(),
                &"blobs/sha256/bb".to_string(),
                &"blobs/sha256/mm".to_string(),
                &"blobs/sha256/zz".to_string(),
            ],
        );
        // And the surrounding lex order: blobs… < index.json < oci-layout.
        let last_blob_at = paths.iter().rposition(|p| p.starts_with("blobs/")).unwrap();
        let index_at = paths.iter().position(|p| p == "index.json").unwrap();
        let layout_at = paths.iter().position(|p| p == "oci-layout").unwrap();
        assert!(last_blob_at < index_at);
        assert!(index_at < layout_at);
    }

    #[test]
    fn blob_bodies_pass_through_byte_for_byte() {
        // Including non-UTF-8 bytes — the body path must be a raw byte
        // copy, not a string round-trip.
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(
            tmp.path(),
            &[("aa", b"\x00\x01\x02"), ("bb", b"\xff\xfe\xfd"), ("cc", b"normal")],
        );
        let output = tmp.path().join("out.tar");
        finalize_tar(&staging, &dummy_index(), &[], &output, T0::from_unix_seconds(0)).unwrap();

        let entries = read_back(&fs::read(&output).unwrap());
        let by_path: HashMap<String, Vec<u8>> = entries
            .into_iter()
            .map(|(m, b)| (m.path.to_str().unwrap().to_string(), b))
            .collect();
        assert_eq!(by_path["blobs/sha256/aa"], b"\x00\x01\x02");
        assert_eq!(by_path["blobs/sha256/bb"], b"\xff\xfe\xfd");
        assert_eq!(by_path["blobs/sha256/cc"], b"normal");
    }

    #[test]
    fn oci_layout_carries_the_canonical_marker_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[("aa", b"x")]);
        let output = tmp.path().join("out.tar");
        finalize_tar(&staging, &dummy_index(), &[], &output, T0::from_unix_seconds(0)).unwrap();

        let entries = read_back(&fs::read(&output).unwrap());
        let (_, body) = entries
            .iter()
            .find(|(m, _)| m.path.to_str() == Some("oci-layout"))
            .unwrap();
        assert_eq!(body, OCI_LAYOUT_BODY);
        // Also a JSON sanity check.
        let v: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(v["imageLayoutVersion"], "1.0.0");
    }

    #[test]
    fn index_json_carries_canonical_bytes_with_sorted_keys() {
        // Spec 11 §11.6: HashMap-backed annotations on the descriptor
        // must serialise in lex order.
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[("aa", b"x")]);
        let output = tmp.path().join("out.tar");

        let descriptor = dummy_descriptor(
            &"cd".repeat(32),
            42,
            &[
                (ANNOTATION_REF_NAME, "z:tag"),
                (ANNOTATION_CREATED, "2024-01-01T00:00:00Z"),
            ],
        );
        let idx = ImageIndexBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageIndex)
            .manifests(vec![descriptor])
            .build()
            .unwrap();
        finalize_tar(&staging, &idx, &[], &output, T0::from_unix_seconds(0)).unwrap();
        let entries = read_back(&fs::read(&output).unwrap());
        let (_, body) = entries
            .iter()
            .find(|(m, _)| m.path.to_str() == Some("index.json"))
            .unwrap();
        let s = std::str::from_utf8(body).unwrap();
        let created_at = s.find("org.opencontainers.image.created").unwrap();
        let ref_name_at = s.find("org.opencontainers.image.ref.name").unwrap();
        assert!(created_at < ref_name_at, "annotations not sorted: {s}");

        // And the in-tar bytes must equal the canonicalisation primitive
        // — same content as the dir packager emits.
        assert_eq!(body, &canonical_json_bytes(&idx).unwrap());
    }

    #[test]
    fn t0_lands_as_mtime_on_every_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[("aa", b"x"), ("bb", b"y")]);
        let output = tmp.path().join("out.tar");
        let t0 = T0::from_unix_seconds(1_700_000_000);
        finalize_tar(&staging, &dummy_index(), &[], &output, t0).unwrap();

        let entries = read_back(&fs::read(&output).unwrap());
        for (m, _) in &entries {
            assert_eq!(m.mtime, 1_700_000_000, "entry {} has wrong mtime", m.path.display());
        }
    }

    #[test]
    fn negative_t0_clamps_to_zero_for_tar_mtime() {
        // tar mtime is unsigned. Spec 06 §6.6 keeps the original T0 in
        // OCI `created`, but tar can't represent negative seconds —
        // clamp to 0, matching emit.rs's behaviour.
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[("aa", b"x")]);
        let output = tmp.path().join("out.tar");
        finalize_tar(&staging, &dummy_index(), &[], &output, T0::from_unix_seconds(-99)).unwrap();
        let entries = read_back(&fs::read(&output).unwrap());
        for (m, _) in &entries {
            assert_eq!(m.mtime, 0);
        }
    }

    #[test]
    fn mode_is_0755_for_dirs_and_0644_for_files() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[("aa", b"x")]);
        let output = tmp.path().join("out.tar");
        finalize_tar(&staging, &dummy_index(), &[], &output, T0::from_unix_seconds(0)).unwrap();
        let entries = read_back(&fs::read(&output).unwrap());
        for (m, _) in &entries {
            let want = match m.kind {
                EntryKind::Directory => 0o755,
                EntryKind::Regular => 0o644,
                _ => panic!("unexpected entry kind {:?}", m.kind),
            };
            assert_eq!(m.mode & 0o7777, want, "wrong mode on {}", m.path.display());
        }
    }

    #[test]
    fn uid_gid_are_zero_and_uname_gname_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[("aa", b"x")]);
        let output = tmp.path().join("out.tar");
        finalize_tar(&staging, &dummy_index(), &[], &output, T0::from_unix_seconds(0)).unwrap();
        let entries = read_back(&fs::read(&output).unwrap());
        for (m, _) in &entries {
            assert_eq!(m.uid, 0);
            assert_eq!(m.gid, 0);
            assert!(m.uname.as_deref().unwrap_or("").is_empty());
            assert!(m.gname.as_deref().unwrap_or("").is_empty());
        }
    }

    #[test]
    fn output_dialect_is_ustar_pax() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[("aa", b"x")]);
        let output = tmp.path().join("out.tar");
        finalize_tar(&staging, &dummy_index(), &[], &output, T0::from_unix_seconds(0)).unwrap();
        let bytes = fs::read(&output).unwrap();
        // First entry's ustar magic — `blobs/` directory header at offset 0.
        assert_eq!(&bytes[257..263], b"ustar\0", "expected ustar magic");
        assert_eq!(&bytes[263..265], b"00");
    }

    #[test]
    fn tar_ends_with_two_zero_blocks() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[("aa", b"x")]);
        let output = tmp.path().join("out.tar");
        finalize_tar(&staging, &dummy_index(), &[], &output, T0::from_unix_seconds(0)).unwrap();
        let bytes = fs::read(&output).unwrap();
        assert!(bytes.len() >= 1024);
        assert!(
            bytes[bytes.len() - 1024..].iter().all(|&b| b == 0),
            "trailer must be two zero blocks",
        );
    }

    #[test]
    fn empty_blob_set_still_emits_layout_entries() {
        // Degenerate but well-formed: no blobs, just the layout
        // documents and the empty `blobs/sha256/` dir entries.
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[]);
        let output = tmp.path().join("out.tar");
        finalize_tar(&staging, &dummy_index(), &[], &output, T0::from_unix_seconds(0)).unwrap();
        let entries = read_back(&fs::read(&output).unwrap());
        let paths: Vec<String> = entries
            .iter()
            .map(|(m, _)| m.path.to_str().unwrap().to_string())
            .collect();
        assert_eq!(
            paths,
            vec!["blobs/", "blobs/sha256/", "index.json", "manifest.json", "oci-layout"]
        );
    }

    #[test]
    fn determinism_two_runs_produce_identical_bytes() {
        // Spec 11 §11.6: byte-identical output for the same input + T0.
        let tmp_a = tempfile::tempdir().unwrap();
        let tmp_b = tempfile::tempdir().unwrap();
        let staging_a = make_staging(tmp_a.path(), &[("aa", b"alpha"), ("bb", b"bravo")]);
        let staging_b = make_staging(tmp_b.path(), &[("aa", b"alpha"), ("bb", b"bravo")]);
        let out_a = tmp_a.path().join("out.tar");
        let out_b = tmp_b.path().join("out.tar");
        let t0 = T0::from_unix_seconds(42);
        finalize_tar(&staging_a, &dummy_index(), &[], &out_a, t0).unwrap();
        finalize_tar(&staging_b, &dummy_index(), &[], &out_b, t0).unwrap();
        assert_eq!(fs::read(&out_a).unwrap(), fs::read(&out_b).unwrap());
    }

    #[test]
    fn fails_when_output_already_exists_as_file() {
        // Spec 09 §9.4: collision handling is the caller's concern —
        // this function surfaces the OS rename failure as Error::Io.
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[("aa", b"x")]);
        let output = tmp.path().join("out.tar");
        // Make the output path a non-empty *directory* so rename(2)
        // fails with ENOTDIR / EISDIR (renaming a regular file onto a
        // non-empty dir is forbidden on every POSIX system; renaming
        // onto an existing regular file would silently succeed).
        fs::create_dir_all(&output).unwrap();
        fs::write(output.join("squatter"), b"x").unwrap();

        let err = finalize_tar(&staging, &dummy_index(), &[], &output, T0::from_unix_seconds(0)).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "got: {err:?}");
        // Partial must be cleaned up so the digest namespace is left
        // tidy when the caller decides to retry.
        assert!(!tmp.path().join("out.tar.partial").exists());
    }

    #[test]
    fn missing_blobs_dir_surfaces_io_error() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = tmp.path().join("does-not-exist");
        let output = tmp.path().join("out.tar");
        let err = finalize_tar(&staging, &dummy_index(), &[], &output, T0::from_unix_seconds(0)).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "got: {err:?}");
    }

    #[test]
    fn output_with_no_file_name_is_validation_error() {
        // `/` has no file name — partial path can't be derived.
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[("aa", b"x")]);
        let err = finalize_tar(&staging, &dummy_index(), &[], Path::new("/"), T0::from_unix_seconds(0)).unwrap_err();
        assert!(matches!(err, Error::Validation(_)), "got: {err:?}");
    }

    #[test]
    fn partial_path_appends_partial_extension_in_same_dir() {
        let p = partial_path(Path::new("/tmp/foo/out.tar")).unwrap();
        assert_eq!(p, PathBuf::from("/tmp/foo/out.tar.partial"));

        // No extension on output is fine — append works on the bare name.
        let p = partial_path(Path::new("/tmp/out")).unwrap();
        assert_eq!(p, PathBuf::from("/tmp/out.partial"));
    }

    #[test]
    fn sorted_blob_names_handles_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("empty");
        fs::create_dir_all(&dir).unwrap();
        let names = sorted_blob_names(&dir).unwrap();
        assert!(names.is_empty());
    }

    #[test]
    fn sorted_blob_names_returns_lex_byte_order() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("blobs");
        fs::create_dir_all(&dir).unwrap();
        for name in &["mm", "aa", "zz", "ab"] {
            fs::write(dir.join(name), b"").unwrap();
        }
        let names = sorted_blob_names(&dir).unwrap();
        let strs: Vec<&str> = names.iter().map(|n| n.to_str().unwrap()).collect();
        assert_eq!(strs, vec!["aa", "ab", "mm", "zz"]);
    }

    #[test]
    fn re_feeding_output_back_as_input_is_supported_round_trip() {
        // Spec 09 §9.3: "The tarred form is the input format described
        // in 01 §1.2, so re-feeding the tool's output back as input is
        // supported." Confirm the output is at least parseable as a
        // standalone tar via the same Reader the input pipeline uses.
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[("aa", b"alpha"), ("bb", b"bravo")]);
        let output = tmp.path().join("out.tar");
        finalize_tar(&staging, &dummy_index(), &[], &output, T0::from_unix_seconds(0)).unwrap();

        let bytes = fs::read(&output).unwrap();
        let mut reader = Reader::new(Cursor::new(bytes));
        let mut entries = reader.entries().unwrap();
        let mut count = 0usize;
        for e in entries.by_ref() {
            let _ = e.unwrap();
            count += 1;
        }
        // 2 dirs + 2 blobs + index.json + manifest.json + oci-layout = 7.
        assert_eq!(count, 7);
    }

    #[test]
    fn docker_manifest_lands_at_top_of_tar_as_json_array() {
        // Spec 09 §9.5: `podman load` requires a top-level Docker
        // `manifest.json` to restore multi-image archives. Confirm it
        // sits in the tar at the layout root and parses back as the
        // typed array shape.
        use crate::docker_manifest::DockerManifestEntry;

        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[("aa", b"alpha")]);
        let output = tmp.path().join("out.tar");
        let docker = vec![DockerManifestEntry {
            config: "blobs/sha256/cf".to_string(),
            repo_tags: vec!["repo:tag".to_string()],
            layers: vec!["blobs/sha256/aa".to_string()],
            layer_sources: BTreeMap::new(),
        }];

        finalize_tar(&staging, &dummy_index(), &docker, &output, T0::from_unix_seconds(0)).unwrap();
        let entries = read_back(&fs::read(&output).unwrap());
        let (_, body) = entries
            .iter()
            .find(|(m, _)| m.path.to_str() == Some("manifest.json"))
            .expect("manifest.json must be in the tar");
        let v: serde_json::Value = serde_json::from_slice(body).unwrap();
        let arr = v.as_array().expect("docker manifest is a JSON array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["Config"], "blobs/sha256/cf");
        assert_eq!(arr[0]["Layers"][0], "blobs/sha256/aa");
        assert_eq!(arr[0]["RepoTags"][0], "repo:tag");
    }

    #[test]
    fn docker_manifest_emits_in_lex_position_between_index_and_oci_layout() {
        // Lex order of the three top-level documents pins
        // `index.json` < `manifest.json` < `oci-layout`. Spec 11 §11.6
        // determinism rests on this ordering — anything else would
        // shift `oci-layout`'s offset and break byte-identical re-runs.
        let tmp = tempfile::tempdir().unwrap();
        let staging = make_staging(tmp.path(), &[]);
        let output = tmp.path().join("out.tar");

        finalize_tar(&staging, &dummy_index(), &[], &output, T0::from_unix_seconds(0)).unwrap();
        let entries = read_back(&fs::read(&output).unwrap());
        let paths: Vec<String> = entries
            .iter()
            .map(|(m, _)| m.path.to_str().unwrap().to_string())
            .collect();
        let index_at = paths.iter().position(|p| p == "index.json").unwrap();
        let docker_at = paths.iter().position(|p| p == "manifest.json").unwrap();
        let layout_at = paths.iter().position(|p| p == "oci-layout").unwrap();
        assert!(index_at < docker_at);
        assert!(docker_at < layout_at);
    }
}
