//! Synthetic image fixture used by the round-trip + determinism test
//! families (spec 11 §11.6.2).
//!
//! The canonical fixture exercises every entry kind the writer can emit
//! (regular, directory, symlink, hardlink, character device, block
//! device, FIFO) plus the metadata corners spec 11 §11.5 requires the
//! round-trip to preserve: setuid, sticky bit, non-zero uid/gid, and
//! `SCHILY.xattr.*` byte payloads.
//!
//! Two output shapes are supported:
//!
//! * [`SyntheticImage::layer_tar`] — a single uncompressed PAX tar in
//!   memory, suitable as input to the squash + dedup unit harnesses
//!   without touching the filesystem.
//! * [`SyntheticImage::write_dir_transport`] — a minimal `dir:`
//!   transport image at a given root, suitable for end-to-end CLI
//!   tests via `CARGO_BIN_EXE_layermeld`.
//!
//! The builder is intentionally narrow: it only knows how to produce a
//! single-layer image. Multi-layer / multi-image scenarios are left to
//! the consuming test by stacking calls.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use layermeld::tar_io::reader::{EntryKind, EntryMeta};
use layermeld::tar_io::writer::Writer;
use oci_spec::image::{
    Arch, ConfigBuilder, DescriptorBuilder, Digest, ImageConfigurationBuilder, ImageManifestBuilder, MediaType, Os,
    RootFsBuilder,
};
use sha2::{Digest as _, Sha256};

/// One pre-built tar entry: header metadata plus its body bytes.
///
/// Bodies are non-empty only for [`EntryKind::Regular`]; the writer
/// ignores them otherwise (spec 02 §2.4).
#[derive(Debug, Clone)]
pub struct LayerEntry {
    pub meta: EntryMeta,
    pub body: Vec<u8>,
}

/// Fully-formed in-memory image fixture.
///
/// Entries are stored in lex-path order so test assertions can compare
/// against the writer's output without an intermediate sort.
pub struct SyntheticImage {
    pub entries: Vec<LayerEntry>,
}

/// Paths emitted by [`SyntheticImage::write_dir_transport`]. Returned
/// so tests can drive the CLI with the right argv shape and assert on
/// the resulting blob layout.
#[derive(Debug, Clone)]
pub struct DirTransportArtifact {
    pub root: PathBuf,
    pub layer_hex: String,
    pub config_hex: String,
}

impl SyntheticImage {
    /// Canonical fixture per spec 11 §11.6.2: every entry kind, plus
    /// xattrs / setuid / sticky / non-zero ownership.
    ///
    /// Hardlink target ordering: the link target (`etc/hostname`)
    /// appears *before* its alias in the entry list so a naive consumer
    /// that streams bottom-up sees the regular file first.
    #[must_use]
    pub fn canonical() -> Self {
        let mut xattrs: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        xattrs.insert(b"user.flag".to_vec(), b"on".to_vec());
        xattrs.insert(b"security.selinux".to_vec(), b"u:r:s".to_vec());
        let mut data = regular("var/data", 0o640, 1000, 1000, b"payload\n");
        data.meta.xattrs = xattrs;

        let entries = vec![
            dir("bin", 0o755),
            regular("bin/setuid-bin", 0o4755, 0, 0, b"#!/bin/true\n"),
            dir("dev", 0o755),
            char_device("dev/null", 0o666, 1, 3),
            block_device("dev/sda", 0o660, 8, 0),
            dir("etc", 0o755),
            regular("etc/hostname", 0o644, 0, 0, b"synthetic\n"),
            hardlink("etc/hostname.alias", 0o644, "etc/hostname"),
            symlink("etc/hostname.link", 0o777, "hostname"),
            dir("tmp", 0o1777),
            dir("var", 0o755),
            // FIFO — bodyless, mode 0o644 is the kernel default.
            fifo("var/run", 0o644),
            // Regular file with non-zero uid/gid + xattrs.
            data,
        ];

        Self { entries }
    }

    /// Encode the entry list as a single uncompressed PAX tar.
    ///
    /// # Panics
    ///
    /// Panics if the underlying writer rejects an entry — none of the
    /// canonical fixture's entries can trip the writer's validation,
    /// so a panic here means the fixture itself is malformed and tests
    /// should fail loudly.
    #[must_use]
    pub fn layer_tar(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            for e in &self.entries {
                w.append(&e.meta, e.body.as_slice())
                    .expect("synthetic fixture entry rejected by writer");
            }
            w.finish().expect("synthetic fixture trailer write failed");
        }
        buf
    }

    /// Materialise the fixture as a `dir:` transport image (spec 01
    /// §1.5) at `root`. Creates `root` if it does not already exist.
    ///
    /// # Errors
    ///
    /// Propagates any [`io::Error`] from the `fs::create_dir_all` /
    /// blob writes. JSON encoding is infallible for the fixture's
    /// shape (bounded size, valid UTF-8 paths) so its `unwrap`s would
    /// only fire on a `serde_json` regression.
    pub fn write_dir_transport(&self, root: &Path) -> io::Result<DirTransportArtifact> {
        fs::create_dir_all(root)?;

        let layer = self.layer_tar();
        let layer_hex = sha256_hex(&layer);
        fs::write(root.join(&layer_hex), &layer)?;

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
        fs::write(root.join(&cfg_hex), &cfg_bytes)?;

        let cfg_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageConfig)
            .digest(Digest::from_str(&format!("sha256:{cfg_hex}")).unwrap())
            .size(cfg_bytes.len() as u64)
            .build()
            .unwrap();
        let layer_descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageLayer)
            .digest(Digest::from_str(&format!("sha256:{layer_hex}")).unwrap())
            .size(layer.len() as u64)
            .build()
            .unwrap();
        let manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .config(cfg_descriptor)
            .layers(vec![layer_descriptor])
            .build()
            .unwrap();
        fs::write(root.join("manifest.json"), serde_json::to_vec(&manifest).unwrap())?;

        Ok(DirTransportArtifact {
            root: root.to_path_buf(),
            layer_hex,
            config_hex: cfg_hex,
        })
    }
}

fn base_meta(path: &str, kind: EntryKind, mode: u32) -> EntryMeta {
    EntryMeta {
        path: PathBuf::from(path),
        kind,
        size: 0,
        mode,
        uid: 0,
        gid: 0,
        // mtime is normalised to T0 by the squash pipeline; the value
        // here is irrelevant for round-trip equality. Use 0 so the raw
        // fixture bytes are deterministic.
        mtime: 0,
        uname: None,
        gname: None,
        link_target: None,
        rdev: None,
        xattrs: BTreeMap::new(),
    }
}

fn regular(path: &str, mode: u32, uid: u64, gid: u64, body: &[u8]) -> LayerEntry {
    let mut meta = base_meta(path, EntryKind::Regular, mode);
    meta.uid = uid;
    meta.gid = gid;
    meta.size = body.len() as u64;
    LayerEntry {
        meta,
        body: body.to_vec(),
    }
}

fn dir(path: &str, mode: u32) -> LayerEntry {
    LayerEntry {
        meta: base_meta(path, EntryKind::Directory, mode),
        body: Vec::new(),
    }
}

fn symlink(path: &str, mode: u32, target: &str) -> LayerEntry {
    let mut meta = base_meta(path, EntryKind::Symlink, mode);
    meta.link_target = Some(PathBuf::from(target));
    LayerEntry { meta, body: Vec::new() }
}

fn hardlink(path: &str, mode: u32, target: &str) -> LayerEntry {
    let mut meta = base_meta(path, EntryKind::Hardlink, mode);
    meta.link_target = Some(PathBuf::from(target));
    LayerEntry { meta, body: Vec::new() }
}

fn char_device(path: &str, mode: u32, major: u32, minor: u32) -> LayerEntry {
    let mut meta = base_meta(path, EntryKind::CharDevice, mode);
    meta.rdev = Some((major, minor));
    LayerEntry { meta, body: Vec::new() }
}

fn block_device(path: &str, mode: u32, major: u32, minor: u32) -> LayerEntry {
    let mut meta = base_meta(path, EntryKind::BlockDevice, mode);
    meta.rdev = Some((major, minor));
    LayerEntry { meta, body: Vec::new() }
}

fn fifo(path: &str, mode: u32) -> LayerEntry {
    LayerEntry {
        meta: base_meta(path, EntryKind::Fifo, mode),
        body: Vec::new(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let out: [u8; 32] = h.finalize().into();
    let mut s = String::with_capacity(64);
    for b in out {
        write!(s, "{b:02x}").unwrap();
    }
    s
}
