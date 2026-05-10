//! In-memory filesystem verifier for the round-trip + determinism test
//! families (spec 11 §11.5 / §11.6).
//!
//! This is the **only** place in the repository that "unpacks" layers
//! into a filesystem-shaped representation. The tool itself never does;
//! see spec 02's hard rule. The verifier exists purely so tests can
//! assert the round-trip-equality contract from spec 11 §11.5: for
//! every input image, the merged filesystem reconstructed from the
//! original layer stack must match the merged filesystem reconstructed
//! from the squashed output's layer stack, byte-for-byte modulo
//! normalised mtimes / cleared `uname` / `gname` PAX strings.
//!
//! The model is deliberately narrow:
//!
//! * Layers are tar streams; the verifier consumes them via
//!   [`tar_io::reader::Reader`] (the same reader the tool uses for
//!   input).
//! * Whiteouts (`.wh.<name>`) and opaque-dir markers (`.wh..wh..opq`)
//!   are honoured exactly as `squash::apply` honours them: the marker
//!   is consumed but never appears as a visible filesystem entry.
//! * Regular file bodies are SHA-256 hashed in-place — bodies are
//!   never spooled to disk.
//! * Hardlink topology is preserved: a tar `Hardlink` entry at `P`
//!   pointing to `T` joins `P` and `T` into the same inode-equivalence
//!   class. After all layers are applied the verifier resolves each
//!   hardlink chain to a terminal `Regular` and exposes the
//!   equivalence classes as [`InMemoryFs::hardlink_groups`].
//! * `mtime`, `uname`, `gname` are dropped — spec 11 §11.5's permitted
//!   diff. Comparing two `InMemoryFs` values therefore implicitly
//!   tolerates exactly the permitted axes of variation.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::{self, Read, Write as IoWrite};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use layermeld::tar_io::reader::{EntryKind, Reader};
use sha2::{Digest as _, Sha256};

/// `io::Write` adapter so [`io::copy`] can stream body bytes through
/// SHA-256 without an intermediate buffer.
struct HashSink(Sha256);

impl IoWrite for HashSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Per-path metadata captured at unpack time. Field set is the spec 11
/// §11.5 round-trip-equality predicate.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FsNode {
    pub kind: EntryKind,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub size: u64,
    /// SHA-256 of the body bytes for [`EntryKind::Regular`]; `None` for
    /// any other kind. For paths that participate in a hardlink group
    /// the hash is inherited from the terminal regular file.
    pub content_hash: Option<[u8; 32]>,
    /// Symlink target verbatim (`Some` for [`EntryKind::Symlink`] only).
    pub link_target: Option<PathBuf>,
    /// `(major, minor)` for char/block devices (`None` otherwise).
    pub rdev: Option<(u32, u32)>,
    /// PAX xattr map. Keys are byte sequences (Linux xattrs are not
    /// required to be valid UTF-8); ordering is the canonical
    /// `BTreeMap` iteration order so equal nodes serialise identically.
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Reconstructed filesystem after applying a layer stack.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct InMemoryFs {
    /// Visible filesystem entries keyed on normalised path. Whiteout /
    /// opaque markers do **not** appear here.
    pub nodes: BTreeMap<PathBuf, FsNode>,
    /// Inode equivalence classes: each element is the set of paths
    /// that share an inode at unpack time. Singleton classes (the
    /// common case) are omitted, so this is non-empty only when the
    /// input actually had hardlinks.
    pub hardlink_groups: BTreeSet<BTreeSet<PathBuf>>,
}

impl InMemoryFs {
    /// Apply the given layer tar streams in order, honouring whiteouts
    /// and opaque-dir markers, and resolve hardlink chains at the end.
    ///
    /// Each layer is consumed bottom-up, matching the order the
    /// container runtime applies them in. The first layer in the
    /// iterator is the lowest.
    ///
    /// # Errors
    ///
    /// Propagates any [`io::Error`] from the underlying tar reader
    /// (truncated layer, malformed header, etc.) and returns
    /// [`io::ErrorKind::InvalidData`] for self-inconsistent input
    /// (hardlink chains that don't terminate at a regular file, etc.).
    pub fn apply_layers<I, R>(layers: I) -> io::Result<Self>
    where
        I: IntoIterator<Item = R>,
        R: Read,
    {
        let mut fs = Self::default();
        for layer in layers {
            fs.apply_layer(layer)?;
        }
        fs.resolve_hardlinks()?;
        Ok(fs)
    }

    fn apply_layer<R: Read>(&mut self, reader: R) -> io::Result<()> {
        let mut reader = Reader::new(reader);
        let entries = reader.entries().map_err(io_err)?;
        for entry in entries {
            let mut entry = entry.map_err(io_err)?;
            let meta = entry.meta().clone();

            // Drain the body before the iterator advances. For regular
            // files the bytes pass through SHA-256 in a single
            // streaming pass; non-regular kinds are zero-length but
            // still need draining so the iterator can advance.
            let content_hash = if meta.kind.has_body() {
                let mut hasher = HashSink(Sha256::new());
                io::copy(&mut entry, &mut hasher)?;
                Some(hasher.0.finalize().into())
            } else {
                io::copy(&mut entry, &mut io::sink())?;
                None
            };
            drop(entry);

            // PAX/GNU meta records (`pax_global_header`, etc.) never
            // surface as filesystem entries.
            if matches!(meta.kind, EntryKind::Meta) {
                continue;
            }

            let path = normalise_path(&meta.path);
            if path.as_os_str().is_empty() {
                continue;
            }

            if let Some(action) = whiteout_action(&path) {
                match action {
                    Whiteout::Opaque { dir } => self.clear_subtree(&dir),
                    Whiteout::Remove { victim } => self.remove_subtree(&victim),
                }
                continue;
            }

            let node = FsNode {
                kind: meta.kind,
                mode: meta.mode,
                uid: meta.uid,
                gid: meta.gid,
                size: meta.size,
                content_hash,
                link_target: match meta.kind {
                    EntryKind::Symlink | EntryKind::Hardlink => meta.link_target,
                    _ => None,
                },
                rdev: meta.rdev,
                xattrs: meta.xattrs,
            };
            self.nodes.insert(path, node);
        }
        Ok(())
    }

    /// Drop `path` and any descendants in lex order.
    fn remove_subtree(&mut self, path: &Path) {
        let victims: Vec<PathBuf> = self
            .nodes
            .range(path.to_path_buf()..)
            .take_while(|(p, _)| p.as_path() == path || is_strict_descendant(path, p))
            .map(|(p, _)| p.clone())
            .collect();
        for v in victims {
            self.nodes.remove(&v);
        }
    }

    /// Drop strict descendants of `dir` while keeping `dir` itself.
    fn clear_subtree(&mut self, dir: &Path) {
        let victims: Vec<PathBuf> = self
            .nodes
            .range(dir.to_path_buf()..)
            .filter(|(p, _)| is_strict_descendant(dir, p))
            .map(|(p, _)| p.clone())
            .collect();
        for v in victims {
            self.nodes.remove(&v);
        }
    }

    /// Walk every [`EntryKind::Hardlink`] node, follow the chain to a
    /// terminal [`EntryKind::Regular`], inherit its metadata, and
    /// record the inode-equivalence class. Singleton classes are not
    /// recorded.
    fn resolve_hardlinks(&mut self) -> io::Result<()> {
        // Snapshot every hardlink edge from the *unmutated* node map
        // so chains that go alias → alias → ... → regular do not get
        // misread once the first alias has been rewritten in-place.
        let edges: Vec<(PathBuf, PathBuf)> = self
            .nodes
            .iter()
            .filter_map(|(p, n)| match (n.kind, &n.link_target) {
                (EntryKind::Hardlink, Some(t)) => Some((p.clone(), normalise_path(t))),
                _ => None,
            })
            .collect();

        // Union-Find over (alias, target) edges. A terminal regular's
        // path is its own root; aliases collapse onto whichever root
        // their chain leads to.
        let mut parent: BTreeMap<PathBuf, PathBuf> = BTreeMap::new();
        for (alias, target) in &edges {
            ensure_parent(&mut parent, alias);
            ensure_parent(&mut parent, target);
            let ra = uf_find(&mut parent, alias);
            let rb = uf_find(&mut parent, target);
            if ra != rb {
                // Pick the lex-smaller root deterministically — every
                // member of a class is a hardlink to the same inode, so
                // the choice is metadata-equivalent.
                let (winner, loser) = if ra <= rb { (ra, rb) } else { (rb, ra) };
                parent.insert(loser, winner);
            }
        }

        // Group every node mentioned in any edge by its root.
        let mut classes: BTreeMap<PathBuf, BTreeSet<PathBuf>> = BTreeMap::new();
        let members: Vec<PathBuf> = parent.keys().cloned().collect();
        for p in members {
            let root = uf_find(&mut parent, &p);
            classes.entry(root).or_default().insert(p);
        }

        // For each class, locate the terminal regular file and
        // propagate its metadata to every alias in the class. A class
        // with no regular member is malformed input.
        let mut groups: BTreeSet<BTreeSet<PathBuf>> = BTreeSet::new();
        for (_, members) in classes {
            let mut terminal: Option<PathBuf> = None;
            for m in &members {
                let node = self.nodes.get(m).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("hardlink class references missing path {}", m.display()),
                    )
                })?;
                match node.kind {
                    EntryKind::Regular => {
                        terminal = Some(m.clone());
                        break;
                    }
                    EntryKind::Hardlink => {}
                    other => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("hardlink class member {} has non-regular kind {other:?}", m.display()),
                        ));
                    }
                }
            }
            let terminal = terminal.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("hardlink class {members:?} has no regular file"),
                )
            })?;
            let inherited = self.nodes.get(&terminal).expect("terminal regular present").clone();
            for m in &members {
                if m != &terminal {
                    let node = self.nodes.get_mut(m).expect("alias node present");
                    *node = FsNode {
                        link_target: None,
                        ..inherited.clone()
                    };
                }
            }
            if members.len() > 1 {
                groups.insert(members);
            }
        }

        self.hardlink_groups = groups;
        Ok(())
    }
}

/// Compare two filesystems for spec 11 §11.5 round-trip equality.
///
/// Returns a human-readable diff on the first observed mismatch, or
/// `Ok(())` when every path, every metadata field, every body hash,
/// every xattr, and every hardlink group matches. The diff message is
/// suitable for `assert!(eq.is_ok(), "{}", eq.unwrap_err())`.
///
/// The permitted differences from spec 11 §11.5 — mtime / uname /
/// gname — are absent from [`FsNode`] entirely, so this comparison is
/// already correct without an explicit allowlist.
///
/// # Errors
///
/// Returns `Err(diff)` describing the first observed discrepancy.
pub fn diff(left: &InMemoryFs, right: &InMemoryFs) -> Result<(), String> {
    let left_paths: BTreeSet<&Path> = left.nodes.keys().map(PathBuf::as_path).collect();
    let right_paths: BTreeSet<&Path> = right.nodes.keys().map(PathBuf::as_path).collect();

    let only_left: Vec<&Path> = left_paths.difference(&right_paths).copied().collect();
    let only_right: Vec<&Path> = right_paths.difference(&left_paths).copied().collect();
    if !only_left.is_empty() || !only_right.is_empty() {
        let mut msg = String::from("path set differs:\n");
        for p in &only_left {
            let _ = writeln!(msg, "  only in left:  {}", p.display());
        }
        for p in &only_right {
            let _ = writeln!(msg, "  only in right: {}", p.display());
        }
        return Err(msg);
    }

    for (path, lnode) in &left.nodes {
        let rnode = right.nodes.get(path).expect("path set already equal");

        if lnode != rnode {
            return Err(format!(
                "path {} differs:\n  left:  {:?}\n  right: {:?}",
                path.display(),
                lnode,
                rnode
            ));
        }
    }

    if left.hardlink_groups != right.hardlink_groups {
        return Err(format!(
            "hardlink topology differs:\n  left:  {:?}\n  right: {:?}",
            left.hardlink_groups, right.hardlink_groups
        ));
    }

    Ok(())
}

fn io_err(e: layermeld::Error) -> io::Error {
    match e {
        layermeld::Error::Io(inner) => inner,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}

const WHITEOUT_PREFIX: &[u8] = b".wh.";
const OPAQUE_MARKER: &[u8] = b".wh..wh..opq";

#[derive(Debug)]
enum Whiteout {
    Opaque { dir: PathBuf },
    Remove { victim: PathBuf },
}

fn whiteout_action(path: &Path) -> Option<Whiteout> {
    let name = path.file_name()?.as_bytes();
    if name == OPAQUE_MARKER {
        let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
        return Some(Whiteout::Opaque { dir });
    }
    let victim_name = name.strip_prefix(WHITEOUT_PREFIX)?;
    if victim_name.is_empty() {
        return None;
    }
    let mut victim = path.parent().map(Path::to_path_buf).unwrap_or_default();
    victim.push(OsStr::from_bytes(victim_name));
    Some(Whiteout::Remove { victim })
}

fn normalise_path(path: &Path) -> PathBuf {
    let mut bytes = path.as_os_str().as_bytes();
    if let Some(rest) = bytes.strip_prefix(b"./") {
        bytes = rest;
    } else if let Some(rest) = bytes.strip_prefix(b"/") {
        bytes = rest;
    }
    while bytes.last() == Some(&b'/') {
        bytes = &bytes[..bytes.len() - 1];
    }
    PathBuf::from(OsStr::from_bytes(bytes))
}

fn is_strict_descendant(ancestor: &Path, candidate: &Path) -> bool {
    let mut a = ancestor.components();
    let mut c = candidate.components();
    loop {
        match (a.next(), c.next()) {
            (Some(ax), Some(cx)) if ax == cx => {}
            (None, Some(_)) => return true,
            _ => return false,
        }
    }
}

fn ensure_parent(parent: &mut BTreeMap<PathBuf, PathBuf>, p: &Path) {
    if !parent.contains_key(p) {
        parent.insert(p.to_path_buf(), p.to_path_buf());
    }
}

fn uf_find(parent: &mut BTreeMap<PathBuf, PathBuf>, p: &Path) -> PathBuf {
    let mut cursor = p.to_path_buf();
    loop {
        let next = parent.get(&cursor).expect("path inserted before find").clone();
        if next == cursor {
            return cursor;
        }
        cursor = next;
    }
}
