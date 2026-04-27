//! Streaming tar reader (spec 02 §02.2).
//!
//! Wraps [`tar::Archive`] to yield each entry as parsed metadata plus a
//! body cursor. The reader is decompression-agnostic — it accepts any
//! [`Read`], so callers must layer gzip/zstd decoders externally
//! (see [`crate::tar_io::compression`]).
//!
//! Bodies are exposed through the [`Read`] impl on [`Entry`]; nothing here
//! ever spools to disk, in line with spec 02's hard rule.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::PathBuf;

use crate::Result;

/// Normalised entry kind across `ustar`, `gnu`, and `pax` dialects.
///
/// Mirrors the `EntryKind` set used by [`crate::identity`] (spec 04 §4.1)
/// plus a `Hardlink` variant that the identity layer later collapses into
/// `Regular` per spec 04 §4.2.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum EntryKind {
    Regular,
    Directory,
    Symlink,
    Hardlink,
    CharDevice,
    BlockDevice,
    Fifo,
    /// PAX/GNU meta entries (e.g. `pax_global_header`) that should not
    /// surface as filesystem entries. Callers typically skip these.
    Meta,
}

impl EntryKind {
    /// `true` for kinds whose tar body carries file contents (regular
    /// files only). All other kinds have a zero-length body.
    #[must_use]
    pub fn has_body(self) -> bool {
        matches!(self, EntryKind::Regular)
    }
}

/// Header metadata for a single tar entry.
///
/// The field set is the union of what spec 04 §4.1 (file identity) and
/// the round-trip tests in spec 11 §11.5 need. Mtime, uname, and gname
/// are captured for round-trip checks but are explicitly excluded from
/// identity per spec 04 §4.2.
#[derive(Debug, Clone)]
pub struct EntryMeta {
    pub path: PathBuf,
    pub kind: EntryKind,
    pub size: u64,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub mtime: u64,
    pub uname: Option<String>,
    pub gname: Option<String>,
    /// Resolved link target for symlinks (`type=2`) and hardlinks (`type=1`).
    pub link_target: Option<PathBuf>,
    /// `(major, minor)` for character/block devices, otherwise `None`.
    pub rdev: Option<(u32, u32)>,
    /// PAX xattrs (`SCHILY.xattr.*` / `LIBARCHIVE.xattr.*`), prefix stripped.
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Streaming tar reader. Generic over any [`Read`] — the caller layers
/// decompression on top.
pub struct Reader<R: Read> {
    inner: tar::Archive<R>,
}

impl<R: Read> Reader<R> {
    /// Wrap any [`Read`] as a streaming tar source.
    pub fn new(inner: R) -> Self {
        let mut archive = tar::Archive::new(inner);
        // We never let the `tar` crate touch the filesystem: the squash
        // and assemble passes consume entries directly. Disabling these
        // toggles makes that intent explicit.
        archive.set_preserve_permissions(false);
        archive.set_preserve_mtime(false);
        archive.set_unpack_xattrs(false);
        Self { inner: archive }
    }

    /// Borrow an iterator over entries.
    ///
    /// Per spec 02 §02.3, callers may make multiple sequential passes over
    /// an input layer by reopening the underlying [`Read`]; this iterator
    /// is single-pass.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the underlying reader is already in
    /// an unrecoverable state when the iterator is set up.
    pub fn entries(&mut self) -> Result<Entries<'_, R>> {
        Ok(Entries {
            inner: self.inner.entries()?,
        })
    }
}

/// Streaming iterator over tar entries.
///
/// Each [`Entry`] borrows the underlying reader; the previous entry must
/// be dropped (or fully consumed) before the next one is fetched. This is
/// the [`tar::Entries`] streaming-iterator pattern surfaced as our own type.
pub struct Entries<'a, R: 'a + Read> {
    inner: tar::Entries<'a, R>,
}

impl<'a, R: 'a + Read> Iterator for Entries<'a, R> {
    type Item = Result<Entry<'a, R>>;

    fn next(&mut self) -> Option<Self::Item> {
        let raw = self.inner.next()?;
        Some(raw.map_err(crate::Error::from).and_then(Entry::from_tar))
    }
}

/// A single tar entry: parsed metadata plus a body cursor.
///
/// `Entry` implements [`Read`]; reading drains the body bytes for regular
/// files. Bodies of non-regular entries are zero-length and yield EOF
/// immediately.
pub struct Entry<'a, R: Read> {
    meta: EntryMeta,
    body: tar::Entry<'a, R>,
}

impl<'a, R: Read> Entry<'a, R> {
    fn from_tar(mut entry: tar::Entry<'a, R>) -> Result<Self> {
        let meta = parse_meta(&mut entry)?;
        Ok(Self { meta, body: entry })
    }

    /// Parsed header metadata.
    #[must_use]
    pub fn meta(&self) -> &EntryMeta {
        &self.meta
    }
}

impl<R: Read> Read for Entry<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.body.read(buf)
    }
}

fn parse_meta<R: Read>(entry: &mut tar::Entry<'_, R>) -> Result<EntryMeta> {
    let path = entry.path()?.into_owned();
    let link_target = entry.link_name()?.map(std::borrow::Cow::into_owned);

    // PAX records are read off the entry, not the header (the header type
    // would only see ustar fields).
    let mut xattrs = BTreeMap::new();
    if let Some(exts) = entry.pax_extensions()? {
        for ext in exts {
            let ext = ext?;
            let key = ext.key_bytes();
            if let Some(name) = key
                .strip_prefix(b"SCHILY.xattr.")
                .or_else(|| key.strip_prefix(b"LIBARCHIVE.xattr."))
            {
                xattrs.insert(name.to_vec(), ext.value_bytes().to_vec());
            }
        }
    }

    let header = entry.header();
    let kind = entry_kind(header);
    let rdev = match kind {
        EntryKind::CharDevice | EntryKind::BlockDevice => match (header.device_major()?, header.device_minor()?) {
            (Some(maj), Some(min)) => Some((maj, min)),
            _ => None,
        },
        _ => None,
    };

    Ok(EntryMeta {
        path,
        kind,
        size: header.size()?,
        mode: header.mode()?,
        uid: header.uid()?,
        gid: header.gid()?,
        mtime: header.mtime()?,
        uname: header.username().ok().flatten().map(str::to_owned),
        gname: header.groupname().ok().flatten().map(str::to_owned),
        link_target,
        rdev,
        xattrs,
    })
}

fn entry_kind(header: &tar::Header) -> EntryKind {
    use tar::EntryType;
    match header.entry_type() {
        EntryType::Regular | EntryType::Continuous => EntryKind::Regular,
        EntryType::Directory => EntryKind::Directory,
        EntryType::Symlink => EntryKind::Symlink,
        EntryType::Link => EntryKind::Hardlink,
        EntryType::Char => EntryKind::CharDevice,
        EntryType::Block => EntryKind::BlockDevice,
        EntryType::Fifo => EntryKind::Fifo,
        _ => EntryKind::Meta,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use tar::{Builder, EntryType, Header};

    use super::*;

    /// Build a tarball in memory with one regular file, one directory,
    /// one symlink, one hardlink, and a regular file carrying an xattr.
    fn fixture_tarball() -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut tb = Builder::new(&mut buf);
            tb.mode(tar::HeaderMode::Deterministic);

            // Directory.
            let mut dh = Header::new_gnu();
            dh.set_entry_type(EntryType::Directory);
            dh.set_path("etc/").unwrap();
            dh.set_mode(0o755);
            dh.set_uid(0);
            dh.set_gid(0);
            dh.set_size(0);
            dh.set_cksum();
            tb.append(&dh, std::io::empty()).unwrap();

            // Regular file.
            let body = b"hello world\n";
            let mut fh = Header::new_gnu();
            fh.set_entry_type(EntryType::Regular);
            fh.set_path("etc/hostname").unwrap();
            fh.set_mode(0o644);
            fh.set_uid(0);
            fh.set_gid(0);
            fh.set_size(body.len() as u64);
            fh.set_cksum();
            tb.append(&fh, &body[..]).unwrap();

            // Symlink.
            let mut sh = Header::new_gnu();
            sh.set_entry_type(EntryType::Symlink);
            sh.set_path("etc/hostname.link").unwrap();
            sh.set_link_name("hostname").unwrap();
            sh.set_mode(0o777);
            sh.set_uid(0);
            sh.set_gid(0);
            sh.set_size(0);
            sh.set_cksum();
            tb.append(&sh, std::io::empty()).unwrap();

            // Hardlink to the regular file.
            let mut hh = Header::new_gnu();
            hh.set_entry_type(EntryType::Link);
            hh.set_path("etc/hostname.alias").unwrap();
            hh.set_link_name("etc/hostname").unwrap();
            hh.set_mode(0o644);
            hh.set_uid(0);
            hh.set_gid(0);
            hh.set_size(0);
            hh.set_cksum();
            tb.append(&hh, std::io::empty()).unwrap();

            // PAX-encoded xattr on a second regular file.
            let body2 = b"data";
            let pax = pax_xattr_record(b"SCHILY.xattr.user.flag", b"on");
            let mut ph = Header::new_gnu();
            ph.set_entry_type(EntryType::XHeader);
            ph.set_uid(0);
            ph.set_gid(0);
            ph.set_mode(0o644);
            ph.set_size(pax.len() as u64);
            ph.set_cksum();
            tb.append(&ph, &pax[..]).unwrap();
            let mut fh2 = Header::new_gnu();
            fh2.set_entry_type(EntryType::Regular);
            fh2.set_path("var/data").unwrap();
            fh2.set_mode(0o600);
            fh2.set_uid(0);
            fh2.set_gid(0);
            fh2.set_size(body2.len() as u64);
            fh2.set_cksum();
            tb.append(&fh2, &body2[..]).unwrap();

            tb.finish().unwrap();
        }
        buf
    }

    /// Encode one PAX extended-header record per pax(1): `<len> <key>=<val>\n`,
    /// where `<len>` counts every byte of the record including itself.
    fn pax_xattr_record(key: &[u8], value: &[u8]) -> Vec<u8> {
        // Iterate digit counts because the length field is self-referential.
        let body_len = key.len() + value.len() + 3; // ' ', '=', '\n'
        let mut digits = 1usize;
        loop {
            let total = body_len + digits;
            if total.to_string().len() == digits {
                let mut out = Vec::with_capacity(total);
                write!(out, "{total} ").unwrap();
                out.extend_from_slice(key);
                out.push(b'=');
                out.extend_from_slice(value);
                out.push(b'\n');
                return out;
            }
            digits += 1;
        }
    }

    #[test]
    fn streams_entries_with_parsed_metadata() {
        let bytes = fixture_tarball();
        let mut reader = Reader::new(Cursor::new(bytes));

        let mut paths = Vec::new();
        let mut entries = reader.entries().unwrap();
        for entry in entries.by_ref() {
            let entry = entry.unwrap();
            paths.push((entry.meta().path.clone(), entry.meta().kind));
        }

        assert_eq!(paths.len(), 5);
        assert_eq!(paths[0].1, EntryKind::Directory);
        assert_eq!(paths[1].1, EntryKind::Regular);
        assert_eq!(paths[2].1, EntryKind::Symlink);
        assert_eq!(paths[3].1, EntryKind::Hardlink);
        assert_eq!(paths[4].1, EntryKind::Regular);
    }

    #[test]
    fn body_cursor_yields_file_contents() {
        let bytes = fixture_tarball();
        let mut reader = Reader::new(Cursor::new(bytes));
        let mut entries = reader.entries().unwrap();

        // Skip the directory.
        let _ = entries.next().unwrap().unwrap();

        let mut file = entries.next().unwrap().unwrap();
        assert_eq!(file.meta().path.to_str().unwrap(), "etc/hostname");
        assert_eq!(file.meta().size, b"hello world\n".len() as u64);
        let mut body = Vec::new();
        file.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"hello world\n");
    }

    #[test]
    fn link_targets_are_parsed() {
        let bytes = fixture_tarball();
        let mut reader = Reader::new(Cursor::new(bytes));
        let entries: Vec<_> = reader
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.meta().kind, e.meta().link_target.clone())
            })
            .collect();

        let symlink = entries.iter().find(|(k, _)| *k == EntryKind::Symlink).unwrap();
        assert_eq!(symlink.1.as_deref().unwrap().to_str().unwrap(), "hostname");

        let hardlink = entries.iter().find(|(k, _)| *k == EntryKind::Hardlink).unwrap();
        assert_eq!(hardlink.1.as_deref().unwrap().to_str().unwrap(), "etc/hostname");
    }

    #[test]
    fn pax_xattrs_round_trip() {
        let bytes = fixture_tarball();
        let mut reader = Reader::new(Cursor::new(bytes));
        let entries = reader.entries().unwrap();

        let with_xattr = entries
            .filter_map(std::result::Result::ok)
            .find(|e| e.meta().path.to_str() == Some("var/data"))
            .expect("var/data entry");

        let xattrs = &with_xattr.meta().xattrs;
        assert_eq!(xattrs.len(), 1);
        assert_eq!(xattrs.get(&b"user.flag".to_vec()).map(Vec::as_slice), Some(&b"on"[..]));
    }

    #[test]
    fn entry_implements_read() {
        // Sanity: confirm `Entry` can be passed to a generic `Read` consumer.
        fn consume<R: Read>(mut r: R) -> Vec<u8> {
            let mut v = Vec::new();
            r.read_to_end(&mut v).unwrap();
            v
        }
        let bytes = fixture_tarball();
        let mut reader = Reader::new(Cursor::new(bytes));
        let mut entries = reader.entries().unwrap();
        let _ = entries.next().unwrap().unwrap();
        let file = entries.next().unwrap().unwrap();
        assert_eq!(consume(file), b"hello world\n");
    }
}
