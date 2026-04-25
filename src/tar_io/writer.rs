//! PAX tar writer (spec 02 §2.4).
//!
//! Emits `ustar`+PAX-extended-header tar streams. The writer is fed
//! pre-parsed [`EntryMeta`] records together with an opaque body
//! [`Read`]; bytes flow through unchanged. Crucially, raw input header
//! bytes are never copied — every output header is reconstructed from
//! [`EntryMeta`] so that mixed-dialect inputs (`ustar`, `gnu`, `pax`)
//! always produce a uniform PAX output.
//!
//! When a field would not fit in its ustar slot the writer prepends a
//! PAX extended-header (`type=x`) entry carrying the authoritative
//! value and clamps the ustar slot to a portable placeholder. The
//! cases handled here:
//!
//! * Long path → PAX `path`.
//! * Long symlink/hardlink target → PAX `linkpath`.
//! * Numeric uid/gid above the 7-octal-digit ustar range → PAX
//!   `uid`/`gid`.
//! * File size above the 11-octal-digit ustar range → PAX `size`.
//! * Every entry's xattrs → PAX `SCHILY.xattr.*`.
//!
//! `uname`/`gname` are *always* emitted empty (numeric-only ownership,
//! per spec 02 §2.4) — input strings are dropped.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use tar::{EntryType, Header};

use crate::tar_io::pax;
use crate::tar_io::reader::{EntryKind, EntryMeta};
use crate::{Error, Result};

const BLOCK_SIZE: usize = 512;

/// Largest uid/gid that fits in the 8-byte ustar field (7 octal digits + NUL).
const USTAR_ID_MAX: u64 = 0o7_777_777;
/// Largest size that fits in the 12-byte ustar field (11 octal digits + NUL).
const USTAR_SIZE_MAX: u64 = 0o77_777_777_777;

/// Streaming PAX tar writer.
///
/// Wraps any [`Write`]: output goes verbatim into it, so callers can layer
/// hashing or compression underneath. The writer takes ownership of the
/// inner sink and returns it from [`Writer::finish`] after the two-block
/// trailer is written.
pub struct Writer<W: Write> {
    inner: Option<W>,
    finished: bool,
}

impl<W: Write> Writer<W> {
    /// Wrap any [`Write`] as a tar destination.
    pub fn new(inner: W) -> Self {
        Self {
            inner: Some(inner),
            finished: false,
        }
    }

    /// Append a single entry. The body must yield exactly `meta.size`
    /// bytes for [`EntryKind::Regular`]; for any other kind the writer
    /// ignores `body` and emits a zero-length body.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] for any I/O failure on the underlying sink
    /// or body reader, [`Error::Validation`] if a regular file's body
    /// length disagrees with `meta.size`, and propagates header-encoding
    /// errors as [`Error::Io`] (the upstream `tar` crate's error type).
    ///
    /// # Panics
    ///
    /// Panics if called after [`Writer::finish`].
    pub fn append(&mut self, meta: &EntryMeta, mut body: impl Read) -> Result<()> {
        let dst = self.inner.as_mut().expect("Writer::append called after finish");
        emit_entry(dst, meta, &mut body)
    }

    /// Write the two zero blocks marking end-of-archive and return the
    /// underlying sink. Idempotent — calling twice is safe.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if writing the trailer fails.
    ///
    /// # Panics
    ///
    /// Panics if called twice on the same writer (the inner sink has
    /// already been moved out).
    pub fn finish(mut self) -> Result<W> {
        self.do_finish()?;
        Ok(self.inner.take().expect("inner taken twice"))
    }

    fn do_finish(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        let dst = self
            .inner
            .as_mut()
            .expect("Writer::finish called twice on the same writer");
        dst.write_all(&[0u8; BLOCK_SIZE * 2])?;
        Ok(())
    }
}

impl<W: Write> Drop for Writer<W> {
    fn drop(&mut self) {
        if !self.finished && self.inner.is_some() {
            // Best-effort trailer on drop; matches `tar::Builder` behavior.
            let _ = self.do_finish();
        }
    }
}

fn emit_entry(dst: &mut dyn Write, meta: &EntryMeta, body: &mut dyn Read) -> Result<()> {
    let entry_type = match meta.kind {
        EntryKind::Regular => EntryType::Regular,
        EntryKind::Directory => EntryType::Directory,
        EntryKind::Symlink => EntryType::Symlink,
        EntryKind::Hardlink => EntryType::Link,
        EntryKind::CharDevice => EntryType::Char,
        EntryKind::BlockDevice => EntryType::Block,
        EntryKind::Fifo => EntryType::Fifo,
        EntryKind::Meta => {
            return Err(Error::Validation(
                "tar_io::writer received a PAX/GNU meta entry; these are reader-only".into(),
            ));
        }
    };

    let mut records: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut header = Header::new_ustar();
    header.set_entry_type(entry_type);

    // Path. Directories conventionally end with '/'.
    let header_path = match meta.kind {
        EntryKind::Directory => with_trailing_slash(&meta.path),
        _ => meta.path.clone(),
    };
    set_path_or_pax(&mut header, &header_path, &mut records)?;

    // Link target — symlinks (`type=2`) and hardlinks (`type=1`).
    if let Some(target) = &meta.link_target {
        set_link_or_pax(&mut header, target, &mut records);
    }

    // Mode (permission bits + setuid/setgid/sticky).
    header.set_mode(meta.mode);

    // uid / gid: PAX-escape values that overflow the ustar octal field.
    if meta.uid > USTAR_ID_MAX {
        records.push((b"uid".to_vec(), meta.uid.to_string().into_bytes()));
        header.set_uid(0);
    } else {
        header.set_uid(meta.uid);
    }
    if meta.gid > USTAR_ID_MAX {
        records.push((b"gid".to_vec(), meta.gid.to_string().into_bytes()));
        header.set_gid(0);
    } else {
        header.set_gid(meta.gid);
    }

    // uname / gname always empty per spec 02 §2.4.
    header.set_username("")?;
    header.set_groupname("")?;

    // mtime: trust the caller (timestamp normalization is upstream's job).
    header.set_mtime(meta.mtime);

    // Body size: only regulars carry one.
    let body_size = if matches!(meta.kind, EntryKind::Regular) {
        meta.size
    } else {
        0
    };
    if body_size > USTAR_SIZE_MAX {
        records.push((b"size".to_vec(), body_size.to_string().into_bytes()));
        header.set_size(0);
    } else {
        header.set_size(body_size);
    }

    // Device numbers for char/block devices.
    if let Some((maj, min)) = meta.rdev {
        header.set_device_major(maj)?;
        header.set_device_minor(min)?;
    }

    // xattrs: emit each as `SCHILY.xattr.<name>` per spec 02 §2.4.
    for (k, v) in &meta.xattrs {
        let mut key = Vec::with_capacity("SCHILY.xattr.".len() + k.len());
        key.extend_from_slice(b"SCHILY.xattr.");
        key.extend_from_slice(k);
        records.push((key, v.clone()));
    }

    // Emit the PAX extended-header entry first, if we accumulated any
    // records. The records body is padded to a 512-block boundary.
    if !records.is_empty() {
        let body_bytes = pax::encode_records(&records);
        let pax_header = build_pax_header(&header_path, body_bytes.len() as u64, meta.mtime)?;
        dst.write_all(pax_header.as_bytes())?;
        dst.write_all(&body_bytes)?;
        write_padding(dst, body_bytes.len())?;
    }

    header.set_cksum();
    dst.write_all(header.as_bytes())?;

    if body_size == 0 {
        return Ok(());
    }
    let copied = io::copy(body, dst)?;
    if copied != body_size {
        return Err(Error::Validation(format!(
            "body length mismatch for {}: header declared {body_size}, body supplied {copied}",
            meta.path.display(),
        )));
    }
    // body_size <= USTAR_SIZE_MAX (~8 GiB) on the small branch, but
    // PAX-escaped bodies can exceed it. `usize::try_from` is therefore
    // necessary for correctness on 32-bit targets.
    let body_size_usize =
        usize::try_from(body_size).map_err(|_| Error::Validation(format!("body size {body_size} exceeds usize")))?;
    write_padding(dst, body_size_usize)?;
    Ok(())
}

fn build_pax_header(entry_path: &Path, size: u64, mtime: u64) -> Result<Header> {
    let mut h = Header::new_ustar();
    h.set_entry_type(EntryType::XHeader);
    let pax_path = pax_header_placeholder(entry_path);
    set_short_path(&mut h, &pax_path)?;
    h.set_mode(0o644);
    h.set_uid(0);
    h.set_gid(0);
    h.set_username("")?;
    h.set_groupname("")?;
    h.set_size(size);
    h.set_mtime(mtime);
    h.set_cksum();
    Ok(h)
}

/// Build a deterministic placeholder name for the PAX-extended-header
/// entry: `<dir>/PaxHeaders/<basename>`. Extractors do not materialize
/// this entry — the records inside it apply to the *next* real entry —
/// but the name still needs to be valid ustar bytes and stable across
/// runs for byte-identical output.
fn pax_header_placeholder(entry_path: &Path) -> PathBuf {
    let bytes = entry_path.as_os_str().as_bytes();
    let trimmed = bytes.strip_suffix(b"/").unwrap_or(bytes);
    let split = trimmed.iter().rposition(|&b| b == b'/');
    let mut out = Vec::with_capacity(trimmed.len() + 12);
    if let Some(i) = split {
        out.extend_from_slice(&trimmed[..i]);
        out.extend_from_slice(b"/PaxHeaders/");
        out.extend_from_slice(&trimmed[i + 1..]);
    } else {
        out.extend_from_slice(b"PaxHeaders/");
        out.extend_from_slice(trimmed);
    }
    PathBuf::from(OsString::from_vec(out))
}

/// Set `path` on `header`, falling back to a PAX `path` record when the
/// path overflows the ustar 100+155 name/prefix slots. The ustar slots
/// always receive a deterministic truncation so the file is identifiable
/// even by extractors that ignore PAX records.
fn set_path_or_pax(header: &mut Header, path: &Path, records: &mut Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
    if header.set_path(path).is_ok() {
        return Ok(());
    }
    records.push((b"path".to_vec(), path.as_os_str().as_bytes().to_vec()));
    set_short_path(header, path)
}

/// Set `link_name` on `header`, falling back to a PAX `linkpath` record
/// when the target overflows the 100-byte linkname slot.
fn set_link_or_pax(header: &mut Header, target: &Path, records: &mut Vec<(Vec<u8>, Vec<u8>)>) {
    if header.set_link_name(target).is_ok() {
        return;
    }
    records.push((b"linkpath".to_vec(), target.as_os_str().as_bytes().to_vec()));
    let bytes = target.as_os_str().as_bytes();
    let truncated = truncate_to_utf8_boundary(bytes, 100);
    if !truncated.is_empty() {
        // Ignore failure: the PAX `linkpath` record is authoritative.
        let _ = header.set_link_name(truncated);
    }
}

/// Write a path of any length into the ustar name field as a best-effort
/// fallback. If the path would exceed ustar's 100/155-byte slots, the
/// caller is responsible for emitting a PAX `path` record; this function
/// only fills the ustar bytes with a deterministic truncation.
fn set_short_path(header: &mut Header, path: &Path) -> Result<()> {
    if header.set_path(path).is_ok() {
        return Ok(());
    }
    let bytes = path.as_os_str().as_bytes();
    let truncated = truncate_to_utf8_boundary(bytes, 100);
    let placeholder = if truncated.is_empty() {
        // Path's leading bytes were not utf-8; pick a stable literal.
        "_pax_placeholder"
    } else {
        truncated
    };
    header.set_path(placeholder)?;
    Ok(())
}

fn truncate_to_utf8_boundary(bytes: &[u8], max: usize) -> &str {
    let cut = bytes.len().min(max);
    match std::str::from_utf8(&bytes[..cut]) {
        Ok(s) => s,
        Err(e) => std::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or(""),
    }
}

fn with_trailing_slash(path: &Path) -> PathBuf {
    let bytes = path.as_os_str().as_bytes();
    if bytes.ends_with(b"/") {
        return path.to_path_buf();
    }
    let mut v = Vec::with_capacity(bytes.len() + 1);
    v.extend_from_slice(bytes);
    v.push(b'/');
    PathBuf::from(OsString::from_vec(v))
}

fn write_padding(dst: &mut dyn Write, written: usize) -> Result<()> {
    let rem = written % BLOCK_SIZE;
    if rem == 0 {
        return Ok(());
    }
    let pad = [0u8; BLOCK_SIZE];
    dst.write_all(&pad[..BLOCK_SIZE - rem])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;

    use super::*;
    use crate::tar_io::reader::Reader;

    fn meta(path: &str, kind: EntryKind) -> EntryMeta {
        EntryMeta {
            path: PathBuf::from(path),
            kind,
            size: 0,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            uname: None,
            gname: None,
            link_target: None,
            rdev: None,
            xattrs: BTreeMap::new(),
        }
    }

    /// Read every entry from `bytes` and collect (meta, body) pairs.
    fn read_back(bytes: &[u8]) -> Vec<(EntryMeta, Vec<u8>)> {
        let mut reader = Reader::new(Cursor::new(bytes.to_vec()));
        let mut out = Vec::new();
        let mut entries = reader.entries().unwrap();
        for entry in entries.by_ref() {
            let mut entry = entry.unwrap();
            let mut body = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut body).unwrap();
            out.push((entry.meta().clone(), body));
        }
        out
    }

    #[test]
    fn round_trips_regular_file_with_body() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            let mut m = meta("etc/hostname", EntryKind::Regular);
            m.size = 12;
            m.mode = 0o644;
            w.append(&m, &b"hello world\n"[..]).unwrap();
            w.finish().unwrap();
        }
        let entries = read_back(&buf);
        assert_eq!(entries.len(), 1);
        let (m, body) = &entries[0];
        assert_eq!(m.path.to_str().unwrap(), "etc/hostname");
        assert_eq!(m.kind, EntryKind::Regular);
        assert_eq!(m.size, 12);
        assert_eq!(m.mode & 0o7777, 0o644);
        assert_eq!(body, b"hello world\n");
    }

    #[test]
    fn directory_keeps_trailing_slash() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            let mut m = meta("etc", EntryKind::Directory);
            m.mode = 0o755;
            w.append(&m, std::io::empty()).unwrap();
            w.finish().unwrap();
        }
        // The reader strips trailing /; observe via the raw header bytes
        // by checking that name field starts with "etc/".
        assert!(
            buf.starts_with(b"etc/"),
            "expected ustar name to be 'etc/', got {:?}",
            &buf[..16]
        );
    }

    #[test]
    fn symlink_round_trips_target() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            let mut m = meta("etc/hostname.link", EntryKind::Symlink);
            m.link_target = Some(PathBuf::from("hostname"));
            m.mode = 0o777;
            w.append(&m, std::io::empty()).unwrap();
            w.finish().unwrap();
        }
        let entries = read_back(&buf);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.kind, EntryKind::Symlink);
        assert_eq!(
            entries[0].0.link_target.as_deref().unwrap().to_str().unwrap(),
            "hostname"
        );
    }

    #[test]
    fn hardlink_emitted_with_target() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            let mut m = meta("etc/hostname.alias", EntryKind::Hardlink);
            m.link_target = Some(PathBuf::from("etc/hostname"));
            w.append(&m, std::io::empty()).unwrap();
            w.finish().unwrap();
        }
        let entries = read_back(&buf);
        assert_eq!(entries[0].0.kind, EntryKind::Hardlink);
        assert_eq!(
            entries[0].0.link_target.as_deref().unwrap().to_str().unwrap(),
            "etc/hostname"
        );
    }

    #[test]
    fn long_path_emits_pax_path_record() {
        // ustar fits 100+155=256; this path is ~280 bytes including the
        // dir separator, with no '/' in the last 200 chars so the
        // prefix/name split cannot rescue it.
        let long_name = "a".repeat(280);
        let path = format!("d/{long_name}");

        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            let mut m = meta(&path, EntryKind::Regular);
            m.size = 3;
            w.append(&m, &b"abc"[..]).unwrap();
            w.finish().unwrap();
        }
        let entries = read_back(&buf);
        assert_eq!(entries.len(), 1, "PAX header is folded into one entry");
        assert_eq!(entries[0].0.path.to_str().unwrap(), path);
        assert_eq!(entries[0].1, b"abc");
    }

    #[test]
    fn long_link_target_uses_pax_linkpath() {
        let target = "b".repeat(150);
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            let mut m = meta("a", EntryKind::Symlink);
            m.link_target = Some(PathBuf::from(&target));
            w.append(&m, std::io::empty()).unwrap();
            w.finish().unwrap();
        }
        let entries = read_back(&buf);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.link_target.as_deref().unwrap().to_str().unwrap(), target);
    }

    #[test]
    fn large_uid_gid_use_pax_records() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            let mut m = meta("usr/bin/big", EntryKind::Regular);
            m.size = 0;
            m.uid = 5_000_000; // > 0o7_777_777 == 2_097_151
            m.gid = 6_000_000;
            w.append(&m, std::io::empty()).unwrap();
            w.finish().unwrap();
        }
        let entries = read_back(&buf);
        assert_eq!(entries[0].0.uid, 5_000_000);
        assert_eq!(entries[0].0.gid, 6_000_000);
    }

    #[test]
    fn xattrs_round_trip_through_pax_schily() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            let mut m = meta("var/data", EntryKind::Regular);
            m.size = 4;
            m.xattrs.insert(b"user.flag".to_vec(), b"on".to_vec());
            m.xattrs.insert(b"security.selinux".to_vec(), b"u:r:s".to_vec());
            w.append(&m, &b"data"[..]).unwrap();
            w.finish().unwrap();
        }
        let entries = read_back(&buf);
        let xattrs = &entries[0].0.xattrs;
        assert_eq!(xattrs.len(), 2);
        assert_eq!(xattrs.get(&b"user.flag"[..].to_vec()).unwrap(), b"on");
        assert_eq!(xattrs.get(&b"security.selinux"[..].to_vec()).unwrap(), b"u:r:s");
        assert_eq!(entries[0].1, b"data");
    }

    #[test]
    fn uname_gname_always_empty() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            let mut m = meta("a", EntryKind::Regular);
            m.size = 0;
            // Setting uname/gname on input has no effect on output.
            m.uname = Some("root".into());
            m.gname = Some("root".into());
            w.append(&m, std::io::empty()).unwrap();
            w.finish().unwrap();
        }
        let entries = read_back(&buf);
        assert!(
            entries[0].0.uname.as_deref().unwrap_or("").is_empty(),
            "uname must be empty in output"
        );
        assert!(
            entries[0].0.gname.as_deref().unwrap_or("").is_empty(),
            "gname must be empty in output"
        );
    }

    #[test]
    fn body_length_mismatch_is_validation_error() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        let mut m = meta("a", EntryKind::Regular);
        m.size = 10; // declared 10
        let err = w.append(&m, &b"only-3"[..]).unwrap_err(); // supply 6
        match err {
            Error::Validation(_) => {}
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn meta_kind_is_rejected() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        let m = meta("x", EntryKind::Meta);
        let err = w.append(&m, std::io::empty()).unwrap_err();
        match err {
            Error::Validation(_) => {}
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn char_device_carries_rdev() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            let mut m = meta("dev/null", EntryKind::CharDevice);
            m.rdev = Some((1, 3));
            w.append(&m, std::io::empty()).unwrap();
            w.finish().unwrap();
        }
        let entries = read_back(&buf);
        assert_eq!(entries[0].0.kind, EntryKind::CharDevice);
        assert_eq!(entries[0].0.rdev, Some((1, 3)));
    }

    #[test]
    fn finish_writes_two_zero_blocks() {
        let mut buf = Vec::new();
        let w = Writer::new(&mut buf);
        w.finish().unwrap();
        assert_eq!(buf.len(), BLOCK_SIZE * 2);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn drop_emits_trailer_when_finish_skipped() {
        let mut buf = Vec::new();
        {
            let _w: Writer<&mut Vec<u8>> = Writer::new(&mut buf);
            // dropped without finish()
        }
        assert_eq!(buf.len(), BLOCK_SIZE * 2);
    }

    #[test]
    fn pax_placeholder_for_root_basename() {
        let p = pax_header_placeholder(Path::new("foo"));
        assert_eq!(p.to_str().unwrap(), "PaxHeaders/foo");

        let p = pax_header_placeholder(Path::new("a/b/c"));
        assert_eq!(p.to_str().unwrap(), "a/b/PaxHeaders/c");

        // Trailing slash on directories is stripped before splitting.
        let p = pax_header_placeholder(Path::new("etc/"));
        assert_eq!(p.to_str().unwrap(), "PaxHeaders/etc");
    }

    #[test]
    fn output_dialect_is_ustar_not_gnu() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf);
            let mut m = meta("a", EntryKind::Regular);
            m.size = 0;
            w.append(&m, std::io::empty()).unwrap();
            w.finish().unwrap();
        }
        // POSIX ustar magic: "ustar\0" + version "00" at offsets 257..265.
        assert_eq!(&buf[257..263], b"ustar\0");
        assert_eq!(&buf[263..265], b"00");
    }
}
