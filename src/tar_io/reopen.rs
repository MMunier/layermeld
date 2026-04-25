//! Two-pass reopen helper (spec 02 §2.3).
//!
//! Most pipeline stages need at least two passes over each input layer:
//! the first walks the tarball to compute identities and indices, the
//! second reopens it to copy specific entry bodies into the output. This
//! module is the bridge between the two — given a way to (re)open a
//! decompressed tar stream and an entry index, it advances to the named
//! entry and exposes its body to a caller-supplied closure.
//!
//! The helper is intentionally agnostic of how the layer is opened. The
//! squash and assemble passes both supply their own opener (an OCI blob
//! file, a docker-archive `layer.tar`, etc. via [`crate::input`]); the
//! reopen logic itself is pure tar streaming and lives here.
//!
//! Body bytes are exposed only through the closure — they never land on
//! disk and never leak past the borrow of the underlying reader, in line
//! with spec 02 §2.1.

use std::io::Read;

use crate::tar_io::reader::{EntryMeta, Reader};
use crate::{Error, Result};

/// Open a fresh tar stream via `open`, advance to the entry at
/// `entry_idx` (0-based, indexing into [`Reader::entries`] output), and
/// invoke `f` with that entry's metadata and a body reader positioned at
/// the start of the body.
///
/// The closure form sidesteps the lifetime entanglement between
/// [`crate::tar_io::reader::Entry`] and its parent [`Reader`]: callers
/// borrow the body for as long as they need it without the helper having
/// to return a self-referential type. Two callers in the pipeline use
/// this:
///
/// * **Squash identity-hashing.** The closure feeds body bytes into a
///   running SHA-256 hasher and discards them.
/// * **Assembly body-copy.** The closure pipes body bytes straight into
///   the output tar writer (which itself wraps a SHA-256 hasher per
///   spec 07).
///
/// Both passes see the same iteration order, so the same `entry_idx`
/// resolves to the same entry across reopens — the determinism this
/// project hinges on (spec 11).
///
/// Entries that precede `entry_idx` are not body-drained explicitly: the
/// underlying `tar` iterator skips past unread bodies when advanced, so
/// the cost is one `seek`-equivalent (forward read of the compressed
/// stream) per skipped entry.
///
/// # Errors
///
/// * [`Error::MalformedInput`] if the layer ends before reaching
///   `entry_idx` — the index was computed against a different stream.
/// * [`Error::Io`] for any read failure on the underlying stream.
/// * Whatever `f` returns, propagated unchanged.
pub fn with_entry_body<R, F, T>(open: impl FnOnce() -> Result<R>, entry_idx: usize, f: F) -> Result<T>
where
    R: Read,
    F: FnOnce(&EntryMeta, &mut dyn Read) -> Result<T>,
{
    let inner = open()?;
    let mut reader = Reader::new(inner);
    let mut entries = reader.entries()?;
    let mut i = 0usize;
    loop {
        let Some(entry) = entries.next() else {
            return Err(Error::MalformedInput(format!(
                "layer ended before reaching entry index {entry_idx}",
            )));
        };
        let mut entry = entry?;
        if i == entry_idx {
            // Snapshot the metadata before lending the body out: the
            // closure may consume the body to EOF, after which the
            // iterator's view of the entry is exhausted. Cloning is cheap
            // — the metadata is small and bounded.
            let meta = entry.meta().clone();
            return f(&meta, &mut entry);
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use tar::{Builder, EntryType, Header};

    use super::*;
    use crate::Error;
    use crate::tar_io::reader::EntryKind;

    /// Three regular files with predictable bodies — the indices are what
    /// the reopen helper is supposed to resolve.
    fn fixture_tarball() -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut tb = Builder::new(&mut buf);
            tb.mode(tar::HeaderMode::Deterministic);
            for (path, body) in [
                ("a.txt", b"alpha-body\n".as_slice()),
                ("b.txt", b"bravo-body\n".as_slice()),
                ("c.txt", b"charlie-body\n".as_slice()),
            ] {
                let mut h = Header::new_gnu();
                h.set_entry_type(EntryType::Regular);
                h.set_path(path).unwrap();
                h.set_mode(0o644);
                h.set_uid(0);
                h.set_gid(0);
                h.set_size(body.len() as u64);
                h.set_cksum();
                tb.append(&h, body).unwrap();
            }
            tb.finish().unwrap();
        }
        buf
    }

    fn open_fixture(bytes: Vec<u8>) -> impl FnOnce() -> Result<Cursor<Vec<u8>>> {
        move || Ok(Cursor::new(bytes))
    }

    #[test]
    fn yields_first_entry_body() {
        let bytes = fixture_tarball();
        let body = with_entry_body(open_fixture(bytes), 0, |meta, body| {
            assert_eq!(meta.path.to_str().unwrap(), "a.txt");
            assert_eq!(meta.kind, EntryKind::Regular);
            let mut buf = Vec::new();
            body.read_to_end(&mut buf)?;
            Ok(buf)
        })
        .unwrap();
        assert_eq!(body, b"alpha-body\n");
    }

    #[test]
    fn yields_middle_entry_body_skipping_predecessors() {
        let bytes = fixture_tarball();
        let body = with_entry_body(open_fixture(bytes), 1, |meta, body| {
            assert_eq!(meta.path.to_str().unwrap(), "b.txt");
            let mut buf = Vec::new();
            body.read_to_end(&mut buf)?;
            Ok(buf)
        })
        .unwrap();
        assert_eq!(body, b"bravo-body\n");
    }

    #[test]
    fn yields_last_entry_body() {
        let bytes = fixture_tarball();
        let body = with_entry_body(open_fixture(bytes), 2, |meta, body| {
            assert_eq!(meta.path.to_str().unwrap(), "c.txt");
            let mut buf = Vec::new();
            body.read_to_end(&mut buf)?;
            Ok(buf)
        })
        .unwrap();
        assert_eq!(body, b"charlie-body\n");
    }

    #[test]
    fn out_of_range_index_is_malformed_input() {
        let bytes = fixture_tarball();
        let err = with_entry_body(open_fixture(bytes), 99, |_, _| Ok(())).unwrap_err();
        match err {
            Error::MalformedInput(msg) => assert!(msg.contains("entry index 99"), "got: {msg}"),
            other => panic!("expected MalformedInput, got {other:?}"),
        }
    }

    #[test]
    fn closure_may_short_read_body() {
        // Assembly may legitimately read fewer than `meta.size` bytes if
        // the caller only needs a prefix (e.g. a sniff). The helper must
        // not enforce full consumption.
        let bytes = fixture_tarball();
        let prefix = with_entry_body(open_fixture(bytes), 1, |_, body| {
            let mut buf = [0u8; 5];
            body.read_exact(&mut buf)?;
            Ok(buf)
        })
        .unwrap();
        assert_eq!(&prefix, b"bravo");
    }

    #[test]
    fn open_failure_propagates() {
        // Simulate a layer that fails to open (missing blob, etc.). The
        // helper must surface the error rather than panicking on the
        // unwrap path.
        let opener = || -> Result<Cursor<Vec<u8>>> { Err(Error::MalformedInput("blob missing".into())) };
        let err = with_entry_body(opener, 0, |_, _| Ok(())).unwrap_err();
        match err {
            Error::MalformedInput(msg) => assert_eq!(msg, "blob missing"),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn reopen_is_repeatable_for_same_index() {
        // Calling the helper twice with the same fixture and index must
        // return identical body bytes. This is the determinism guarantee
        // assembly leans on.
        let bytes = fixture_tarball();
        let read = |idx: usize| -> Vec<u8> {
            with_entry_body(open_fixture(bytes.clone()), idx, |_, body| {
                let mut buf = Vec::new();
                body.read_to_end(&mut buf)?;
                Ok(buf)
            })
            .unwrap()
        };
        assert_eq!(read(0), read(0));
        assert_eq!(read(2), read(2));
        assert_ne!(read(0), read(2));
    }

    #[test]
    fn closure_error_propagates_unchanged() {
        let bytes = fixture_tarball();
        let err = with_entry_body(open_fixture(bytes), 0, |_, _| -> Result<()> {
            Err(Error::Validation("synthetic failure".into()))
        })
        .unwrap_err();
        match err {
            Error::Validation(msg) => assert_eq!(msg, "synthetic failure"),
            other => panic!("unexpected variant: {other:?}"),
        }
    }
}
