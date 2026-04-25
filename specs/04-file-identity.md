# 04 — File identity

The deduplication step (05) needs an equality predicate over file
entries from different squashed images. This file defines that
predicate.

## 4.1 Identity tuple

Two entries are considered "the same file" if and only if every field
of the following tuple matches exactly:

```
FileIdentity {
    path:         PathBuf,         // absolute path inside the rootfs
    kind:         EntryKind,       // File | Symlink | Dir | Char | Block | Fifo
    mode:         u32,             // permission + setuid/setgid/sticky bits
    uid:          u64,
    gid:          u64,
    size:         u64,             // 0 for non-regular kinds
    content_hash: Option<[u8;32]>, // SHA-256 of body, None for non-regular
    link_target:  Option<PathBuf>, // for symlinks
    rdev:         Option<(u32,u32)>,// for char/block devices
    xattrs:       BTreeMap<String, Vec<u8>>,
}
```

Two entries match iff all fields are byte-equal. `xattrs` is compared
as an ordered map; the `BTreeMap` ordering is part of the predicate
so two equal entries always serialize identically.

## 4.2 Fields explicitly excluded from identity

The following are deliberately **not** part of the predicate:

- `mtime`, `atime`, `ctime`. Timestamps are normalized to a single
  value across the whole output (see 06). Including them in identity
  would defeat the dedup of bit-identical files that just happen to
  carry different mtimes between two base-image rebuilds.
- `uname`, `gname` PAX strings. Only the numeric uid/gid matter at
  runtime.
- `username`/`groupname` lookups against `/etc/passwd` /
  `/etc/group`. Two images may resolve the same uid to different
  names; the runtime kernel does not care.
- The original layer index, original tar entry index, or original
  image of origin. These are bookkeeping only.
- The compression and tar-dialect of the originating layer. Identity
  is over the logical entry, not its on-wire encoding.
- Hardlink-vs-regular distinction. A regular file in image A and a
  hardlink in image B that points to a regular file with the same
  identity are deduplicated together; the canonical entry written
  into the shared layer is always emitted as a regular file (see
  02-tar-handling §2.6 for hardlink emission rules).

## 4.3 Path is part of identity

Two files with identical content but different absolute paths are
**not** the same file for our purposes. They will end up either both
in the shared layer (each at its own path) or both in their respective
per-image diff layers; they will not be coalesced into one tar entry.

This is a deliberate simplification:

- It keeps the output layers expressible as ordinary tar streams. A
  tar stream cannot represent "this body lives at two paths" except
  via hardlinks, and emitting cross-path hardlinks into the shared
  layer would create entries the per-image layer cannot easily
  override.
- It matches the OCI overlay model: the on-disk shape of the shared
  layer should be a literal subset of every image's filesystem.

If two images both contain `/usr/bin/foo` and `/usr/bin/bar` with
identical bodies, the shared layer carries two separate entries —
exactly like the original images did. Same-image content-level
deduplication via hardlinks is out of scope (it is the input image's
problem, not ours).

## 4.4 Content hashing

For regular files, `content_hash` is `SHA-256` of the file body bytes
in their decompressed (post-tar-stream) form. The hash is computed
**streaming** during the squash pass: the tar reader is positioned at
the entry, body bytes are pumped through a hasher, and the digest is
recorded in the squashed-fs index. The body is never spooled to disk
purely to be hashed.

SHA-256 is chosen because:

- It is already required to be available — the OCI spec mandates it
  for blob digests, so the dependency is free.
- Collisions are not a security concern here (an attacker who can
  feed crafted layer pairs has already won), but cryptographic
  collision resistance gives us a "no false positives" guarantee for
  free with no adversarial reasoning.

The hash output is 32 raw bytes. It is *not* the OCI blob digest of
any layer or any file; it is internal to the dedup pass.

## 4.5 Directories

Directory entries participate in identity via path, mode, uid, gid,
xattrs. The shared layer must contain a directory entry for every
ancestor of every file it carries; those ancestor entries are taken
from whichever input image has that ancestor — if the same ancestor
in two images has *different* metadata (mode/uid/gid/xattrs), then
that directory's identity does not match across images, and it goes
into the per-image diff layers instead, with the shared layer falling
back to a synthetic minimal entry (see 05).

## 4.6 Sparse files

The tar format can encode sparse regions, but in practice OCI image
layers do not. The tool treats every regular file as fully populated;
content_hash is over the logical (post-expansion) bytes. Sparse PAX
extensions on input are honored when reading; output never emits
sparse encodings.
