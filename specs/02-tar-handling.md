# 02 — Tar handling

This is the load-bearing constraint of the project. Every other spec
assumes it.

## 2.1 The rule

**Layer tarballs MUST NOT be unpacked to the filesystem.** Not in a
temp directory, not in `/tmp`, not under `$XDG_RUNTIME_DIR`, not even
"just to inspect them". The tool runs unprivileged; an extract-then-
repack round trip would be forced to substitute the invoking user's
uid/gid for any entry whose original uid/gid the user does not own,
silently corrupting ownership in the rebuilt image.

This applies to:

- Input layer tarballs (`.tar`, `.tar.gz`, `.tar.zst`, OCI blobs).
- Intermediate state during squashing or deduplication.
- The final shared and per-image diff layers (they are written as tar
  streams directly, not assembled by tarring a staging directory).

## 2.2 What we do instead

Layers are processed as **streams of tar entries**:

1. Open the layer blob as a `Read`. If gzip/zstd, wrap in the matching
   streaming decoder. The compressed length on disk and the
   uncompressed digest are both observed during the same pass when
   needed.
2. Iterate entries with a streaming tar reader (`tar::Archive` style).
   For each entry, read the **header** (name, size, mode, uid, gid,
   xattrs via PAX, link target, type flag) and either:
   - skip the body (advance past `size` bytes) if only metadata is
     needed, or
   - hash the body in chunks (see 04-file-identity) without ever
     writing it to disk.
3. When a file body must be re-emitted into an output layer, the input
   tar reader is positioned at that entry and its body bytes are piped
   directly into the output tar writer. The body never lands on the
   filesystem.

## 2.3 Multi-pass reads

Many algorithms in this tool need at least two passes over each input
layer (one to compute identity, one to copy the bodies that survived
deduplication into the right output layer). Two-pass behavior is
expected and acceptable. Three or more is a smell — refactor before
adding one.

If the input is a non-seekable stream (e.g. an OCI layout served from a
pipe, which is not currently a supported input but may be in future),
the tool may spool the *compressed* blob to a temp file and re-open it
for subsequent passes. It must never spool the *uncompressed* tar
contents, and must never spool individual file bodies.

## 2.4 Tar dialect

Output tarballs are written in **PAX (`ustar` + PAX extended headers)**
format. PAX is required because:

- Long paths and long link targets occur in real-world base images
  (Debian, in particular).
- PAX is the only portable way to carry sub-second mtime, xattrs, and
  arbitrary uid/gid values without GNU-specific extensions.
- OCI image-spec recommends PAX for layer tar streams.

When re-emitting an input entry into an output layer the tool produces
a fresh PAX header from the parsed metadata; it does **not** copy the
raw header bytes. This guarantees the output dialect is uniform even
when inputs mix `ustar`, `gnu`, and `pax`.

## 2.5 Whiteouts and opaque directories

Whiteout markers (`.wh.<name>`, `.wh..wh..opq`) only have meaning
*between* layers within a single input image. They are consumed during
squashing (see 03-squashing) and must never appear in any output
layer. The shared layer and the per-image diff layers represent a
positively-defined filesystem and contain no whiteouts.

## 2.6 Hardlinks

A tar entry of type `1` (hardlink) names another entry within the same
tarball. Hardlinks must always be emitted into the **per-image diff
layer**, never into the shared layer. The image-specific layer is the
last one applied, so by the time the link entry is processed by the
overlay driver its target is guaranteed to already exist in either the
shared layer or earlier in the same per-image layer.

Concretely, during squashing the resolved filesystem records each
hardlink as `(path, target_path)`. When layers are emitted:

- The shared layer contains only regular files, directories, symlinks,
  and special files (whose identity is stable across images per
  04-file-identity). It contains no `type=1` entries.
- The per-image diff layer emits every hardlink as a `type=1` entry
  whose link target is the path of the canonical file (which may live
  in the shared layer or earlier in this same per-image layer).

If the canonical file would otherwise have been deduplicated into the
shared layer, the hardlink in the per-image layer still points at it
by path — the overlay driver resolves the link at unpack time on the
target host, which by then sees the merged filesystem and does have
the target available.
