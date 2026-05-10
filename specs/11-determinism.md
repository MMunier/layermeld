# 11 — Determinism and round-trip correctness

This file pins down two distinct contracts:

1. **Determinism** — when two runs must produce byte-identical
   output (11.1–11.4).
2. **Round-trip correctness** — the rebuilt images must, when
   instantiated, present a filesystem that is identical to each
   original input image's filesystem except for normalized
   timestamps (11.5).

## 11.1 The determinism contract

Given:

- the same set of input image paths (order may differ — see 11.3),
- the same `T0` (either `--timestamp` or `SOURCE_DATE_EPOCH`),
- the same `--min-layer-size` (the dissolve pass in 05 §5.5 is a
  pure function of its threshold and the candidate layers),
- the same tool version,

the tool must produce:

- byte-identical layer blobs, with identical SHA-256 digests,
- byte-identical image config JSON documents, with identical
  digests,
- byte-identical image manifest JSON documents, with identical
  digests,
- a byte-identical `index.json`,
- a byte-identical `oci-layout` file.

In the default tar packaging, the outer tar is also byte-
identical (uncompressed, with normalized entry order, mtime,
uid/gid 0, mode 0644 / 0755). With `--layout dir`, the
filesystem tree is byte-identical at the per-file level; the
on-disk inode layout, allocation order, and `stat(2)` mtimes of
directory entries are not part of the contract.

The on-disk *order* in which blob files are created is not part of
the contract (filesystems are not byte-comparable on that axis),
only the bytes of each file and their final names.

## 11.2 Sources of nondeterminism that are eliminated

- **Wall clock**: `T0` is captured once and reused (06).
- **Filesystem walk order**: every iteration over a set of paths
  or entries uses an explicit sort (`BTreeMap` / `sort()`), never
  the order returned by the OS.
- **HashMap iteration order**: deterministic ordered maps
  (`BTreeMap`) are used everywhere a structure's iteration order
  influences output. Hash-based maps are only used for lookups
  internal to a single decision.
- **Concurrency**: per 07 §7.5, layer-assembly tasks run in
  parallel but their *outputs* are determined by inputs alone.
  Workers do not race on shared output state.
- **`uname` / `gname` PAX strings**: cleared (04 §4.2, 07 §7.4).
- **Tar dialect mixing**: every output entry is re-emitted as a
  fresh PAX header (02 §2.4).
- **Compression-level defaults of system libraries**: not
  applicable in this stage (07 §7.3 — no compression). Will be
  addressed by pinning explicit levels when compression lands.
- **Random / process-id-derived data**: the tool never reads from
  `/dev/urandom`, never embeds the PID, and never uses `tempfile`
  patterns whose names leak into output content.

## 11.3 Input order

The `<INPUT>...` argument order is canonicalized internally:
inputs are assigned `image_id`s by **lexicographic sort of their
absolute, canonicalized paths**, not by argv order. Subset-layer
membership sets are then defined over these stable ids.

Two invocations with the same set of input paths in different
argv orders therefore produce identical output. (The run summary
on stdout reflects the canonical order, not argv order.)

If the same physical path is given more than once on the command
line, duplicates are collapsed: the second occurrence is silently
ignored. Two *different* paths that happen to resolve to the same
inode (e.g. a symlink) are also collapsed via canonicalized-path
comparison.

## 11.4 Sources of nondeterminism that remain

- **Input bytes**: if the user re-pulls a tag from a registry
  between runs and the upstream changed, that's outside our
  control. The tool will faithfully and deterministically produce
  a *different* output for *different* inputs.
- **Tool version**: a different `layermeld` version may
  legitimately produce different output. The version is reported
  in the run summary.
- **`T0`**: if neither `--timestamp` nor `SOURCE_DATE_EPOCH` is
  set, `T0` is the wall clock and the run is intentionally
  non-reproducible across time. Users who need reproducibility
  must pin one of those.

## 11.5 Round-trip correctness contract

For every input image `i`, let `FS(i)` be the filesystem that
results from extracting and applying every layer of `i`'s manifest
in order, with whiteouts honored — i.e. the merged view a
container runtime would see at startup, before any process has
mutated anything.

After running the tool, let `FS'(i)` be the filesystem that
results from extracting and applying every layer of the **output**
manifest for image `i` in order.

The contract: `FS'(i)` and `FS(i)` must be identical for every
image `i`, with the following exceptions and only these:

- `mtime` (and `atime`/`ctime` if the OS exposes them) of every
  filesystem object is `T0` in `FS'(i)`. The originals carried
  whatever the input had.
- Any whiteout markers and opaque-directory markers that existed
  as visible filesystem entries in `FS(i)` (which they should
  not, because they are layer-internal) are absent from `FS'(i)`.
- PAX `uname` / `gname` strings: gone (04 §4.2). Numeric uid /
  gid are unchanged.

Everything else must match byte-for-byte:

- The set of paths is identical.
- For every path: kind (file/dir/symlink/char/block/fifo) is
  identical.
- File body bytes are byte-identical (same SHA-256).
- Mode bits (including setuid, setgid, sticky) are identical.
- Numeric uid and gid are identical.
- Symlink targets are identical.
- Char/block device major/minor are identical.
- The full xattr map (key set and per-key values) is identical.
- Hardlink topology — i.e. which paths share an inode at unpack
  time — is identical.

## 11.6 Test obligation

The project carries two regression test families. Both must pass
before any release.

### 11.6.1 Determinism test

1. Run the tool on a fixed set of small, hermetic inputs with a
   pinned `T0`.
2. Capture the SHA-256 of every output blob plus `index.json`
   and `oci-layout`.
3. Re-run the tool and assert the digests are identical.

### 11.6.2 Round-trip test

For each input image used in the test corpus (including the
`hack/images/` postgres samples, plus a synthetic image that
exercises every entry kind, hardlinks, xattrs, setuid bits, and
non-zero uid/gid):

1. Run the tool on the corpus producing an output OCI layout.
2. Apply each input image's original layer stack into an
   in-memory `FS(i)` representation. (The verifier may unpack
   layers into in-memory structures for *test purposes*; the
   tool itself never does.)
3. Apply each output image's layer stack into an in-memory
   `FS'(i)` representation.
4. Assert `FS'(i)` matches `FS(i)` per 11.5 — every path, every
   metadata field, every body hash, every xattr, every hardlink
   group. The only permitted differences are the timestamp
   normalization and the absence of whiteout/opaque markers as
   visible entries.

A diff that surfaces any other discrepancy is a hard failure.

#### Alternative manual verification via `docker export`

For ad-hoc sanity checks against real images outside the test
corpus, the round-trip property can also be verified by relying
on a container runtime to do the unpacking:

```
docker load   -i <input-archive>
docker create --name in-img  <input-tag>
docker export in-img  | tar -tvf - | sort > in.list

docker load   -i <squashed-archive>
docker create --name out-img <squashed-tag>
docker export out-img | tar -tvf - | sort > out.list

diff in.list out.list   # only mtimes should differ
```

A more thorough check pipes each export through a body-hashing
step (e.g. `tar -xOf - <path> | sha256sum`) and compares the
resulting `(path, mode, uid, gid, size, sha256)` tuples. This
recipe is what humans actually run during development; the
in-memory verifier above is what CI runs.

This is the test that makes the "no unpacking" rule (02) and the
"don't change uid/gid" guarantee falsifiable: any bug that
causes ownership corruption, mode loss, xattr drop, or hardlink
flattening would surface here.

Changes that intentionally alter output bytes (e.g. enabling
compression in a later phase) update the **determinism** test's
expected digests and call out the break in the changelog. They
must never alter the **round-trip** test's pass/fail status —
the rebuilt filesystem is invariant under encoding choices.
