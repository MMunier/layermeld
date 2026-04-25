# 07 — Layer assembly

This pass turns the abstract layer partition produced by 05-
deduplication into actual on-disk tar blobs that can be referenced
from an OCI manifest.

## 7.1 Inputs to this pass

- The set of subset layers from 05, each represented as a list of
  `(image_id, layer_idx, entry_idx)` references back into the
  original input archives plus the resolved `FileIdentity`.
- The synthetic ancestor directory entries from 05 §5.4.
- The normalized timestamp `T0` from 06.
- A scratch output directory provided by the CLI.

## 7.2 Output, per layer

Each subset layer is written to disk as one file:

```
<scratch>/blobs/sha256/<digest>
```

where `<digest>` is the SHA-256 of the tar bytes as they land on
disk. Because layers are emitted uncompressed in this stage of the
project (see 7.3), this digest is *also* the layer's `diff_id` — the
two values are the same SHA-256, computed in one streaming pass:
the uncompressed tar bytes go through a single hasher en route to
the output file. No intermediate files.

The media type used in the manifest is
`application/vnd.oci.image.layer.v1.tar`.

## 7.3 Compression — out of scope for now

Layers are written as **uncompressed tar**. Adding gzip / zstd
compression is deferred to a later phase of the project. The
rationale:

- Uncompressed layers reduce the digest pipeline to one hasher
  instead of two, so the assembly code stays simple while we are
  still iterating on the squash and dedup logic.
- The OCI spec permits uncompressed `tar` layers
  (`application/vnd.oci.image.layer.v1.tar`); they are accepted by
  podman, skopeo, and modern Docker.
- Once the rest of the pipeline is stable, a `--compress
  gzip|zstd` switch can be added without rethinking any other
  spec — only this file changes.

Until that future work lands, the tool never writes a gzipped or
zstd-compressed layer, and never emits the corresponding media
types.

## 7.4 Tar entry emission

For each entry in the layer's sorted entry list (per 05 §5.5):

1. Build a fresh PAX header from the squashed-fs metadata:
   - `path`, `linkname` (for symlinks/hardlinks).
   - `mode`, `uid`, `gid`, `size`.
   - `mtime = T0`. No `atime`/`ctime`.
   - `uname = ""`, `gname = ""` (numeric ids only — see 04 §4.2).
   - PAX `SCHILY.xattr.<key>` records for every xattr on the entry,
     in lexicographic order of `key`.
   - For char/block devices: `devmajor`, `devminor`.
2. Write the PAX header into the output tar stream.
3. If the entry is a regular file with non-zero size, open the
   originating input layer's tar reader, seek to
   `(layer_idx, entry_idx)`, and copy the body bytes directly into
   the output tar writer. The body never lands on the filesystem.
4. The output tar writer pads to the 512-byte boundary as required
   by the tar format.

After every entry has been emitted, the tar stream is finalized with
two zero-filled 512-byte blocks (the standard tar end-of-archive
marker).

## 7.5 Bounded concurrency

Each subset layer is independent and may be assembled in parallel.
The implementation may run up to `--jobs` (default: number of
logical CPUs) layer-assembly tasks concurrently. Each task owns its
own input-tar readers; readers are not shared across threads.

Concurrency must not change output bytes. In particular, the order
of entries within a layer is determined by 05 §5.5, not by which
worker picked up which file first.

## 7.6 Failure semantics

If any input layer's bytes hash to a digest that disagrees with the
digest declared in its source manifest, the run aborts with a clear
error before any output blob is finalized. Output blobs are first
written to a temporary file in the same directory, fsync'd, then
renamed into their final `blobs/sha256/<digest>` path. A run that
aborts mid-assembly leaves no partial blobs in the digest namespace.

## 7.7 Per-layer size accounting

For every output blob the tool records:

- size on disk (== uncompressed size, given 7.3),
- digest (== diff_id, given 7.3),
- the membership set `M` it was assembled for.

These are reported in the run summary (see 10) so the user can see
the actual savings achieved. When compression is added later, a
second "compressed size" column will be added here.
