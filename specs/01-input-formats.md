# 01 — Input formats

The tool accepts two or more image references on its command line. Each
reference is a local filesystem path. The following layouts must be
auto-detected from the path's content, not from its extension:

## 1.1 OCI image layout (directory)

Directory containing `oci-layout`, `index.json`, and a `blobs/<algo>/`
tree. Produced by e.g. `podman image save --format oci-dir`. The
`index.json` may reference one or many manifests; each manifest
referenced is treated as one input image.

## 1.2 OCI image layout (tar)

The same tree as 1.1 but packaged as a single tar file. It is read with
a streaming tar reader; entries are indexed by name so blobs can be
opened on demand without materializing the archive to disk. If the
underlying file is seekable the reader uses random access; otherwise it
falls back to a single pass that buffers blob offsets.

## 1.3 Docker "save" archive (tar)

A tar file containing `manifest.json` at the root, one or more
`<config>.json` files, and per-layer `<id>/layer.tar` or `<id>.tar`
entries. Produced by `docker save` and `podman image save --format
docker-archive`. May contain multiple images (e.g. `podman image save -m
...`), in which case each entry in `manifest.json` is one input image.

## 1.4 Docker "save" archive (extracted directory)

The same files as 1.3 but extracted into a directory. Detected by the
presence of a top-level `manifest.json` plus the absence of
`oci-layout`. The per-layer `layer.tar` files are *never* re-packed —
they are consumed directly as tar streams.

## 1.5 Podman / Docker "dir" transport

Directory containing `manifest.json` (OCI or Docker schema) and a flat
set of blob files named by their digest, as produced by
`podman image save --format docker-dir` or `--format oci-dir` without
the `blobs/sha256/` prefix. Detected by a `manifest.json` whose
`layers[].digest` values resolve to sibling files.

## 1.6 Ambiguity and rejection

If more than one layout marker is present (e.g. both `oci-layout` and a
top-level `manifest.json`), the OCI layout wins and a warning is
emitted. If no layout matches, the input is rejected with a clear error
naming the path and the markers that were looked for.

## 1.7 What is *not* accepted as input

- Remote references (`docker.io/...`, `ghcr.io/...`). The user is
  expected to pull first with their tool of choice.
- Individual layer tarballs without a surrounding manifest.
- Container storage directories (`/var/lib/containers/storage`,
  `/var/lib/docker`). Those use overlay/driver-specific layouts the
  tool does not attempt to read.
- `.sif`, `.sqfs`, or other non-OCI container formats.

## 1.8 Compression

Layer blobs may be uncompressed tar, gzip, or zstd. The media type on
the referring manifest is authoritative; the magic bytes are used only
as a consistency check. If the two disagree, the input is rejected.
