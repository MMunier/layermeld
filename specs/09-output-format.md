# 09 — Output format

The tool produces one output artifact: a single OCI image layout
that contains every rebuilt image and shares the deduplicated blobs
between them. By default the layout is packaged as a single tar
file; an opt-in flag emits the same layout as a directory tree
instead (9.3).

## 9.1 Logical layout

Whether packaged as a tar file or written as a directory, the
artifact is a tree conforming to the **OCI Image Layout
Specification** (`oci-layout` v1.0):

```
<output>/
├── oci-layout                # {"imageLayoutVersion":"1.0.0"}
├── index.json                # OCI image index (8.x manifest list)
└── blobs/
    └── sha256/
        ├── <digest1>         # an output layer blob (07)
        ├── <digest2>         # another output layer blob
        ├── …
        ├── <config-digest-A> # image config for output image A
        ├── <config-digest-B> # image config for output image B
        ├── <manifest-digest-A>
        └── <manifest-digest-B>
```

Every blob — layers, configs, and manifests — is content-addressed
by SHA-256 and lives exactly once on disk. The index references
manifests, the manifests reference configs and layers; cross-image
sharing happens implicitly through digest equality.

## 9.2 The index

`index.json` is an OCI image index
(`application/vnd.oci.image.index.v1+json`) containing one
`manifests[]` entry per **(output image, repo tag)** pair:

- `mediaType:
  "application/vnd.oci.image.manifest.v1+json"`.
- `digest`, `size` of the image manifest (8.2).
- `platform.architecture`, `platform.os` copied from the image
  config.
- `annotations`:
  - `org.opencontainers.image.ref.name` = the repo tag (e.g.
    `postgres:17.9-trixie`), if the input had one. Inputs with
    multiple tags produce multiple index entries, all pointing at
    the same manifest digest.
  - `org.opencontainers.image.created` = `T0`.

If any input image had no tag, its manifest is still listed in the
index but with no `ref.name` annotation; consumers can refer to it
by digest only.

The index itself is not a "manifest list" in the multi-arch sense —
its entries are not platform alternatives of a single image, they
are unrelated images that happen to share blobs. Tooling that
understands OCI layouts (`skopeo`, `crane`, `podman load`,
`docker buildx imagetools`) handles this shape correctly.

## 9.3 Packaging: tar by default, directory opt-in

By default the artifact is written as a single tar file at the
exact path the user passed to `--output`. The outer tar is
uncompressed (the inner layer blobs are already in their final
form per 07) and uses the same PAX dialect as output layers (02
§2.4). Entry mtimes are `T0`; uid/gid are `0`; modes are `0755`
for directories and `0644` for regular files.

The tarred form is the input format described in 01 §1.2, so
re-feeding the tool's output back as input is supported.

With `--layout dir`, the same tree is written as a directory
instead of a tar file. This is useful when the output will be
consumed by tools that read OCI layouts directly off disk
(`skopeo copy oci:<dir>:<tag> ...`) without an extra unpack step.

## 9.4 Atomic write

**Tar output (default).** The tar file is first written to a
sibling temp path `<output>.partial` in the same directory, then
fsynced and `rename(2)`'d onto `<output>`. A run that aborts
mid-write leaves only the `.partial` file, which the next run
will refuse to overwrite unless `--force` is given.

**Directory output (`--layout dir`).** The directory tree is
constructed under a sibling `<output>.partial/` path and renamed
into `<output>` only after every blob, the index, and
`oci-layout` have been written and fsynced. Same `.partial`
recovery behavior.

In both modes, if the destination already exists when the tool
starts, it is refused unless `--force` is given. With `--force`,
the existing destination is moved aside to `<output>.old-<T0>`
before the new output is renamed in. The aside copy is left for
the user to delete; the tool does not remove it.

## 9.5 Loading the result

The output can be consumed by:

- `podman load --input <output>` (default tar form).
- `skopeo copy oci-archive:<output> docker://<registry>/...`
  (default tar form).
- `skopeo copy oci:<output>:<tag> docker://<registry>/...`
  (with `--layout dir`).
- `crane push <output> <registry>/...` (with appropriate flags
  for the chosen layout).
- Any other OCI-layout-aware tool.

A registry that performs blob-level deduplication will store each
shared layer once, regardless of how many of the rebuilt images
reference it. This is where the wire-level savings come from.
