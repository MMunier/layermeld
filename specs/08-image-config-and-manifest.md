# 08 — Image config and manifest

After 07 has produced the output blobs, each output image needs a
fresh OCI image config and a fresh OCI image manifest pointing at
those blobs. This file specifies what those documents look like.

## 8.1 Image config

For each output image `i` the tool emits one image config JSON
document, derived from the input image's config:

- **Carry over verbatim** (under `config.*`): `Env`, `Cmd`,
  `Entrypoint`, `WorkingDir`, `User`, `ExposedPorts`, `Volumes`,
  `Labels`, `StopSignal`, `Healthcheck`, `ArgsEscaped`. These
  describe how the image runs and are independent of the layer
  layout.
- **Carry over verbatim** (top-level): `architecture`, `os`,
  `os.version`, `os.features`, `variant`. These describe the
  platform and must match the squashed inputs.
- **Rewrite**: `created` is set to `T0` (06).
- **Rewrite**: `rootfs.type` is `"layers"`. `rootfs.diff_ids` is
  the diff_id of every output blob in image `i`'s stack, in the
  exact order specified by 05 §5.3 (largest membership set first,
  per-image layer last).
- **Rewrite**: `history` is replaced with one entry per output
  layer in the same order as `diff_ids`. Each history entry has:
  - `created` = `T0`.
  - `created_by` = a short, deterministic string identifying the
    layer's role, e.g.
    `"layermeld: shared layer for {0,1,2}"` or
    `"layermeld: per-image layer for image-1"`. The exact
    text is part of the determinism contract — see 11.
  - `empty_layer` is omitted (no empty-layer history entries are
    produced).
  - `comment` and `author` are omitted.

`config.Image`, `container`, `container_config`, and any other
Docker-specific top-level fields from a `docker-archive` input
config are dropped on output. The output config is a strict OCI
image config v1.

## 8.2 Image manifest

For each output image `i` the tool emits one OCI image manifest
JSON document:

- `schemaVersion: 2`.
- `mediaType:
  "application/vnd.oci.image.manifest.v1+json"`.
- `config`: descriptor of the image config from 8.1
  (`mediaType: "application/vnd.oci.image.config.v1+json"`,
  `digest`, `size`).
- `layers`: an ordered array of one descriptor per output blob in
  image `i`'s stack, with the order from 05 §5.3.
  - `mediaType:
    "application/vnd.oci.image.layer.v1.tar"` (uncompressed; see
    07 §7.3).
  - `digest` and `size` are the values recorded by 07 §7.7.
- `annotations`:
  - `org.opencontainers.image.created` = `T0` (RFC 3339 string).
  - `org.opencontainers.image.ref.name`, if known from the input
    image's repo tags, is preserved verbatim. Multiple repo tags
    on a single input image become multiple distinct entries in
    the output index (see 09), all referencing the same manifest
    digest.
  - All other input annotations are dropped. Re-applying them is
    out of scope; users who care can post-process with `skopeo
    copy --additional-tag` or similar.

## 8.3 Platform consistency

Before any dedup decision is made, the tool inspects every input
image's `architecture`, `os`, and `variant` fields. If those values
are not identical across all inputs, a **warning** is logged to
stderr listing the divergent images and the fields that differ.
The run continues — sharing layers across platforms is unusual but
not strictly invalid (e.g. a pure-script `noarch` image can be
dedup-shared with anything). The warning exists so the user can
abort if it was unintentional.

The output is *not* turned into a multi-arch manifest list.
Per 09 §9.2, the index lists each image independently with its own
`platform` annotation; cross-platform dedup just means a shared
blob may carry bytes that several different platforms happen to
agree on byte-for-byte.

## 8.4 Cross-image blob sharing

A blob produced by 07 for membership set `M` is referenced from the
manifest of **every** output image `i ∈ M`. The blob lives once on
disk under `blobs/sha256/<digest>`; the manifests just point at it.
This is what actually realizes the size savings on consumer
registries that dedup by digest.

## 8.4a Serialization

Output configs, manifests, and the index (09 §9.2) are
constructed and serialized via `oci-spec`'s typed builders, not
by hand-assembling `serde_json::Value` trees. The same crate is
used to parse inputs (01 §1.7a), so a round-trip through
`oci-spec` is the canonical schema for both directions.

`oci-spec`'s default JSON serialization is the byte form that
lands in `blobs/sha256/<digest>` and is what the digest is
computed over. Field ordering inside each document is whatever
`oci-spec` emits; the determinism contract (11) holds because
that ordering is a pure function of the crate version pinned in
`Cargo.toml`. A bump of `oci-spec` may legitimately change
output digests and is treated like any other determinism-test
expected-digest update.

## 8.5 Validation

Before writing the output, each manifest is validated against:

- Every `digest` it references resolves to a file under
  `blobs/sha256/`.
- The `size` of every descriptor matches the on-disk size of the
  referenced blob.
- The number of `layers` equals the number of `rootfs.diff_ids` in
  the referenced config.
- Every `diff_id` matches the diff_id recorded for the
  corresponding layer in 07.

A validation failure aborts the run; no output index is written.

## 8.6 What is *not* preserved

- Image signatures, attestations, SBOMs attached as referrers.
  These are tied to specific blob digests and become invalid the
  moment a layer is rewritten.
- The original layer digests, diff_ids, history strings,
  `created_by` commands, and any layer-level annotations.
- Build-time metadata such as `container`, `docker_version`, and
  any Docker-specific fields outside the OCI image config schema.

If any of these are needed downstream, the user must re-attach
them after `layermeld` runs.
