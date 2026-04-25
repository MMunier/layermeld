# container-squash — Project Scope

A tool that takes multiple Docker / OCI container images as input and
produces a single combined multi-image artifact whose on-disk footprint is
smaller than the sum of its inputs.

The size reduction is achieved by:

1. **Squashing** each input image down to its final filesystem so that
   deduplication only has to reason about the end state, not the history
   of intermediate layers, whiteouts, or overwrites.
2. **Cross-image deduplication**: files whose *content* and *portable
   metadata* (mode bits, uid, gid, xattrs, symlink target, etc.) are
   identical across two or more of the squashed images are pulled into a
   single **shared layer**.
3. **Per-image diff layers**: each output image is expressed as
   `shared_layer + image_specific_layer`. The image-specific layer is
   always applied last so that image-specific files win over the shared
   baseline.
4. **Timestamp normalization**: every `mtime` (and `atime`/`ctime` where a
   format exposes it) in every output layer, in every config blob, and in
   every manifest, is set to one single value — the tool invocation
   timestamp — so that determinism is not broken by the inputs.
5. **Multi-image assembly**: the output is a single OCI / Docker
   multi-image archive that references all of the rebuilt images and
   shares the deduplicated blob(s) between them.

## Hard constraints

- **Never unpack tar streams to disk.** Layer tarballs carry uid/gid
  values the invoking user typically cannot faithfully reproduce on an
  unprivileged extraction, so unpacking would corrupt ownership metadata
  on the way back out. Everything is processed by streaming tar readers
  and writing new tar streams directly.
- No root, no `CAP_CHOWN`, no fakeroot. Operates purely as an unprivileged
  user.
- Input archives are treated as read-only.

## Non-goals

- Block-level / content-defined chunking (Nydus, eStargz, zstd:chunked).
  Deduplication is whole-file only.
- Rebasing, rewriting, or "optimizing" the history of an image. The tool
  explicitly discards history by squashing.
- Registry I/O. Input and output are local filesystem paths.
- Signature or attestation preservation. Any cosign/notation metadata on
  input is dropped; re-sign downstream if needed.
- Running containers, executing image entrypoints, or any form of
  sandboxed exec.

## Spec index

Each spec file below is intentionally single-concern. Read in order the
first time; individual files are self-contained after that.

- [00-project-structure.md](00-project-structure.md) — language,
  crate shape, module-to-spec mapping, dependency policy, and
  test layout. Meta-spec: describes the implementation, not the
  tool's behavior.
- [01-input-formats.md](01-input-formats.md) — which on-disk image
  layouts are accepted as input.
- [02-tar-handling.md](02-tar-handling.md) — the "no unpacking" rule and
  how tar streams are actually processed.
- [03-squashing.md](03-squashing.md) — collapsing an input image's layer
  stack into one logical filesystem.
- [04-file-identity.md](04-file-identity.md) — the equality predicate
  used to decide whether two files from different images are "the same".
- [05-deduplication.md](05-deduplication.md) — how the shared set is
  chosen and how per-image diffs are computed against it.
- [06-timestamp-normalization.md](06-timestamp-normalization.md) —
  unifying all time-bearing fields to the invocation timestamp.
- [07-layer-assembly.md](07-layer-assembly.md) — turning the shared set
  and the diffs into real layer tarballs on disk.
- [08-image-config-and-manifest.md](08-image-config-and-manifest.md) —
  rewriting image configs and manifests so they reference the new
  layers.
- [09-output-format.md](09-output-format.md) — the multi-image archive
  that ships the rebuilt images.
- [10-cli.md](10-cli.md) — command-line interface and exit codes.
- [11-determinism.md](11-determinism.md) — what must be byte-identical
  across two invocations with the same inputs.
- [99-backburner.md](99-backburner.md) — features and content
  intentionally deferred to a later phase, including notes that
  must end up in the user-facing README.
