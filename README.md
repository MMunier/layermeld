# container-squash

A deterministic, unprivileged squasher for OCI / Docker container
images, with cross-image deduplication.

Given one or more local container images, `container-squash`
produces a single multi-image OCI artifact in which:

- each input image has been collapsed to its final filesystem
  (whiteouts, opaque dirs, and intermediate-layer churn are
  resolved away);
- files that are byte-identical across images are pulled into
  shared layers, so the on-disk footprint of N images is smaller
  than the sum of N independent squashes;
- every timestamp (layer `mtime`s, image config `created`,
  history entries) is normalized to a single value `T0`, making
  output bytes reproducible.

The tool runs as an unprivileged user, never unpacks tar streams
to disk, and never talks to a registry: inputs and outputs are
local paths.

## Install

```
cargo install --path .
```

A pinned stable Rust toolchain is declared in `rust-toolchain.toml`.

## Usage

```
container-squash [OPTIONS] --output <PATH> <INPUT>...
```

Minimal example — squash one image into a single tar:

```
container-squash --output squashed.tar ./postgres-oci/
```

Dedup two images into one shared multi-image archive:

```
container-squash \
    --output combined.tar \
    ./postgres-17-oci/ \
    ./postgres-18-oci/
```

Accepted input shapes (auto-detected): OCI layout directories,
OCI layout tarballs, `docker save` archives (tar or pre-extracted),
and `skopeo copy dir:` transport directories.

Selected flags:

- `--layout <tar|dir>` — output as a tar (default) or a directory
  tree.
- `--min-layer-size <BYTES>` — drop tiny shared layers below this
  estimated tar size and cascade their files into the next-largest
  enclosing subset. Accepts `16k` / `1M` / etc. Default `16k`,
  `0` disables.
- `--timestamp <UNIX-SECONDS>` — pin `T0` explicitly. Falls back
  to `$SOURCE_DATE_EPOCH`, then to wall clock.
- `--force` — replace an existing output by moving it aside to
  `<output>.old-<T0>` (never deleted).
- `--jobs <N>` — bound on concurrent layer assembly tasks.
- `--dry-run` — print the would-be run summary without writing
  any output.

See `container-squash --help` for the full list, and `specs/`
for the full behavioural contract.

## Caveats

Sharp edges to be aware of before running this against production
images:

- **Timestamps are rewritten.** Every `mtime`, every config
  `created`, and every history entry in the output is set to
  `T0`. This is almost always harmless, but a small number of
  programs use on-disk mtimes as a trust signal — most notably
  `dpkg --verify` and a handful of integrity-checking package
  managers — and those will report spurious changes against a
  squashed image. If that matters in your environment, run
  integrity checks against the *original* images, not the
  squashed output.

- **Signatures and attestations are invalidated.** Cosign /
  notation signatures, in-toto attestations, and SBOMs are bound
  to specific blob digests. Squashing rewrites every layer, so
  every such reference becomes dangling. Re-attach signatures
  and SBOMs *downstream* of this tool, never upstream.

- **Cross-platform dedup is allowed but warned about.** If the
  inputs disagree on `architecture` / `os` / `variant`, the tool
  emits a single warning to stderr and continues. Pipelines that
  want a hard refusal in CI should grep stderr or fail the build
  on a non-zero warning count.

- **No registry I/O.** Inputs and outputs are local filesystem
  paths only. Pull with `podman` / `docker` / `skopeo` first;
  push the squashed result with `skopeo` / `crane` afterwards.

## Exit codes

- `0` success
- `1` I/O, validation, or malformed-input error
- `2` bad CLI usage (no file written or moved)
- `3` output destination already exists and `--force` was not
  given
- `4` input layer digest mismatch
