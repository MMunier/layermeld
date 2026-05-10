# 10 — CLI

## 10.1 Synopsis

```
layermeld [OPTIONS] --output <PATH> <INPUT>...
```

The tool is a single binary with no subcommands.

## 10.2 Positional arguments

- `<INPUT>...` — one or more local filesystem paths to input
  images. Each may resolve to a single image or to multiple images
  (multi-image archives — see 01). Order is significant only as a
  tiebreaker for determinism (see 11); it does not affect which
  files end up where.

Minimum: one input. With one input, the tool squashes that image
and emits a one-image OCI layout (per 05 §5.1.2).

## 10.3 Required options

- `-o, --output <PATH>` — output path. By default this is a tar
  file containing an OCI image layout; with `--layout dir` it is
  a directory tree instead (09 §9.3).

## 10.4 Optional flags

- `--layout <tar|dir>` — output packaging. Default: `tar`. Use
  `dir` to write a directory tree instead of a tar file (09
  §9.3).
- `--min-layer-size <BYTES>` — minimum estimated tar size for a
  shared subset layer (05 §5.5). Layers below this are dissolved
  and their files cascaded into smaller subset layers. Accepts
  human-friendly suffixes (`16k`, `1M`). Default: `16k`. Set to
  `0` to disable.
- `--force` — overwrite an existing output destination by moving
  it aside to `<output>.old-<T0>` (09 §9.4).
- `--timestamp <UNIX-SECONDS>` — pin `T0` to the given value (06
  §6.1). Overrides `SOURCE_DATE_EPOCH`.
- `--jobs <N>` — bound on concurrent layer assembly tasks (07
  §7.5). Default: number of logical CPUs.
- `--scratch <PATH>` — directory for temporary files. Default: a
  freshly created `<output>.partial/` next to the output. Useful
  when the final destination is on a slow / network filesystem
  and the user wants the heavy lifting on local disk.
- `-v, --verbose` — enable progress logging on stderr. Repeating
  (`-vv`) enables per-entry tracing — high volume, intended for
  debugging.
- `-q, --quiet` — suppress all non-error output, including the
  run summary (10.6).
- `--dry-run` — perform every step except the final
  blob/index/oci-layout writes. Reports the would-be summary so
  the user can preview savings.

## 10.5 Environment

- `SOURCE_DATE_EPOCH` — fallback for `T0` if `--timestamp` is not
  given (06 §6.1).
- `RUST_LOG` — standard `tracing-subscriber` filter, applied on
  top of `-v`/`-q`. The CLI flags set the default; this overrides
  it.

## 10.6 Run summary

On a successful run (and on `--dry-run`) the tool prints a
human-readable summary to stdout:

```
layermeld run summary
  inputs:
    [0] postgres:17.9-trixie       (1 image,  N layers, M bytes)
    [1] postgres:18.3-trixie       (1 image,  N layers, M bytes)
  outputs (oci layout: <path>):
    layers:                       size      vs-naive    diff_id
      shared {0,1,2}              S₁        +2·S₁       …
      shared {0,1}                S₂        +1·S₂       …
      per-image {0}                S₃        —           …
      per-image {1}                S₄        —           …
      per-image {2}                S₅        —           …
    images:
      postgres:17.9-trixie -> manifest sha256:…
      postgres:18.3-trixie -> manifest sha256:…
  bytes summary:
    inputs total (squashed):      X
    outputs total (deduplicated): Y
    saved:                        X-Y  (P%)
  T0 = <iso-8601>
```

The `vs-naive` column is `(|M| − 1) · size` for each shared
subset layer — the bytes that would have been duplicated across
images if the layer hadn't been shared. Per-image layers (|M|=1)
get `—`; they are never deduplicated against anything. Summing
the `vs-naive` column gives the total dedup gain and makes
`--min-layer-size` tuning empirical: if a layer's `vs-naive`
falls under the cost of its own existence (per-blob descriptor +
manifest entry overhead), it should have been dissolved.

The exact format of this summary is **not** part of the
determinism contract (it is for humans). Machine-readable output is
intentionally not emitted by default; if needed in future, a
`--summary-json <path>` flag can be added without affecting the
artifact bytes.

## 10.7 Exit codes

- `0` — success.
- `1` — generic failure (I/O, validation, malformed input).
- `2` — bad CLI usage (unknown flag, missing required arg). This
  is the only exit code for which the tool does not write or move
  any file.
- `3` — output destination already exists and `--force` was not
  given.
- `4` — input digest verification failed (07 §7.6).

## 10.8 Stdout / stderr discipline

- Stdout: the run summary on success, nothing on failure.
- Stderr: log lines (controlled by `-v`/`-q`/`RUST_LOG`) and the
  final error message on failure.
- The summary is written *after* the output has been atomically
  renamed into place, so its presence on stdout is a reliable
  "the artifact exists at the named path" signal for scripts.
