# 00 — Project structure

This file pins down the on-disk layout of the source tree, the
crate / module boundaries, and the third-party dependency surface.
It is a meta-spec: it describes the implementation, not the tool's
behavior. The behavioral specs (01–11) are the source of truth for
*what* the tool does; this file is the source of truth for *where
in the tree each piece of behavior lives*.

## 0.1 Language and toolchain

The tool is written in **Rust**, edition 2021. The MSRV (minimum
supported rustc) is pinned in `rust-toolchain.toml` at the
repository root and tracked alongside the code; bumping it is a
deliberate change, not an accident of CI. Stable toolchain only —
no nightly features, no `feature(...)` gates.

`cargo` is the only build system. There is no `Makefile`, no
`build.sh`, no out-of-tree codegen. `cargo build --release`
produces the shipped binary; `cargo test` runs every test family
in 11.6.

## 0.2 Repository layout

```
container-squash/
├── Cargo.toml                 # single-crate manifest (see 0.3)
├── Cargo.lock                 # committed
├── rust-toolchain.toml        # pinned stable channel + MSRV
├── rustfmt.toml               # formatting rules
├── .gitignore
├── README.md                  # user-facing readme (see 99 §99.1)
├── specs/                     # this directory — design specs
│   ├── README.md
│   ├── 00-project-structure.md
│   └── 01-…11-…, 99-backburner.md
├── src/                       # library + binary sources (see 0.4)
│   ├── lib.rs
│   ├── main.rs
│   └── …
├── tests/                     # integration tests (see 0.6)
│   ├── determinism.rs
│   ├── round_trip.rs
│   └── support/
└── hack/                      # developer-only assets (see 0.7)
    ├── images/                # fixture images (large, gitignored)
    └── prepare_images.sh
```

Anything not on this list does not belong at the root. In
particular: no `examples/` directory (the tool is one CLI
invocation, not a library API surface), no `docs/` (specs live in
`specs/`, user docs in `README.md`), no `vendor/` (we vendor only
through `Cargo.lock`).

## 0.3 Crate shape

The project is **one crate** with both a `lib.rs` and a `main.rs`:

- `src/lib.rs` exposes the entire pipeline as a library API,
  centered on a single top-level `run(Config) -> Result<Summary>`
  entry point.
- `src/main.rs` is a thin shell: parse CLI, build a `Config`,
  call `lib::run`, print the summary, map errors to exit codes
  (10 §10.7). It contains no pipeline logic.

A workspace with multiple crates is **not** used. The pipeline
stages share enough types (`FileIdentity`, `SquashedFs`,
membership sets, `T0`) that splitting them into separate crates
would either duplicate those types or force a "core types" crate
that everything depends on — overhead with no benefit at the
current scope. Revisit if a second binary or an external consumer
of the library appears.

## 0.4 Module layout

Modules under `src/` map one-to-one onto the behavioral specs.
Each spec has exactly one module (or one module directory) that
owns its implementation; cross-module calls go through public
items, not through reaching into siblings' private internals.

```
src/
├── lib.rs              # re-exports + pub fn run(Config) -> Result<Summary>
├── main.rs             # thin CLI shell
├── error.rs            # crate-wide Error / Result type
├── config.rs           # Config struct (parsed CLI → typed inputs)
│
├── input/              # 01 — input formats
│   ├── mod.rs          # detect() dispatcher
│   ├── oci_layout.rs   # 1.1, 1.2
│   ├── docker_archive.rs # 1.3, 1.4
│   └── dir_transport.rs  # 1.5
│
├── tar_io/             # 02 — tar streaming primitives
│   ├── mod.rs
│   ├── reader.rs       # streaming entry iterator
│   ├── writer.rs       # PAX-only writer
│   ├── pax.rs          # PAX header build / parse
│   └── compression.rs  # gzip / zstd decoders (read-only at this stage)
│
├── squash/             # 03 — squashing pass
│   ├── mod.rs          # SquashedFs build entry point
│   ├── index.rs        # SquashedFs map type
│   ├── apply.rs        # whiteout / opaque-dir application
│   └── hardlink.rs     # 3.3 hardlink resolution
│
├── identity.rs         # 04 — FileIdentity tuple + equality
│
├── dedup/              # 05 — deduplication
│   ├── mod.rs
│   ├── membership.rs   # naive + effective membership (5.1)
│   ├── partition.rs    # subset-layer construction (5.2, 5.4)
│   └── dissolve.rs     # min-layer-size pass (5.5)
│
├── timestamp.rs        # 06 — T0 capture + propagation
│
├── assemble/           # 07 — layer assembly
│   ├── mod.rs
│   ├── emit.rs         # tar entry emission (7.4)
│   └── digest.rs       # streaming SHA-256 hashing (7.2)
│
├── oci/                # 08 — image config / manifest / index
│   ├── mod.rs
│   ├── config.rs       # 8.1
│   ├── manifest.rs     # 8.2
│   ├── index.rs        # 9.2
│   └── validate.rs     # 8.5
│
├── output/             # 09 — packaging + atomic write
│   ├── mod.rs
│   ├── tar.rs          # default tar packaging (9.3)
│   └── dir.rs          # --layout dir (9.3)
│
├── cli.rs              # 10 — clap derive structs
└── summary.rs          # 10.6 — run summary formatting
```

Determinism (11) does not get its own module: it is a
cross-cutting contract enforced by every other module's choice
of ordered maps, explicit sorts, and pinned formatters.

## 0.5 Dependency policy

Third-party crates are added deliberately, not reflexively. Every
direct dependency in `Cargo.toml` falls into one of four
categories:

**Required, no in-tree replacement worth writing.**

- `tar` — streaming tar reader and PAX-aware writer.
- `flate2` — gzip decompression for input layers (01 §1.8).
- `zstd` — zstd decompression for input layers (01 §1.8).
- `sha2` — SHA-256 for content_hash (04 §4.4) and blob digests
  (07 §7.2).
- `serde`, `serde_json` — OCI config / manifest / index JSON
  (08, 09).
- `oci-spec` — typed Rust models of the OCI image config,
  manifest, index, and `oci-layout` documents (08, 09). Used
  for both parsing inputs (01) and emitting outputs; avoids
  re-deriving the OCI v1 schema in tree. Pin a single major
  version in `Cargo.toml` so schema drift is a deliberate bump.
- `clap` (derive feature) — CLI parsing (10).

**Useful for the implementation shape we want.**

- `rayon` — bounded data parallelism for layer assembly
  (07 §7.5). The job pool size comes from `--jobs`.
- `tracing`, `tracing-subscriber` — structured logging on
  stderr, controllable via `-v` / `RUST_LOG` (10 §10.5).
- `thiserror` — error enum derivation in `error.rs`. `anyhow` is
  used only in `main.rs` for the top-level error chain printout;
  library code returns the typed `Error`.

**Test-only.**

- `tempfile` — scratch dirs for integration tests. Never used in
  the library or binary at runtime; the tool's own scratch
  handling lives in `output/` (09 §9.4) and does not depend on
  this crate.
- `insta` (optional) — snapshot tests for stable output formats
  (manifest JSON, run summary). Snapshots live next to the test
  files.

**Forbidden.**

- Async runtimes (`tokio`, `async-std`). The pipeline is
  CPU-bound and disk-streaming; adding an async runtime buys
  nothing and complicates the determinism story for `rayon`-
  parallel sections.
- `chrono`, `time` for our own timestamp formatting beyond
  RFC 3339 of `T0`. Use `std::time` plus a small local helper if
  needed; pulling in a date library for one integer is overkill.
- Anything pulling `openssl-sys` (we have no TLS surface — 01
  §1.7 forbids registry I/O).
- `lazy_static` — use `std::sync::OnceLock` instead.

Adding a dependency outside these lists requires a note in the
PR explaining which category it falls into and why an in-tree
implementation was rejected.

## 0.6 Tests

`tests/` carries the two regression families from 11.6:

- `tests/determinism.rs` — 11.6.1. Runs the tool against a
  fixed input set with a pinned `T0`, asserts every output
  digest matches a checked-in expected value.
- `tests/round_trip.rs` — 11.6.2. Runs the tool, then reapplies
  both input and output layer stacks into an in-memory FS
  representation and asserts equality per 11.5. The in-memory
  verifier is the *only* place in the codebase that
  reconstructs a filesystem view from layers; the tool itself
  never does.
- `tests/support/` — shared helpers for both files. Anything
  used by exactly one test file stays inline in that file.

Tests may consume fixture images from `hack/images/` (see 0.7)
by passing the relevant subdirectory or tarball path as the
tool's input. They must not assume a fixture exists: a missing
`hack/images/` directory or any specific subpath causes the
dependent test cases to be skipped with a clear message, not to
fail. CI is responsible for populating `hack/images/` (via
`hack/prepare_images.sh`) before running the affected tests.

Unit tests live `#[cfg(test)] mod tests` inside the module they
exercise. Integration-only behavior (CLI surface, multi-image
runs, end-to-end determinism) lives under `tests/`. A test that
only exercises one module's internals does not belong in
`tests/`.

## 0.7 `hack/`

`hack/` holds developer-only assets that ship with the source
tree but are not part of the build:

- `hack/images/` — fixture images used as input by the
  round-trip and determinism test corpora (11.6.1, 11.6.2).
  Holdings include real-world images on the order of hundreds
  of megabytes (e.g. postgres in OCI-layout, docker-archive,
  and dir-transport shapes), so the directory is **gitignored
  in full**. Contents are reproduced locally by running
  `hack/prepare_images.sh`, which pulls and saves the images
  via `podman` / `skopeo` into the canonical subpaths the tests
  expect.
- `hack/prepare_images.sh` — the regeneration script for
  `hack/images/`. Idempotent: running it on a populated
  directory is a no-op for already-present images, and the
  script is the single source of truth for which images and
  which transport variants exist.

Source code under `src/` never reads from `hack/`. Only test
code under `tests/` may, and only as an external input the user
supplied to the tool — i.e. the same way an end user would pass
`-o ... /some/local/image.tar` on the command line. There is no
in-process coupling: tests invoke the tool's library entry
point with a path under `hack/images/` exactly as if the user
had typed it.

`hack/` is not part of the released artifact. A `cargo package`
of the crate excludes it via `Cargo.toml`'s `exclude` field.

## 0.8 Formatting and lint policy

- `rustfmt` is run with the repo's `rustfmt.toml`; CI fails on
  any diff from `cargo fmt --check`.
- `cargo clippy --all-targets -- -D warnings` is part of CI.
  Local `#[allow(clippy::...)]` requires a one-line comment
  explaining why.
- No `unsafe` blocks. The tool processes adversarial input (tar
  archives from arbitrary registries) and has no need for raw
  pointers; if a future change requires `unsafe`, it gets its
  own discussion and a `// SAFETY:` comment per occurrence.

## 0.9 What this file does not pin

- Specific function signatures inside modules. Modules own their
  internal API; only the cross-module surface (the items
  documented in `lib.rs`) is stable.
- The exact set of `pub` items in `lib.rs`. Treat `lib.rs` as a
  curated re-export list that grows as integration tests need
  more handles, not as a frozen API.
- The choice between `BTreeMap` and a sorted `Vec<(K, V)>` for
  any individual ordered collection. Either satisfies the
  determinism contract (11 §11.2); pick per call site.
