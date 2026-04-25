# 99 — Backburner

Things we have decided are good ideas but explicitly out of scope
for the initial implementation. Each entry should be self-contained
enough that a future developer can pick it up without re-litigating
the design discussion.

## 99.1 Real-README user-facing caveats

When a user-facing `README.md` is written for the published tool
(distinct from `specs/README.md`, which describes project scope),
it must call out the following sharp edges:

- **Timestamps are rewritten.** Every `mtime`, every config
  `created`, every history entry is set to `T0` (06). Almost
  always harmless, but a small number of programs use on-disk
  mtimes as a trust signal — most notably `dpkg --verify` and a
  handful of integrity-checking package managers — and those will
  report spurious changes after a squash. If that matters in your
  environment, run integrity checks against the original images,
  not the squashed output.
- **Signatures and attestations are invalidated.** Cosign /
  notation signatures, in-toto attestations, and SBOMs are bound
  to specific blob digests. Squashing rewrites every layer, so
  every such reference becomes dangling. Re-attach signatures
  and SBOMs downstream of this tool, not upstream.
- **Cross-platform dedup is allowed but warned about.** If the
  inputs disagree on `architecture` / `os` / `variant`, the tool
  emits a warning and continues (08 §8.3). Users who want a
  hard refusal in CI should grep stderr or fail on non-zero
  warning counts in the run summary.
- **No registry I/O.** Inputs and outputs are local paths; pull
  with podman/docker/skopeo first, push with skopeo/crane after.

These belong in the *real* README that ships with the binary, not
in `specs/README.md`.

## 99.2 Path filters (`--exclude` / `--include`)

Apply user-supplied glob patterns during squash so well-known
bloat paths can be dropped before any dedup decision is made.

Sketch:

- `--exclude '/var/cache/**'`, `--exclude '/usr/share/doc/**'`,
  `--exclude '/usr/share/man/**'`.
- Patterns are applied per input image, not globally, so the
  user can `--exclude-from <image-id>:<glob>`.
- Excluded paths are removed from the squashed-fs index before
  membership-set computation, exactly as if the input image had
  never contained them.
- Directories that become empty as a result of exclusions are
  *not* removed automatically — users may want the empty dir to
  exist as a mount point. A separate `--prune-empty-dirs` flag
  can be added if needed.

Out of scope until the rest of the pipeline is stable, because
this interacts with every later stage (it can change membership
sets, dissolve thresholds, and round-trip equality).

## 99.3 Setuid / capability audit

Surface every setuid/setgid bit and every `security.capability`
xattr in the run summary. Cross-image dedup can move these
between layers; an explicit list lets a security reviewer
confirm nothing moved that shouldn't have.

These bits and xattrs were already in the input images, so
exposing them in the summary cannot *introduce* a security
issue — it only makes existing ones visible. That is also why
this is a reporting-only feature: it never refuses or alters
anything.

Sketch of the report shape:

```
security audit:
  setuid binaries:
    /usr/bin/passwd      (0o4755 root:root) layer={0,1}
    /usr/bin/sudo        (0o4755 root:root) layer={0}
  capabilities:
    /usr/bin/ping        cap_net_raw+ep     layer={0,1}
```

Implementation is trivial once the squashed-fs index exists; it
is just an extra projection over the same data.

## 99.4 `--verify` mode

A self-check mode that, after producing the output, reapplies
both the original input layer stack and the new output layer
stack into in-memory representations and asserts they match per
the round-trip contract (11 §11.5). Effectively the round-trip
test (11 §11.6.2) generalized to arbitrary user inputs.

Lower priority because the same check is achievable manually:

```
docker load   < <(produce input archive)
docker create … input-image   ; docker export … > input.tar
docker load   < squashed-output.tar
docker create … output-image  ; docker export … > output.tar
diff <(tar tvf input.tar  | sort) \
     <(tar tvf output.tar | sort)
# … plus a body-hash diff per file …
```

For day-to-day development the manual recipe is fine. A built-in
`--verify` is worth implementing once the test corpus has shaken
out the obvious bugs and we want a tool a release engineer can
run on production images without standing up a docker daemon.

## 99.5 Layer compression

Per 07 §7.3, the initial implementation emits uncompressed tar
layers. A future `--compress gzip|zstd` switch will:

- Pin compression levels explicitly (gzip default `6`, zstd
  default `3`) so the digest pipeline stays deterministic across
  zlib / libzstd versions.
- Emit the matching media types
  (`application/vnd.oci.image.layer.v1.tar+gzip` /
  `…tar+zstd`).
- Run the digest pipeline as two hashers (uncompressed-tar →
  diff_id, compressed-tar → blob digest) instead of one.
- Update the determinism test's expected digests; round-trip
  test must remain pass/fail invariant.

Nothing else in the spec set should need to change.

## 99.6 Machine-readable summary

`--summary-json <path>` emits the run summary (10 §10.6) as a
JSON document with the same data plus stable field names. Useful
for CI pipelines that want to gate on `bytes_saved >= K` or
similar.
