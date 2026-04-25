# 06 — Timestamp normalization

The tool collapses every time-bearing field in its output to a single
value, the **invocation timestamp** `T0`.

## 6.1 What `T0` is

`T0` is captured once at the start of the run, before any output is
written, as the current wall-clock time in seconds since the Unix
epoch (UTC, no sub-second precision). It is recorded in the run's
internal context and reused everywhere downstream so that no part of
the output can possibly disagree with another.

`T0` may be overridden by the user via:

- The `--timestamp <unix-seconds>` CLI flag, or
- The `SOURCE_DATE_EPOCH` environment variable (commonly understood
  by reproducible-build tooling).

If both are set, `--timestamp` wins. If neither is set, the wall
clock is used. The chosen `T0` is reported in the run summary so the
user always knows what was baked in.

## 6.2 What gets set to `T0`

Every one of the following fields is overwritten with `T0`,
regardless of what the input said:

- The `mtime` of every tar entry in every output layer (shared,
  partial-shared, per-image diff).
- The PAX `atime` and `ctime` headers, if emitted at all. The
  default is to **not emit** them; if emitted (e.g. for archive-
  format compatibility) they are also `T0`.
- The OCI image config's `created` field of every output image.
- The `created` field on every entry of the rewritten `history`
  array of every output image config.
- Any `org.opencontainers.image.created` annotation on the output
  manifests and on the output image index.

## 6.3 What is **not** touched

- File contents are never rewritten in any way that depends on
  time. If a file body happens to embed a timestamp (e.g. a
  pre-compiled `.pyc`, a build manifest), that timestamp is part of
  the bytes and is preserved verbatim. The tool does not look
  inside file bodies.
- The on-disk `mtime` of the output archive itself, as observed by
  `stat(2)`, is whatever the OS sets when the file is written. The
  tool makes no attempt to `utimes()` its own output files.
- The `T0` value is not propagated to xattrs or other metadata
  unless the field is explicitly named in 6.2.

## 6.4 Sub-second precision

Output timestamps are emitted at second precision. PAX permits
nanosecond `mtime` via `mtime=<float>` headers; the tool does not
emit a fractional component, so the value is always an integer
number of seconds.

## 6.5 Interaction with deduplication

Because `mtime` is excluded from `FileIdentity` (see 04 §4.2), two
files that are otherwise byte- and metadata-equal but carry
different mtimes in their input images still match and end up in a
shared layer. That shared layer entry is emitted with `mtime = T0`,
which is what every input image's per-image layer would have written
anyway, so applying the layers in stack order produces the same
visible mtime in every image.

In other words: dedup is correct precisely *because* timestamps are
normalized.

## 6.6 Pre-1970 and far-future inputs

If an input entry carries an `mtime` that is negative or absurdly
large (a sentinel sometimes seen in malformed images), it is
silently replaced by `T0` exactly like every other value. There is
no special handling, warning, or refusal — the tool is overwriting
the field unconditionally.

## 6.7 Reproducibility hook

Setting `SOURCE_DATE_EPOCH=<n>` once and re-running the tool with
the same inputs must produce a byte-identical output (see 11). `T0`
is the only source of nondeterminism the tool itself introduces;
fixing it is sufficient to fix the whole output.
