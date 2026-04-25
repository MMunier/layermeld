# 05 — Deduplication

Given `N >= 1` squashed-fs indexes (one per input image) computed per
03-squashing, this pass partitions every entry into layers such that
each entry is emitted **exactly once** across the entire output —
regardless of how many images contain it — while still producing a
valid linear layer stack for each output image.

The savings target is "every byte that appears in two or more images
is stored on disk exactly once", which is stronger than the simple
"layer common to all images" model.

## 5.1 Membership sets

For every entry `e` (identified by its full `FileIdentity` per
04-file-identity, i.e. path + mode + uid + gid + content_hash + …),
its **membership set** is the set of input images that contain a
byte-equal `FileIdentity`:

```
members(e) = { i ∈ 0..N : e ∈ entries(i) }
```

Two entries that match by `FileIdentity` always have the same
membership set, by construction.

## 5.2 Subset layers

The output contains one layer per **distinct, non-empty membership
set** that occurs in the inputs. Concretely:

- All entries whose membership set is `{0,1,…,N-1}` (the maximal set
  — present in every input) go into the **fully-shared layer**.
- All entries whose membership set is some proper subset
  `M ⊊ {0,…,N-1}` with `|M| ≥ 2` go into a **partial-shared layer**
  for `M`. There is one such layer per `M` that actually occurs.
- All entries whose membership set is a singleton `{i}` go into the
  **per-image layer** for image `i`.

Empty membership sets are impossible by construction (every entry
came from at least one image).

In the worst case there are `2^N − 1` subset layers; in practice many
subsets do not occur and produce no layer at all. With `N = 2` the
model degenerates to exactly the three layers `{0,1}`, `{0}`, `{1}`,
which is the minimal "one shared + two specific" shape.

## 5.3 Per-image layer stacks

The OCI manifest for output image `i` references, in order:

1. Every subset layer `M` such that `i ∈ M`, ordered first by
   **descending `|M|`** (largest subsets — most universal content —
   applied first), then by the ascending lexicographic order of the
   image ids in `M` as a tiebreaker. The fully-shared layer is
   therefore always first.
2. The per-image layer `{i}` itself, applied last.

This ordering is well-defined and identical across runs (see 11), and
every member layer of image `i` is present in its stack.

Within each layer, entries are written in lexicographic order of
path with directories emitted before any of their children (same
rule as before — required for determinism and friendly to
compression).

## 5.4 Ancestor directories across subset layers

For every entry that is emitted into some subset layer `M`, every
strict ancestor directory of its path must be visible to image `i`
(for every `i ∈ M`) by the time `M` is applied. There are three
cases:

1. **Ancestor's `FileIdentity` is identical across every image in
   `M`** *(the common case)*. The ancestor entry is itself a member
   of some superset `M' ⊇ M`. It is emitted in `M'`'s layer (which
   precedes `M` in every stack that contains `M`, because `|M'| ≥
   |M|`). No special handling needed.
2. **Ancestor's `FileIdentity` differs across images in `M`** (e.g.
   image 0 and 1 share `/usr/lib/foo/bar` but disagree about the
   mode of `/usr/lib/foo`). Layer `M` emits a *synthetic* minimal
   directory entry for the ancestor: mode `0755`, uid `0`, gid `0`,
   no xattrs, normalized timestamp. Each affected image's smaller
   subset layers (or per-image layer) then carry the actual
   directory entry, which overrides the synthetic one because it is
   applied later.
3. **Ancestor exists only in some images of `M`.** Cannot happen: an
   ancestor that does not exist in image `i` means image `i` cannot
   contain a child of it either, so `i` would not be in `M` to begin
   with.

The synthetic-ancestor escape hatch is the **only** mechanism by
which any output layer carries metadata that did not appear verbatim
in some input image.

## 5.5 Minimum-layer-size compaction

The naive partition from 5.2 can produce many tiny subset layers
when only a handful of files happen to share an unusual membership
set. Each layer carries a fixed manifest/descriptor cost (a JSON
descriptor in the manifest, an entry in `rootfs.diff_ids`, a tar
end-of-archive marker, plus per-file 512-byte tar headers); below
some threshold this overhead exceeds the savings from sharing.

After 5.2 builds the candidate layers and before 07 assembles them,
the tool runs a **dissolve pass**:

### 5.5.1 Threshold

A layer's *estimated tar size* is

```
sum over entries e in layer of:
    512                            (PAX header block)
  + 512 * ceil(xattr_blob_len/512) (PAX extended-header block, if any)
  + 512 * ceil(e.size/512)         (body, padded)
+ 1024                              (tar end-of-archive)
```

(no compression — see 07 §7.3). If this estimate is strictly less
than `--min-layer-size` (default **16 KiB**, configurable; `0`
disables the pass), the layer is *dissolved*.

The estimate is computed without ever opening file bodies: every
field needed is already in the squashed-fs index from 03.

### 5.5.2 Dissolve rule

For each file `f` in a dissolved layer `M`, and for each image
`i ∈ M`, `f` is re-emitted into the **largest existing subset layer
`M' ⊂ M` such that `i ∈ M'` and `M'` is itself not dissolved**.

If no such `M'` exists (e.g. `|M| = 2`, so the only smaller subsets
are the singletons), `f` falls into image `i`'s per-image layer
`{i}`, which always exists and is never dissolved.

The same file may be added to several different smaller layers —
one per image in `M` — because each image needs its own path to
the content once `M`'s shared layer is gone. The on-disk byte cost
grows by `|M| - 1` extra copies of each dissolved file in the
worst case (one per image of `M` minus the one that was already
"natively" in some destination layer); the offset is the layer
overhead saved.

### 5.5.3 Cascade order

The dissolve pass visits candidate layers in order of **descending
`|M|`**, with lexicographic order on `M` as a tiebreaker. This is
the right direction because dissolution pushes content **down**
into smaller subsets; visiting larger layers first means smaller
layers have a chance to absorb content from above before being
sized themselves.

Per-image layers (`|M| = 1`) are never visited: they are the
absorbers of last resort.

A layer that was visited and kept may not be revisited — its size
only ever grows during this pass, so it cannot become eligible for
dissolution after the fact. The pass is therefore single-pass and
terminates in `O(L)` layer visits where `L` is the number of
candidate subset layers.

### 5.5.4 Synthetic ancestors after dissolve

Synthetic ancestor directories (§5.4) are recomputed *after* the
dissolve pass, against the final layer set. A directory that was
synthesized for a now-dissolved layer is dropped; one that becomes
necessary because content moved into a previously-clean layer is
added.

### 5.5.5 Disabling the pass

`--min-layer-size 0` skips the dissolve pass entirely and emits
exactly the candidate layers from 5.2. Useful for benchmarking
the raw deduplication ratio, debugging the partition, or testing
round-trip correctness against the unaltered partition.

## 5.6 Hardlinks revisited

Hardlinks are always emitted into the per-image layer `{i}`, never
into any shared subset layer (per 02-tar-handling §2.6). Their link
targets may resolve to entries that live in any of the subset layers
above them in `i`'s stack — that is fine because `{i}` is applied
last, so by then every superset layer including the target's has
already been unpacked into the merged view.

## 5.7 What dedup does *not* try to do

- Look inside files. Files that share 99% of their bytes are treated
  as wholly distinct unless byte-identical end-to-end.
- Merge files across paths (see 04-file-identity §4.3).
- Deduplicate within a single image. Squashing already collapses the
  layer history; intra-image content duplication is considered the
  input's problem.
- Coalesce two subset layers whose contents are tiny just to reduce
  layer count, *unless* one of them is below the minimum-layer-size
  threshold (5.5). Layer count is not a goal in itself; the dissolve
  pass exists only because per-layer fixed overhead can outweigh the
  sharing benefit.
