# 05 — Deduplication

Given `N >= 1` squashed-fs indexes (one per input image) computed per
03-squashing, this pass partitions every entry into layers such that
each entry is emitted **exactly once** across the entire output —
regardless of how many images contain it — while still producing a
valid linear layer stack for each output image.

The savings target is "every byte that appears in two or more images
is stored on disk exactly once", which is stronger than the simple
"layer common to all images" model.

## 5.1 Naive and effective membership

For every entry `e` (identified by its full `FileIdentity` per
04-file-identity, i.e. path + mode + uid + gid + content_hash + …),
its **naive membership** is the set of input images that contain a
byte-equal `FileIdentity` at the same path:

```
naive(e) = { i ∈ 0..N : e ∈ entries(i) }
```

Naive membership is not directly usable for layer placement,
because of the overlayfs "implicit-parent" pitfall (5.4). The
correct quantity is **effective membership**:

```
eff(e) = naive(e) ∩ ⋂_{A strict ancestor of e.path} naive(A_in_image_i)
```

evaluated for any reference image `i ∈ naive(e)`. (The choice of
`i` does not change the result inside the intersection: if any
ancestor's identity disagrees with image `i`'s view, the
disagreeing image is removed from the intersection regardless of
which `i` we picked.)

Equivalently: `eff(e)` is the largest set of images that agree on
`e`'s identity *and* on every ancestor's identity all the way up
to `/`. Files whose naive membership splits into multiple
ancestor-equivalence classes appear once per class — their bytes
are duplicated across those classes' layers. This is the price of
overlayfs correctness; see 5.4 for why.

Two entries with the same `FileIdentity` *and* the same effective
membership go into the same layer. Files with the same
`FileIdentity` but different effective memberships (because their
ancestors diverge differently) go into different layers, with
their bodies duplicated.

## 5.2 Subset layers

The output contains one layer per **distinct, non-empty effective
membership set** that occurs in the inputs. Concretely:

- All entries with `eff(e) = {0,1,…,N-1}` go into the
  **fully-shared layer**.
- All entries with `eff(e) = M` for some proper subset
  `M ⊊ {0,…,N-1}` with `|M| ≥ 2` go into a **partial-shared layer**
  for `M`. There is one such layer per `M` that actually occurs.
- All entries with `eff(e) = {i}` go into the **per-image layer**
  for image `i`.

Empty effective memberships are impossible by construction (every
entry came from at least one image, and the singleton `{i}` is
always achievable since image `i`'s view of any path agrees with
itself on every ancestor).

In the worst case there are `2^N − 1` subset layers; in practice
many subsets do not occur and produce no layer at all. With
`N = 2` the model degenerates to exactly the three layers
`{0,1}`, `{0}`, `{1}`, which is the minimal "one shared + two
specific" shape.

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

## 5.4 Ancestor directories: why the implicit-parent rule fails

It is tempting to assume that a tar layer can omit ancestor
directory entries and rely on the unpacker to "fix things up"
later. This assumption is *wrong* under overlayfs, and 5.1's
effective-membership rule and 5.4.2's duplication rule exist
precisely to avoid the failure mode it produces.

### 5.4.1 The shadow problem

When a tar layer is unpacked into an overlayfs upperdir (the
mechanism used by containerd's overlay snapshotter, podman's
overlay storage driver, and every other major image runtime),
each tar entry materializes inside that single layer's
upperdir. To create a regular file at `/a/b/c`, the unpacker
must `mkdir -p` the parent path *inside the upperdir*, because
the upperdir is just an empty directory at the start of the
unpack — it has no awareness of lower layers.

`mkdir -p` creates `/a/` and `/a/b/` with the unpacker's
default metadata (`0755 root:root`, no xattrs). Once those
directory inodes exist in the upperdir, overlayfs treats them
as the authoritative version: any lower-layer `/a/` with
mode `0700` (say) is **shadowed** by the upperdir's
`0755 root:root`. The merged view that runc and userspace see
is the wrong metadata.

A later layer in the same image's stack that explicitly emits
`/a/` with the correct metadata *can* fix this — but only
because that later layer's upperdir then takes precedence in
its turn. If no such later layer exists, the wrong metadata
sticks. Synthetic placeholders in the offending layer plus
"trust later layers to override" is a fragile design that
breaks the moment the stack ends without an override.

### 5.4.2 The rule

Every layer L must explicitly contain an entry for every
strict ancestor of every path in L, with metadata consistent
across L's effective membership. There are no implicit
parents in any output layer.

This forces two structural rules on the partition from 5.2:

1. **Effective membership for files** (5.1). A file P with
   naive membership `M_naive` cannot be placed in a layer
   whose membership exceeds `M_eff(P)`, because layers with
   larger membership cannot include a coherent ancestor
   chain for P (some ancestor's identity diverges across
   that larger membership). When `M_naive(P)` strictly
   exceeds `M_eff(P)`, P appears in multiple layers — one
   per ancestor-agreement class — and its body bytes are
   duplicated across those layers.

2. **Directory duplication across layers**. A directory D
   with effective membership `M_D` is emitted into:
   - its **natural layer** `L(M_D)`, AND
   - every other layer `L(M)` whose contents include any
     descendant of D, with `M ⊆ M_D`.

   In every such layer, D's entry uses the same single
   `FileIdentity` (D's identity is consistent across `M_D`
   by definition, and every smaller `M ⊆ M_D` inherits that
   consistency). The duplicated entries differ only in
   *which layer* they live in — same path, same metadata,
   same numeric ids, same xattrs. The cost of duplication
   is one tar header (≈ 512 bytes plus PAX xattr overhead);
   directory entries have no body.

File entries are NOT duplicated this way. Files appear once
per ancestor-agreement class (potentially more than once
across layers, but each appearance has its own distinct
`(path, M_eff)` reason), not once per layer that happens to
sit inside the directory.

### 5.4.3 Layer ordering still works

The descending-`|M|` ordering from 5.3 ensures that when a
layer L's directory entry for D is encountered, any
larger-membership layer that also contains D has already
been applied. The two emissions agree on D's identity
(rule 2 above), so the later application is a no-op for D's
metadata. The point of the duplicated entry is not to
override anything; it is to *prevent* the implicit-parent
shadow described in 5.4.1 from creating the wrong inode in
L's upperdir in the first place.

### 5.4.4 What never happens

- The tool never emits synthetic `0755 root:root` placeholder
  ancestors. Every directory entry in every output layer
  comes from some input image's squashed filesystem, with
  metadata verbatim from that input.
- No output layer relies on a later layer to "fix" a wrong
  ancestor entry. Each layer is internally complete: applying
  it produces a correct-metadata view of every path it
  references, including all ancestors.
- The "ancestor exists only in some images of `M`" case from
  the previous draft cannot happen: `M ⊆ naive(A)` is implied
  by `M ⊆ M_eff(P)` for any `P` whose ancestors include `A`.

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

For each entry `e` in a dissolved layer `M`, and for each image
`i ∈ M`, `e` is re-emitted into the **largest existing subset layer
`M' ⊂ M` such that `i ∈ M'` and `M'` is itself not dissolved**.

If no such `M'` exists (e.g. `|M| = 2`, so the only smaller subsets
are the singletons), `e` falls into image `i`'s per-image layer
`{i}`, which always exists and is never dissolved.

The same entry may be added to several different smaller layers —
one per image in `M` — because each image needs its own path to
the content once `M`'s shared layer is gone. The on-disk byte cost
grows by `|M| - 1` extra copies of each dissolved file in the
worst case (one per image of `M` minus the one that was already
"natively" in some destination layer); the offset is the layer
overhead saved.

This applies uniformly to every entry kind, including directories.
Non-leaf directories from the dissolved layer would also be
recreated in the destination as a side effect of the ancestor
back-fill in 5.5.4 once a descendant file migrates, but a **leaf**
directory has no descendants to drag it along — explicitly
migrating directory entries here is what keeps an empty `tmp/` (or
any other shared leaf dir) from vanishing across the dissolve
pass. When the destination already carries a byte-equal entry at
the same path (the common case for dirs back-filled by partition
pass 2), the existing entry wins per the smallest-`image_id`
canonical-source rule from 5.4.4 — the result is byte-equal output
either way.

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

### 5.5.4 Ancestor invariant after dissolve

The 5.4.2 invariant — every layer contains explicit entries for
all ancestors of every path it carries — must be preserved by
the dissolve pass. When file `f` is migrated into destination
layer `L'`, every strict ancestor of `f.path` that is not
already explicit in `L'` is added to `L'` as well, with the
ancestor's `FileIdentity` taken from the consensus across
`M_{L'}` (which is consistent because `M_{L'} ⊆ M_eff(f) ⊆
naive(ancestor)`).

Dissolving therefore grows the destination layer by the
migrated file's body bytes plus possibly a handful of extra
directory headers. The size estimate from 5.5.1 is recomputed
for `L'` after each migration so a destination layer that is
itself near the threshold does not accidentally cross it
unnoticed.

A layer that crosses the threshold *upward* via dissolve
absorption simply stops being a dissolve candidate. The pass
never re-visits a layer that has grown past `--min-layer-size`.

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
