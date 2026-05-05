#!/bin/sh
# Pull a small fixture set into hack/images/ in every input shape the
# tool detects (spec 01 §1.1–1.5). Idempotent: each fixture is skipped
# if its target path already exists. To regenerate one, remove its
# path and re-run.
#
# Tools: prefers `skopeo` (handles every transport directly). Falls
# back to `podman` for the multi-image docker-archive shape, which
# skopeo does not produce in a single invocation.
#
# Output is gitignored in full (see .gitignore + spec 00 §0.7).

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
IMAGES_DIR="$SCRIPT_DIR/images"

# Two postgres tags share most layers, exercising spec 05 dedup on
# the multi-image fixture. Trixie keeps the base layer count modest.
TAG_A=17.9-trixie
TAG_B=18.3-trixie
REF_A="docker.io/library/postgres:$TAG_A"
REF_B="docker.io/library/postgres:$TAG_B"

have() { command -v "$1" >/dev/null 2>&1; }

# Tool presence is checked lazily — only when a fixture actually
# needs to be fetched. A fully-populated tree is a clean no-op even
# without skopeo / podman in PATH.
require_tool() {
    if ! have "$1"; then
        echo "error: $1 not found in PATH ($2)" >&2
        exit 1
    fi
}

mkdir -p "$IMAGES_DIR"
cd "$IMAGES_DIR"

log() { printf '==> %s\n' "$*"; }
skip() { printf '    %s already present, skipping\n' "$1"; }

# skopeo_copy <dest-path> <source-ref> <transport> [tag]
#
# Skips when the destination path already exists. Writes through a
# `.partial` sibling so an interrupted pull never leaves a half-written
# fixture that the next run mistakes for complete.
#
# `transport` is the skopeo destination transport keyword
# (`oci`, `oci-archive`, `docker-archive`, `dir`). `tag` is required
# for transports that take a `:tag` suffix and ignored otherwise.
skopeo_copy() {
    dest_path=$1
    source_ref=$2
    transport=$3
    tag=${4:-}

    if [ -e "$dest_path" ]; then
        skip "$dest_path"
        return 0
    fi

    require_tool skopeo "needed to fetch $dest_path"
    log "fetching $dest_path from $source_ref ($transport)"
    partial="${dest_path}.partial"
    rm -rf "$partial"

    case "$transport" in
        oci|oci-archive)
            partial_spec="$transport:$partial:$tag"
            ;;
        docker-archive)
            partial_spec="$transport:$partial:$tag"
            ;;
        dir)
            partial_spec="dir:$partial"
            ;;
        *)
            echo "internal error: unsupported transport $transport" >&2
            return 1
            ;;
    esac

    skopeo copy --quiet "docker://$source_ref" "$partial_spec"
    mv "$partial" "$dest_path"
}

# extract_tar <tar-path> <dest-dir>
#
# Idempotent extracted-dir companion to a tar fixture. Only runs when
# the dir is absent; uses a partial sibling so an interrupted extract
# does not leave a partial dir behind.
extract_tar() {
    tar_path=$1
    dest_dir=$2

    if [ -e "$dest_dir" ]; then
        skip "$dest_dir"
        return 0
    fi
    if [ ! -f "$tar_path" ]; then
        echo "error: cannot extract $tar_path: file missing" >&2
        return 1
    fi

    log "extracting $tar_path into $dest_dir"
    partial="${dest_dir}.partial"
    rm -rf "$partial"
    mkdir -p "$partial"
    tar -xf "$tar_path" -C "$partial"
    mv "$partial" "$dest_dir"
}

# Single-image fixtures from $TAG_A, one per spec 01 input shape.
skopeo_copy "postgres-oci"                "$REF_A" oci             "$TAG_A"          # 1.1 OCI layout dir
skopeo_copy "postgres-oci.tar"            "$REF_A" oci-archive     "$TAG_A"          # 1.2 OCI layout tar
skopeo_copy "postgres-docker-archive.tar" "$REF_A" docker-archive  "postgres:$TAG_A" # 1.3 docker-archive tar
extract_tar "postgres-docker-archive.tar" "postgres-docker-archive"                  # 1.4 docker-archive dir
skopeo_copy "postgres-dir"                "$REF_A" dir                               # 1.5 dir transport

# Second tag, OCI layout only — pairs with $TAG_A for dedup-style
# runs ("squash both into one output").
skopeo_copy "postgres-18-oci"             "$REF_B" oci             "$TAG_B"

# Multi-image docker-archive: skopeo cannot produce these in one
# invocation, so use podman save -m. Same partial-sibling discipline.
multi_tar="postgres-multi-docker-archive.tar"
multi_dir="postgres-multi-docker-archive"
if [ -e "$multi_tar" ]; then
    skip "$multi_tar"
else
    require_tool podman "needed for multi-image docker-archive"
    log "fetching $multi_tar via podman save -m"
    podman pull --quiet "$REF_A" >/dev/null
    podman pull --quiet "$REF_B" >/dev/null
    partial="${multi_tar}.partial"
    rm -f "$partial"
    podman save --quiet --format docker-archive -o "$partial" -m "$REF_A" "$REF_B"
    mv "$partial" "$multi_tar"
fi
extract_tar "$multi_tar" "$multi_dir"

log "done. fixtures live under $IMAGES_DIR"
