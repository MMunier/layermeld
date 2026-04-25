#!/bin/sh
set -ex

SCRIPT_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
cd "$SCRIPT_DIR"

rm -rf images/*
podman image pull docker.io/postgres:18.3-trixie
podman image pull docker.io/postgres:17.9-trixie
podman image save --format oci-dir        -o images/postgres-oci                docker.io/postgres:17.9-trixie
podman image save --format docker-dir     -o images/postgres-docker             docker.io/postgres:17.9-trixie
podman image save --format docker-archive -o images/postgres-docker-archive.tar docker.io/postgres:17.9-trixie
podman image save --format docker-archive -o images/podman-multi-image          -m docker.io/postgres:17.9-trixie docker.io/postgres:18.3-trixie

mkdir images/postgres-docker-archive
tar -xf images/postgres-docker-archive.tar -C images/postgres-docker-archive

docker image pull postgres:17.9-trixie
docker image save postgres:17.9-trixie -o images/pg17.tar
mkdir images/postgres-unpack
tar -xf images/pg17.tar -C images/postgres-unpack