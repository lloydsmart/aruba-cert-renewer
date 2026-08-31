#!/usr/bin/env bash

set -euo pipefail

readonly trivy_image='ghcr.io/aquasecurity/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969'

if [[ $# -ne 1 || -z $1 || $1 == -* ]]; then
    printf 'Usage: %s IMAGE\n' "$0" >&2
    exit 2
fi

image=$1

if ! command -v docker >/dev/null 2>&1; then
    printf '%s\n' 'Docker is required but is not available on PATH.' >&2
    exit 1
fi

if ! docker image inspect "$image" >/dev/null 2>&1; then
    printf 'Container image does not exist locally: %s\n' "$image" >&2
    exit 1
fi

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/aruba-cert-renewer-trivy.XXXXXX")
cleanup() {
    rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

archive="$temporary_directory/image.tar"
cache_directory="$temporary_directory/cache"
trivy_tmp_directory="$temporary_directory/tmp"
mkdir -- "$cache_directory" "$trivy_tmp_directory"
docker save --output "$archive" "$image"

printf '%s\n' 'Reporting all HIGH/CRITICAL vulnerabilities'
docker run --rm \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp \
    --env TMPDIR=/trivy-tmp \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
    --mount "type=bind,src=$archive,dst=/scan/image.tar,readonly" \
    --mount "type=bind,src=$cache_directory,dst=/cache" \
    --mount "type=bind,src=$trivy_tmp_directory,dst=/trivy-tmp" \
    "$trivy_image" \
    --cache-dir /cache \
    image \
    --input /scan/image.tar \
    --scanners vuln \
    --severity HIGH,CRITICAL \
    --exit-code 0

printf '%s\n' 'Enforcing fixes for HIGH/CRITICAL vulnerabilities'
docker run --rm \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp \
    --env TMPDIR=/trivy-tmp \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
    --mount "type=bind,src=$archive,dst=/scan/image.tar,readonly" \
    --mount "type=bind,src=$cache_directory,dst=/cache" \
    --mount "type=bind,src=$trivy_tmp_directory,dst=/trivy-tmp" \
    "$trivy_image" \
    --cache-dir /cache \
    image \
    --input /scan/image.tar \
    --scanners vuln \
    --severity HIGH,CRITICAL \
    --ignore-unfixed \
    --exit-code 1
