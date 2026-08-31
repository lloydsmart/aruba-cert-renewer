#!/usr/bin/env bash

set -euo pipefail

readonly gitleaks_image='ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f'
repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

if ! command -v git >/dev/null 2>&1; then
    printf '%s\n' 'Git is required but is not available on PATH.' >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    printf '%s\n' 'Docker is required but is not available on PATH.' >&2
    exit 1
fi

if [[ $(git -C "$repository_root" rev-parse --is-inside-work-tree 2>/dev/null) != 'true' ]] ||
    [[ $(git -C "$repository_root" rev-parse --is-bare-repository 2>/dev/null) != 'false' ]]; then
    printf 'A Git working tree is required at %s.\n' "$repository_root" >&2
    exit 1
fi

if [[ -z $(git -C "$repository_root" rev-list --all --max-count=1) ]]; then
    printf '%s\n' 'The repository has no reachable commits to scan.' >&2
    exit 1
fi

# Do not trust Gitleaks' exit status until the equivalent host Git operation
# succeeds: Gitleaks can otherwise report a failed git log as a clean scan.
git -C "$repository_root" log \
    -p \
    -U0 \
    --cc \
    --full-history \
    --all \
    --diff-filter=tuxdb \
    >/dev/null

docker run --rm \
    --network none \
    --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$repository_root,dst=/repository,readonly" \
    "$gitleaks_image" \
    --no-banner \
    --no-color \
    --redact=100 \
    git \
    --log-opts='--cc --full-history --all --diff-filter=tuxdb' \
    /repository
