#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(git -C "$script_dir/.." rev-parse --show-toplevel)

config_status=0
existing_hooks_path=$(git -C "$repo_root" config --local --get-all core.hooksPath) || config_status=$?

if ((config_status > 1)); then
    printf 'Unable to inspect repository-local core.hooksPath.\n' >&2
    exit "$config_status"
fi

if [[ -n "$existing_hooks_path" && "$existing_hooks_path" != ".githooks" ]]; then
    printf 'Refusing to replace existing repository-local core.hooksPath: %s\n' \
        "$existing_hooks_path" >&2
    exit 1
fi

if [[ "$existing_hooks_path" != ".githooks" ]]; then
    git -C "$repo_root" config --local core.hooksPath .githooks
fi

configured_hooks_path=$(git -C "$repo_root" config --local --get core.hooksPath)
if [[ "$configured_hooks_path" != ".githooks" ]]; then
    printf 'Repository-local core.hooksPath verification failed.\n' >&2
    exit 1
fi

printf 'Configured repository Git hooks from .githooks\n'
