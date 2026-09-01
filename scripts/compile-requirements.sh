#!/usr/bin/env bash

set -euo pipefail

repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

if [[ $# -gt 1 || ( $# -eq 1 && $1 != "--upgrade" ) ]]; then
    printf 'Usage: %s [--upgrade]\n' "$0" >&2
    exit 2
fi

if ! command -v python >/dev/null 2>&1; then
    printf '%s\n' 'Python 3.12 is required but python is not available on PATH.' >&2
    exit 1
fi

python_version=$(python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [[ "$python_version" != "3.12" ]]; then
    printf 'Python 3.12 is required; found Python %s.\n' "$python_version" >&2
    exit 1
fi

pip_version=$(python -c 'import importlib.metadata as metadata; print(metadata.version("pip"))' 2>/dev/null || true)
pip_tools_version=$(python -c 'import importlib.metadata as metadata; print(metadata.version("pip-tools"))' 2>/dev/null || true)
if [[ "$pip_version" != "26.2.1" || "$pip_tools_version" != "7.6.1" ]]; then
    printf '%s\n' 'Lock generation requires pip 26.2.1 and pip-tools 7.6.1.' >&2
    printf 'Found pip %s and pip-tools %s.\n' \
        "${pip_version:-not installed}" \
        "${pip_tools_version:-not installed}" >&2
    exit 1
fi

upgrade_option=--no-upgrade
if [[ $# -eq 1 ]]; then
    upgrade_option=--upgrade
fi

export CUSTOM_COMPILE_COMMAND='./scripts/compile-requirements.sh'
export PIP_CONFIG_FILE=/dev/null
export PIP_INDEX_URL=https://pypi.org/simple
unset PIP_EXTRA_INDEX_URL PIP_FIND_LINKS PIP_NO_INDEX PIP_TRUSTED_HOST

compile_options=(
    --no-config
    --quiet
    --resolver=backtracking
    --generate-hashes
    --reuse-hashes
    --header
    --annotate
    --strip-extras
    --no-allow-unsafe
    --annotation-style=split
    --newline=lf
    --index-url=https://pypi.org/simple
    --no-emit-index-url
    --no-emit-trusted-host
    --no-emit-find-links
    "$upgrade_option"
)

python -m piptools compile \
    "${compile_options[@]}" \
    --output-file=requirements.txt \
    requirements.in

python -m piptools compile \
    "${compile_options[@]}" \
    --output-file=requirements-dev.txt \
    requirements-dev.in

python -m piptools compile \
    "${compile_options[@]}" \
    --allow-unsafe \
    --output-file=requirements-tools.txt \
    requirements-tools.in

python -m piptools compile \
    "${compile_options[@]}" \
    --allow-unsafe \
    --output-file=requirements-security.txt \
    requirements-security.in
