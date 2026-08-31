#!/usr/bin/env bash

set -euo pipefail

repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

if ! command -v python >/dev/null 2>&1; then
    printf '%s\n' 'Python 3.12 is required but python is not available on PATH.' >&2
    exit 1
fi

python_version=$(python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [[ "$python_version" != '3.12' ]]; then
    printf 'Python 3.12 is required; found Python %s.\n' "$python_version" >&2
    exit 1
fi

pip_audit_version=$(
    python -c 'import importlib.metadata as metadata; print(metadata.version("pip-audit"))' 2>/dev/null || true
)
if [[ "$pip_audit_version" != '2.10.1' ]]; then
    printf '%s\n' 'Dependency scanning requires pip-audit 2.10.1.' >&2
    printf 'Found pip-audit %s.\n' "${pip_audit_version:-not installed}" >&2
    exit 1
fi

locks=(
    requirements.txt
    requirements-dev.txt
    requirements-tools.txt
    requirements-security.txt
)

scan_status=0
for lock in "${locks[@]}"; do
    printf 'Auditing %s\n' "$lock"
    ignore_options=()
    if [[ "$lock" == 'requirements.txt' ]]; then
        # Documented temporary accepted risk; this is not a false positive.
        ignore_options=(--ignore-vuln PYSEC-2026-2858)
    fi
    if ! python -m pip_audit \
        --require-hashes \
        --disable-pip \
        --progress-spinner off \
        "${ignore_options[@]}" \
        -r "$lock"; then
        scan_status=1
    fi
done

exit "$scan_status"
