#!/usr/bin/env python3
"""Require every release qualification workflow to confirm complete success."""

from __future__ import annotations

import json
import os
import re
import sys

REQUIRED = frozenset(
    {"actions", "markdown", "python_lint", "python_tests", "security", "container_lint"}
)


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate job result")
        result[key] = value
    return result


def validate(raw: str, source_sha: str) -> None:
    if len(raw.encode()) > 65536 or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("invalid qualification input")
    needs = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(needs, dict) or set(needs) != REQUIRED:
        raise ValueError("missing or unexpected qualification job")
    for job in needs.values():
        if (
            not isinstance(job, dict)
            or set(job) != {"result", "outputs"}
            or job["result"] != "success"
            or job["outputs"] != {"passed": "true"}
        ):
            raise ValueError("every qualification job must explicitly pass")


def main() -> int:
    source_sha = os.environ.get("GITHUB_SHA", "")
    try:
        validate(os.environ.get("QUALIFICATION_NEEDS", ""), source_sha)
    except (ValueError, RecursionError):
        print(
            "Release qualification blocked: incomplete or invalid results.",
            file=sys.stderr,
        )
        return 1
    print("passed=true")
    print(f"source_sha={source_sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
