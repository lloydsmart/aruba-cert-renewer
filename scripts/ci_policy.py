#!/usr/bin/env python3
"""Fail-closed PR relevance and aggregate-result policy; standard library only."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

MAX_INPUT = 8 * 1024 * 1024
REQUIRED_JOBS = (
    "changes",
    "actions",
    "markdown",
    "python_lint",
    "python_tests",
    "security",
)
DOC_FILES = frozenset({"README.md", "CONTRIBUTING.md", "CHANGELOG.md"})


class PolicyError(ValueError):
    """Inputs do not prove that all required work succeeded."""


def containers_required(changes: bytes) -> bool:
    """Consume git diff --no-renames --name-status -z, including deleted paths."""
    if len(changes) > MAX_INPUT:
        raise PolicyError("changed-path input exceeds the limit")
    if not changes:
        return True  # An empty diff is not evidence of a documentation-only PR.
    if not changes.endswith(b"\0"):
        raise PolicyError("changed-path input is not NUL terminated")
    fields = changes[:-1].split(b"\0")
    if len(fields) % 2 or len(fields) > 20000:
        raise PolicyError("invalid changed-path record count")
    required = False
    for status, raw_path in zip(fields[::2], fields[1::2], strict=True):
        if status not in (b"A", b"M", b"D", b"T", b"U", b"X", b"B"):
            raise PolicyError("unexpected change status; rename detection must be off")
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError as error:
            raise PolicyError("changed path is not UTF-8") from error
        if (
            not path
            or len(raw_path) > 4096
            or path.startswith("/")
            or any(part in ("", ".", "..") for part in path.split("/"))
            or any(ord(char) < 32 or ord(char) == 127 for char in path)
        ):
            raise PolicyError("invalid changed path")
        documentation = path in DOC_FILES or (
            path.startswith("docs/") and path.endswith(".md")
        )
        if status not in (b"A", b"M") or not documentation:
            required = True
    return required


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("duplicate result key")
        result[key] = value
    return result


def validate_gate(raw: str) -> None:
    if len(raw.encode("utf-8")) > MAX_INPUT:
        raise PolicyError("job results exceed the limit")
    try:
        needs = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, RecursionError) as error:
        raise PolicyError("invalid job-result JSON") from error
    if not isinstance(needs, dict) or set(needs) != {*REQUIRED_JOBS, "deployment"}:
        raise PolicyError("missing or unexpected required jobs")
    for name, job in needs.items():
        if (
            not isinstance(job, dict)
            or set(job) != {"result", "outputs"}
            or not isinstance(job["outputs"], dict)
        ):
            raise PolicyError(f"invalid job record: {name}")
    for name in REQUIRED_JOBS:
        if needs[name]["result"] != "success":
            raise PolicyError(f"required job did not succeed: {name}")
        # Reusable workflows explicitly confirm every required internal job.
        if name != "changes" and needs[name]["outputs"].get("passed") != "true":
            raise PolicyError(f"internal checks did not all succeed: {name}")
    relevant = needs["changes"]["outputs"].get("containers")
    deployment = needs["deployment"]
    if relevant == "true":
        if (
            deployment["result"] != "success"
            or deployment["outputs"].get("passed") != "true"
        ):
            raise PolicyError("required container validation did not succeed")
    elif relevant == "false":
        if deployment["result"] != "skipped" or deployment["outputs"]:
            raise PolicyError("unexpected result for inapplicable container validation")
    else:
        raise PolicyError("invalid container relevance output")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    changes = commands.add_parser("changes")
    changes.add_argument("path", type=Path)
    commands.add_parser("gate")
    args = parser.parse_args(argv)
    try:
        if args.command == "changes":
            with args.path.open("rb") as source:
                required = containers_required(source.read(MAX_INPUT + 1))
            print(f"containers={str(required).lower()}")
        else:
            validate_gate(os.environ.get("CI_NEEDS", ""))
            print("Every required CI check passed.")
    except (PolicyError, OSError) as error:
        # Do not echo untrusted paths, result values, or file content to logs.
        detail = (
            str(error) if isinstance(error, PolicyError) else "unreadable policy input"
        )
        print(f"CI policy blocked: {detail}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
