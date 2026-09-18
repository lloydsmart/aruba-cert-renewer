#!/usr/bin/env python3
"""Validate GitHub release-tag metadata before publication."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 1024 * 1024
RELEASE_TAG_PATTERN = re.compile(
    r"v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
)
SHA_PATTERN = re.compile(r"[0-9a-f]{40}")


class ReleaseTagValidationError(ValueError):
    """Raised when release-tag metadata is unsafe or inconsistent."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseTagValidationError("JSON contains a duplicate object key")
        result[key] = value
    return result


def load_json_object(path: Path, description: str) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ReleaseTagValidationError(f"{description} is not readable") from error
    if size == 0:
        raise ReleaseTagValidationError(f"{description} is empty")
    if size > MAX_INPUT_BYTES:
        raise ReleaseTagValidationError(f"{description} exceeds the size limit")
    try:
        with path.open(encoding="utf-8") as input_file:
            document = json.load(input_file, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseTagValidationError(
            f"{description} is not valid UTF-8 JSON"
        ) from error
    if not isinstance(document, dict):
        raise ReleaseTagValidationError(f"{description} must be a JSON object")
    return document


def validate_release_version(tag_name: str) -> bool:
    """Validate the existing Aruba release syntax and return prerelease state."""
    if not RELEASE_TAG_PATTERN.fullmatch(tag_name):
        raise ReleaseTagValidationError("release tag has unsupported syntax")
    return "-" in tag_name


def _required_object(container: dict[str, Any], key: str) -> dict[str, Any]:
    value = container.get(key)
    if not isinstance(value, dict):
        raise ReleaseTagValidationError(f"{key} must be an object")
    return value


def _required_sha(value: Any, description: str) -> str:
    if not isinstance(value, str) or not SHA_PATTERN.fullmatch(value):
        raise ReleaseTagValidationError(f"{description} must be a full commit SHA")
    return value


def validate_tag_ref(ref_document: dict[str, Any], expected_tag: str) -> str:
    """Require an exact tag ref whose target is an annotated tag object."""
    validate_release_version(expected_tag)
    if ref_document.get("ref") != f"refs/tags/{expected_tag}":
        raise ReleaseTagValidationError("Git tag ref name does not match the release")
    target = _required_object(ref_document, "object")
    if target.get("type") != "tag":
        raise ReleaseTagValidationError(
            "release ref does not point to an annotated tag"
        )
    return _required_sha(target.get("sha"), "annotated tag object SHA")


def validate_tag_object(
    tag_document: dict[str, Any], expected_tag: str, expected_tag_sha: str
) -> str:
    """Require a verified signed annotated tag that directly targets a commit."""
    validate_release_version(expected_tag)
    expected_tag_sha = _required_sha(expected_tag_sha, "expected tag object SHA")
    if tag_document.get("tag") != expected_tag:
        raise ReleaseTagValidationError(
            "annotated tag object name does not match the release"
        )
    if tag_document.get("sha") != expected_tag_sha:
        raise ReleaseTagValidationError(
            "annotated tag object SHA does not match the tag ref"
        )

    target = _required_object(tag_document, "object")
    if target.get("type") != "commit":
        raise ReleaseTagValidationError(
            "annotated release tag does not point directly to a commit"
        )

    verification = _required_object(tag_document, "verification")
    if verification.get("verified") is not True:
        raise ReleaseTagValidationError("annotated release tag is not verified")
    if verification.get("reason") != "valid":
        raise ReleaseTagValidationError(
            "annotated release tag verification reason is not valid"
        )
    return _required_sha(target.get("sha"), "release commit SHA")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    version_parser = subparsers.add_parser("version")
    version_parser.add_argument("tag")

    ref_parser = subparsers.add_parser("ref")
    ref_parser.add_argument("tag")
    ref_parser.add_argument("ref_json", type=Path)

    tag_parser = subparsers.add_parser("tag")
    tag_parser.add_argument("tag")
    tag_parser.add_argument("tag_object_sha")
    tag_parser.add_argument("tag_json", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    try:
        if arguments.command == "version":
            result = "true" if validate_release_version(arguments.tag) else "false"
        elif arguments.command == "ref":
            result = validate_tag_ref(
                load_json_object(arguments.ref_json, "Git tag ref response"),
                arguments.tag,
            )
        else:
            result = validate_tag_object(
                load_json_object(arguments.tag_json, "annotated tag response"),
                arguments.tag,
                arguments.tag_object_sha,
            )
    except ReleaseTagValidationError as error:
        print(f"Release tag validation failed: {error}", file=sys.stderr)
        return 1

    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
