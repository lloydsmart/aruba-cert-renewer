from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
validator = importlib.import_module("validate_release_tag")

TAG = "v0.1.0-rc.1"
TAG_OBJECT_SHA = "a" * 40
COMMIT_SHA = "b" * 40


def valid_ref() -> dict[str, object]:
    return {
        "ref": f"refs/tags/{TAG}",
        "object": {"type": "tag", "sha": TAG_OBJECT_SHA},
    }


def valid_tag() -> dict[str, object]:
    return {
        "tag": TAG,
        "sha": TAG_OBJECT_SHA,
        "object": {"type": "commit", "sha": COMMIT_SHA},
        "verification": {"verified": True, "reason": "valid"},
    }


@pytest.mark.parametrize(
    ("tag", "prerelease"),
    [
        ("v0.1.0", False),
        ("v0.1.0-rc.1", True),
        ("v12.34.56", False),
        ("v1.2.3-beta.1", True),
        ("v1.2.3-rc.0", True),
        ("v1.2.3-rc.01", True),
        ("v1.2.3-preview-build", True),
        ("v12.34.56-rc.789", True),
    ],
)
def test_validate_release_version_accepts_supported_syntax(
    tag: str, prerelease: bool
) -> None:
    assert validator.validate_release_version(tag) is prerelease


@pytest.mark.parametrize(
    "tag",
    [
        "0.1.0",
        "v0.1",
        "v01.1.0",
        "v0.1.0+build",
        "v0.1.0/other",
        "v0.1.0-",
        "v0.1.0-rc..1",
    ],
)
def test_validate_release_version_rejects_malformed_versions(tag: str) -> None:
    with pytest.raises(validator.ReleaseTagValidationError):
        validator.validate_release_version(tag)


def test_validate_tag_ref_returns_annotated_tag_object_sha() -> None:
    assert validator.validate_tag_ref(valid_ref(), TAG) == TAG_OBJECT_SHA


def test_validate_tag_ref_rejects_lightweight_tag() -> None:
    document = valid_ref()
    document["object"] = {"type": "commit", "sha": COMMIT_SHA}
    with pytest.raises(validator.ReleaseTagValidationError):
        validator.validate_tag_ref(document, TAG)


def test_validate_tag_object_returns_target_commit() -> None:
    assert validator.validate_tag_object(valid_tag(), TAG, TAG_OBJECT_SHA) == COMMIT_SHA


@pytest.mark.parametrize(
    "verification",
    [
        {"verified": False, "reason": "unsigned"},
        {"verified": False, "reason": "unknown_key"},
        {"verified": True, "reason": "expired_key"},
    ],
)
def test_validate_tag_object_rejects_unverified_or_nonvalid_verification(
    verification: dict[str, object],
) -> None:
    document = valid_tag()
    document["verification"] = verification
    with pytest.raises(validator.ReleaseTagValidationError):
        validator.validate_tag_object(document, TAG, TAG_OBJECT_SHA)


def test_validate_tag_object_rejects_noncommit_target() -> None:
    document = valid_tag()
    document["object"] = {"type": "tree", "sha": COMMIT_SHA}
    with pytest.raises(validator.ReleaseTagValidationError):
        validator.validate_tag_object(document, TAG, TAG_OBJECT_SHA)


def test_validate_tag_object_rejects_mismatched_tag_name() -> None:
    document = valid_tag()
    document["tag"] = "v0.1.0"
    with pytest.raises(validator.ReleaseTagValidationError):
        validator.validate_tag_object(document, TAG, TAG_OBJECT_SHA)


def test_validate_tag_object_rejects_mismatched_object_sha() -> None:
    document = valid_tag()
    document["sha"] = "c" * 40
    with pytest.raises(validator.ReleaseTagValidationError):
        validator.validate_tag_object(document, TAG, TAG_OBJECT_SHA)


def test_cli_validates_synthetic_github_responses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ref_path = tmp_path / "ref.json"
    tag_path = tmp_path / "tag.json"
    ref_path.write_text(json.dumps(valid_ref()), encoding="utf-8")
    tag_path.write_text(json.dumps(valid_tag()), encoding="utf-8")

    assert validator.main(["ref", TAG, str(ref_path)]) == 0
    assert capsys.readouterr().out == f"{TAG_OBJECT_SHA}\n"
    assert validator.main(["tag", TAG, TAG_OBJECT_SHA, str(tag_path)]) == 0
    assert capsys.readouterr().out == f"{COMMIT_SHA}\n"
