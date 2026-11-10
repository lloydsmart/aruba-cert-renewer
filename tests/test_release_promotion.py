from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest
from test_release_candidate import write_classic_archive, write_oci_archive

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
candidate = importlib.import_module("release_candidate")
normalizer = importlib.import_module("normalize_release_archive")
promotion = importlib.import_module("release_promotion").promotion
DIGEST = "sha256:" + "a" * 64


def signed(message: str) -> bytes:
    return (
        "object "
        + "b" * 40
        + "\ntype commit\n\n"
        + message
        + "\n-----BEGIN PGP SIGNATURE-----\nsignature"
    ).encode()


def test_stable_promotion_is_bound_to_same_version_and_exact_digest():
    assert promotion(
        "v0.4.0",
        signed(f"v0.4.0\n\nPromotion-Source: v0.4.0-rc.3\nPromotion-Digest: {DIGEST}"),
    ) == ("v0.4.0-rc.3", DIGEST)


@pytest.mark.parametrize(
    "message",
    [
        "v0.4.0",
        "Promotion-Source: v0.4.0-rc.3",
        f"Promotion-Source: v0.3.0-rc.3\nPromotion-Digest: {DIGEST}",
        f"Promotion-Source: v0.4.0-rc.0\nPromotion-Digest: {DIGEST}",
        f"Promotion-Source: v0.4.0\nPromotion-Digest: {DIGEST}",
        "Promotion-Source: v0.4.0-rc.3\nPromotion-Digest: latest",
        f"Promotion-Source: v0.4.0-rc.3\nPromotion-Digest: {DIGEST}\nPromotion-Digest: {DIGEST}",
        "Promotion-Source: v0.4.0-rc.3\nPromotion-Source: v0.4.0-rc.4",
        f"Promotion-Source: v0.4.0-rc.3\nPromotion-Digest:{DIGEST}",
    ],
)
def test_rejects_missing_ambiguous_or_unbound_promotion(message):
    with pytest.raises(ValueError):
        promotion("v0.4.0", signed(message))


def test_prereleases_cannot_reuse_promotion_metadata():
    assert promotion("v0.4.0-rc.3", signed("v0.4.0-rc.3")) == ("", "")
    with pytest.raises(ValueError):
        promotion("v0.4.0-rc.3", signed(f"Promotion-Digest: {DIGEST}"))


@pytest.mark.parametrize("representation", ["classic", "gzip-oci", "raw-oci"])
def test_normalization_preserves_exact_image_and_publisher_format(
    tmp_path, representation
):
    source, output = tmp_path / "docker-save.tar", tmp_path / "candidate.tar"
    if representation == "classic":
        write_classic_archive(source)
    else:
        write_oci_archive(source, raw_layer=representation == "raw-oci")
    before = candidate.inspect_archive(source, allow_raw_oci=True)
    normalizer.normalize(source, output)
    after = candidate.inspect_archive(output)
    assert after["format"] == "docker-single-image"
    assert after["manifest_digest"] is None
    assert all(
        before[key] == after[key]
        for key in ("config_digest", "layer_diff_ids", "reference")
    )


def test_uncompressed_oci_remains_rejected_at_handoff_boundary(tmp_path):
    source = tmp_path / "archive.tar"
    write_oci_archive(source, raw_layer=True)
    with pytest.raises(candidate.CandidateError, match="layer 0 is inconsistent"):
        candidate.inspect_archive(source)


def test_normalization_rejects_tampered_layer_before_output(tmp_path):
    source, output = tmp_path / "source.tar", tmp_path / "output.tar"
    write_oci_archive(source, raw_layer=True)
    source.write_bytes(
        source.read_bytes().replace(b"candidate layer", b"tampered! layer")
    )
    with pytest.raises(candidate.CandidateError):
        normalizer.normalize(source, output)
    assert not output.exists()


def test_normalization_never_overwrites_an_output(tmp_path):
    source, output = tmp_path / "source.tar", tmp_path / "output.tar"
    write_oci_archive(source, raw_layer=True)
    output.write_text("preserve")
    with pytest.raises(FileExistsError):
        normalizer.normalize(source, output)
    assert output.read_text() == "preserve"


def test_normalized_handoff_passes_independent_publisher(tmp_path, monkeypatch):
    from test_release_publisher import (
        handoff,
        refresh_file_record,
        rewrite_manifest,
        run_step,
        spdx,
    )

    directory, environment = handoff.__wrapped__(tmp_path, monkeypatch)
    source = tmp_path / "raw-oci.tar"
    write_oci_archive(source, raw_layer=True)
    output = tmp_path / "normalized.tar"
    normalizer.normalize(source, output)
    archive = directory / candidate.ARCHIVE_NAME
    archive.write_bytes(output.read_bytes())
    identity = candidate.inspect_archive(archive)
    (directory / candidate.SBOM_NAME).write_text(
        json.dumps(
            spdx(
                identity["syft_manifest_digest"],
                identity["syft_manifest_digest"].removeprefix("sha256:"),
            )
        )
    )
    manifest_path = directory / candidate.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    manifest["archive"].update(identity)
    refresh_file_record(manifest, directory, "archive")
    refresh_file_record(manifest, directory, "sbom")
    rewrite_manifest(manifest_path, manifest)
    result = run_step(
        "Validate candidate handoff independently", environment, Path("/tmp")
    )
    assert result.returncode == 0, result.stderr
