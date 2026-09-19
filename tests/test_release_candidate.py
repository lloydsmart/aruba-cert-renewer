from __future__ import annotations

import gzip
import hashlib
import importlib
import io
import json
import lzma
import os
import re
import resource
import subprocess
import sys
import tarfile
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/publish-container.yml"
sys.path.insert(0, str(ROOT / "scripts"))
candidate = importlib.import_module("release_candidate")


def workflow_candidate_image(job: str) -> str:
    block = WORKFLOW.read_text().split(f"  {job}:\n", 1)[1]
    block = re.split(r"\n  [a-z_]+:\n", block, maxsplit=1)[0]
    return re.search(r"^      CANDIDATE_IMAGE: ([^\n]+)$", block, re.MULTILINE).group(1)


BUILDER_CANDIDATE_IMAGE = workflow_candidate_image("verify")

SOURCE = "a" * 40
TAG_OBJECT = "b" * 40
CONFIG_ID = "sha256:" + "c" * 64
IMAGE_DIGEST = "d" * 64


def spdx(
    config_id: str = CONFIG_ID, image_digest: str = IMAGE_DIGEST
) -> dict[str, object]:
    digest = config_id.removeprefix("sha256:")
    root = "SPDXRef-DocumentRoot-Image-" + digest[:12]
    package = "SPDXRef-Package-python"
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "aruba-cert-renewer:release-candidate",
        "documentNamespace": "https://anchore.com/syft/image/test",
        "creationInfo": {"creators": ["Tool: syft-1.51.1"]},
        "packages": [
            {
                "SPDXID": root,
                "name": "aruba-cert-renewer",
                "primaryPackagePurpose": "CONTAINER",
                "versionInfo": config_id,
                "checksums": [{"algorithm": "SHA256", "checksumValue": image_digest}],
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": (
                            "pkg:oci/aruba-cert-renewer@sha256%3A"
                            f"{image_digest}"
                            "?arch=amd64&tag=release-candidate"
                        ),
                    }
                ],
            },
            {"SPDXID": package, "name": "python"},
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": root,
            },
            {
                "spdxElementId": root,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": package,
            },
        ],
    }


def write_classic_archive(
    path: Path,
    marker: bytes = b"candidate layer",
    *,
    reference: str | list[str] = BUILDER_CANDIDATE_IMAGE,
    pax_metadata: bool = False,
) -> None:
    repo_tags = [reference] if isinstance(reference, str) else reference
    layer_digest = hashlib.sha256(marker).hexdigest()
    layer_path = f"{layer_digest}/layer.tar"
    config = json.dumps(
        {"rootfs": {"type": "layers", "diff_ids": [f"sha256:{layer_digest}"]}},
        separators=(",", ":"),
    ).encode()
    config_path = hashlib.sha256(config).hexdigest() + ".json"
    manifest = json.dumps(
        [
            {
                "Config": config_path,
                "RepoTags": repo_tags,
                "Layers": [layer_path],
            }
        ],
        separators=(",", ":"),
    ).encode()
    with tarfile.open(path, "w") as archive:
        for name, raw in (
            (config_path, config),
            (layer_path, marker),
            ("manifest.json", manifest),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            if pax_metadata:
                info.pax_headers = {"comment": "bounded release candidate"}
            archive.addfile(info, io.BytesIO(raw))


def write_oci_archive(
    path: Path,
    marker: bytes = b"candidate layer",
    *,
    compressed_layer: bytes | None = None,
    duplicate_index: bool = False,
    reference: str | list[str] = BUILDER_CANDIDATE_IMAGE,
) -> None:
    repo_tags = [reference] if isinstance(reference, str) else reference
    compressed = (
        gzip.compress(marker, mtime=0) if compressed_layer is None else compressed_layer
    )
    diff_id = "sha256:" + hashlib.sha256(marker).hexdigest()
    layer_digest = "sha256:" + hashlib.sha256(compressed).hexdigest()
    config = json.dumps(
        {"rootfs": {"type": "layers", "diff_ids": [diff_id]}},
        separators=(",", ":"),
    ).encode()
    config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
    image_manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": layer_digest,
                    "size": len(compressed),
                }
            ],
        },
        separators=(",", ":"),
    ).encode()
    manifest_digest = "sha256:" + hashlib.sha256(image_manifest).hexdigest()
    descriptor = {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": manifest_digest,
        "size": len(image_manifest),
    }
    index = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [descriptor, descriptor] if duplicate_index else [descriptor],
        },
        separators=(",", ":"),
    ).encode()
    docker_manifest = json.dumps(
        [
            {
                "Config": "blobs/sha256/" + config_digest.removeprefix("sha256:"),
                "RepoTags": repo_tags,
                "Layers": ["blobs/sha256/" + layer_digest.removeprefix("sha256:")],
            }
        ],
        separators=(",", ":"),
    ).encode()
    files = {
        "blobs/sha256/" + config_digest.removeprefix("sha256:"): config,
        "blobs/sha256/" + layer_digest.removeprefix("sha256:"): compressed,
        "blobs/sha256/" + manifest_digest.removeprefix("sha256:"): image_manifest,
        "index.json": index,
        "manifest.json": docker_manifest,
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
    }
    with tarfile.open(path, "w") as archive:
        for name, raw in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))


def pax_record(key: str, value: str) -> bytes:
    payload = f" {key}={value}\n".encode()
    length = len(payload) + 1
    while True:
        record = str(length).encode() + payload
        if len(record) == length:
            return record
        length = len(record)


def prefix_tar_extension(path: Path, kind: bytes, raw: bytes) -> None:
    archive = path.read_bytes()
    info = tarfile.TarInfo("././@PaxHeader")
    info.type = kind
    info.size = len(raw)
    path.write_bytes(
        info.tobuf(format=tarfile.USTAR_FORMAT)
        + raw
        + bytes((-len(raw)) % 512)
        + archive
    )


def gzip_member_with_header_text(flag: int, size: int) -> bytes:
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    payload = compressor.compress(b"") + compressor.flush()
    return (
        b"\x1f\x8b\x08"
        + bytes([flag])
        + bytes(6)
        + b"a" * size
        + b"\0"
        + payload
        + bytes(8)
    )


def write_hostile_archive(path: Path, attack: str) -> None:
    if attack in {"pax", "compressed-pax"}:
        size = 256 * 1024 * 1024 if attack == "compressed-pax" else 128 * 1024
        info = tarfile.TarInfo("././@PaxHeader")
        info.type = tarfile.XHDTYPE
        info.size = size
        header = info.tobuf(format=tarfile.USTAR_FORMAT)
        if attack == "compressed-pax":
            with (
                path.open("wb") as raw_output,
                gzip.GzipFile(
                    fileobj=raw_output, mode="wb", compresslevel=1, mtime=0
                ) as output,
            ):
                output.write(header)
                block = bytes(1024 * 1024)
                for _ in range(size // len(block)):
                    output.write(block)
                output.write(bytes(1024))
        else:
            path.write_bytes(header + bytes(size) + bytes((-size) % 512 + 1024))
    elif attack in {
        "extensions",
        "extension-total",
        "pax-numeric",
        "pax-global-records",
    }:
        with path.open("wb") as output:
            if attack in {"extensions", "extension-total"}:
                info = tarfile.TarInfo("././@PaxHeader")
                info.type = tarfile.XHDTYPE
                if attack == "extensions":
                    for _ in range(candidate.TAR_CONSECUTIVE_EXTENSION_MAX + 1):
                        output.write(info.tobuf(format=tarfile.USTAR_FORMAT))
                else:
                    extensions = 0
                    position = 0
                    while extensions < candidate.TAR_EXTENSION_COUNT_MAX:
                        for _ in range(candidate.TAR_CONSECUTIVE_EXTENSION_MAX):
                            output.write(info.tobuf(format=tarfile.USTAR_FORMAT))
                            extensions += 1
                        output.write(
                            tarfile.TarInfo(f"member-{position}").tobuf(
                                format=tarfile.USTAR_FORMAT
                            )
                        )
                        position += 1
                    output.write(info.tobuf(format=tarfile.USTAR_FORMAT))
            else:
                if attack == "pax-numeric":
                    raw = b"9" * 5000 + b" malformed=value\n"
                else:
                    raw = b"".join(
                        pax_record(f"candidate.key.{position}", "x")
                        for position in range(candidate.TAR_PAX_GLOBAL_RECORD_MAX + 1)
                    )
                info = tarfile.TarInfo("././@PaxHeader")
                info.type = tarfile.XGLTYPE
                info.size = len(raw)
                output.write(info.tobuf(format=tarfile.USTAR_FORMAT))
                output.write(raw)
                output.write(bytes((-len(raw)) % 512))
            output.write(bytes(1024))
    elif attack in {"pax-record-total", "solaris-pax-record-total"}:
        with path.open("wb") as output:
            records = 0
            position = 0
            while records < candidate.TAR_PAX_RECORD_MAX:
                batch_size = min(64, candidate.TAR_PAX_RECORD_MAX - records)
                raw = b"".join(
                    pax_record(f"candidate.key.{records + offset}", "x")
                    for offset in range(batch_size)
                )
                info = tarfile.TarInfo("././@PaxHeader")
                info.type = (
                    b"X" if attack == "solaris-pax-record-total" else tarfile.XHDTYPE
                )
                info.size = len(raw)
                output.write(info.tobuf(format=tarfile.USTAR_FORMAT))
                output.write(raw)
                output.write(bytes((-len(raw)) % 512))
                output.write(
                    tarfile.TarInfo(f"member-{position}").tobuf(
                        format=tarfile.USTAR_FORMAT
                    )
                )
                records += batch_size
                position += 1
            raw = pax_record("candidate.extra", "x")
            info = tarfile.TarInfo("././@PaxHeader")
            info.type = (
                b"X" if attack == "solaris-pax-record-total" else tarfile.XHDTYPE
            )
            info.size = len(raw)
            output.write(info.tobuf(format=tarfile.USTAR_FORMAT))
            output.write(raw)
            output.write(bytes((-len(raw)) % 512 + 1024))
    elif attack == "metadata":
        with tarfile.open(path, "w") as archive:
            raw = bytes(candidate.ARCHIVE_METADATA_MAX_BYTES + 1)
            info = tarfile.TarInfo("manifest.json")
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    elif attack == "members":
        with path.open("wb") as output:
            for position in range(candidate.ARCHIVE_MEMBER_MAX + 1):
                output.write(
                    tarfile.TarInfo(f"member-{position}").tobuf(
                        format=tarfile.USTAR_FORMAT
                    )
                )
            output.write(bytes(1024))
    elif attack == "truncated":
        path.write_bytes(bytes(511))
    elif attack == "trailing":
        path.write_bytes(bytes(1024 + candidate.TAR_TRAILING_MAX_BYTES + 1))
    elif attack == "compressed-trailing":
        path.write_bytes(
            gzip.compress(bytes(1024 + candidate.TAR_TRAILING_MAX_BYTES + 1), mtime=0)
        )
    elif attack == "gzip-header":
        path.write_bytes(
            b"\x1f\x8b\x08\x08"
            + bytes(6)
            + b"a" * (candidate.GZIP_HEADER_TEXT_MAX_BYTES + 1)
        )
    elif attack in {"gzip-concatenated-name", "gzip-concatenated-comment"}:
        write_classic_archive(path)
        plain = path.read_bytes()
        flag = 0x08 if attack.endswith("name") else 0x10
        path.write_bytes(
            gzip.compress(plain, mtime=0)
            + gzip_member_with_header_text(
                flag, candidate.GZIP_HEADER_TEXT_MAX_BYTES + 1
            )
        )
    elif attack == "solaris-pax-oversized":
        write_classic_archive(path)
        prefix_tar_extension(
            path,
            b"X",
            pax_record("comment", "a" * candidate.TAR_EXTENSION_MAX_BYTES),
        )
    elif attack == "solaris-pax-sparse":
        write_classic_archive(path)
        prefix_tar_extension(path, b"X", pax_record("GNU.sparse.size", "1"))
    elif attack == "sparse":
        info = tarfile.TarInfo("sparse-layer")
        info.type = tarfile.GNUTYPE_SPARSE
        path.write_bytes(info.tobuf(format=tarfile.GNU_FORMAT) + bytes(1024))
    elif attack == "layers":
        manifest = json.dumps(
            [
                {
                    "Config": "0" * 64 + ".json",
                    "RepoTags": [BUILDER_CANDIDATE_IMAGE],
                    "Layers": [
                        f"{position:064x}/layer.tar"
                        for position in range(candidate.ARCHIVE_LAYER_MAX + 1)
                    ],
                }
            ],
            separators=(",", ":"),
        ).encode()
        with tarfile.open(path, "w") as archive:
            info = tarfile.TarInfo("manifest.json")
            info.size = len(manifest)
            archive.addfile(info, io.BytesIO(manifest))
    elif attack == "json-integer":
        manifest = b'[{"Config":' + b"9" * 5000 + b"}]"
        with tarfile.open(path, "w") as archive:
            info = tarfile.TarInfo("manifest.json")
            info.size = len(manifest)
            archive.addfile(info, io.BytesIO(manifest))
    elif attack == "xz":
        path.write_bytes(lzma.compress(bytes(1024)))
    elif attack == "layer-gzip-header":
        write_oci_archive(
            path,
            compressed_layer=(
                b"\x1f\x8b\x08\x08"
                + bytes(6)
                + b"a" * (candidate.GZIP_HEADER_TEXT_MAX_BYTES + 1)
            ),
        )
    elif attack in {
        "layer-gzip-concatenated-name",
        "layer-gzip-concatenated-comment",
    }:
        marker = b"candidate layer"
        flag = 0x08 if attack.endswith("name") else 0x10
        write_oci_archive(
            path,
            marker,
            compressed_layer=(
                gzip.compress(marker, mtime=0)
                + gzip_member_with_header_text(
                    flag, candidate.GZIP_HEADER_TEXT_MAX_BYTES + 1
                )
            ),
        )
    else:
        header = bytearray(
            tarfile.TarInfo("manifest.json").tobuf(format=tarfile.USTAR_FORMAT)
        )
        header[0] ^= 1
        path.write_bytes(header + bytes(1024))


def run_bounded_producer_parser(path: Path) -> subprocess.CompletedProcess[bytes]:
    code = """
import sys
sys.path.insert(0, sys.argv[1])
import release_candidate
try:
    release_candidate.inspect_archive(release_candidate.Path(sys.argv[2]))
except release_candidate.CandidateError as error:
    print(f"controlled rejection: {error}", file=sys.stderr)
    raise SystemExit(1)
"""

    def limits() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (160 * 1024 * 1024, 160 * 1024 * 1024))

    return subprocess.run(
        [sys.executable, "-I", "-c", code, str(ROOT / "scripts"), str(path)],
        capture_output=True,
        timeout=15,
        preexec_fn=limits,
    )


@pytest.fixture
def candidate_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    handoff = tmp_path / "handoff"
    handoff.mkdir()
    archive = handoff / candidate.ARCHIVE_NAME
    write_oci_archive(archive)
    identity = candidate.inspect_archive(archive)
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(
        json.dumps(
            spdx(
                identity["syft_manifest_digest"],
                identity["syft_manifest_digest"].removeprefix("sha256:"),
            )
        )
    )
    environment = {
        "GITHUB_REPOSITORY": "lloydsmart/aruba-cert-renewer",
        "GITHUB_REPOSITORY_ID": "123456",
        "GITHUB_RUN_ID": "789012",
        "GITHUB_RUN_ATTEMPT": "3",
        "GITHUB_WORKFLOW_SHA": SOURCE,
        "GITHUB_WORKFLOW_REF": (
            "lloydsmart/aruba-cert-renewer/.github/workflows/"
            "publish-container.yml@refs/tags/v1.2.3"
        ),
        "RELEASE_ID": "345678",
        "RELEASE_TAG": "v1.2.3",
        "SOURCE_SHA": SOURCE,
        "TAG_OBJECT_SHA": TAG_OBJECT,
        "ARTIFACT_NAME": "aruba-cert-renewer-v1.2.3-candidate",
        "IMAGE_NAME": "ghcr.io/lloydsmart/aruba-cert-renewer",
        "IS_GITHUB_PRERELEASE": "false",
        "PUBLISH_LATEST": "true",
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    return handoff, sbom_path, identity


def test_creates_exact_canonical_handoff(candidate_inputs) -> None:
    handoff, sbom_path, identity = candidate_inputs
    manifest = candidate.create_candidate(handoff, sbom_path)
    assert {path.name for path in handoff.iterdir()} == {
        "candidate-manifest.json",
        "release-candidate.tar",
        "release-sbom.spdx.json",
    }
    raw = (handoff / "candidate-manifest.json").read_bytes()
    assert raw == candidate.canonical_json(manifest)
    assert manifest["schema_version"] == 2
    assert manifest["repository_id"] == 123456
    assert manifest["run_attempt"] == 3
    assert manifest["archive"]["config_digest"] == identity["config_digest"]
    assert (
        manifest["archive"]["syft_manifest_digest"] == identity["syft_manifest_digest"]
    )
    assert (
        len(
            {
                identity["config_digest"],
                identity["manifest_digest"],
                identity["index_digest"],
                identity["syft_manifest_digest"],
            }
        )
        == 4
    )
    assert len(manifest["archive"]["sha256"]) == 64


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("GITHUB_REPOSITORY", "attacker/repository"),
        ("GITHUB_REPOSITORY_ID", "true"),
        ("GITHUB_REPOSITORY_ID", str(candidate.MAX_SAFE_INTEGER + 1)),
        ("GITHUB_RUN_ID", "0"),
        ("GITHUB_RUN_ATTEMPT", "1.0"),
        ("GITHUB_WORKFLOW_SHA", "d" * 40),
        ("GITHUB_WORKFLOW_REF", "attacker/workflow@refs/tags/v1.2.3"),
        ("RELEASE_ID", "-1"),
        ("RELEASE_TAG", "v1.2.3+build"),
        ("SOURCE_SHA", "main"),
        ("TAG_OBJECT_SHA", "e" * 39),
        ("ARTIFACT_NAME", "prior-run-candidate"),
        ("IMAGE_NAME", "ghcr.io/attacker/image"),
        ("IS_GITHUB_PRERELEASE", "False"),
        ("PUBLISH_LATEST", "false"),
    ],
)
def test_rejects_untrusted_identity(
    candidate_inputs, monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    handoff, sbom_path, _ = candidate_inputs
    monkeypatch.setenv(name, value)
    with pytest.raises(candidate.CandidateError):
        candidate.create_candidate(handoff, sbom_path)


@pytest.mark.parametrize("damage", ["version", "checksum", "purl", "relationship"])
def test_rejects_wrong_sbom_subject(candidate_inputs, damage: str) -> None:
    handoff, sbom_path, identity = candidate_inputs
    document = spdx(
        identity["syft_manifest_digest"],
        identity["syft_manifest_digest"].removeprefix("sha256:"),
    )
    root = document["packages"][0]
    if damage == "version":
        root["versionInfo"] = "sha256:" + "d" * 64
    elif damage == "checksum":
        root["checksums"][0]["checksumValue"] = "e" * 64
    elif damage == "purl":
        root["externalRefs"][0]["referenceLocator"] = (
            f"pkg:oci/another-image@{CONFIG_ID}?arch=amd64&tag=release-candidate"
        )
    else:
        document["relationships"] = document["relationships"][:1]
    sbom_path.write_text(json.dumps(document))
    with pytest.raises(candidate.CandidateError):
        candidate.create_candidate(handoff, sbom_path)


def test_rejects_realistic_wrong_image_sbom_with_matching_version_override(
    candidate_inputs, tmp_path: Path
) -> None:
    handoff, sbom_path, identity = candidate_inputs
    wrong_archive = tmp_path / "wrong-image.tar"
    write_oci_archive(wrong_archive, b"different image layer")
    wrong_identity = candidate.inspect_archive(wrong_archive)
    assert wrong_identity["config_digest"] != identity["config_digest"]
    sbom_path.write_text(
        json.dumps(
            spdx(
                identity["syft_manifest_digest"],
                wrong_identity["syft_manifest_digest"].removeprefix("sha256:"),
            )
        )
    )
    with pytest.raises(candidate.CandidateError, match="checksum"):
        candidate.create_candidate(handoff, sbom_path)


def test_rejects_ambiguous_multi_descriptor_index(tmp_path: Path) -> None:
    archive = tmp_path / "ambiguous.tar"
    write_oci_archive(archive, duplicate_index=True)
    with pytest.raises(candidate.CandidateError, match="index is ambiguous"):
        candidate.inspect_archive(archive)


@pytest.mark.parametrize("archive_format", ["classic", "hybrid"])
def test_accepts_archive_saved_under_actual_builder_reference(
    tmp_path: Path, archive_format: str
) -> None:
    archive = tmp_path / "candidate-reference.tar"
    writer = write_classic_archive if archive_format == "classic" else write_oci_archive
    writer(archive)
    identity = candidate.inspect_archive(archive)
    assert identity["reference"] == BUILDER_CANDIDATE_IMAGE
    assert candidate.EXPECTED_CANDIDATE_IMAGE == BUILDER_CANDIDATE_IMAGE


@pytest.mark.parametrize("archive_format", ["classic", "hybrid"])
@pytest.mark.parametrize(
    "references",
    [
        ["attacker.invalid/image:release-candidate"],
        [BUILDER_CANDIDATE_IMAGE, "attacker.invalid/image:release-candidate"],
    ],
    ids=["wrong", "ambiguous"],
)
def test_rejects_wrong_or_ambiguous_archive_reference(
    tmp_path: Path, archive_format: str, references: list[str]
) -> None:
    archive = tmp_path / "wrong-reference.tar"
    writer = write_classic_archive if archive_format == "classic" else write_oci_archive
    writer(archive, reference=references)
    with pytest.raises(candidate.CandidateError, match="ambiguous"):
        candidate.inspect_archive(archive)


def test_rejects_duplicate_json_key_and_bom(candidate_inputs) -> None:
    handoff, sbom_path, _ = candidate_inputs
    sbom_path.write_bytes(b'{"spdxVersion":"SPDX-2.3","spdxVersion":"SPDX-2.3"}')
    with pytest.raises(candidate.CandidateError, match="duplicate JSON key"):
        candidate.create_candidate(handoff, sbom_path)
    sbom_path.write_bytes(b"\xef\xbb\xbf{}")
    with pytest.raises(candidate.CandidateError, match="BOM"):
        candidate.create_candidate(handoff, sbom_path)


def test_rejects_unexpected_and_unsafe_inventory(candidate_inputs) -> None:
    handoff, sbom_path, _ = candidate_inputs
    (handoff / "unexpected").write_text("x")
    with pytest.raises(candidate.CandidateError, match="only the archive"):
        candidate.create_candidate(handoff, sbom_path)
    (handoff / "unexpected").unlink()
    archive = handoff / candidate.ARCHIVE_NAME
    archive.unlink()
    archive.symlink_to(sbom_path)
    with pytest.raises(candidate.CandidateError, match="regular"):
        candidate.create_candidate(handoff, sbom_path)


def test_rejects_sparse_files_over_bounds(candidate_inputs) -> None:
    handoff, sbom_path, _ = candidate_inputs
    archive = handoff / candidate.ARCHIVE_NAME
    os.truncate(archive, candidate.ARCHIVE_MAX_BYTES + 1)
    with pytest.raises(candidate.CandidateError, match="bound"):
        candidate.create_candidate(handoff, sbom_path)


@pytest.mark.parametrize(
    "attack",
    [
        "pax",
        "compressed-pax",
        "extensions",
        "extension-total",
        "pax-numeric",
        "pax-global-records",
        "pax-record-total",
        "solaris-pax-oversized",
        "solaris-pax-record-total",
        "solaris-pax-sparse",
        "metadata",
        "members",
        "layers",
        "json-integer",
        "trailing",
        "compressed-trailing",
        "gzip-header",
        "gzip-concatenated-name",
        "gzip-concatenated-comment",
        "sparse",
        "xz",
        "layer-gzip-header",
        "layer-gzip-concatenated-name",
        "layer-gzip-concatenated-comment",
        "truncated",
        "checksum",
    ],
)
def test_tar_attacks_are_rejected_under_memory_limit(
    tmp_path: Path, attack: str
) -> None:
    archive = tmp_path / f"{attack}.tar"
    write_hostile_archive(archive, attack)
    result = run_bounded_producer_parser(archive)
    assert result.returncode != 0
    assert b"controlled rejection:" in result.stderr
    assert b"MemoryError" not in result.stderr
    expected_boundary = {
        "extensions": b"consecutive tar extensions",
        "extension-total": b"tar extension count",
        "pax-numeric": b"malformed PAX metadata",
        "pax-global-records": b"global PAX record count",
        "pax-record-total": b"PAX record count",
        "solaris-pax-oversized": b"tar extension exceeds",
        "solaris-pax-record-total": b"PAX record count",
        "solaris-pax-sparse": b"ambiguous PAX metadata",
        "layers": b"layer count exceeds",
        "json-integer": b"JSON integer exceeds",
        "trailing": b"trailing padding",
        "compressed-trailing": b"trailing padding",
        "gzip-header": b"gzip header text exceeds",
        "gzip-concatenated-name": b"concatenated gzip members are unsupported",
        "gzip-concatenated-comment": b"concatenated gzip members are unsupported",
        "sparse": b"unsupported sparse metadata",
        "xz": b"XZ-compressed candidate archives are unsupported",
        "layer-gzip-header": b"gzip header text exceeds",
        "layer-gzip-concatenated-name": b"concatenated gzip members are unsupported",
        "layer-gzip-concatenated-comment": b"concatenated gzip members are unsupported",
    }.get(attack)
    if expected_boundary is not None:
        assert expected_boundary in result.stderr


def test_accepts_bounded_outer_gzip_archive(tmp_path: Path) -> None:
    plain = tmp_path / "plain.tar"
    compressed = tmp_path / "compressed.tar.gz"
    write_classic_archive(plain)
    with (
        plain.open("rb") as source,
        compressed.open("wb") as raw_output,
        gzip.GzipFile(
            fileobj=raw_output, mode="wb", compresslevel=1, mtime=0
        ) as output,
    ):
        while chunk := source.read(64 * 1024):
            output.write(chunk)
    assert candidate.inspect_archive(compressed) == candidate.inspect_archive(plain)


def test_accepts_bounded_pax_metadata(tmp_path: Path) -> None:
    plain = tmp_path / "plain.tar"
    with_pax = tmp_path / "pax.tar"
    write_classic_archive(plain)
    write_classic_archive(with_pax, pax_metadata=True)
    assert candidate.inspect_archive(with_pax) == candidate.inspect_archive(plain)


def test_accepts_bounded_solaris_pax_metadata(tmp_path: Path) -> None:
    plain = tmp_path / "plain.tar"
    with_pax = tmp_path / "solaris-pax.tar"
    write_classic_archive(plain)
    write_classic_archive(with_pax)
    prefix_tar_extension(with_pax, b"X", pax_record("comment", "bounded"))
    assert candidate.inspect_archive(with_pax) == candidate.inspect_archive(plain)
