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
import textwrap
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
PUBLISHER_CANDIDATE_IMAGE = workflow_candidate_image("publish")

SOURCE = "a" * 40
TAG_OBJECT = "b" * 40
CONFIG_ID = "sha256:" + "c" * 64
IMAGE_DIGEST = "d" * 64
LAYER_DIFF_ID = "sha256:" + "a" * 64
SECOND_LAYER_DIFF_ID = "sha256:" + "b" * 64


def workflow_step(name: str) -> str:
    workflow = WORKFLOW.read_text()
    step = workflow.split(f"      - name: {name}\n", 1)[1]
    step = re.split(r"\n(?:      - name:|  [a-z_]+:\n)", step, maxsplit=1)[0]
    return textwrap.dedent(step.split("        run: |\n", 1)[1])


def run_step(
    name: str,
    environment: dict[str, str],
    directory: Path,
    *,
    memory_limit: int | None = None,
):
    def limits() -> None:
        if memory_limit is not None:
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))

    return subprocess.run(
        ["bash", "-c", workflow_step(name)],
        cwd=directory,
        env=environment,
        capture_output=True,
        timeout=20,
        preexec_fn=limits if memory_limit is not None else None,
    )


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


@pytest.fixture
def handoff(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    release_handoff = tmp_path / "release-candidate"
    release_handoff.mkdir()
    archive = release_handoff / candidate.ARCHIVE_NAME
    write_oci_archive(archive)
    identity = candidate.inspect_archive(archive)
    sbom_path = tmp_path / "source-sbom.json"
    sbom_path.write_text(
        json.dumps(
            spdx(
                identity["syft_manifest_digest"],
                identity["syft_manifest_digest"].removeprefix("sha256:"),
            )
        )
    )
    trusted = {
        "GITHUB_REPOSITORY": "lloydsmart/aruba-cert-renewer",
        "GITHUB_REPOSITORY_ID": "123456",
        "GITHUB_RUN_ID": "789012",
        "GITHUB_RUN_ATTEMPT": "3",
        "GITHUB_WORKFLOW_SHA": SOURCE,
        "GITHUB_SHA": SOURCE,
        "GITHUB_WORKFLOW_REF": (
            "lloydsmart/aruba-cert-renewer/.github/workflows/"
            "publish-container.yml@refs/tags/v1.2.3"
        ),
        "RELEASE_ID": "345678",
        "EXPECTED_RELEASE_ID": "345678",
        "RELEASE_TAG": "v1.2.3",
        "SOURCE_SHA": SOURCE,
        "COMMIT_SHA": SOURCE,
        "TAG_OBJECT_SHA": TAG_OBJECT,
        "AUTHORIZED_TAG_OBJECT": TAG_OBJECT,
        "ARTIFACT_NAME": "aruba-cert-renewer-v1.2.3-candidate",
        "CANDIDATE_ARTIFACT_NAME": "aruba-cert-renewer-v1.2.3-candidate",
        "IMAGE_NAME": "ghcr.io/lloydsmart/aruba-cert-renewer",
        "CANDIDATE_IMAGE": PUBLISHER_CANDIDATE_IMAGE,
        "TESTED_CONFIG_DIGEST": identity["config_digest"],
        "GITHUB_ENV": str(tmp_path / "github-env"),
        "IS_GITHUB_PRERELEASE": "false",
        "PUBLISH_LATEST": "true",
        "RUNNER_TEMP": str(tmp_path),
    }
    for name, value in trusted.items():
        monkeypatch.setenv(name, value)
    candidate.create_candidate(release_handoff, sbom_path)
    return release_handoff, {**os.environ, **trusted}


def rewrite_manifest(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(candidate.canonical_json(value))


def refresh_file_record(manifest: dict[str, object], handoff: Path, key: str) -> None:
    path = handoff / manifest[key]["name"]
    manifest[key]["size"] = path.stat().st_size
    manifest[key]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()


def replace_handoff_archive(directory: Path, archive_format: str) -> None:
    archive = directory / candidate.ARCHIVE_NAME
    writer = write_classic_archive if archive_format == "classic" else write_oci_archive
    writer(archive)
    identity = candidate.inspect_archive(archive)
    sbom_path = directory / candidate.SBOM_NAME
    sbom_path.write_text(
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


def test_actual_inline_boundary_accepts_valid_handoff_outside_checkout(handoff) -> None:
    _, environment = handoff
    result = run_step(
        "Validate candidate handoff independently", environment, Path("/tmp")
    )
    assert result.returncode == 0, result.stderr


def test_builder_and_publisher_use_the_same_candidate_reference() -> None:
    expected = "aruba-cert-renewer:release-candidate"
    assert expected == BUILDER_CANDIDATE_IMAGE
    assert expected == PUBLISHER_CANDIDATE_IMAGE
    assert expected == candidate.EXPECTED_CANDIDATE_IMAGE
    workflow = WORKFLOW.read_text()
    verify_job = workflow.split("  verify:\n", 1)[1].split("\n  publish:\n", 1)[0]
    assert 'run: tests/container-smoke.sh "$CANDIDATE_IMAGE"' in verify_job
    assert '"$CANDIDATE_IMAGE"' in workflow_step("Export verified release candidate")
    assert 'docker image inspect "$CANDIDATE_IMAGE"' in workflow_step(
        "Load and inspect validated candidate"
    )
    assert 'docker image tag "$CANDIDATE_IMAGE"' in workflow_step(
        "Promote immutable release aliases"
    )


@pytest.mark.parametrize("archive_format", ["classic", "hybrid"])
def test_actual_inline_accepts_actual_builder_reference(
    handoff, archive_format: str
) -> None:
    directory, environment = handoff
    replace_handoff_archive(directory, archive_format)
    result = run_step(
        "Validate candidate handoff independently", environment, Path("/tmp")
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("archive_format", ["classic", "hybrid"])
@pytest.mark.parametrize(
    "references",
    [
        ["attacker.invalid/image:release-candidate"],
        [BUILDER_CANDIDATE_IMAGE, "attacker.invalid/image:release-candidate"],
    ],
    ids=["wrong", "ambiguous"],
)
def test_actual_inline_boundary_rejects_wrong_or_ambiguous_archive_reference(
    handoff, archive_format: str, references: list[str]
) -> None:
    directory, environment = handoff
    writer = write_classic_archive if archive_format == "classic" else write_oci_archive
    writer(directory / candidate.ARCHIVE_NAME, reference=references)
    manifest_path = directory / candidate.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    refresh_file_record(manifest, directory, "archive")
    rewrite_manifest(manifest_path, manifest)
    result = run_step(
        "Validate candidate handoff independently", environment, Path("/tmp")
    )
    assert result.returncode != 0
    assert b"descriptor is ambiguous" in result.stderr
    publish = WORKFLOW.read_text().split("  publish:\n", 1)[1]
    assert publish.index("Validate candidate handoff independently") < publish.index(
        "Log in to GHCR"
    )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("repository", "attacker/repository"),
        ("repository_id", 999999),
        ("workflow_ref", "attacker/workflow@refs/tags/v1.2.3"),
        ("workflow_sha", "d" * 40),
        ("run_id", 1),
        ("run_attempt", 4),
        ("release_id", 1),
        ("release_tag", "v9.9.9"),
        ("tag_object_sha", "d" * 40),
        ("source_sha", "d" * 40),
        ("github_prerelease", True),
        ("publish_latest", False),
        ("image_name", "ghcr.io/attacker/image"),
        ("archive", {"name": "substituted"}),
    ],
)
def test_actual_inline_boundary_rejects_identity_substitution(
    handoff, key: str, value: object
) -> None:
    directory, environment = handoff
    manifest_path = directory / candidate.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    manifest[key] = value
    rewrite_manifest(manifest_path, manifest)
    result = run_step(
        "Validate candidate handoff independently", environment, Path("/tmp")
    )
    assert result.returncode != 0


@pytest.mark.parametrize(
    "damage",
    ["missing", "unknown", "float", "boolean-id", "noncanonical", "duplicate", "bom"],
)
def test_actual_inline_boundary_rejects_manifest_schema_and_encoding(
    handoff, damage: str
) -> None:
    directory, environment = handoff
    path = directory / candidate.MANIFEST_NAME
    manifest = json.loads(path.read_text())
    if damage == "missing":
        del manifest["source_sha"]
        rewrite_manifest(path, manifest)
    elif damage == "unknown":
        manifest["surprise"] = "x"
        rewrite_manifest(path, manifest)
    elif damage == "float":
        manifest["run_id"] = 1.0
        path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
        )
    elif damage == "boolean-id":
        manifest["run_id"] = True
        rewrite_manifest(path, manifest)
    elif damage == "noncanonical":
        path.write_text(json.dumps(manifest, indent=2) + "\n")
    elif damage == "duplicate":
        raw = candidate.canonical_json(manifest).decode()
        path.write_text(raw.replace('{"archive":', '{"schema_version":1,"archive":', 1))
    else:
        path.write_bytes(b"\xef\xbb\xbf" + candidate.canonical_json(manifest))
    result = run_step(
        "Validate candidate handoff independently", environment, Path("/tmp")
    )
    assert result.returncode != 0


@pytest.mark.parametrize(
    "damage",
    ["archive-size", "archive-hash", "sbom-hash", "sbom-subject", "sbom-relationship"],
)
def test_actual_inline_boundary_rejects_content_mismatch(handoff, damage: str) -> None:
    directory, environment = handoff
    path = directory / candidate.MANIFEST_NAME
    manifest = json.loads(path.read_text())
    if damage == "archive-size":
        manifest["archive"]["size"] += 1
    elif damage == "archive-hash":
        manifest["archive"]["sha256"] = "d" * 64
    elif damage == "sbom-hash":
        manifest["sbom"]["sha256"] = "d" * 64
    else:
        sbom_path = directory / candidate.SBOM_NAME
        document = json.loads(sbom_path.read_text())
        if damage == "sbom-subject":
            document["packages"][0]["versionInfo"] = "sha256:" + "d" * 64
        else:
            document["relationships"] = document["relationships"][:1]
        sbom_path.write_text(json.dumps(document))
        refresh_file_record(manifest, directory, "sbom")
    rewrite_manifest(path, manifest)
    result = run_step(
        "Validate candidate handoff independently", environment, Path("/tmp")
    )
    assert result.returncode != 0


def test_actual_inline_boundary_rejects_wrong_image_syft_identity(
    handoff, tmp_path
) -> None:
    directory, environment = handoff
    binary = tmp_path / "boundary-bin"
    binary.mkdir()
    docker = binary / "docker"
    docker.write_text(FAKE_LOAD_DOCKER)
    docker.chmod(0o755)
    trace = tmp_path / "boundary-trace"
    environment = {
        **environment,
        "PATH": str(binary) + os.pathsep + environment["PATH"],
        "DOCKER_TRACE": str(trace),
    }
    wrong_archive = tmp_path / "wrong-image.tar"
    write_oci_archive(wrong_archive, b"different image layer")
    wrong_identity = candidate.inspect_archive(wrong_archive)
    manifest_path = directory / candidate.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    document = spdx(
        manifest["archive"]["syft_manifest_digest"],
        wrong_identity["syft_manifest_digest"].removeprefix("sha256:"),
    )
    (directory / candidate.SBOM_NAME).write_text(json.dumps(document))
    refresh_file_record(manifest, directory, "sbom")
    rewrite_manifest(manifest_path, manifest)
    result = run_step(
        "Validate candidate handoff independently", environment, Path("/tmp")
    )
    assert result.returncode != 0
    assert b"checksum is not the archive image" in result.stderr
    assert not trace.exists()
    publish = WORKFLOW.read_text().split("  publish:\n", 1)[1]
    assert publish.index("Validate candidate handoff independently") < publish.index(
        "Log in to GHCR"
    )


def test_actual_inline_boundary_rejects_ambiguous_index(handoff) -> None:
    directory, environment = handoff
    write_oci_archive(directory / candidate.ARCHIVE_NAME, duplicate_index=True)
    manifest_path = directory / candidate.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    refresh_file_record(manifest, directory, "archive")
    rewrite_manifest(manifest_path, manifest)
    result = run_step(
        "Validate candidate handoff independently", environment, Path("/tmp")
    )
    assert result.returncode != 0
    assert b"index is ambiguous" in result.stderr


@pytest.mark.parametrize(
    "damage",
    [
        "extra",
        "directory",
        "symlink",
        "hardlink",
        "archive-limit",
        "sbom-limit",
        "manifest-limit",
    ],
)
def test_actual_inline_boundary_rejects_unsafe_inventory_and_limits(
    handoff, damage: str
) -> None:
    directory, environment = handoff
    if damage == "extra":
        (directory / "extra").write_text("x")
    elif damage == "directory":
        (directory / candidate.SBOM_NAME).unlink()
        (directory / candidate.SBOM_NAME).mkdir()
    elif damage == "symlink":
        (directory / candidate.ARCHIVE_NAME).unlink()
        (directory / candidate.ARCHIVE_NAME).symlink_to(directory / candidate.SBOM_NAME)
    elif damage == "hardlink":
        source = directory / candidate.ARCHIVE_NAME
        os.link(source, directory.parent / "second-link")
    elif damage == "archive-limit":
        os.truncate(directory / candidate.ARCHIVE_NAME, candidate.ARCHIVE_MAX_BYTES + 1)
    elif damage == "sbom-limit":
        os.truncate(directory / candidate.SBOM_NAME, candidate.SBOM_MAX_BYTES + 1)
    else:
        os.truncate(
            directory / candidate.MANIFEST_NAME, candidate.MANIFEST_MAX_BYTES + 1
        )
    result = run_step(
        "Validate candidate handoff independently", environment, Path("/tmp")
    )
    assert result.returncode != 0


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
def test_actual_inline_tar_attacks_reject_under_memory_limit(
    handoff, attack: str
) -> None:
    directory, environment = handoff
    archive = directory / candidate.ARCHIVE_NAME
    write_hostile_archive(archive, attack)
    manifest_path = directory / candidate.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    refresh_file_record(manifest, directory, "archive")
    rewrite_manifest(manifest_path, manifest)
    result = run_step(
        "Validate candidate handoff independently",
        environment,
        Path("/tmp"),
        memory_limit=160 * 1024 * 1024,
    )
    assert result.returncode != 0
    assert b"candidate validation failed:" in result.stderr
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
        "xz": b"XZ-compressed archives are unsupported",
        "layer-gzip-header": b"gzip header text exceeds",
        "layer-gzip-concatenated-name": b"concatenated gzip members are unsupported",
        "layer-gzip-concatenated-comment": b"concatenated gzip members are unsupported",
    }.get(attack)
    if expected_boundary is not None:
        assert expected_boundary in result.stderr


def test_actual_inline_accepts_bounded_outer_gzip_archive(handoff) -> None:
    directory, environment = handoff
    archive = directory / candidate.ARCHIVE_NAME
    plain = directory.parent / "plain.tar"
    archive.replace(plain)
    with (
        plain.open("rb") as source,
        archive.open("wb") as raw_output,
        gzip.GzipFile(
            fileobj=raw_output, mode="wb", compresslevel=1, mtime=0
        ) as output,
    ):
        while chunk := source.read(64 * 1024):
            output.write(chunk)
    manifest_path = directory / candidate.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    refresh_file_record(manifest, directory, "archive")
    rewrite_manifest(manifest_path, manifest)
    result = run_step(
        "Validate candidate handoff independently", environment, Path("/tmp")
    )
    assert result.returncode == 0, result.stderr


def test_actual_inline_accepts_bounded_pax_metadata(handoff) -> None:
    directory, environment = handoff
    archive = directory / candidate.ARCHIVE_NAME
    write_classic_archive(archive, pax_metadata=True)
    identity = candidate.inspect_archive(archive)
    sbom_path = directory / candidate.SBOM_NAME
    sbom_path.write_text(
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


def test_actual_inline_accepts_bounded_solaris_pax_metadata(handoff) -> None:
    directory, environment = handoff
    archive = directory / candidate.ARCHIVE_NAME
    write_classic_archive(archive)
    prefix_tar_extension(archive, b"X", pax_record("comment", "bounded"))
    identity = candidate.inspect_archive(archive)
    sbom_path = directory / candidate.SBOM_NAME
    sbom_path.write_text(
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


FAKE_LOAD_DOCKER = r"""#!/usr/bin/env python3
import json
import os
import sys
import tarfile
from pathlib import Path

args = sys.argv[1:]
with Path(os.environ["DOCKER_TRACE"]).open("a") as trace:
    trace.write(" ".join(args) + "\n")
if args[:2] == ["image", "load"]:
    archive_path = Path(args[args.index("--input") + 1])
    with tarfile.open(archive_path, "r:*") as archive:
        manifest = json.load(archive.extractfile("manifest.json"))
    tags = manifest[0]["RepoTags"]
    Path(os.environ["LOADED_TAGS_FILE"]).write_text(json.dumps(tags))
    sys.exit(0)
if args[:2] == ["image", "inspect"]:
    reference = args[-1]
    tags_path = Path(os.environ["LOADED_TAGS_FILE"])
    tags = json.loads(tags_path.read_text()) if tags_path.exists() else []
    if reference not in tags:
        print("No such image: " + reference, file=sys.stderr)
        sys.exit(1)
    if "--format" not in args:
        print("{}")
        sys.exit(0)
    formatting = args[args.index("--format") + 1]
    if formatting == "{{.Id}}":
        print(os.environ.get("LOADED_IMAGE_ID", os.environ["TESTED_CONFIG_DIGEST"]))
    elif "org.opencontainers.image.source" in formatting:
        print(os.environ.get("SOURCE_LABEL", "https://github.com/lloydsmart/aruba-cert-renewer"))
    elif "org.opencontainers.image.licenses" in formatting:
        print(os.environ.get("LICENSE_LABEL", "GPL-3.0-only"))
    elif "net.unraid.docker.icon" in formatting:
        print(os.environ.get("ICON_LABEL", "https://raw.githubusercontent.com/lloydsmart/aruba-cert-renewer/" + os.environ["COMMIT_SHA"] + "/assets/icon.png"))
    else:
        sys.exit(97)
else:
    sys.exit(98)
"""


@pytest.mark.parametrize("archive_format", ["classic", "hybrid"])
@pytest.mark.parametrize(
    ("publisher_reference", "expected_success"),
    [
        (PUBLISHER_CANDIDATE_IMAGE, True),
        ("local/aruba-cert-renewer:release-candidate", False),
    ],
    ids=["corrected", "reviewed-mismatch"],
)
def test_manifest_backed_load_uses_only_the_archived_builder_reference(
    handoff,
    tmp_path: Path,
    archive_format: str,
    publisher_reference: str,
    expected_success: bool,
) -> None:
    directory, environment = handoff
    writer = write_classic_archive if archive_format == "classic" else write_oci_archive
    writer(directory / candidate.ARCHIVE_NAME)
    binary = tmp_path / "load-reference-bin"
    binary.mkdir()
    docker = binary / "docker"
    docker.write_text(FAKE_LOAD_DOCKER)
    docker.chmod(0o755)
    loaded_tags = tmp_path / "loaded-reference-tags.json"
    assert not loaded_tags.exists()
    environment = {
        **environment,
        "PATH": str(binary) + os.pathsep + environment["PATH"],
        "CANDIDATE_IMAGE": publisher_reference,
        "DOCKER_TRACE": str(tmp_path / "load-reference-trace"),
        "LOADED_TAGS_FILE": str(loaded_tags),
    }
    result = run_step("Load and inspect validated candidate", environment, Path("/tmp"))
    assert (result.returncode == 0) == expected_success, result.stderr
    assert json.loads(loaded_tags.read_text()) == [BUILDER_CANDIDATE_IMAGE]
    trace = (tmp_path / "load-reference-trace").read_text()
    commands = {
        tuple(line.split(maxsplit=2)[:2]) for line in trace.splitlines() if line
    }
    assert commands
    assert commands <= {("image", "load"), ("image", "inspect")}


@pytest.mark.parametrize("damage", ["none", "source", "license", "icon"])
def test_loaded_image_identity_is_checked_before_login(
    handoff, tmp_path: Path, damage: str
) -> None:
    _, environment = handoff
    binary = tmp_path / "load-bin"
    binary.mkdir()
    docker = binary / "docker"
    docker.write_text(FAKE_LOAD_DOCKER)
    docker.chmod(0o755)
    environment = {
        **environment,
        "PATH": str(binary) + os.pathsep + environment["PATH"],
        "DOCKER_TRACE": str(tmp_path / "load-trace"),
        "LOADED_TAGS_FILE": str(tmp_path / "loaded-tags.json"),
    }
    changed = {
        "source": ("SOURCE_LABEL", "https://example.invalid/repository"),
        "license": ("LICENSE_LABEL", "UNKNOWN"),
        "icon": ("ICON_LABEL", "https://example.invalid/icon.png"),
    }.get(damage)
    if changed:
        environment[changed[0]] = changed[1]
    result = run_step("Load and inspect validated candidate", environment, Path("/tmp"))
    assert (result.returncode == 0) == (damage == "none"), result.stderr
    trace = (tmp_path / "load-trace").read_text()
    commands = {
        tuple(line.split(maxsplit=2)[:2]) for line in trace.splitlines() if line
    }
    assert commands
    assert commands <= {("image", "load"), ("image", "inspect")}


FAKE_DOCKER = r"""#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
state_path = Path(os.environ["REGISTRY_STATE"])
trace_path = Path(os.environ["DOCKER_TRACE"])
state = json.loads(state_path.read_text())
with trace_path.open("a") as trace:
    trace.write(" ".join(args) + "\n")

if args[:3] == ["buildx", "imagetools", "inspect"]:
    reference = args[3]
    if "@sha256:" in reference:
        digest = reference.rsplit("@", 1)[1]
        state["raw_count"] = state.get("raw_count", 0) + 1
        state_path.write_text(json.dumps(state))
        if state.get("fail_raw_at") == state["raw_count"]:
            print("synthetic raw-manifest failure", file=sys.stderr)
            sys.exit(1)
        override = state.get("raw_overrides", {}).get(digest)
        if override is not None:
            sys.stdout.write(override)
            sys.exit(0)
        config_digest = state.get("config_digests", {}).get(
            digest, os.environ["TESTED_CONFIG_DIGEST"]
        )
        manifest = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": config_digest,
                    "size": 123,
                },
                "layers": [{
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:" + "f" * 64,
                    "size": 456,
                }],
            },
            separators=(",", ":"),
        )
        if "--raw" in args:
            sys.stdout.write(manifest)
        else:
            print("Name: synthetic")
        sys.exit(0)
    digest = state["aliases"].get(reference)
    if digest is None:
        stdout_diagnostic = state.get("diagnostic_stdout", {}).get(reference)
        if stdout_diagnostic is not None:
            print(stdout_diagnostic)
        diagnostic = state.get("diagnostics", {}).get(
            reference, f"ERROR: {reference}: manifest unknown"
        )
        print(diagnostic, file=sys.stderr)
        sys.exit(1)
    print("Name: synthetic")
    print("Digest: " + digest)
elif args[0] == "pull":
    digest = args[1].rsplit("@", 1)[1]
    if state.get("pull_failures", {}).get(digest):
        print(state["pull_failures"][digest], file=sys.stderr)
        sys.exit(1)
elif args[:2] == ["image", "inspect"]:
    if "--format" in args:
        digest = args[-1].rsplit("@", 1)[-1]
        requested_format = args[args.index("--format") + 1]
        if requested_format == "{{.Id}}":
            print(state.get("pulled_config_digests", {}).get(
                digest, os.environ["TESTED_CONFIG_DIGEST"]
            ))
        elif requested_format == "{{json .RootFS.Layers}}":
            failure = state.get("rootfs_inspect_failures", {}).get(digest)
            if failure:
                print(failure, file=sys.stderr)
                sys.exit(1)
            override = state.get("rootfs_inspect_outputs", {}).get(digest)
            if override is not None:
                print(override)
            else:
                layers = state.get("pulled_rootfs_diff_ids", {}).get(
                    digest, json.loads(os.environ["CANDIDATE_LAYER_DIFF_IDS"])
                )
                print(json.dumps(layers, separators=(",", ":")))
        else:
            print("unexpected image inspect format: " + requested_format, file=sys.stderr)
            sys.exit(97)
    else:
        print("{}")
elif args[:2] == ["image", "tag"]:
    pass
elif args[0] == "push":
    state["aliases"][args[1]] = state["push_digest"]
elif args[:3] == ["buildx", "imagetools", "create"]:
    destination = args[args.index("--tag") + 1]
    source = args[-1]
    state["aliases"][destination] = source.rsplit("@", 1)[1]
    if state.get("fail_create") == destination:
        state_path.write_text(json.dumps(state))
        print("synthetic copy failure after possible mutation", file=sys.stderr)
        sys.exit(1)
else:
    print("unexpected docker invocation: " + repr(args), file=sys.stderr)
    sys.exit(97)
state_path.write_text(json.dumps(state))
"""


def registry_digest(config_digest: str = CONFIG_ID) -> str:
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": 123,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:" + "f" * 64,
                    "size": 456,
                }
            ],
        },
        separators=(",", ":"),
    ).encode()
    return "sha256:" + hashlib.sha256(manifest).hexdigest()


def registry_environment(tmp_path: Path, aliases: dict[str, str]):
    binary = tmp_path / "bin"
    binary.mkdir()
    docker = binary / "docker"
    docker.write_text(FAKE_DOCKER)
    docker.chmod(0o755)
    digest = registry_digest()
    state_path = tmp_path / "registry.json"
    state_path.write_text(
        json.dumps({"aliases": aliases, "push_digest": digest, "config_digests": {}})
    )
    output = tmp_path / "output"
    environment = {
        **os.environ,
        "PATH": str(binary) + os.pathsep + os.environ["PATH"],
        "REGISTRY_STATE": str(state_path),
        "DOCKER_TRACE": str(tmp_path / "docker-trace"),
        "GITHUB_OUTPUT": str(output),
        "RUNNER_TEMP": str(tmp_path),
        "IMAGE_NAME": "ghcr.io/lloydsmart/aruba-cert-renewer",
        "RELEASE_TAG": "v1.2.3",
        "COMMIT_SHA": SOURCE,
        "TESTED_CONFIG_DIGEST": CONFIG_ID,
        "ARCHIVE_MANIFEST_DIGEST": "",
        "CANDIDATE_LAYER_DIFF_IDS": json.dumps([LAYER_DIFF_ID]),
        "CANDIDATE_IMAGE": PUBLISHER_CANDIDATE_IMAGE,
    }
    return environment, state_path, digest, output


@pytest.mark.parametrize("archive_format", ["classic", "hybrid"])
@pytest.mark.parametrize("existing", ["none", "both", "version", "source"])
def test_immutable_alias_matrix_and_exact_digest_copy(
    tmp_path: Path, existing: str, archive_format: str
) -> None:
    image = "ghcr.io/lloydsmart/aruba-cert-renewer"
    version = f"{image}:v1.2.3"
    source = f"{image}:sha-{SOURCE}"
    digest = registry_digest()
    aliases = {}
    if existing in {"both", "version"}:
        aliases[version] = digest
    if existing in {"both", "source"}:
        aliases[source] = digest
    environment, state_path, _, output = registry_environment(tmp_path, aliases)
    if archive_format == "hybrid":
        environment["ARCHIVE_MANIFEST_DIGEST"] = digest
    result = run_step("Promote immutable release aliases", environment, Path("/tmp"))
    assert result.returncode == 0, result.stderr
    state = json.loads(state_path.read_text())
    assert state["aliases"] == {version: digest, source: digest}
    trace = (tmp_path / "docker-trace").read_text()
    if existing == "none":
        assert f"push {version}" in trace
        assert f"--tag {source} {image}@{digest}" in trace
    elif existing == "both":
        assert " push " not in f" {trace}"
        assert "imagetools create" not in trace
    elif existing == "version":
        assert f"--tag {source} {image}@{digest}" in trace
        assert f"--tag {version}" not in trace
    else:
        assert f"--tag {version} {image}@{digest}" in trace
        assert f"--tag {source}" not in trace
    expected_origins = {
        "none": ("published", "published"),
        "both": ("reused", "reused"),
        "version": ("reused", "published"),
        "source": ("published", "reused"),
    }
    version_origin, source_origin = expected_origins[existing]
    assert output.read_text() == (
        f"digest={digest}\n"
        f"version_origin={version_origin}\n"
        f"source_origin={source_origin}\n"
    )


def test_existing_alias_digest_conflict_fails_without_mutation(tmp_path: Path) -> None:
    image = "ghcr.io/lloydsmart/aruba-cert-renewer"
    aliases = {
        f"{image}:v1.2.3": registry_digest(),
        f"{image}:sha-{SOURCE}": "sha256:" + "e" * 64,
    }
    environment, state_path, _, _ = registry_environment(tmp_path, aliases)
    result = run_step("Promote immutable release aliases", environment, Path("/tmp"))
    assert result.returncode != 0
    assert json.loads(state_path.read_text())["aliases"] == aliases
    trace = (tmp_path / "docker-trace").read_text()
    assert " push " not in f" {trace}"
    assert "imagetools create" not in trace


def test_existing_same_digest_wrong_config_fails_without_mutation(
    tmp_path: Path,
) -> None:
    image = "ghcr.io/lloydsmart/aruba-cert-renewer"
    digest = registry_digest()
    aliases = {
        f"{image}:v1.2.3": digest,
        f"{image}:sha-{SOURCE}": digest,
    }
    environment, state_path, _, _ = registry_environment(tmp_path, aliases)
    state = json.loads(state_path.read_text())
    state["config_digests"][digest] = "sha256:" + "e" * 64
    state_path.write_text(json.dumps(state))
    result = run_step("Promote immutable release aliases", environment, Path("/tmp"))
    assert result.returncode != 0
    assert json.loads(state_path.read_text())["aliases"] == aliases
    trace = (tmp_path / "docker-trace").read_text()
    assert " push " not in f" {trace}"
    assert "imagetools create" not in trace


@pytest.mark.parametrize(
    "failure",
    [
        "candidate config does not match the downloaded layer",
        "registry blob is missing",
        "registry blob digest is corrupt",
    ],
)
def test_classic_registry_content_failure_blocks_alias_copy_and_attestation(
    tmp_path: Path, failure: str
) -> None:
    image = "ghcr.io/lloydsmart/aruba-cert-renewer"
    version = f"{image}:v1.2.3"
    digest = registry_digest()
    environment, state_path, _, output = registry_environment(
        tmp_path, {version: digest}
    )
    state = json.loads(state_path.read_text())
    state["pull_failures"] = {digest: failure}
    state_path.write_text(json.dumps(state))
    result = run_step("Promote immutable release aliases", environment, Path("/tmp"))
    assert result.returncode != 0
    assert json.loads(state_path.read_text())["aliases"] == {version: digest}
    trace = (tmp_path / "docker-trace").read_text()
    assert f"pull {image}@{digest}" in trace
    assert "imagetools create" not in trace
    assert not output.exists()


def test_same_config_with_unrelated_rootfs_blocks_alias_copy_and_attestation(
    tmp_path: Path,
) -> None:
    image = "ghcr.io/lloydsmart/aruba-cert-renewer"
    version = f"{image}:v1.2.3"
    digest = registry_digest()
    environment, state_path, _, output = registry_environment(
        tmp_path, {version: digest}
    )
    state = json.loads(state_path.read_text())
    state["pulled_rootfs_diff_ids"] = {digest: ["sha256:" + "e" * 64]}
    state_path.write_text(json.dumps(state))

    result = run_step("Promote immutable release aliases", environment, Path("/tmp"))

    assert result.returncode != 0
    assert json.loads(state_path.read_text())["aliases"] == {version: digest}
    trace = (tmp_path / "docker-trace").read_text()
    assert f"pull {image}@{digest}" in trace
    assert (
        f"image inspect --format {{{{json .RootFS.Layers}}}} {image}@{digest}" in trace
    )
    assert "imagetools create" not in trace
    assert not output.exists()
    assert b"ordered layer diff IDs do not match" in result.stderr


def test_registry_rootfs_layer_order_must_match_candidate(tmp_path: Path) -> None:
    image = "ghcr.io/lloydsmart/aruba-cert-renewer"
    version = f"{image}:v1.2.3"
    raw = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": CONFIG_ID,
                "size": 123,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:" + "e" * 64,
                    "size": 456,
                },
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:" + "f" * 64,
                    "size": 789,
                },
            ],
        },
        separators=(",", ":"),
    )
    digest = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
    environment, state_path, _, _ = registry_environment(tmp_path, {version: digest})
    environment["CANDIDATE_LAYER_DIFF_IDS"] = json.dumps(
        [LAYER_DIFF_ID, SECOND_LAYER_DIFF_ID]
    )
    state = json.loads(state_path.read_text())
    state["raw_overrides"] = {digest: raw}
    state["pulled_rootfs_diff_ids"] = {
        digest: [SECOND_LAYER_DIFF_ID, LAYER_DIFF_ID],
    }
    state_path.write_text(json.dumps(state))

    result = run_step("Promote immutable release aliases", environment, Path("/tmp"))

    assert result.returncode != 0
    assert json.loads(state_path.read_text())["aliases"] == {version: digest}
    assert "imagetools create" not in (tmp_path / "docker-trace").read_text()
    assert b"ordered layer diff IDs do not match" in result.stderr


@pytest.mark.parametrize("failure", ["command", "malformed"])
def test_registry_rootfs_inspection_failure_is_ambiguous_and_blocks_copy(
    tmp_path: Path, failure: str
) -> None:
    image = "ghcr.io/lloydsmart/aruba-cert-renewer"
    version = f"{image}:v1.2.3"
    digest = registry_digest()
    environment, state_path, _, _ = registry_environment(tmp_path, {version: digest})
    state = json.loads(state_path.read_text())
    if failure == "command":
        state["rootfs_inspect_failures"] = {digest: "synthetic inspect failure"}
    else:
        state["rootfs_inspect_outputs"] = {digest: "not-json"}
    state_path.write_text(json.dumps(state))

    result = run_step("Promote immutable release aliases", environment, Path("/tmp"))

    assert result.returncode != 0
    assert json.loads(state_path.read_text())["aliases"] == {version: digest}
    assert "imagetools create" not in (tmp_path / "docker-trace").read_text()


def test_registry_layer_count_mismatch_fails_before_pull_or_alias_copy(
    tmp_path: Path,
) -> None:
    image = "ghcr.io/lloydsmart/aruba-cert-renewer"
    version = f"{image}:v1.2.3"
    raw = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": CONFIG_ID,
                "size": 123,
            },
            "layers": [],
        },
        separators=(",", ":"),
    )
    digest = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
    environment, state_path, _, _ = registry_environment(tmp_path, {version: digest})
    state = json.loads(state_path.read_text())
    state["raw_overrides"] = {digest: raw}
    state_path.write_text(json.dumps(state))
    result = run_step("Promote immutable release aliases", environment, Path("/tmp"))
    assert result.returncode != 0
    trace = (tmp_path / "docker-trace").read_text()
    assert " pull " not in f" {trace}"
    assert "imagetools create" not in trace


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",
        (
            '{"schemaVersion":2,'
            '"mediaType":"application/vnd.oci.image.manifest.v1+json",'
            '"config":{"digest":"sha256:'
            + "e" * 64
            + '"},"config":{"digest":"'
            + CONFIG_ID
            + '"},"layers":[{"digest":"sha256:'
            + "f" * 64
            + '"}]}'
        ),
        json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [],
            },
            separators=(",", ":"),
        ),
    ],
)
def test_malformed_or_index_registry_manifest_fails_without_mutation(
    tmp_path: Path, raw: str
) -> None:
    image = "ghcr.io/lloydsmart/aruba-cert-renewer"
    digest = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
    aliases = {
        f"{image}:v1.2.3": digest,
        f"{image}:sha-{SOURCE}": digest,
    }
    environment, state_path, _, _ = registry_environment(tmp_path, aliases)
    state = json.loads(state_path.read_text())
    state["raw_overrides"] = {digest: raw}
    state_path.write_text(json.dumps(state))
    result = run_step("Promote immutable release aliases", environment, Path("/tmp"))
    assert result.returncode != 0
    assert json.loads(state_path.read_text())["aliases"] == aliases
    trace = (tmp_path / "docker-trace").read_text()
    assert " push " not in f" {trace}"
    assert "imagetools create" not in trace
    assert b"No mutation attempted by this run" in result.stderr


def test_changed_same_source_rebuild_fails_without_filling_version(
    tmp_path: Path,
) -> None:
    image = "ghcr.io/lloydsmart/aruba-cert-renewer"
    source = f"{image}:sha-{SOURCE}"
    digest = registry_digest()
    environment, state_path, _, _ = registry_environment(tmp_path, {source: digest})
    state = json.loads(state_path.read_text())
    state["config_digests"][digest] = "sha256:" + "e" * 64
    state_path.write_text(json.dumps(state))
    result = run_step("Promote immutable release aliases", environment, Path("/tmp"))
    assert result.returncode != 0
    assert json.loads(state_path.read_text())["aliases"] == {source: digest}
    assert b"No mutation attempted by this run" in result.stderr


def test_failed_postpush_identity_check_reports_confirmed_partial_state(
    tmp_path: Path,
) -> None:
    image = "ghcr.io/lloydsmart/aruba-cert-renewer"
    version = f"{image}:v1.2.3"
    environment, state_path, digest, _ = registry_environment(tmp_path, {})
    state = json.loads(state_path.read_text())
    state["config_digests"][digest] = "sha256:" + "e" * 64
    state_path.write_text(json.dumps(state))
    result = run_step("Promote immutable release aliases", environment, Path("/tmp"))
    assert result.returncode != 0
    assert json.loads(state_path.read_text())["aliases"] == {version: digest}
    assert b"Confirmed version alias publication by this run" in result.stderr
    assert b"No aliases were changed" not in result.stderr


def test_failed_postpush_rootfs_check_reports_confirmed_partial_state(
    tmp_path: Path,
) -> None:
    image = "ghcr.io/lloydsmart/aruba-cert-renewer"
    version = f"{image}:v1.2.3"
    source = f"{image}:sha-{SOURCE}"
    environment, state_path, digest, output = registry_environment(tmp_path, {})
    state = json.loads(state_path.read_text())
    state["pulled_rootfs_diff_ids"] = {digest: ["sha256:" + "e" * 64]}
    state_path.write_text(json.dumps(state))

    result = run_step("Promote immutable release aliases", environment, Path("/tmp"))

    assert result.returncode != 0
    assert json.loads(state_path.read_text())["aliases"] == {version: digest}
    trace = (tmp_path / "docker-trace").read_text()
    assert f"--tag {source}" not in trace
    assert not output.exists()
    assert b"Confirmed version alias publication by this run" in result.stderr
    assert b"source alias remains incomplete" in result.stderr


def test_failed_copy_reports_uncertain_remote_outcome_without_rollback(
    tmp_path: Path,
) -> None:
    image = "ghcr.io/lloydsmart/aruba-cert-renewer"
    version = f"{image}:v1.2.3"
    source = f"{image}:sha-{SOURCE}"
    digest = registry_digest()
    environment, state_path, _, _ = registry_environment(tmp_path, {version: digest})
    state = json.loads(state_path.read_text())
    state["fail_create"] = source
    state_path.write_text(json.dumps(state))
    result = run_step("Promote immutable release aliases", environment, Path("/tmp"))
    assert result.returncode != 0
    assert json.loads(state_path.read_text())["aliases"] == {
        version: digest,
        source: digest,
    }
    assert b"Mutation attempted" in result.stderr
    assert b"outcome of source alias" in result.stderr
    assert b"No aliases were changed" not in result.stderr


def test_final_identity_failure_reports_confirmed_aliases(
    tmp_path: Path,
) -> None:
    image = "ghcr.io/lloydsmart/aruba-cert-renewer"
    version = f"{image}:v1.2.3"
    source = f"{image}:sha-{SOURCE}"
    digest = registry_digest()
    environment, state_path, _, _ = registry_environment(tmp_path, {version: digest})
    state = json.loads(state_path.read_text())
    state["fail_raw_at"] = 2
    state_path.write_text(json.dumps(state))
    result = run_step("Promote immutable release aliases", environment, Path("/tmp"))
    assert result.returncode != 0
    assert json.loads(state_path.read_text())["aliases"] == {
        version: digest,
        source: digest,
    }
    assert b"Confirmed immutable aliases" in result.stderr
    assert b"outcome of source alias" not in result.stderr
    assert b"No aliases were changed" not in result.stderr


@pytest.mark.parametrize(
    "diagnostic",
    [
        "ERROR: credential helper not found",
        "ERROR: unauthorized",
        "ERROR: denied",
        "ERROR: transport timeout",
        "ERROR: TLS handshake failed",
        "ERROR: registry returned 429",
        "ERROR: registry returned 500",
        "ERROR: 404 Not Found",
        "manifest unknown",
        "ERROR: manifest unknown\nERROR: unauthorized",
    ],
)
def test_ambiguous_absence_fails_closed_before_mutation(
    tmp_path: Path, diagnostic: str
) -> None:
    image = "ghcr.io/lloydsmart/aruba-cert-renewer"
    version = f"{image}:v1.2.3"
    environment, state_path, _, _ = registry_environment(tmp_path, {})
    state = json.loads(state_path.read_text())
    state["diagnostics"] = {version: diagnostic}
    state_path.write_text(json.dumps(state))
    result = run_step("Promote immutable release aliases", environment, Path("/tmp"))
    assert result.returncode != 0
    assert json.loads(state_path.read_text())["aliases"] == {}
    assert b"ambiguous" in result.stderr
    trace = (tmp_path / "docker-trace").read_text()
    assert " push " not in f" {trace}"
    assert "imagetools create" not in trace
    assert b"No mutation attempted by this run" in result.stderr


def test_contradictory_absence_stdout_fails_closed_before_mutation(
    tmp_path: Path,
) -> None:
    image = "ghcr.io/lloydsmart/aruba-cert-renewer"
    version = f"{image}:v1.2.3"
    environment, state_path, digest, _ = registry_environment(tmp_path, {})
    state = json.loads(state_path.read_text())
    state["diagnostic_stdout"] = {version: f"Digest: {digest}"}
    state["diagnostics"] = {version: f"ERROR: {version}: manifest unknown"}
    state_path.write_text(json.dumps(state))
    result = run_step("Promote immutable release aliases", environment, Path("/tmp"))
    assert result.returncode != 0
    assert json.loads(state_path.read_text())["aliases"] == {}
    assert b"ambiguous" in result.stderr
    trace = (tmp_path / "docker-trace").read_text()
    assert " push " not in f" {trace}"
    assert "imagetools create" not in trace
    assert b"No mutation attempted by this run" in result.stderr


def test_latest_is_a_final_exact_digest_copy_after_both_attestations() -> None:
    workflow = WORKFLOW.read_text()
    publish = workflow.split("  publish:\n", 1)[1]
    immutable = publish.index("Promote immutable release aliases")
    provenance = publish.index("Attest build provenance")
    sbom = publish.index("Attest release SBOM")
    incomplete = publish.index("Report incomplete immutable publication")
    latest = publish.index("Promote eligible latest alias last")
    logout = publish.index("Log out of GHCR")
    assert immutable < provenance < sbom < incomplete < latest < logout
    assert "id: provenance_attestation" in publish
    assert "id: sbom_attestation" in publish
    assert "failure() && steps.published.outcome == 'success'" in publish
    latest_step = workflow_step("Promote eligible latest alias last")
    assert "success() && env.PUBLISH_LATEST == 'true'" in publish
    assert '"$IMAGE_NAME@$SELECTED_DIGEST"' in latest_step
    assert "--prefer-index=false" in latest_step
    assert "latest_digest" in latest_step
    assert "consumer" not in publish.lower()
