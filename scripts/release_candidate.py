#!/usr/bin/env python3
"""Create the bounded release-candidate handoff manifest.

This helper runs only in the unprivileged build job.  The publisher performs
its own validation from fixed workflow code and must never import this module.
"""

from __future__ import annotations

import bz2
import gzip
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
import zlib
from contextlib import ExitStack
from pathlib import Path
from urllib.parse import parse_qs, unquote

MANIFEST_NAME = "candidate-manifest.json"
ARCHIVE_NAME = "release-candidate.tar"
SBOM_NAME = "release-sbom.spdx.json"
MANIFEST_MAX_BYTES = 32 * 1024
SBOM_MAX_BYTES = 64 * 1024 * 1024
ARCHIVE_MAX_BYTES = 1024 * 1024 * 1024
ARCHIVE_MEMBER_MAX = 1024
ARCHIVE_METADATA_MAX_BYTES = 4 * 1024 * 1024
ARCHIVE_LAYER_MAX = 128
TAR_EXTENSION_MAX_BYTES = 64 * 1024
TAR_EXTENSIONS_TOTAL_MAX_BYTES = 256 * 1024
TAR_EXTENSION_COUNT_MAX = 2 * ARCHIVE_MEMBER_MAX
TAR_CONSECUTIVE_EXTENSION_MAX = 4
TAR_PAX_RECORD_MAX = 4 * ARCHIVE_MEMBER_MAX
TAR_PAX_GLOBAL_RECORD_MAX = 64
TAR_TRAILING_MAX_BYTES = 1024 * 1024
GZIP_HEADER_TEXT_MAX_BYTES = 64 * 1024
UNCOMPRESSED_LAYERS_MAX_BYTES = 4 * ARCHIVE_MAX_BYTES
IDENTITY_MAX_BYTES = 512
RELEASE_TAG_MAX_BYTES = 128
MAX_SAFE_INTEGER = 9_007_199_254_740_991
EXPECTED_REPOSITORY = "lloydsmart/aruba-cert-renewer"
EXPECTED_IMAGE_NAME = "ghcr.io/lloydsmart/aruba-cert-renewer"
EXPECTED_SBOM_NAME = "aruba-cert-renewer"
EXPECTED_CANDIDATE_IMAGE = "aruba-cert-renewer:release-candidate"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
TAG_RE = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$"
)
OCI_MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
OCI_CONFIG_MEDIA_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
GZIP_LAYER_MEDIA_TYPES = {
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}


class CandidateError(ValueError):
    """The candidate handoff is malformed or inconsistent."""


def _reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _json_integer(value: str) -> int:
    digits = value.removeprefix("-")
    if len(digits) > len(str(MAX_SAFE_INTEGER)):
        raise CandidateError("JSON integer exceeds the safe-integer bound")
    number = int(value)
    if abs(number) > MAX_SAFE_INTEGER:
        raise CandidateError("JSON integer exceeds the safe-integer bound")
    return number


def _read_json(path: Path, maximum: int) -> tuple[dict[str, object], bytes]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise CandidateError(f"cannot inspect {path.name}: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise CandidateError(f"{path.name} must be one regular, unlinked file")
    if info.st_size <= 0 or info.st_size > maximum:
        raise CandidateError(f"{path.name} size is outside its allowed bound")
    raw = path.read_bytes()
    if len(raw) != info.st_size:
        raise CandidateError(f"{path.name} changed while it was read")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise CandidateError(f"{path.name} must not contain a UTF-8 BOM")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CandidateError(f"{path.name} is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate,
            parse_int=_json_integer,
            parse_float=lambda value: (_ for _ in ()).throw(
                CandidateError(f"JSON floating point is not permitted: {value}")
            ),
            parse_constant=lambda value: (_ for _ in ()).throw(
                CandidateError(f"JSON constant is not permitted: {value}")
            ),
        )
    except (json.JSONDecodeError, CandidateError, RecursionError) as exc:
        raise CandidateError(f"invalid {path.name}: {exc}") from exc
    if type(value) is not dict:
        raise CandidateError(f"{path.name} must contain one JSON object")
    return value, raw


def _bounded_string(value: object, name: str, maximum: int = IDENTITY_MAX_BYTES) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise CandidateError(f"{name} must be a non-empty bounded string")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise CandidateError(f"{name} must not contain control characters")
    return value


def _positive_integer(value: str, name: str) -> int:
    if len(value) > len(str(MAX_SAFE_INTEGER)) or not re.fullmatch(
        r"[1-9][0-9]*", value
    ):
        raise CandidateError(f"{name} must be a positive decimal integer")
    number = int(value)
    if number > MAX_SAFE_INTEGER:
        raise CandidateError(f"{name} exceeds the JSON safe-integer bound")
    return number


def _boolean(value: str, name: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise CandidateError(f"{name} must be true or false")


def _regular_file(path: Path, maximum: int) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise CandidateError(f"cannot inspect {path.name}: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise CandidateError(f"{path.name} must be one regular, unlinked file")
    if info.st_size <= 0 or info.st_size > maximum:
        raise CandidateError(f"{path.name} size is outside its allowed bound")
    return info


def _sha256(path: Path, expected_size: int) -> str:
    digest = hashlib.sha256()
    consumed = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            consumed += len(chunk)
            if consumed > expected_size:
                raise CandidateError(f"{path.name} grew while it was hashed")
            digest.update(chunk)
    if consumed != expected_size:
        raise CandidateError(f"{path.name} changed while it was hashed")
    return digest.hexdigest()


def _json_value(raw: bytes, name: str, expected_type: type) -> object:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise CandidateError(f"{name} must not contain a UTF-8 BOM")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate,
            parse_int=_json_integer,
            parse_float=lambda number: (_ for _ in ()).throw(
                CandidateError(f"JSON floating point is not permitted: {number}")
            ),
            parse_constant=lambda constant: (_ for _ in ()).throw(
                CandidateError(f"JSON constant is not permitted: {constant}")
            ),
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        CandidateError,
        RecursionError,
    ) as exc:
        raise CandidateError(f"invalid {name}: {exc}") from exc
    if type(value) is not expected_type:
        raise CandidateError(f"{name} has the wrong JSON type")
    return value


def _digest_from_path(name: str, *, classic_config: bool = False) -> str:
    if classic_config:
        match = re.fullmatch(r"([0-9a-f]{64})\.json", name)
    else:
        match = re.fullmatch(r"blobs/sha256/([0-9a-f]{64})", name)
    if match is None:
        raise CandidateError(f"unsupported archive content path: {name}")
    return "sha256:" + match.group(1)


def _hash_stream(stream, maximum: int, name: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    consumed = 0
    while chunk := stream.read(1024 * 1024):
        consumed += len(chunk)
        if consumed > maximum:
            raise CandidateError(f"{name} exceeds its uncompressed safety bound")
        digest.update(chunk)
    return "sha256:" + digest.hexdigest(), consumed


class _BoundedReader:
    def __init__(self, source, maximum: int):
        self.source = source
        self.maximum = maximum
        self.consumed = 0

    def read(self, size: int) -> bytes:
        if size < 0:
            raise CandidateError("unbounded archive read is forbidden")
        raw = self.source.read(min(size, self.maximum - self.consumed + 1))
        self.consumed += len(raw)
        if self.consumed > self.maximum:
            raise CandidateError("expanded candidate archive exceeds its safety bound")
        return raw


def _gzip_exact(source, size: int, name: str) -> bytes:
    raw = bytearray()
    while len(raw) < size:
        chunk = source.read(size - len(raw))
        if not chunk:
            raise CandidateError(f"{name} gzip stream is truncated")
        raw.extend(chunk)
    return bytes(raw)


def _validate_single_gzip(source, name: str, maximum: int) -> None:
    """Bound one gzip header and reject unsupported concatenated members."""
    header = _gzip_exact(source, 10, name)
    if header[:3] != b"\x1f\x8b\x08" or header[3] & 0xE0:
        raise CandidateError(f"{name} is not valid gzip")
    flags = header[3]
    if flags & 0x04:
        extra_size = int.from_bytes(_gzip_exact(source, 2, name), "little")
        _gzip_exact(source, extra_size, name)
    header_text_size = 0
    for flag in (0x08, 0x10):
        if flags & flag:
            while True:
                header_text_size += 1
                if header_text_size > GZIP_HEADER_TEXT_MAX_BYTES:
                    raise CandidateError(
                        f"{name} gzip header text exceeds its safety bound"
                    )
                if _gzip_exact(source, 1, name) == b"\0":
                    break
    if flags & 0x02:
        _gzip_exact(source, 2, name)

    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
    pending = b""
    expanded = 0
    try:
        while not decompressor.eof:
            if not pending:
                pending = source.read(64 * 1024)
                if not pending:
                    raise CandidateError(f"{name} gzip stream is truncated")
            raw = decompressor.decompress(
                pending, min(64 * 1024, maximum - expanded + 1)
            )
            expanded += len(raw)
            if expanded > maximum:
                raise CandidateError(f"{name} exceeds its uncompressed safety bound")
            pending = decompressor.unconsumed_tail
    except zlib.error as exc:
        raise CandidateError(f"{name} is not valid gzip") from exc

    trailer = bytearray(decompressor.unused_data)
    if len(trailer) < 8:
        trailer.extend(_gzip_exact(source, 8 - len(trailer), name))
    if len(trailer) > 8 or source.read(1):
        raise CandidateError(f"{name} concatenated gzip members are unsupported")


def _tar_number(raw: bytes, name: str) -> int:
    if raw and raw[0] & 0x80:
        if raw[0] & 0x40:
            raise CandidateError(f"negative tar {name} is forbidden")
        return int.from_bytes(bytes([raw[0] & 0x7F]) + raw[1:], "big")
    value = raw.rstrip(b"\0 ").lstrip(b" ")
    if not value:
        return 0
    if any(character not in b"01234567" for character in value):
        raise CandidateError(f"invalid tar {name}")
    return int(value, 8)


def _read_exact(source: _BoundedReader, size: int, name: str) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = source.read(min(remaining, 64 * 1024))
        if not chunk:
            raise CandidateError(f"candidate archive is truncated in {name}")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _skip_exact(source: _BoundedReader, size: int, name: str) -> None:
    remaining = size
    while remaining:
        chunk = source.read(min(remaining, 64 * 1024))
        if not chunk:
            raise CandidateError(f"candidate archive is truncated in {name}")
        remaining -= len(chunk)


def _pax_values(raw: bytes) -> tuple[dict[str, str], int]:
    values: dict[str, str] = {}
    offset = 0
    record_count = 0
    while offset < len(raw):
        separator = raw.find(b" ", offset)
        length_raw = raw[offset:separator]
        if (
            separator < 0
            or not length_raw.isdigit()
            or len(length_raw) > len(str(TAR_EXTENSION_MAX_BYTES))
        ):
            raise CandidateError("candidate archive contains malformed PAX metadata")
        length = int(length_raw)
        end = offset + length
        if length <= separator - offset + 2 or end > len(raw) or raw[end - 1] != 10:
            raise CandidateError("candidate archive contains malformed PAX metadata")
        record = raw[separator + 1 : end - 1]
        if b"=" not in record:
            raise CandidateError("candidate archive contains malformed PAX metadata")
        key_raw, value_raw = record.split(b"=", 1)
        try:
            key = key_raw.decode("utf-8")
            value = value_raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CandidateError("candidate archive PAX metadata is not UTF-8") from exc
        if not key or key in values or key.startswith("GNU.sparse"):
            raise CandidateError("candidate archive contains ambiguous PAX metadata")
        values[key] = value
        record_count += 1
        offset = end
    return values, record_count


def _preflight_archive(path: Path) -> None:
    """Bound tar expansion and extension metadata before tarfile parses it."""
    with path.open("rb") as raw_source:
        magic = raw_source.read(6)
        raw_source.seek(0)
        if magic.startswith(b"\x1f\x8b"):
            _validate_single_gzip(raw_source, "candidate archive", ARCHIVE_MAX_BYTES)
            raw_source.seek(0)
            decoded = gzip.GzipFile(fileobj=raw_source)
        elif magic.startswith(b"BZh"):
            decoded = bz2.BZ2File(raw_source)
        elif magic.startswith(b"\xfd7zXZ\0"):
            raise CandidateError("XZ-compressed candidate archives are unsupported")
        else:
            decoded = raw_source
        source = _BoundedReader(decoded, ARCHIVE_MAX_BYTES)
        member_count = 0
        extension_count = 0
        consecutive_extension_count = 0
        extension_total = 0
        pax_record_count = 0
        global_pax_record_count = 0
        global_pax: dict[str, str] = {}
        next_pax: dict[str, str] = {}
        zero_blocks = 0
        try:
            while True:
                header = source.read(512)
                if not header:
                    raise CandidateError("candidate archive has no complete end marker")
                if len(header) != 512:
                    raise CandidateError("candidate archive has a truncated tar header")
                if header == bytes(512):
                    zero_blocks += 1
                    if zero_blocks == 2:
                        trailing_size = 0
                        while trailing := source.read(64 * 1024):
                            trailing_size += len(trailing)
                            if trailing_size > TAR_TRAILING_MAX_BYTES:
                                raise CandidateError(
                                    "candidate archive trailing padding exceeds its bound"
                                )
                            if trailing.strip(b"\0"):
                                raise CandidateError(
                                    "candidate archive has data after its end marker"
                                )
                        break
                    continue
                if zero_blocks:
                    raise CandidateError("candidate archive has an invalid end marker")
                stored_checksum = _tar_number(header[148:156], "checksum")
                if sum(header[:148]) + 8 * 32 + sum(header[156:]) != stored_checksum:
                    raise CandidateError("candidate archive tar checksum is invalid")
                size = _tar_number(header[124:136], "member size")
                kind = header[156:157]
                if kind in {b"x", b"X", b"g", b"L", b"K"}:
                    extension_count += 1
                    consecutive_extension_count += 1
                    if extension_count > TAR_EXTENSION_COUNT_MAX:
                        raise CandidateError(
                            "candidate archive tar extension count exceeds its bound"
                        )
                    if consecutive_extension_count > TAR_CONSECUTIVE_EXTENSION_MAX:
                        raise CandidateError(
                            "candidate archive consecutive tar extensions exceed "
                            "their bound"
                        )
                    if size > TAR_EXTENSION_MAX_BYTES:
                        raise CandidateError(
                            "candidate archive tar extension exceeds its safety bound"
                        )
                    extension_total += size
                    if extension_total > TAR_EXTENSIONS_TOTAL_MAX_BYTES:
                        raise CandidateError(
                            "candidate archive tar extensions exceed their total bound"
                        )
                    extension = _read_exact(source, size, "tar extension")
                    _skip_exact(source, (-size) % 512, "tar extension padding")
                    if kind == b"K":
                        raise CandidateError("candidate archive contains a long link")
                    if kind == b"L":
                        try:
                            long_name = extension.rstrip(b"\0").decode("utf-8")
                        except UnicodeDecodeError as exc:
                            raise CandidateError(
                                "candidate archive long name is not UTF-8"
                            ) from exc
                        if (
                            not long_name
                            or len(long_name.encode()) > TAR_EXTENSION_MAX_BYTES
                        ):
                            raise CandidateError(
                                "candidate archive long name is invalid"
                            )
                        next_pax["path"] = long_name
                    else:
                        values, record_count = _pax_values(extension)
                        pax_record_count += record_count
                        if pax_record_count > TAR_PAX_RECORD_MAX:
                            raise CandidateError(
                                "candidate archive PAX record count exceeds its bound"
                            )
                        if kind == b"g":
                            global_pax_record_count += record_count
                            if global_pax_record_count > TAR_PAX_GLOBAL_RECORD_MAX:
                                raise CandidateError(
                                    "candidate archive global PAX record count "
                                    "exceeds its bound"
                                )
                            global_pax.update(values)
                        else:
                            next_pax.update(values)
                    continue
                if kind == b"S":
                    raise CandidateError(
                        "candidate archive contains unsupported sparse metadata"
                    )
                consecutive_extension_count = 0
                member_count += 1
                if member_count > ARCHIVE_MEMBER_MAX:
                    raise CandidateError(
                        "candidate archive member count exceeds its bound"
                    )
                pax_size = next_pax.get("size", global_pax.get("size"))
                next_pax.clear()
                if pax_size is not None:
                    if (
                        len(pax_size) > len(str(ARCHIVE_MAX_BYTES))
                        or re.fullmatch(r"0|[1-9][0-9]*", pax_size) is None
                    ):
                        raise CandidateError("candidate archive PAX size is invalid")
                    size = int(pax_size)
                if size > ARCHIVE_MAX_BYTES:
                    raise CandidateError(
                        "candidate archive member exceeds its safety bound"
                    )
                _skip_exact(source, size, "tar member")
                _skip_exact(source, (-size) % 512, "tar member padding")
        except (OSError, EOFError) as exc:
            raise CandidateError(
                f"invalid compressed candidate archive: {exc}"
            ) from exc


def inspect_archive(path: Path) -> dict[str, object]:
    """Validate one Docker archive and derive scanner-native image identities."""
    _preflight_archive(path)
    with ExitStack() as stack:
        try:
            archive = stack.enter_context(tarfile.open(path, mode="r:*"))
        except (OSError, tarfile.TarError) as exc:
            raise CandidateError(f"invalid candidate archive: {exc}") from exc
        by_name: dict[str, tarfile.TarInfo] = {}
        for member in archive:
            if len(by_name) >= ARCHIVE_MEMBER_MAX:
                raise CandidateError(
                    "candidate archive member count is outside its bound"
                )
            name = member.name
            if (
                not name
                or name.startswith("/")
                or "\\" in name
                or any(part in {"", ".", ".."} for part in name.split("/"))
            ):
                raise CandidateError("candidate archive contains an unsafe path")
            if name in by_name:
                raise CandidateError(f"candidate archive repeats member {name}")
            if not (member.isfile() or member.isdir()):
                raise CandidateError("candidate archive contains a non-regular member")
            by_name[name] = member

        if not by_name:
            raise CandidateError("candidate archive is empty")

        def member_bytes(name: str) -> bytes:
            member = by_name.get(name)
            if member is None or not member.isfile():
                raise CandidateError(
                    f"candidate archive is missing regular file {name}"
                )
            if member.size <= 0 or member.size > ARCHIVE_METADATA_MAX_BYTES:
                raise CandidateError(
                    f"candidate archive member {name} has invalid size"
                )
            source = archive.extractfile(member)
            if source is None:
                raise CandidateError(f"candidate archive member {name} cannot be read")
            raw = source.read(member.size + 1)
            if len(raw) != member.size:
                raise CandidateError(
                    f"candidate archive member {name} changed while read"
                )
            return raw

        docker_manifest = _json_value(
            member_bytes("manifest.json"), "archive manifest.json", list
        )
        if len(docker_manifest) != 1 or type(docker_manifest[0]) is not dict:
            raise CandidateError("candidate archive must contain exactly one image")
        entry = docker_manifest[0]
        config_path = entry.get("Config")
        layer_paths = entry.get("Layers")
        repo_tags = entry.get("RepoTags")
        if (
            type(layer_paths) is not list
            or not layer_paths
            or len(layer_paths) > ARCHIVE_LAYER_MAX
        ):
            raise CandidateError("candidate archive layer count exceeds its bound")
        if (
            type(config_path) is not str
            or any(type(name) is not str for name in layer_paths)
            or len(set(layer_paths)) != len(layer_paths)
            or type(repo_tags) is not list
            or len(repo_tags) != 1
            or repo_tags != [EXPECTED_CANDIDATE_IMAGE]
        ):
            raise CandidateError("candidate archive image descriptor is ambiguous")

        is_oci = config_path.startswith("blobs/sha256/")
        config_digest = _digest_from_path(config_path, classic_config=not is_oci)
        config_raw = member_bytes(config_path)
        if "sha256:" + hashlib.sha256(config_raw).hexdigest() != config_digest:
            raise CandidateError(
                "candidate archive config digest does not match its bytes"
            )
        config = _json_value(config_raw, "archive image config", dict)
        rootfs = config.get("rootfs")
        diff_ids = rootfs.get("diff_ids") if type(rootfs) is dict else None
        if (
            rootfs is None
            or rootfs.get("type") != "layers"
            or type(diff_ids) is not list
            or len(diff_ids) > ARCHIVE_LAYER_MAX
            or len(diff_ids) != len(layer_paths)
            or any(
                type(digest) is not str or DIGEST_RE.fullmatch(digest) is None
                for digest in diff_ids
            )
        ):
            raise CandidateError(
                "candidate archive config has invalid rootfs identities"
            )

        archive_manifest_digest: str | None = None
        archive_index_digest: str | None = None
        layer_media_types: list[str]
        layer_sizes: list[int]
        if is_oci:
            if not {"index.json", "oci-layout"} <= set(by_name):
                raise CandidateError("OCI candidate archive metadata is incomplete")
            index_raw = member_bytes("index.json")
            index = _json_value(index_raw, "archive index.json", dict)
            descriptors = index.get("manifests")
            if (
                index.get("schemaVersion") != 2
                or type(descriptors) is not list
                or len(descriptors) != 1
                or type(descriptors[0]) is not dict
            ):
                raise CandidateError("candidate archive index is ambiguous")
            descriptor = descriptors[0]
            if descriptor.get("mediaType") not in OCI_MANIFEST_MEDIA_TYPES:
                raise CandidateError(
                    "candidate archive index does not select one image manifest"
                )
            archive_manifest_digest = _bounded_string(
                descriptor.get("digest"), "archive manifest digest"
            )
            if DIGEST_RE.fullmatch(archive_manifest_digest) is None:
                raise CandidateError("candidate archive manifest digest is invalid")
            manifest_path = "blobs/sha256/" + archive_manifest_digest.removeprefix(
                "sha256:"
            )
            manifest_raw = member_bytes(manifest_path)
            if (
                "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
                != archive_manifest_digest
            ):
                raise CandidateError(
                    "candidate archive manifest digest does not match its bytes"
                )
            if descriptor.get("size") != len(manifest_raw):
                raise CandidateError("candidate archive manifest size is inconsistent")
            image_manifest = _json_value(manifest_raw, "archive image manifest", dict)
            layers = image_manifest.get("layers")
            image_config = image_manifest.get("config")
            if (
                image_manifest.get("schemaVersion") != 2
                or image_manifest.get("mediaType") not in OCI_MANIFEST_MEDIA_TYPES
                or type(image_config) is not dict
                or image_config.get("mediaType") not in OCI_CONFIG_MEDIA_TYPES
                or image_config.get("digest") != config_digest
                or image_config.get("size") != len(config_raw)
                or type(layers) is not list
                or len(layers) != len(layer_paths)
                or any(type(layer) is not dict for layer in layers)
            ):
                raise CandidateError("candidate archive image manifest is inconsistent")
            layer_media_types = [layer.get("mediaType") for layer in layers]
            layer_sizes = [layer.get("size") for layer in layers]
            for position, (layer, layer_path) in enumerate(
                zip(layers, layer_paths, strict=True)
            ):
                if (
                    layer.get("mediaType") not in GZIP_LAYER_MEDIA_TYPES
                    or layer.get("digest") != _digest_from_path(layer_path)
                    or type(layer.get("size")) is not int
                    or layer.get("size")
                    != by_name.get(layer_path, tarfile.TarInfo()).size
                    or layer_path
                    != "blobs/sha256/" + layer["digest"].removeprefix("sha256:")
                ):
                    raise CandidateError(
                        f"candidate archive layer {position} is inconsistent"
                    )
            archive_index_digest = "sha256:" + hashlib.sha256(index_raw).hexdigest()
        else:
            if {"index.json", "oci-layout"} & set(by_name):
                raise CandidateError(
                    "candidate archive mixes classic and OCI representations"
                )
            layer_media_types = ["application/vnd.docker.image.rootfs.diff.tar"] * len(
                layer_paths
            )
            layer_sizes = [
                by_name.get(name, tarfile.TarInfo()).size for name in layer_paths
            ]

        total_uncompressed = 0
        for position, (name, media_type, expected_diff_id) in enumerate(
            zip(layer_paths, layer_media_types, diff_ids, strict=True)
        ):
            member = by_name.get(name)
            if member is None or not member.isfile() or member.size <= 0:
                raise CandidateError(f"candidate archive layer {position} is missing")
            source = archive.extractfile(member)
            if source is None:
                raise CandidateError(
                    f"candidate archive layer {position} cannot be read"
                )
            if media_type in GZIP_LAYER_MEDIA_TYPES:
                compressed_hash, compressed_size = _hash_stream(
                    source, ARCHIVE_MAX_BYTES, f"candidate archive layer {position}"
                )
                if (
                    compressed_hash != _digest_from_path(name)
                    or compressed_size != member.size
                ):
                    raise CandidateError(
                        f"candidate archive layer {position} digest is invalid"
                    )
                source = archive.extractfile(member)
                if source is None:
                    raise CandidateError(
                        f"candidate archive layer {position} cannot be reread"
                    )
                _validate_single_gzip(
                    source,
                    f"candidate archive layer {position}",
                    UNCOMPRESSED_LAYERS_MAX_BYTES - total_uncompressed,
                )
                source = archive.extractfile(member)
                if source is None:
                    raise CandidateError(
                        f"candidate archive layer {position} cannot be reread"
                    )
                try:
                    with gzip.GzipFile(fileobj=source) as uncompressed:
                        actual_diff_id, uncompressed_size = _hash_stream(
                            uncompressed,
                            UNCOMPRESSED_LAYERS_MAX_BYTES - total_uncompressed,
                            f"candidate archive layer {position}",
                        )
                except (OSError, EOFError) as exc:
                    raise CandidateError(
                        f"candidate archive layer {position} is not valid gzip"
                    ) from exc
            else:
                actual_diff_id, uncompressed_size = _hash_stream(
                    source,
                    UNCOMPRESSED_LAYERS_MAX_BYTES - total_uncompressed,
                    f"candidate archive layer {position}",
                )
            total_uncompressed += uncompressed_size
            if actual_diff_id != expected_diff_id:
                raise CandidateError(
                    f"candidate archive layer {position} diff ID is invalid"
                )

        syft_manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": len(config_raw),
                "digest": config_digest,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "size": size,
                    "digest": diff_id,
                }
                for size, diff_id in zip(layer_sizes, diff_ids, strict=True)
            ],
        }
        syft_raw = json.dumps(syft_manifest, separators=(",", ":")).encode()
        return {
            "format": "oci-single-manifest" if is_oci else "docker-single-image",
            "reference": EXPECTED_CANDIDATE_IMAGE,
            "config_digest": config_digest,
            "layer_diff_ids": diff_ids,
            "manifest_digest": archive_manifest_digest,
            "index_digest": archive_index_digest,
            "syft_manifest_digest": "sha256:" + hashlib.sha256(syft_raw).hexdigest(),
        }


def validate_spdx(
    document: dict[str, object], config_digest: str, syft_manifest_digest: str
) -> None:
    required = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
    }
    for key, expected in required.items():
        if document.get(key) != expected:
            raise CandidateError(f"SBOM {key} must equal {expected}")
    _bounded_string(document.get("name"), "SBOM name")
    _bounded_string(document.get("documentNamespace"), "SBOM documentNamespace")

    creation = document.get("creationInfo")
    if type(creation) is not dict:
        raise CandidateError("SBOM creationInfo must be an object")
    creators = creation.get("creators")
    if type(creators) is not list or not creators or len(creators) > 32:
        raise CandidateError("SBOM creators must be a non-empty bounded list")
    for creator in creators:
        _bounded_string(creator, "SBOM creator")

    packages = document.get("packages")
    relationships = document.get("relationships")
    if type(packages) is not list or not packages or len(packages) > 100_000:
        raise CandidateError("SBOM packages must be a non-empty bounded list")
    if (
        type(relationships) is not list
        or not relationships
        or len(relationships) > 500_000
    ):
        raise CandidateError("SBOM relationships must be a non-empty bounded list")

    package_by_id: dict[str, dict[str, object]] = {}
    for package in packages:
        if type(package) is not dict:
            raise CandidateError("every SBOM package must be an object")
        package_id = _bounded_string(package.get("SPDXID"), "package SPDXID")
        _bounded_string(package.get("name"), "package name")
        if package_id in package_by_id:
            raise CandidateError(f"duplicate package SPDXID: {package_id}")
        package_by_id[package_id] = package

    described: list[str] = []
    for relationship in relationships:
        if type(relationship) is not dict:
            raise CandidateError("every SBOM relationship must be an object")
        source = _bounded_string(
            relationship.get("spdxElementId"), "relationship source"
        )
        target = _bounded_string(
            relationship.get("relatedSpdxElement"), "relationship target"
        )
        relation = _bounded_string(
            relationship.get("relationshipType"), "relationship type"
        )
        if source == "SPDXRef-DOCUMENT" and relation == "DESCRIBES":
            described.append(target)

    if len(described) != 1 or described[0] not in package_by_id:
        raise CandidateError("SBOM must describe exactly one package in the document")
    root_id = described[0]
    root = package_by_id[root_id]
    if root.get("name") != EXPECTED_SBOM_NAME:
        raise CandidateError("SBOM describes the wrong image name")
    if root.get("primaryPackagePurpose") != "CONTAINER":
        raise CandidateError("SBOM root package must represent a container")
    if root.get("versionInfo") != syft_manifest_digest:
        raise CandidateError("SBOM root version does not match the archive image")

    if DIGEST_RE.fullmatch(config_digest) is None:
        raise CandidateError("archive config digest is invalid")
    checksums = root.get("checksums")
    image_checksums = [
        checksum.get("checksumValue")
        for checksum in checksums or []
        if type(checksum) is dict
        and checksum.get("algorithm") in {"SHA256", "SHA-256"}
        and type(checksum.get("checksumValue")) is str
        and HASH_RE.fullmatch(checksum["checksumValue"])
    ]
    if len(image_checksums) != 1:
        raise CandidateError("SBOM root must have exactly one SHA-256 image checksum")
    if "sha256:" + image_checksums[0] != syft_manifest_digest:
        raise CandidateError("SBOM root checksum does not match the archive image")

    external_refs = root.get("externalRefs")
    if type(external_refs) is not list:
        raise CandidateError("SBOM root package has no external references")
    matching_purls = []
    for reference in external_refs:
        if type(reference) is not dict:
            continue
        locator = reference.get("referenceLocator")
        if (
            reference.get("referenceCategory") == "PACKAGE-MANAGER"
            and reference.get("referenceType") == "purl"
            and type(locator) is str
            and "?" in locator
        ):
            identity, query_text = locator.split("?", 1)
            expected_identity = (
                f"pkg:oci/{EXPECTED_SBOM_NAME}@sha256:{image_checksums[0]}"
            )
            try:
                query = parse_qs(
                    query_text, keep_blank_values=True, strict_parsing=True
                )
            except ValueError as exc:
                raise CandidateError("SBOM OCI subject purl is malformed") from exc
            valid_query = (
                "arch" in query
                and set(query) <= {"arch", "os", "repository_url", "tag"}
                and all(
                    len(values) == 1
                    and len(values[0].encode("utf-8")) <= IDENTITY_MAX_BYTES
                    for values in query.values()
                )
                and query.get("tag", ["release-candidate"]) == ["release-candidate"]
            )
            if unquote(identity) == expected_identity and valid_query:
                matching_purls.append(locator)
    if len(matching_purls) != 1:
        raise CandidateError("SBOM OCI subject does not identify the tested image")

    if len(packages) > 1 and not any(
        type(relationship) is dict
        and relationship.get("spdxElementId") == root_id
        and relationship.get("relationshipType") == "CONTAINS"
        and relationship.get("relatedSpdxElement") in package_by_id
        and relationship.get("relatedSpdxElement") != root_id
        for relationship in relationships
    ):
        raise CandidateError("SBOM root package does not contain its package inventory")


def canonical_json(value: dict[str, object]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _copy_exclusive(source: Path, destination: Path, expected_size: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    copied = 0
    try:
        with source.open("rb") as input_file, os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            while chunk := input_file.read(1024 * 1024):
                copied += len(chunk)
                if copied > expected_size:
                    raise CandidateError(f"{source.name} grew while it was copied")
                output.write(chunk)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if copied != expected_size:
        raise CandidateError(f"{source.name} changed while it was copied")


def create_candidate(handoff: Path, sbom_source: Path) -> dict[str, object]:
    if not handoff.is_dir() or handoff.is_symlink():
        raise CandidateError("handoff path must be an existing real directory")
    if set(path.name for path in handoff.iterdir()) != {ARCHIVE_NAME}:
        raise CandidateError(
            "handoff directory must initially contain only the archive"
        )

    repository = _bounded_string(os.environ.get("GITHUB_REPOSITORY"), "repository")
    if repository != EXPECTED_REPOSITORY:
        raise CandidateError("unexpected repository")
    repository_id = _positive_integer(
        os.environ.get("GITHUB_REPOSITORY_ID", ""), "repository_id"
    )
    run_id = _positive_integer(os.environ.get("GITHUB_RUN_ID", ""), "run_id")
    run_attempt = _positive_integer(
        os.environ.get("GITHUB_RUN_ATTEMPT", ""), "run_attempt"
    )
    release_id = _positive_integer(os.environ.get("RELEASE_ID", ""), "release_id")

    release_tag = _bounded_string(
        os.environ.get("RELEASE_TAG"), "release_tag", RELEASE_TAG_MAX_BYTES
    )
    if TAG_RE.fullmatch(release_tag) is None:
        raise CandidateError("invalid release tag")
    source_sha = _bounded_string(os.environ.get("SOURCE_SHA"), "source_sha")
    tag_object_sha = _bounded_string(os.environ.get("TAG_OBJECT_SHA"), "tag_object_sha")
    workflow_sha = _bounded_string(
        os.environ.get("GITHUB_WORKFLOW_SHA"), "workflow_sha"
    )
    if not SHA_RE.fullmatch(source_sha) or not SHA_RE.fullmatch(tag_object_sha):
        raise CandidateError("source and tag-object identities must be full SHAs")
    if workflow_sha != source_sha:
        raise CandidateError("workflow SHA must equal the qualified source SHA")

    workflow_ref = _bounded_string(
        os.environ.get("GITHUB_WORKFLOW_REF"), "workflow_ref"
    )
    expected_workflow_ref = (
        f"{repository}/.github/workflows/publish-container.yml@refs/tags/{release_tag}"
    )
    if workflow_ref != expected_workflow_ref:
        raise CandidateError("workflow ref does not identify the release tag workflow")

    artifact_name = _bounded_string(os.environ.get("ARTIFACT_NAME"), "artifact_name")
    if artifact_name != f"aruba-cert-renewer-{release_tag}-candidate":
        raise CandidateError("unexpected artifact name")
    image_name = _bounded_string(os.environ.get("IMAGE_NAME"), "image_name")
    if image_name != EXPECTED_IMAGE_NAME:
        raise CandidateError("unexpected image name")
    github_prerelease = _boolean(
        os.environ.get("IS_GITHUB_PRERELEASE", ""), "github_prerelease"
    )
    publish_latest = _boolean(os.environ.get("PUBLISH_LATEST", ""), "publish_latest")
    expected_latest = not github_prerelease and "-" not in release_tag
    if publish_latest is not expected_latest:
        raise CandidateError("publish_latest is inconsistent with the release")

    archive = handoff / ARCHIVE_NAME
    archive_info = _regular_file(archive, ARCHIVE_MAX_BYTES)
    archive_identity = inspect_archive(archive)
    sbom_document, _ = _read_json(sbom_source, SBOM_MAX_BYTES)
    validate_spdx(
        sbom_document,
        archive_identity["config_digest"],
        archive_identity["syft_manifest_digest"],
    )
    sbom_info = _regular_file(sbom_source, SBOM_MAX_BYTES)
    sbom_destination = handoff / SBOM_NAME
    _copy_exclusive(sbom_source, sbom_destination, sbom_info.st_size)
    sbom_document, _ = _read_json(sbom_destination, SBOM_MAX_BYTES)
    validate_spdx(
        sbom_document,
        archive_identity["config_digest"],
        archive_identity["syft_manifest_digest"],
    )
    sbom_info = _regular_file(sbom_destination, SBOM_MAX_BYTES)

    manifest: dict[str, object] = {
        "schema_version": 2,
        "repository": repository,
        "repository_id": repository_id,
        "workflow_ref": workflow_ref,
        "workflow_sha": workflow_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "release_id": release_id,
        "artifact_name": artifact_name,
        "release_tag": release_tag,
        "tag_object_sha": tag_object_sha,
        "source_sha": source_sha,
        "github_prerelease": github_prerelease,
        "publish_latest": publish_latest,
        "image_name": image_name,
        "archive": {
            "name": ARCHIVE_NAME,
            "size": archive_info.st_size,
            "sha256": _sha256(archive, archive_info.st_size),
            **archive_identity,
        },
        "sbom": {
            "name": SBOM_NAME,
            "size": sbom_info.st_size,
            "sha256": _sha256(sbom_destination, sbom_info.st_size),
        },
    }
    manifest_bytes = canonical_json(manifest)
    if len(manifest_bytes) > MANIFEST_MAX_BYTES:
        raise CandidateError("candidate manifest exceeds its size bound")
    manifest_path = handoff / MANIFEST_NAME
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(manifest_path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(manifest_bytes)
    if set(path.name for path in handoff.iterdir()) != {
        MANIFEST_NAME,
        ARCHIVE_NAME,
        SBOM_NAME,
    }:
        raise CandidateError("candidate inventory changed during manifest creation")
    return manifest


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 2:
        print(
            "usage: release_candidate.py HANDOFF_DIRECTORY SPDX_JSON",
            file=sys.stderr,
        )
        return 2
    try:
        create_candidate(Path(arguments[0]), Path(arguments[1]))
    except (CandidateError, OSError) as exc:
        print(f"release candidate error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
