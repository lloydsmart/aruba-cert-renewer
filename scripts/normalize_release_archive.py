#!/usr/bin/env python3
"""Convert a validated single-image Docker export to the classic handoff format.

Docker 29 can save OCI metadata with uncompressed layer blobs. The archive's
manifest is then an export representation, not the registry's compressed image
manifest. Keep those identities separate: validate every source byte, preserve
the exact config and ordered uncompressed layer identities, and emit the classic
Docker archive already understood independently by the publisher and Syft.
"""

from __future__ import annotations

import gzip
import io
import json
import sys
import tarfile
import tempfile
from pathlib import Path

from release_candidate import CandidateError, inspect_archive


def normalize(source: Path, destination: Path) -> None:
    identity = inspect_archive(source, allow_raw_oci=True)
    # Exclusive output prevents overwriting another candidate or the input.
    with tarfile.open(source, "r:*") as original, destination.open("xb") as output:
        manifest = json.load(original.extractfile("manifest.json"))[0]
        media_types = ["application/vnd.docker.image.rootfs.diff.tar"] * len(
            manifest["Layers"]
        )
        if identity["format"] == "oci-single-manifest":
            image_manifest = json.load(
                original.extractfile(
                    "blobs/sha256/"
                    + identity["manifest_digest"].removeprefix("sha256:")
                )
            )
            media_types = [layer["mediaType"] for layer in image_manifest["layers"]]
        config_name = identity["config_digest"].removeprefix("sha256:") + ".json"
        layer_names = [
            f"{diff_id.removeprefix('sha256:')}/layer.tar"
            for diff_id in identity["layer_diff_ids"]
        ]
        # The validated input rejects repeated layer paths; reject repeated diff
        # IDs too because the classic format must not contain duplicate members.
        if len(set(layer_names)) != len(layer_names):
            raise CandidateError("repeated layer diff IDs cannot be normalized")
        with tarfile.open(
            fileobj=output, mode="w", format=tarfile.USTAR_FORMAT
        ) as target:
            config = original.extractfile(manifest["Config"]).read()
            info = tarfile.TarInfo(config_name)
            info.size = len(config)
            target.addfile(info, io.BytesIO(config))
            for old_name, new_name, media_type in zip(
                manifest["Layers"], layer_names, media_types, strict=True
            ):
                stream = original.extractfile(old_name)
                if media_type.endswith("gzip"):
                    # Source gzip expansion was bounded and authenticated above.
                    # Spool to disk, rather than retaining a large layer in RAM.
                    with tempfile.TemporaryFile() as expanded:
                        with gzip.GzipFile(fileobj=stream) as decoded:
                            while chunk := decoded.read(1024 * 1024):
                                expanded.write(chunk)
                        info = tarfile.TarInfo(new_name)
                        info.size = expanded.tell()
                        expanded.seek(0)
                        target.addfile(info, expanded)
                else:
                    info = tarfile.TarInfo(new_name)
                    info.size = original.getmember(old_name).size
                    target.addfile(info, stream)
            raw = json.dumps(
                [
                    {
                        "Config": config_name,
                        "RepoTags": [identity["reference"]],
                        "Layers": layer_names,
                    }
                ],
                separators=(",", ":"),
            ).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size = len(raw)
            target.addfile(info, io.BytesIO(raw))
    normalized = inspect_archive(destination)
    for field in ("config_digest", "layer_diff_ids", "reference"):
        if normalized[field] != identity[field]:
            raise CandidateError(f"normalization changed {field}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: normalize_release_archive.py SOURCE DESTINATION")
    normalize(Path(sys.argv[1]), Path(sys.argv[2]))
