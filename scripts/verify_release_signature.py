#!/usr/bin/env python3
"""Authenticate the exact release tag against the reviewed public signing key."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

APPROVED_PRIMARY = "02EBB31CC0032A86C2C0401A1534542E61DC82D3"
PUBLIC_KEY = Path(__file__).resolve().parents[1] / ".security/release-signing-key.asc"
MAX_TAG_BYTES = 1024 * 1024
FINGERPRINT = re.compile(r"[0-9A-F]{40}")
SHA = re.compile(r"[0-9a-f]{40}")
SIGNATURE_START = b"-----BEGIN PGP SIGNATURE-----\n"
SIGNATURE_END = b"-----END PGP SIGNATURE-----\n"
BAD_STATUS = frozenset(
    {
        "BADSIG",
        "ERRSIG",
        "EXPSIG",
        "EXPKEYSIG",
        "REVKEYSIG",
        "NO_PUBKEY",
        "KEYEXPIRED",
        "KEYREVOKED",
        "SIGEXPIRED",
        "FAILURE",
        "ERROR",
        "NODATA",
    }
)


class SignatureError(ValueError):
    """The tag cannot be authenticated under the release signing policy."""


def split_tag(
    raw: bytes, tag: str, tag_sha: str, source_sha: str
) -> tuple[bytes, bytes]:
    if not SHA.fullmatch(tag_sha) or not SHA.fullmatch(source_sha):
        raise SignatureError("expected identities must be full Git object IDs")
    if not raw or len(raw) > MAX_TAG_BYTES:
        raise SignatureError("tag object is empty or oversized")
    # Git's object ID binds the signature as well as its signed payload.
    actual = hashlib.sha1(b"tag " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if actual != tag_sha:
        raise SignatureError("tag bytes do not match the expected object ID")
    headers, separator, _ = raw.partition(b"\n\n")
    expected = [f"object {source_sha}".encode(), b"type commit", f"tag {tag}".encode()]
    lines = headers.split(b"\n")
    if (
        not separator
        or len(lines) != 4
        or lines[:3] != expected
        or not lines[3].startswith(b"tagger ")
    ):
        raise SignatureError("tag headers do not match the release identity")
    if (
        raw.count(SIGNATURE_START) != 1
        or raw.count(SIGNATURE_END) != 1
        or not raw.endswith(SIGNATURE_END)
    ):
        raise SignatureError("tag must contain exactly one terminal OpenPGP signature")
    payload, signature = raw.split(SIGNATURE_START)
    if not payload.endswith(b"\n"):
        raise SignatureError("tag signature is not on a separate line")
    return payload, SIGNATURE_START + signature


def approved_signature(status: bytes) -> str:
    try:
        lines = status.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise SignatureError("invalid signature status encoding") from error
    records = [line.removeprefix("[GNUPG:] ").split() for line in lines]
    if any(not line.startswith("[GNUPG:] ") for line in lines) or any(
        not record or record[0] in BAD_STATUS for record in records
    ):
        raise SignatureError("signature verification reported an error")
    valid = [record for record in records if record[0] == "VALIDSIG"]
    if (
        len(valid) != 1
        or len(valid[0]) != 11
        or sum(record[0] == "GOODSIG" for record in records) != 1
        or sum(record[0] == "NEWSIG" for record in records) != 1
    ):
        raise SignatureError("exactly one valid, current signature is required")
    record = valid[0]
    if (
        not FINGERPRINT.fullmatch(record[1])
        or record[10] != APPROVED_PRIMARY
        or record[8] not in {"8", "9", "10"}
        or record[9] != "00"
    ):
        raise SignatureError(
            "signature is outside the approved signer or algorithm policy"
        )
    return record[10]


def verify(raw: bytes, tag: str, tag_sha: str, source_sha: str) -> str:
    payload, signature = split_tag(raw, tag, tag_sha, source_sha)
    with PUBLIC_KEY.open("rb") as key_file:
        public_key = key_file.read(65537)
    if len(public_key) > 65536 or not public_key.startswith(
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----"
    ):
        raise SignatureError("reviewed public key is missing or invalid")
    with tempfile.TemporaryDirectory(prefix="release-gpg-") as directory:
        home = Path(directory)
        home.chmod(0o700)
        gpg = [
            "gpg",
            "--no-options",
            "--homedir",
            str(home),
            "--batch",
            "--no-tty",
            "--no-auto-key-retrieve",
            "--no-auto-key-import",
            "--auto-key-locate",
            "clear",
        ]
        imported = subprocess.run(
            [*gpg, "--import-options", "import-minimal", "--import"],
            input=public_key,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if imported.returncode:
            raise SignatureError("cannot import reviewed public signing key")
        (home / "payload").write_bytes(payload)
        (home / "signature.asc").write_bytes(signature)
        result = subprocess.run(
            [
                *gpg,
                "--status-fd",
                "1",
                "--verify",
                str(home / "signature.asc"),
                str(home / "payload"),
            ],
            capture_output=True,
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise SignatureError("OpenPGP signature verification failed")
        return approved_signature(result.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    parser.add_argument("tag_object_sha")
    parser.add_argument("source_sha")
    parser.add_argument("tag_object", type=Path)
    args = parser.parse_args(argv)
    try:
        with args.tag_object.open("rb") as tag_file:
            raw = tag_file.read(MAX_TAG_BYTES + 1)
        signer = verify(raw, args.tag, args.tag_object_sha, args.source_sha)
    except (SignatureError, OSError, subprocess.SubprocessError) as error:
        detail = (
            str(error)
            if isinstance(error, SignatureError)
            else "verification unavailable"
        )
        print(f"Release signature blocked: {detail}", file=sys.stderr)
        return 1
    print(f"Approved release signer: {signer}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
