from __future__ import annotations

import hashlib
import importlib
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
verifier = importlib.import_module("verify_release_signature")
TAG = "v1.2.3-rc.1"
SOURCE = "b" * 40
PAYLOAD = (
    f"object {SOURCE}\ntype commit\ntag {TAG}\n"
    "tagger Synthetic Release <release@example.invalid> 1700000000 +0000\n\n"
    "Synthetic release\n"
).encode()


def object_id(raw: bytes) -> str:
    return hashlib.sha1(b"tag " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def good_status(signer: str | None = None) -> bytes:
    primary = verifier.APPROVED_PRIMARY
    signer = signer or primary
    return (
        f"[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG {signer[-16:]} Synthetic signer\n"
        f"[GNUPG:] VALIDSIG {signer} 2026-09-18 1789689600 0 4 0 1 10 00 {primary}\n"
        "[GNUPG:] TRUST_UNDEFINED 0 pgp\n"
    ).encode()


@pytest.mark.parametrize("signer", [None, "A" * 40])
def test_primary_and_certified_subkey_with_unknown_ownertrust(signer) -> None:
    assert verifier.approved_signature(good_status(signer)) == verifier.APPROVED_PRIMARY


@pytest.mark.parametrize("status", sorted(verifier.BAD_STATUS))
def test_negative_gpg_status_rejected_even_with_validsig(status) -> None:
    with pytest.raises(verifier.SignatureError):
        verifier.approved_signature(
            good_status() + f"[GNUPG:] {status} detail\n".encode()
        )


@pytest.mark.parametrize(
    "damage",
    [
        "empty",
        "issuer-only",
        "duplicate",
        "unknown-primary",
        "no-primary",
        "bad-fpr",
        "weak-hash",
        "text-signature",
        "missing-goodsig",
        "missing-newsig",
        "nonstatus",
        "utf8",
    ],
)
def test_incomplete_or_ambiguous_status_rejected(damage) -> None:
    status = good_status()
    primary = verifier.APPROVED_PRIMARY.encode()
    if damage == "empty":
        status = b""
    elif damage == "issuer-only":
        status = b"[GNUPG:] GOODSIG " + primary + b" User\n"
    elif damage == "duplicate":
        status += good_status()
    elif damage == "unknown-primary":
        status = status.replace(b"00 " + primary, b"00 " + b"A" * 40)
    elif damage == "no-primary":
        status = status.replace(b"00 " + primary, b"00")
    elif damage == "bad-fpr":
        status = status.replace(b"VALIDSIG " + primary, b"VALIDSIG short")
    elif damage == "weak-hash":
        status = status.replace(b"1 10 00", b"1 2 00")
    elif damage == "text-signature":
        status = status.replace(b"1 10 00", b"1 10 01")
    elif damage == "missing-goodsig":
        status = status.replace(b"GOODSIG", b"UNKNOWN")
    elif damage == "missing-newsig":
        status = status.replace(b"NEWSIG", b"UNKNOWN")
    elif damage == "nonstatus":
        status += b"not a status record\n"
    else:
        status += b"\xff"
    with pytest.raises(verifier.SignatureError):
        verifier.approved_signature(status)


@pytest.fixture(scope="module")
def signed_tags():
    # Synthetic private keys exist only in the disposable test environment.
    # Never access the user's GNUPGHOME or network key servers.
    with tempfile.TemporaryDirectory(prefix="test-release-gpg-") as temporary:
        home = Path(temporary)
        home.chmod(0o700)
        command = ["gpg", "--no-options", "--homedir", str(home), "--batch", "--no-tty"]

        def gpg(*args: str, data: bytes | None = None) -> bytes:
            return subprocess.run(
                [*command, *args],
                input=data,
                capture_output=True,
                check=True,
                timeout=30,
            ).stdout

        try:
            keys = []
            for name in ("approved", "unapproved"):
                uid = f"Synthetic {name} <{name}@example.invalid>"
                gpg(
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--quick-generate-key",
                    uid,
                    "ed25519",
                    "cert,sign",
                    "0",
                )
                listing = gpg("--with-colons", "--list-keys", uid).decode()
                keys.append(
                    next(
                        line.split(":")[9]
                        for line in listing.splitlines()
                        if line.startswith("fpr:")
                    )
                )
            primary, other = keys
            gpg(
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-add-key",
                primary,
                "ed25519",
                "sign",
                "0",
            )
            fingerprints = [
                line.split(":")[9]
                for line in gpg("--with-colons", "--list-keys", primary)
                .decode()
                .splitlines()
                if line.startswith("fpr:")
            ]
            public_key = home / "public.asc"
            # Both public keys are present: authorization must check fingerprint,
            # not just whether the signature can be verified by an imported key.
            public_key.write_bytes(gpg("--armor", "--export"))
            tags = {}
            for name, signer in (
                ("primary", primary),
                ("subkey", fingerprints[1]),
                ("unapproved", other),
            ):
                signature = gpg(
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--armor",
                    "--local-user",
                    signer + "!",
                    "--detach-sign",
                    data=PAYLOAD,
                )
                tags[name] = PAYLOAD + signature
            yield primary, public_key, tags
        finally:
            subprocess.run(
                ["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
                capture_output=True,
                check=False,
                timeout=10,
            )


@pytest.mark.parametrize("name", ["primary", "subkey"])
def test_real_gpg_accepts_approved_primary_and_subkey(
    signed_tags, monkeypatch, name
) -> None:
    primary, public_key, tags = signed_tags
    monkeypatch.setattr(verifier, "APPROVED_PRIMARY", primary)
    monkeypatch.setattr(verifier, "PUBLIC_KEY", public_key)
    raw = tags[name]
    assert verifier.verify(raw, TAG, object_id(raw), SOURCE) == primary


@pytest.mark.parametrize(
    "damage",
    [
        "unapproved",
        "tampered",
        "object-id",
        "source",
        "name",
        "unsigned",
        "multiple",
        "trailing",
        "nested",
        "header",
        "oversized",
    ],
)
def test_real_gpg_rejects_unauthorized_or_changed_tag(
    signed_tags, monkeypatch, damage
) -> None:
    primary, public_key, tags = signed_tags
    monkeypatch.setattr(verifier, "APPROVED_PRIMARY", primary)
    monkeypatch.setattr(verifier, "PUBLIC_KEY", public_key)
    raw, tag, source = tags["primary"], TAG, SOURCE
    if damage == "unapproved":
        raw = tags["unapproved"]
    elif damage == "tampered":
        raw = raw.replace(b"Synthetic release", b"Altered release")
    elif damage == "source":
        source = "c" * 40
    elif damage == "name":
        tag = "v1.2.4"
    elif damage == "unsigned":
        raw = PAYLOAD
    elif damage == "multiple":
        raw += raw[raw.index(verifier.SIGNATURE_START) :]
    elif damage == "trailing":
        raw += b"unsigned content\n"
    elif damage == "nested":
        raw = raw.replace(b"type commit", b"type tag")
    elif damage == "header":
        raw = raw.replace(b"\n\nSynthetic", b"\nextra header\n\nSynthetic")
    elif damage == "oversized":
        raw = b"x" * (verifier.MAX_TAG_BYTES + 1)
    tag_sha = "0" * 40 if damage == "object-id" else object_id(raw)
    with pytest.raises(verifier.SignatureError):
        verifier.verify(raw, tag, tag_sha, source)


def test_gpg_process_isolated_and_no_failed_verification_status_is_accepted(
    signed_tags, monkeypatch
) -> None:
    _, public_key, tags = signed_tags
    monkeypatch.setattr(verifier, "PUBLIC_KEY", public_key)
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        assert "--no-options" in args and "--no-auto-key-retrieve" in args
        assert "--no-auto-key-import" in args and "--homedir" in args
        assert kwargs["timeout"] == 30
        if "--verify" in args:
            return subprocess.CompletedProcess(args, 1, good_status(), b"failure")
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(verifier.subprocess, "run", run)
    raw = tags["primary"]
    with pytest.raises(verifier.SignatureError):
        verifier.verify(raw, TAG, object_id(raw), SOURCE)
    assert len(calls) == 2
    assert not Path(calls[0][calls[0].index("--homedir") + 1]).exists()


def test_cli_fails_without_emitting_untrusted_content(tmp_path, capsys) -> None:
    path = tmp_path / "tag"
    path.write_bytes(b"secret-like untrusted contents")
    assert verifier.main([TAG, "a" * 40, SOURCE, str(path)]) == 1
    captured = capsys.readouterr()
    assert not captured.out and "secret-like" not in captured.err


def test_public_policy_has_exact_approved_fingerprint() -> None:
    assert verifier.APPROVED_PRIMARY == "02EBB31CC0032A86C2C0401A1534542E61DC82D3"
    assert verifier.PUBLIC_KEY.read_bytes().startswith(
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----"
    )
