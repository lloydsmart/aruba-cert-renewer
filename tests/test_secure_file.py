import os
import stat
from types import SimpleNamespace

import pytest

import secure_file


@pytest.mark.parametrize("mode", [0o600, 0o400, 0o440, 0o640])
def test_open_secure_file_accepts_trusted_owner_without_unsafe_write_bits(
    tmp_path, mode
):
    path = tmp_path / "sensitive-file"
    path.write_bytes(b"safe contents")
    path.chmod(mode)

    with secure_file.open_secure_file(path, source_name="Sensitive file") as file:
        assert file.read() == b"safe contents"


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        (0o620, "group-writable"),
        (0o602, "world-writable"),
    ],
)
def test_open_secure_file_rejects_unsafe_write_permissions(tmp_path, mode, message):
    path = tmp_path / "sensitive-file"
    path.write_bytes(b"secret contents")
    path.chmod(mode)

    with pytest.raises(secure_file.SecureFileError, match=message) as raised:
        secure_file.open_secure_file(path, source_name="Sensitive file")

    assert "secret contents" not in str(raised.value)


def test_open_secure_file_rejects_final_component_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"contents")
    link = tmp_path / "link"
    link.symlink_to(target)

    with pytest.raises(secure_file.SecureFileError, match="symbolic link"):
        secure_file.open_secure_file(link, source_name="Sensitive file")


def test_open_secure_file_rejects_directory(tmp_path):
    with pytest.raises(secure_file.SecureFileError, match="not a regular file"):
        secure_file.open_secure_file(tmp_path, source_name="Sensitive file")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable")
def test_open_secure_file_rejects_fifo_without_blocking(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)

    with pytest.raises(secure_file.SecureFileError, match="not a regular file"):
        secure_file.open_secure_file(fifo, source_name="Sensitive file")


@pytest.mark.parametrize("owner_uid", [0, 10001])
def test_metadata_policy_trusts_root_and_effective_user(monkeypatch, owner_uid):
    monkeypatch.setattr(secure_file.os, "geteuid", lambda: 10001)
    file_status = SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_uid=owner_uid)

    secure_file._check_opened_metadata(
        file_status,
        "Sensitive file",
        "unused",
        False,
    )


def test_metadata_policy_rejects_unrelated_owner(monkeypatch):
    monkeypatch.setattr(secure_file.os, "geteuid", lambda: 10001)
    file_status = SimpleNamespace(st_mode=stat.S_IFREG | 0o400, st_uid=20002)

    with pytest.raises(secure_file.SecureFileError, match="untrusted owner"):
        secure_file._check_opened_metadata(
            file_status,
            "Sensitive file",
            "unused",
            False,
        )


def test_fallback_rejects_symlink_when_nofollow_is_unavailable(monkeypatch, tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"contents")
    link = tmp_path / "link"
    link.symlink_to(target)
    monkeypatch.delattr(secure_file.os, "O_NOFOLLOW", raising=False)

    with pytest.raises(secure_file.SecureFileError, match="symbolic link"):
        secure_file.open_secure_file(link, source_name="Sensitive file")


def test_fallback_accepts_unchanged_regular_file(monkeypatch, tmp_path):
    path = tmp_path / "sensitive-file"
    path.write_bytes(b"contents")
    path.chmod(0o600)
    monkeypatch.delattr(secure_file.os, "O_NOFOLLOW", raising=False)

    with secure_file.open_secure_file(path, source_name="Sensitive file") as file:
        assert file.read() == b"contents"


def test_fallback_rejects_identity_change_and_closes_descriptor(monkeypatch, tmp_path):
    path = tmp_path / "sensitive-file"
    path.write_bytes(b"contents")
    path.chmod(0o600)
    actual_status = os.lstat(path)
    lstat_results = iter(
        [
            actual_status,
            SimpleNamespace(
                st_mode=actual_status.st_mode,
                st_dev=actual_status.st_dev,
                st_ino=actual_status.st_ino + 1,
            ),
        ]
    )
    opened_descriptors = []
    original_open = os.open
    original_fstat = os.fstat
    monkeypatch.delattr(secure_file.os, "O_NOFOLLOW", raising=False)
    monkeypatch.setattr(
        secure_file.os, "lstat", lambda unused_path: next(lstat_results)
    )
    monkeypatch.setattr(
        secure_file.os,
        "open",
        lambda opened_path, flags: (
            opened_descriptors.append(original_open(opened_path, flags))
            or opened_descriptors[-1]
        ),
    )

    with pytest.raises(secure_file.SecureFileError, match="changed while being opened"):
        secure_file.open_secure_file(path, source_name="Sensitive file")

    with pytest.raises(OSError):
        original_fstat(opened_descriptors[0])


def test_supported_open_hardening_flags_are_used(monkeypatch, tmp_path):
    path = tmp_path / "sensitive-file"
    path.write_bytes(b"contents")
    path.chmod(0o600)
    captured_flags = []
    original_open = os.open

    def capture_open(opened_path, flags):
        captured_flags.append(flags)
        return original_open(opened_path, flags)

    monkeypatch.setattr(secure_file.os, "open", capture_open)

    with secure_file.open_secure_file(path, source_name="Sensitive file") as file:
        assert file.read() == b"contents"

    access_mode_mask = getattr(os, "O_ACCMODE", 3)
    assert captured_flags[0] & access_mode_mask == os.O_RDONLY
    for flag_name in ("O_CLOEXEC", "O_NOFOLLOW"):
        flag = getattr(os, flag_name, 0)
        if flag:
            assert captured_flags[0] & flag
