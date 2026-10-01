import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import lifecycle_lock as locks
from aruba_cert_renewer import CSRSigningError, parse_identity


@pytest.fixture
def store(monkeypatch, tmp_path):
    directory = tmp_path / "lifecycle"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(locks, "LIFECYCLE_DIRECTORY", str(directory))
    return directory


def test_lock_is_persistent_reusable_and_keeps_inode(store):
    filename = store / locks.lock_filename("switch.example.com")
    with locks.lifecycle_lock("switch.example.com"):
        assert filename.is_file()
        first_inode = filename.stat().st_ino
        assert filename.stat().st_size == 0
        with (
            pytest.raises(locks.LifecycleLockBusy, match="already in progress"),
            locks.lifecycle_lock("switch.example.com"),
        ):
            pytest.fail("Same device acquired twice")
        with locks.lifecycle_lock("other.example.com"):
            pass

    with locks.lifecycle_lock("switch.example.com"):
        assert filename.stat().st_ino == first_inode
    assert filename.stat().st_ino == first_inode


def test_lock_releases_on_exception(store):
    with (
        pytest.raises(RuntimeError, match="synthetic"),
        locks.lifecycle_lock("switch.example.com"),
    ):
        raise RuntimeError("synthetic")
    with locks.lifecycle_lock("switch.example.com"):
        pass


def test_protected_oserror_propagates_and_releases_lock(store):
    operation_error = OSError("operation failed")
    with pytest.raises(OSError) as raised, locks.lifecycle_lock("switch.example.com"):
        raise operation_error
    assert raised.value is operation_error
    with locks.lifecycle_lock("switch.example.com"):
        pass


def test_close_failure_does_not_mask_protected_oserror(store, monkeypatch):
    operation_error = OSError("operation failed")
    original_close = os.close

    def close_then_fail(descriptor):
        original_close(descriptor)
        raise OSError("synthetic close failure")

    with monkeypatch.context() as patch:
        patch.setattr(locks.os, "close", close_then_fail)
        with (
            pytest.raises(OSError) as raised,
            locks.lifecycle_lock("switch.example.com"),
        ):
            raise operation_error
    assert raised.value is operation_error
    with locks.lifecycle_lock("switch.example.com"):
        pass


def test_close_failure_after_success_is_distinct_release_error(store, monkeypatch):
    original_close = os.close
    failed = False

    def close_then_fail_once(descriptor):
        nonlocal failed
        original_close(descriptor)
        if not failed:
            failed = True
            raise OSError("synthetic close failure")

    with (
        monkeypatch.context() as patch,
        pytest.raises(locks.LifecycleLockReleaseError, match="release failed"),
        locks.lifecycle_lock("switch.example.com"),
    ):
        patch.setattr(locks.os, "close", close_then_fail_once)
    assert failed
    with locks.lifecycle_lock("switch.example.com"):
        pass


def test_outer_exception_does_not_hide_release_failure(store, monkeypatch):
    original_close = os.close

    def close_then_fail(descriptor):
        original_close(descriptor)
        raise OSError("synthetic close failure")

    try:
        raise RuntimeError("unrelated outer exception")
    except RuntimeError:
        with (
            monkeypatch.context() as patch,
            pytest.raises(locks.LifecycleLockReleaseError, match="release failed"),
            locks.lifecycle_lock("switch.example.com"),
        ):
            patch.setattr(locks.os, "close", close_then_fail)


@pytest.mark.parametrize(
    "body_error",
    [
        CSRSigningError("known renewal failure"),
        RuntimeError("unexpected failure"),
        KeyboardInterrupt(),
        SystemExit(),
        BaseException(),
    ],
)
def test_body_exception_wins_over_close_failure(store, monkeypatch, body_error):
    original_close = os.close

    def close_then_fail(descriptor):
        original_close(descriptor)
        raise OSError("synthetic close failure")

    with monkeypatch.context() as patch:
        patch.setattr(locks.os, "close", close_then_fail)
        with (
            pytest.raises(type(body_error)) as raised,
            locks.lifecycle_lock("switch.example.com"),
        ):
            raise body_error
    assert raised.value is body_error


def test_acquisition_exception_wins_over_cleanup_failure(store, monkeypatch):
    acquisition_error = locks.LifecycleLockError("unsafe directory")
    original_close = os.close

    def close_then_fail(descriptor):
        original_close(descriptor)
        raise OSError("synthetic close failure")

    def reject_directory(metadata):
        raise acquisition_error

    with monkeypatch.context() as patch:
        patch.setattr(locks, "_validate_directory", reject_directory)
        patch.setattr(locks.os, "close", close_then_fail)
        with (
            pytest.raises(locks.LifecycleLockError) as raised,
            locks.lifecycle_lock("switch.example.com"),
        ):
            pytest.fail("Acquisition unexpectedly succeeded")
    assert raised.value is acquisition_error


def test_open_failure_is_classified_as_lock_error(store):
    store.rmdir()
    with (
        pytest.raises(locks.LifecycleLockError, match="unavailable or unsafe"),
        locks.lifecycle_lock("switch.example.com"),
    ):
        pytest.fail("Missing lifecycle store accepted")


def test_production_directory_metadata_rule(monkeypatch):
    metadata = SimpleNamespace(st_mode=stat.S_IFDIR | 0o770, st_uid=0, st_gid=10001)
    monkeypatch.setattr(locks.os, "geteuid", lambda: 10001)
    monkeypatch.setattr(locks.os, "getegid", lambda: 10001)
    locks._validate_directory(metadata)
    monkeypatch.setattr(locks.os, "getegid", lambda: 10002)
    with pytest.raises(locks.LifecycleLockError, match="directory"):
        locks._validate_directory(metadata)


def test_wrong_owner_lock_metadata_is_rejected(store):
    metadata = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600,
        st_uid=os.geteuid() + 1,
        st_nlink=1,
        st_size=0,
    )
    with pytest.raises(locks.LifecycleLockError, match="file is unsafe"):
        locks._validate_lock_file(metadata)


def test_native_owner_group_writable_directory_is_accepted(store):
    store.chmod(0o770)
    with locks.lifecycle_lock("switch.example.com"):
        pass


def test_independent_process_contends_for_same_lock(store):
    src = Path(__file__).resolve().parents[1] / "src"
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(src)!r})\n"
        "import lifecycle_lock as locks\n"
        f"locks.LIFECYCLE_DIRECTORY = {str(store)!r}\n"
        "with locks.lifecycle_lock('switch.example.com'):\n"
        "    pass\n"
    )
    with locks.lifecycle_lock("switch.example.com"):
        busy = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, check=False
        )
    released = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, check=False
    )
    assert busy.returncode != 0
    assert b"LifecycleLockBusy" in busy.stderr
    assert released.returncode == 0


def test_canonical_host_identity_gives_the_same_lock_filename():
    dns_upper = parse_identity("SWITCH.EXAMPLE.COM")["value"]
    dns_lower = parse_identity("switch.example.com")["value"]
    ipv6_long = parse_identity("2001:0DB8:0:0:0:0:0:1")["value"]
    ipv6_short = parse_identity("2001:db8::1")["value"]
    assert locks.lock_filename(dns_upper) == locks.lock_filename(dns_lower)
    assert locks.lock_filename(ipv6_long) == locks.lock_filename(ipv6_short)


@pytest.mark.parametrize(
    "unsafe_type", ["symlink", "directory", "fifo", "hardlink", "content", "mode"]
)
def test_unsafe_lock_file_is_rejected(store, tmp_path, unsafe_type):
    filename = store / locks.lock_filename("switch.example.com")
    if unsafe_type == "symlink":
        filename.symlink_to(tmp_path / "target")
    elif unsafe_type == "directory":
        filename.mkdir()
    elif unsafe_type == "fifo":
        os.mkfifo(filename, 0o600)
    else:
        filename.write_bytes(b"x" if unsafe_type == "content" else b"")
        filename.chmod(0o666 if unsafe_type == "mode" else 0o600)
        if unsafe_type == "hardlink":
            os.link(filename, tmp_path / "other-link")

    with (
        pytest.raises(locks.LifecycleLockError),
        locks.lifecycle_lock("switch.example.com"),
    ):
        pytest.fail("Unsafe lock file acquired")


@pytest.mark.parametrize("unsafe_type", ["missing", "symlink", "world_writable"])
def test_unsafe_or_missing_directory_fails_closed(store, tmp_path, unsafe_type):
    if unsafe_type == "missing":
        store.rmdir()
    elif unsafe_type == "symlink":
        store.rmdir()
        store.symlink_to(tmp_path, target_is_directory=True)
    else:
        store.chmod(0o777)

    with (
        pytest.raises(locks.LifecycleLockError),
        locks.lifecycle_lock("switch.example.com"),
    ):
        pytest.fail("Unsafe directory accepted")


def test_pathname_replacement_after_flock_fails_closed(store, monkeypatch):
    filename = store / locks.lock_filename("switch.example.com")
    original_flock = locks.fcntl.flock

    def replace_after_lock(fd, operation):
        original_flock(fd, operation)
        filename.rename(store / "old-lock")
        filename.write_bytes(b"")
        filename.chmod(0o600)

    monkeypatch.setattr(locks.fcntl, "flock", replace_after_lock)
    with (
        pytest.raises(locks.LifecycleLockError, match="pathname changed"),
        locks.lifecycle_lock("switch.example.com"),
    ):
        pytest.fail("Replaced pathname accepted")
