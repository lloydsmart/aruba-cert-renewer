"""Local, per-device flock for one-shot renewal operations."""

import errno
import fcntl
import hashlib
import os
import stat
import sys
from contextlib import contextmanager

LIFECYCLE_DIRECTORY = "/run/aruba-cert-renewer-lifecycle"


class LifecycleLockError(ValueError):
    """The local lifecycle store is unsafe or unavailable."""


class LifecycleLockBusy(LifecycleLockError):
    """Another invocation owns this device's lifecycle lock."""


def lock_filename(canonical_host):
    return hashlib.sha256(canonical_host.encode("ascii")).hexdigest() + ".lock"


def _identity(metadata):
    return metadata.st_dev, metadata.st_ino


def _validate_directory(metadata):
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & 0o007
        or (metadata.st_mode & stat.S_IWGRP and metadata.st_gid != os.getegid())
    ):
        raise LifecycleLockError("Lifecycle lock directory has unsafe permissions")


def _validate_lock_file(metadata):
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size != 0
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise LifecycleLockError("Lifecycle lock file is unsafe")


@contextmanager
def lifecycle_lock(canonical_host):
    """Hold one host-visible lock until the protected operation completes."""
    directory_fd = lock_fd = None
    try:
        try:
            directory_fd = os.open(
                LIFECYCLE_DIRECTORY,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            _validate_directory(os.fstat(directory_fd))

            filename = lock_filename(canonical_host)
            lock_fd = os.open(
                filename,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                0o600,
                dir_fd=directory_fd,
            )
            metadata = os.fstat(lock_fd)
            _validate_lock_file(metadata)

            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise LifecycleLockBusy(
                        "Another lifecycle operation is already in progress for this switch"
                    ) from error
                raise

            metadata = os.fstat(lock_fd)
            _validate_lock_file(metadata)
            pathname = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
            if _identity(pathname) != _identity(metadata) or not stat.S_ISREG(
                pathname.st_mode
            ):
                raise LifecycleLockError(
                    "Lifecycle lock pathname changed during acquisition"
                )
        except OSError as error:
            raise LifecycleLockError(
                "Lifecycle lock is unavailable or unsafe"
            ) from error

        yield
    finally:
        active_error = sys.exc_info()[0] is not None
        close_error = None
        for descriptor in (lock_fd, directory_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError as error:
                    if close_error is None:
                        close_error = error
        if close_error is not None and not active_error:
            raise LifecycleLockError("Lifecycle lock release failed") from close_error
