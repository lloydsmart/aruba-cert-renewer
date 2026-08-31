"""Safe opening for local files that influence security-sensitive behavior."""

import errno
import os
import stat


class SecureFileError(ValueError):
    """A safe-to-display error for an untrusted local file."""


def _error_message(source_name, condition, path, disclose_path):
    message = f"{source_name} {condition}"
    if disclose_path:
        message = f"{message}: {path}"
    return message


def _raise_file_error(source_name, condition, path, disclose_path):
    raise SecureFileError(
        _error_message(source_name, condition, path, disclose_path)
    ) from None


def _raise_open_error(source_name, path, disclose_path, error):
    if not disclose_path:
        _raise_file_error(source_name, "could not be read", path, False)

    if isinstance(error, FileNotFoundError):
        _raise_file_error(source_name, "not found", path, True)

    _raise_file_error(source_name, "cannot be read", path, True)


def _check_opened_metadata(file_status, source_name, path, disclose_path):
    if not stat.S_ISREG(file_status.st_mode):
        _raise_file_error(
            source_name,
            "is not a regular file",
            path,
            disclose_path,
        )

    try:
        effective_uid = os.geteuid()
    except AttributeError:
        _raise_file_error(
            source_name,
            "ownership cannot be validated on this platform",
            path,
            disclose_path,
        )
    if file_status.st_uid not in {0, effective_uid}:
        _raise_file_error(
            source_name,
            "has an untrusted owner",
            path,
            disclose_path,
        )

    if file_status.st_mode & stat.S_IWGRP:
        _raise_file_error(
            source_name,
            "is group-writable",
            path,
            disclose_path,
        )

    if file_status.st_mode & stat.S_IWOTH:
        _raise_file_error(
            source_name,
            "is world-writable",
            path,
            disclose_path,
        )


def _lstat_for_fallback(path, source_name, disclose_path):
    try:
        file_status = os.lstat(path)
    except OSError as error:
        _raise_open_error(source_name, path, disclose_path, error)

    if stat.S_ISLNK(file_status.st_mode):
        _raise_file_error(
            source_name,
            "is a symbolic link",
            path,
            disclose_path,
        )
    if not stat.S_ISREG(file_status.st_mode):
        _raise_file_error(
            source_name,
            "is not a regular file",
            path,
            disclose_path,
        )
    return file_status


def _raise_classified_open_error(source_name, path, disclose_path, error):
    try:
        file_status = os.lstat(path)
    except OSError:
        _raise_open_error(source_name, path, disclose_path, error)

    if stat.S_ISLNK(file_status.st_mode):
        _raise_file_error(
            source_name,
            "is a symbolic link",
            path,
            disclose_path,
        )
    if not stat.S_ISREG(file_status.st_mode):
        _raise_file_error(
            source_name,
            "is not a regular file",
            path,
            disclose_path,
        )
    _raise_open_error(source_name, path, disclose_path, error)


def open_secure_file(path, *, source_name, disclose_path=True):
    """Open and validate an existing security-sensitive file as binary.

    The returned file owns its descriptor and is intended for use as a context
    manager. The final path component is not followed where ``O_NOFOLLOW`` is
    available. On other platforms, pre- and post-open ``lstat`` results are
    compared with the opened descriptor as a defensive fallback.
    """

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)

    before_open = None
    if not nofollow:
        before_open = _lstat_for_fallback(path, source_name, disclose_path)
    else:
        flags |= nofollow

    try:
        file_descriptor = os.open(path, flags)
    except OSError as error:
        if nofollow and error.errno == errno.ELOOP:
            _raise_file_error(
                source_name,
                "is a symbolic link",
                path,
                disclose_path,
            )
        _raise_classified_open_error(
            source_name,
            path,
            disclose_path,
            error,
        )

    try:
        try:
            opened_status = os.fstat(file_descriptor)
        except OSError:
            _raise_file_error(
                source_name,
                "cannot be inspected safely",
                path,
                disclose_path,
            )
        if not stat.S_ISREG(opened_status.st_mode):
            _raise_file_error(
                source_name,
                "is not a regular file",
                path,
                disclose_path,
            )

        if before_open is not None:
            try:
                after_open = os.lstat(path)
            except OSError:
                _raise_file_error(
                    source_name,
                    "changed while being opened",
                    path,
                    disclose_path,
                )

            expected_identity = (before_open.st_dev, before_open.st_ino)
            if (
                stat.S_ISLNK(after_open.st_mode)
                or (after_open.st_dev, after_open.st_ino) != expected_identity
                or (opened_status.st_dev, opened_status.st_ino) != expected_identity
            ):
                _raise_file_error(
                    source_name,
                    "changed while being opened",
                    path,
                    disclose_path,
                )

        _check_opened_metadata(
            opened_status,
            source_name,
            path,
            disclose_path,
        )

        try:
            return os.fdopen(file_descriptor, "rb", closefd=True)
        except OSError:
            _raise_file_error(
                source_name,
                "cannot be read",
                path,
                disclose_path,
            )
    except BaseException:
        os.close(file_descriptor)
        raise
