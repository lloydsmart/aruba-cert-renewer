"""Raw-byte limits for the post-shell Aruba Netmiko channel."""

import hashlib
import inspect
import re
import sys
import unicodedata
from contextlib import contextmanager, suppress
from importlib.metadata import version

from netmiko import log
from netmiko.base_connection import BaseConnection
from netmiko.channel import SSHChannel
from netmiko.exceptions import ReadException
from netmiko.hp.hp_procurve import HPProcurveSSH
from netmiko.netmiko_globals import MAX_BUFFER

from bounded_paramiko import (
    BoundedSSHClient,
    BoundedSSHClientNoAuth,
    assert_paramiko_contract,
)

SETUP_READ_BYTES = 32 * 1024
FRAMING_BYTES = 4 * 1024
CONFIG_READ_BYTES = 4 * 1024
ANSI_INSERT_LINE = re.compile("\x1b" + r"\[(\d+)L")
# Exact Netmiko 4.8.0 implementation reviewed for all substitutions, including
# its first-count-for-all insert-line behavior. Any vendor edit needs review.
ANSI_METHOD_SHA256 = "f5e982ea02e8e69fe0af518fb9ac95f0ab1c0ff4f925065c17d662c84f1b677c"


class SSHOutputLimitError(ValueError):
    """The SSH channel supplied more raw bytes than the active budget."""


def assert_netmiko_contract():
    """Fail closed if the reviewed Netmiko construction/read path changes."""
    message = "Netmiko transport changed; review the bounded SSH channel before use"
    if version("netmiko") != "4.8.0":
        raise RuntimeError(message)
    try:
        establish = inspect.getsource(BaseConnection.establish_connection)
        channel = inspect.getsource(SSHChannel.read_channel)
        buffer = inspect.getsource(SSHChannel.read_buffer)
        ansi = inspect.getsource(BaseConnection.strip_ansi_escape_codes)
    except (OSError, TypeError) as error:
        raise RuntimeError(message) from error
    if not (
        issubclass(HPProcurveSSH, BaseConnection)
        and "self.channel = SSHChannel(conn=self.remote_conn, encoding=self.encoding)"
        in establish
        and "self.special_login_handler()" in establish
        and establish.index("self.channel = SSHChannel(")
        < establish.index("self.special_login_handler()")
        and "self.read_buffer()" in channel
        and "self.remote_conn.recv(MAX_BUFFER)" in buffer
        and 'outbuf.decode(self.encoding, "ignore")' in buffer
        and hashlib.sha256(ansi.encode()).hexdigest() == ANSI_METHOD_SHA256
        and 'code_insert_line = chr(27) + r"\\[(\\d+)L"' in ansi
        and "insert_line_match = re.search(code_insert_line, output)" in ansi
        and "count = int(insert_line_match.group(1))" in ansi
        and "output = re.sub(code_insert_line, count * self.RETURN, output)" in ansi
        and hasattr(HPProcurveSSH, "special_login_handler")
    ):
        raise RuntimeError(message)


class BoundedSSHChannel(SSHChannel):
    def __init__(self, conn, encoding, owner):
        super().__init__(conn=conn, encoding=encoding)
        self.owner = owner
        self.limit = SETUP_READ_BYTES
        self.used = 0
        self.processed_limit = SETUP_READ_BYTES
        self.processed_used = 0
        self.poisoned = False

    def _require_healthy(self):
        if self.poisoned:
            raise SSHOutputLimitError("SSH read budget exceeded")

    def poison(self):
        self.poisoned = True
        self.owner._dispose_poisoned()

    def read_buffer(self):
        self._require_healthy()
        if self.remote_conn is None:
            raise ReadException("Attempt to read, but there is no active channel.")
        if not self.remote_conn.recv_ready():
            return ""
        raw = self.remote_conn.recv(min(MAX_BUFFER, self.limit - self.used + 1))
        if not raw:
            raise ReadException("Channel stream closed by remote device.")
        self.used += len(raw)
        if self.used > self.limit:
            self.poison()
            raise SSHOutputLimitError("SSH read budget exceeded")
        return raw.decode(self.encoding, "ignore")

    def read_channel(self):
        self._require_healthy()
        return super().read_channel()

    def write_channel(self, out_data):
        self._require_healthy()
        return super().write_channel(out_data)


class BoundedArubaConnection(HPProcurveSSH):
    """Install the bounded channel before Netmiko's first CLI read."""

    def __init__(self, **kwargs):
        assert_netmiko_contract()
        assert_paramiko_contract()
        self._bounded_channel_poisoned = False
        super().__init__(**kwargs)

    def _get_ssh_client_instance(self):
        if not self.use_keys and not self.allow_agent and not self.password:
            return BoundedSSHClientNoAuth()
        return BoundedSSHClient()

    def special_login_handler(self, delay_factor=1.0):
        if type(self.channel) is not SSHChannel:
            self._dispose_poisoned()
            raise RuntimeError("Netmiko channel construction changed")
        if self.RETURN != "\n" or self.RESPONSE_RETURN != "\n":
            self._dispose_poisoned()
            raise RuntimeError("Netmiko newline handling changed")
        self.channel = BoundedSSHChannel(self.remote_conn, self.encoding, self)

    def _require_healthy(self):
        if self._bounded_channel_poisoned:
            raise SSHOutputLimitError("SSH read budget exceeded")

    def _charge_processed(self, length):
        channel = self.channel
        if length < 0 or channel.processed_used + length > channel.processed_limit:
            channel.poison()
            raise SSHOutputLimitError("SSH read budget exceeded")
        channel.processed_used += length

    def strip_ansi_escape_codes(self, string_buffer):
        """Preflight Netmiko's numeric insert-line expansion before allocation."""
        self._require_healthy()
        channel = self.channel
        # Netmiko removes other ANSI codes before searching for insert-line
        # codes. Removal can create a new ESC[digitsL across the removed text.
        # Neutralize every L with a private-use character absent from the
        # bounded input, then let the pinned vendor method perform only its
        # safe removals and fixed newline substitution. Restore L for matching.
        if "L" in string_buffer:
            present = set(string_buffer)
            sentinel = next(
                chr(code)
                for code in range(0xF0000, 0x110000)
                if chr(code) not in present
            )
            safe_buffer = (
                super()
                .strip_ansi_escape_codes(string_buffer.replace("L", sentinel))
                .replace(sentinel, "L")
            )
        else:
            safe_buffer = string_buffer
        match_count = 0
        matched_length = 0
        first_digits = None
        for match in ANSI_INSERT_LINE.finditer(safe_buffer):
            match_count += 1
            matched_length += len(match.group())
            if first_digits is None:
                first_digits = match.group(1)

        if match_count:
            remaining = channel.processed_limit - channel.processed_used
            # The safe prefix has already removed other ANSI codes and applied
            # ESC E. Netmiko uses the FIRST L count for ALL L replacements.
            base = len(safe_buffer) - matched_length
            replacement_unit = match_count * len(self.RETURN)
            if base > remaining or replacement_unit == 0:
                channel.poison()
                raise SSHOutputLimitError("SSH read budget exceeded")
            maximum_count = (remaining - base) // replacement_unit
            maximum_digits = str(maximum_count)
            # Python permits this many digits even at its strictest configured
            # int() limit. Reject longer padded decimals before Netmiko's int().
            if len(first_digits) > sys.int_info.str_digits_check_threshold:
                channel.poison()
                raise SSHOutputLimitError("SSH read budget exceeded")
            # Unicode decimal digits match Netmiko's \d. Discard leading zeros
            # only for comparison; Netmiko still receives the original text.
            digits = (
                "".join(
                    chr(48 + unicodedata.decimal(char)) for char in first_digits
                ).lstrip("0")
                or "0"
            )
            if len(digits) > len(maximum_digits) or (
                len(digits) == len(maximum_digits) and digits > maximum_digits
            ):
                channel.poison()
                raise SSHOutputLimitError("SSH read budget exceeded")

        output = super().strip_ansi_escape_codes(string_buffer)
        self._charge_processed(len(output))
        return output

    def _dispose_poisoned(self):
        self._bounded_channel_poisoned = True
        for attr in ("remote_conn", "remote_conn_pre"):
            transport = getattr(self, attr, None)
            setattr(self, attr, None)
            if transport is not None:
                with suppress(Exception):
                    transport.close()

    @property
    def poisoned(self):
        return self._bounded_channel_poisoned

    @contextmanager
    def read_budget(self, limit):
        self._require_healthy()
        if not isinstance(limit, int) or limit <= 0:
            raise ValueError("SSH read budget must be a positive integer")
        if getattr(self, "_budget_scope_active", False):
            raise RuntimeError("Nested SSH read budgets are not supported")
        channel = self.channel
        if not isinstance(channel, BoundedSSHChannel):
            raise RuntimeError("Bounded SSH channel is missing")
        # Netmiko can retain text after a prompt match. Charge it again when a
        # new operation could consume it; its original raw bytes were charged.
        retained = len(self._read_buffer.encode("utf-8"))
        processed_retained = len(self._read_buffer)
        if retained > limit or processed_retained > limit:
            channel.poison()
            raise SSHOutputLimitError("SSH read budget exceeded")
        old_limit, old_used = channel.limit, channel.used
        old_processed_limit = channel.processed_limit
        old_processed_used = channel.processed_used
        self._budget_scope_active = True
        channel.limit, channel.used = limit, retained
        channel.processed_limit, channel.processed_used = limit, processed_retained
        try:
            yield
        finally:
            retained_after = len(self._read_buffer.encode("utf-8"))
            processed_after = len(self._read_buffer)
            channel.limit, channel.used = old_limit, old_used + retained_after
            channel.processed_limit = old_processed_limit
            channel.processed_used = old_processed_used + processed_after
            self._budget_scope_active = False
            if not channel.poisoned and (
                channel.used > channel.limit
                or channel.processed_used > channel.processed_limit
            ):
                channel.poison()
                if sys.exception() is None:
                    raise SSHOutputLimitError("SSH read budget exceeded")

    def read_channel(self):
        self._require_healthy()
        retained = len(self._read_buffer)
        output = super().read_channel()
        if not self.ansi_escape_codes:
            # The normal path charges inside strip_ansi_escape_codes(), before
            # Netmiko prepends already-accounted retained text.
            self._charge_processed(len(output) - retained)
        return output

    def write_channel(self, out_data):
        self._require_healthy()
        return super().write_channel(out_data)

    def send_command(self, *args, **kwargs):
        self._require_healthy()
        return super().send_command(*args, **kwargs)

    def send_command_timing(self, *args, **kwargs):
        self._require_healthy()
        return super().send_command_timing(*args, **kwargs)

    def config_mode(self, *args, **kwargs):
        self._require_healthy()
        return super().config_mode(*args, **kwargs)

    def exit_config_mode(self, *args, **kwargs):
        self._require_healthy()
        return super().exit_config_mode(*args, **kwargs)

    def disconnect(self):
        if self.poisoned:
            self._dispose_poisoned()
            session_log = getattr(self, "session_log", None)
            if session_log is not None:
                with suppress(Exception):
                    session_log.close()
            secrets_filter = getattr(self, "_secrets_filter", None)
            if secrets_filter is not None:
                log.removeFilter(secrets_filter)
            return
        return super().disconnect()
