"""Synthetic channel tests for the Netmiko 4.8.0 SSH read boundary."""

from threading import Lock

import netmiko.base_connection as netmiko_base
import pytest
from netmiko.base_connection import BaseConnection
from netmiko.channel import SSHChannel
from netmiko.hp.hp_procurve import HPProcurveSSH

import bounded_netmiko
from bounded_netmiko import (
    SETUP_READ_BYTES,
    BoundedArubaConnection,
    BoundedSSHChannel,
    SSHOutputLimitError,
    assert_netmiko_contract,
)


class FakeChannel:
    def __init__(self, chunks=(), *, endless=False, close_error=False):
        self.chunks = list(chunks)
        self.endless = endless
        self.close_error = close_error
        self.requests = []
        self.writes = []
        self.closed = False

    def recv_ready(self):
        return bool(self.chunks) or self.endless

    def recv(self, size):
        self.requests.append(size)
        data = self.chunks.pop(0) if self.chunks else b"x" * size
        if len(data) > size:
            self.chunks.insert(0, data[size:])
        return data[:size]

    def sendall(self, data):
        self.writes.append(data)

    def close(self):
        self.closed = True
        if self.close_error:
            raise OSError("synthetic close failure")

    def settimeout(self, value):
        self.timeout = value


class FakeSSHClient:
    def __init__(self, channel):
        self.channel = channel
        self.closed = False
        self.connected = False

    def connect(self, **kwargs):
        self.connected = True

    def invoke_shell(self, **kwargs):
        return self.channel

    def close(self):
        self.closed = True


def make_connection(chunks=(), **kwargs):
    conn = BoundedArubaConnection.__new__(BoundedArubaConnection)
    conn._bounded_channel_poisoned = False
    conn._budget_scope_active = False
    conn._read_buffer = ""
    conn.remote_conn = FakeChannel(chunks, **kwargs)
    conn.remote_conn_pre = FakeChannel()
    conn.encoding = "utf-8"
    conn.channel = BoundedSSHChannel(conn.remote_conn, conn.encoding, conn)
    conn._session_locker = Lock()
    conn.session_timeout = 1
    conn.disable_lf_normalization = False
    conn.ansi_escape_codes = True
    conn.RETURN = "\n"
    conn.RESPONSE_RETURN = "\n"
    conn.session_log = None
    return conn


def test_dependency_and_installation_contract():
    assert_netmiko_contract()
    assert issubclass(BoundedArubaConnection, HPProcurveSSH)
    assert issubclass(BoundedSSHChannel, SSHChannel)


def test_dependency_drift_fails_closed(monkeypatch):
    monkeypatch.setattr(bounded_netmiko, "version", lambda name: "4.9.0")
    with pytest.raises(RuntimeError, match="review the bounded SSH channel"):
        assert_netmiko_contract()


def test_ansi_method_drift_fails_closed(monkeypatch):
    monkeypatch.setattr(bounded_netmiko, "ANSI_METHOD_SHA256", "0" * 64)
    with pytest.raises(RuntimeError, match="review the bounded SSH channel"):
        assert_netmiko_contract()


def test_hook_installs_guard_before_first_setup_read(monkeypatch):
    observed = []

    def fake_constructor(self, **kwargs):
        self.remote_conn = FakeChannel([b"prompt#"])
        self.remote_conn_pre = FakeChannel()
        self.encoding = "utf-8"
        self.RETURN = "\n"
        self.RESPONSE_RETURN = "\n"
        self.channel = SSHChannel(self.remote_conn, self.encoding)
        self.special_login_handler()
        observed.append(type(self.channel))
        observed.append(self.channel.read_channel())

    monkeypatch.setattr(BaseConnection, "__init__", fake_constructor)
    BoundedArubaConnection()
    assert observed == [BoundedSSHChannel, "prompt#"]


def test_real_netmiko_constructor_installs_guard_before_first_cli_read(monkeypatch):
    assert_netmiko_contract()
    events = []
    channel = FakeChannel([b"prompt#"])
    client = FakeSSHClient(channel)
    original_constructor = SSHChannel
    original_bounded_read = BoundedSSHChannel.read_buffer

    def create_ordinary_channel(*args, **kwargs):
        events.append("ordinary channel constructed")
        return original_constructor(*args, **kwargs)

    def bounded_read(self):
        events.append("bounded first read")
        return original_bounded_read(self)

    def unbounded_read(self):
        pytest.fail("ordinary channel read before bounded installation")

    def prepare(self):
        self.ansi_escape_codes = True
        events.append("session preparation")
        assert type(self.channel) is BoundedSSHChannel
        assert self.read_channel() == "prompt#"

    monkeypatch.setattr(netmiko_base, "SSHChannel", create_ordinary_channel)
    monkeypatch.setattr(SSHChannel, "read_buffer", unbounded_read)
    monkeypatch.setattr(BoundedSSHChannel, "read_buffer", bounded_read)
    # The checked vendor method is instrumented below; its source was checked
    # above before instrumentation.
    monkeypatch.setattr(bounded_netmiko, "assert_netmiko_contract", lambda: None)
    monkeypatch.setattr(HPProcurveSSH, "session_preparation", prepare)
    monkeypatch.setattr(
        BoundedArubaConnection, "_build_ssh_client", lambda self: client
    )
    connection = BoundedArubaConnection(
        device_type="aruba_osswitch", host="switch.example.invalid", auto_connect=True
    )
    assert events[:3] == [
        "ordinary channel constructed",
        "session preparation",
        "bounded first read",
    ]
    assert client.connected
    connection._dispose_poisoned()
    connection.disconnect()


def test_real_session_preparation_rejects_ansi_expansion(monkeypatch):
    channel = FakeChannel([b"\x1b[100000L"])
    client = FakeSSHClient(channel)
    monkeypatch.setattr(
        BoundedArubaConnection, "_build_ssh_client", lambda self: client
    )
    with pytest.raises(SSHOutputLimitError, match="SSH read budget exceeded"):
        BoundedArubaConnection(
            device_type="aruba_osswitch",
            host="switch.example.invalid",
            auto_connect=True,
        )
    assert channel.requests
    assert channel.closed
    assert client.closed


@pytest.mark.parametrize("body", [b"", b"abc", "£".encode(), b"\xffa\xfe"])
def test_finite_reads_preserve_netmiko_decode(body):
    conn = make_connection([body] if body else [])
    with conn.read_budget(max(1, len(body))):
        assert conn.channel.read_channel() == body.decode("utf-8", "ignore")
    assert not conn.poisoned


def test_exact_budget_and_one_byte_overflow():
    conn = make_connection([b"abcde"])
    with (
        conn.read_budget(4),
        pytest.raises(SSHOutputLimitError, match="SSH read budget exceeded") as error,
    ):
        conn.channel.read_channel()
    assert b"abcde" not in str(error.value).encode()
    assert conn.channel.used == SETUP_READ_BYTES * 0
    assert conn.poisoned
    assert conn.remote_conn is None
    assert conn.channel.remote_conn.closed
    assert conn.channel.remote_conn.requests == [5]

    exact = make_connection([b"abcd"])
    with exact.read_budget(4):
        assert exact.channel.read_channel() == "abcd"
    assert not exact.poisoned


def test_endless_one_byte_producer_stops_and_poison_blocks_io():
    conn = make_connection([], endless=True, close_error=True)
    fake = conn.remote_conn
    with conn.read_budget(3), pytest.raises(SSHOutputLimitError):
        conn.channel.read_channel()
    assert fake.requests == [4]
    assert fake.closed
    before = (len(fake.requests), len(fake.writes))
    for operation in (
        lambda: conn.channel.read_channel(),
        lambda: conn.channel.write_channel("x"),
        lambda: conn.send_command("x"),
        lambda: conn.send_command_timing("x"),
        conn.config_mode,
        conn.exit_config_mode,
    ):
        with pytest.raises(SSHOutputLimitError):
            operation()
    conn.disconnect()
    assert (len(fake.requests), len(fake.writes)) == before


def test_one_byte_chunks_cannot_evade_cumulative_limit():
    conn = make_connection([b"x"] * 4)
    with conn.read_budget(3), pytest.raises(SSHOutputLimitError):
        conn.channel.read_channel()
    assert conn.channel.remote_conn.requests == [4, 3, 2, 1]


def test_prompt_after_limit_is_rejected_without_truncated_success():
    conn = make_connection([b"body#"])
    with conn.read_budget(4), pytest.raises(SSHOutputLimitError):
        conn.channel.read_channel()
    assert conn.poisoned

    exact = make_connection([b"body#"])
    with exact.read_budget(5):
        assert exact.channel.read_channel().endswith("#")


def test_poisoned_disconnect_skips_procurve_cleanup(monkeypatch):
    conn = make_connection([b"abc"])
    monkeypatch.setattr(
        HPProcurveSSH,
        "cleanup",
        lambda *args, **kwargs: pytest.fail("protocol cleanup attempted"),
    )
    with conn.read_budget(2), pytest.raises(SSHOutputLimitError):
        conn.channel.read_channel()
    conn.disconnect()


def test_default_budget_and_scopes_restore_on_success_and_error():
    conn = make_connection([b"a"])
    assert (conn.channel.limit, conn.channel.used) == (SETUP_READ_BYTES, 0)
    assert conn.channel.read_channel() == "a"
    with conn.read_budget(5):
        assert (conn.channel.limit, conn.channel.used) == (5, 0)
        with pytest.raises(RuntimeError, match="Nested"), conn.read_budget(5):
            pass
    assert (conn.channel.limit, conn.channel.used) == (SETUP_READ_BYTES, 1)
    with pytest.raises(OSError), conn.read_budget(6):
        raise OSError("synthetic")
    assert (conn.channel.limit, conn.channel.used) == (SETUP_READ_BYTES, 1)


def test_retained_read_buffer_is_charged_on_scope_entry():
    conn = make_connection()
    conn._read_buffer = "é" * 3
    with pytest.raises(SSHOutputLimitError), conn.read_budget(5):
        pass
    assert conn.poisoned

    conn = make_connection([b"z"])
    conn._read_buffer = "é" * 3
    with conn.read_budget(7):
        assert conn.channel.read_channel() == "z"
    assert not conn.poisoned


def test_retained_buffer_is_charged_when_restoring_default_budget():
    conn = make_connection()
    conn.channel.used = SETUP_READ_BYTES - 2
    with pytest.raises(SSHOutputLimitError), conn.read_budget(10):
        conn._read_buffer = "abc"
    assert conn.poisoned


def test_retained_buffer_overflow_does_not_mask_original_error():
    conn = make_connection()
    conn.channel.used = SETUP_READ_BYTES - 2
    with pytest.raises(OSError, match="primary"), conn.read_budget(10):
        conn._read_buffer = "abc"
        raise OSError("primary")
    assert conn.poisoned


def test_setup_exact_limit_and_overflow():
    exact = make_connection([b"a" * SETUP_READ_BYTES])
    assert len(exact.channel.read_channel()) == SETUP_READ_BYTES
    overflow = make_connection([b"a" * (SETUP_READ_BYTES + 1)])
    with pytest.raises(SSHOutputLimitError):
        overflow.channel.read_channel()
    assert overflow.poisoned


def test_read_exception_propagates_without_poison():
    conn = make_connection([b""])
    with pytest.raises(Exception, match="Channel stream closed"):
        conn.channel.read_buffer()
    assert not conn.poisoned


def test_actual_netmiko_read_rejects_small_raw_ansi_bomb_before_expansion(monkeypatch):
    body = b"x\x1b[100000L"
    conn = make_connection([body], close_error=True)
    original = BaseConnection.strip_ansi_escape_codes

    def forbid_expansion(self, value):
        if bounded_netmiko.ANSI_INSERT_LINE.search(value):
            pytest.fail("Netmiko expansion was reached")
        return original(self, value)

    monkeypatch.setattr(BaseConnection, "strip_ansi_escape_codes", forbid_expansion)
    with pytest.raises(SSHOutputLimitError, match="SSH read budget exceeded") as error:
        conn.read_channel()
    assert body.decode() not in str(error.value)
    assert conn.poisoned
    assert conn.channel.remote_conn.closed
    assert conn.channel.processed_used == 0
    calls = (
        len(conn.channel.remote_conn.requests),
        len(conn.channel.remote_conn.writes),
    )
    with pytest.raises(SSHOutputLimitError):
        conn.read_channel()
    with pytest.raises(SSHOutputLimitError):
        conn.write_channel("x")
    assert (
        len(conn.channel.remote_conn.requests),
        len(conn.channel.remote_conn.writes),
    ) == calls
    monkeypatch.setattr(BaseConnection, "strip_ansi_escape_codes", original)


def test_ansi_removal_cannot_create_unchecked_insert_line():
    body = b"\x1b[\x1b[2J100000L"
    conn = make_connection([body])
    with pytest.raises(SSHOutputLimitError):
        conn.read_channel()
    assert conn.poisoned


def test_processed_boundary_uses_output_after_safe_ansi_removal():
    conn = make_connection([b"\x1b[2J\x1b[5L"])
    with conn.read_budget(9):
        conn.channel.processed_limit = 5
        assert conn.read_channel() == "\n" * 5
    assert not conn.poisoned


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (b"abc", "abc"),
        (b"\x1bE", "\n"),
        (b"\x1b[0L", ""),
        (b"\x1b[0002L", "\n" * 2),
        (b"\x1b[5L", "\n" * 5),
        ("\x1b[٥L".encode(), "\n" * 5),
        (b"\x1b[2L\x1b[9L", "\n" * 4),
        (b"\x1b[9L\x1b[2L", "\n" * 18),
    ],
)
def test_processed_output_matches_netmiko_first_count_semantics(body, expected):
    conn = make_connection([body])
    with conn.read_budget(max(len(body), len(expected))):
        assert conn.read_channel() == expected
        assert conn.channel.processed_used == len(expected)
    assert not conn.poisoned


def test_processed_exact_boundary_and_one_over():
    exact = make_connection([b"\x1b[5L"])
    with exact.read_budget(5):
        assert exact.read_channel() == "\n" * 5
    over = make_connection([b"\x1b[6L"])
    with over.read_budget(5), pytest.raises(SSHOutputLimitError):
        over.read_channel()
    assert over.poisoned
    assert over.channel.processed_used == 0


def test_processed_expansion_is_cumulative_across_reads():
    conn = make_connection([b"\x1b[3L"])
    with conn.read_budget(8):
        conn.channel.processed_limit = 5
        assert conn.read_channel() == "\n" * 3
        conn.channel.remote_conn.chunks.append(b"\x1b[3L")
        with pytest.raises(SSHOutputLimitError):
            conn.read_channel()
    assert conn.poisoned


def test_very_long_decimal_rejected_before_int_or_netmiko_expansion(monkeypatch):
    body = b"\x1b[" + b"0" * 10000 + b"1L"
    conn = make_connection([body])
    original = BaseConnection.strip_ansi_escape_codes

    def forbid_expansion(self, value):
        if bounded_netmiko.ANSI_INSERT_LINE.search(value):
            pytest.fail("Netmiko decimal parsing was reached")
        return original(self, value)

    monkeypatch.setattr(
        BaseConnection,
        "strip_ansi_escape_codes",
        forbid_expansion,
    )
    with conn.read_budget(len(body)), pytest.raises(SSHOutputLimitError):
        conn.read_channel()
    assert conn.poisoned


def test_processed_default_scope_accounts_retained_expanded_text():
    conn = make_connection()
    conn.channel.processed_used = SETUP_READ_BYTES - 2
    with pytest.raises(SSHOutputLimitError), conn.read_budget(10):
        conn._read_buffer = "abc"
    assert conn.poisoned


def test_processed_retained_text_is_charged_once_within_scope():
    conn = make_connection([b"c"])
    conn._read_buffer = "ab"
    with conn.read_budget(3):
        assert conn.read_channel() == "abc"
        assert conn.channel.processed_used == 3
    assert not conn.poisoned


def test_repeated_scopes_do_not_reset_retained_processed_cost():
    conn = make_connection()
    conn.channel.processed_used = SETUP_READ_BYTES - 3
    conn._read_buffer = "ab"
    with conn.read_budget(10):
        pass
    assert conn.channel.processed_used == SETUP_READ_BYTES - 1
    with pytest.raises(SSHOutputLimitError), conn.read_budget(10):
        pass
    assert conn.poisoned


def test_plain_text_processed_limit_is_cumulative():
    conn = make_connection([b"abc"])
    with conn.read_budget(3), pytest.raises(SSHOutputLimitError):
        conn.channel.processed_limit = 2
        conn.read_channel()
    assert conn.poisoned


def test_raw_budget_precedes_ansi_processing_with_invalid_utf8():
    conn = make_connection([b"\xff" * 6 + b"\x1b[5L"])
    with conn.read_budget(5), pytest.raises(SSHOutputLimitError):
        conn.read_channel()
    assert conn.channel.processed_used == 0


def test_non_ansi_read_still_charges_processed_text():
    conn = make_connection([b"abc"])
    conn.ansi_escape_codes = False
    with conn.read_budget(3):
        assert conn.read_channel() == "abc"
        assert conn.channel.processed_used == 3
