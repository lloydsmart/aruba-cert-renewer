"""Paramiko 4.0.0 pre-authentication text boundary tests."""

import hashlib
import inspect
import socket
import struct
import threading

import netmiko
import paramiko
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from netmiko.base_connection import BaseConnection
from netmiko.exceptions import NetmikoTimeoutException
from paramiko.packet import Packetizer
from paramiko.transport import Transport

import bounded_paramiko
from bounded_netmiko import BoundedArubaConnection
from bounded_paramiko import (
    MAX_SSH_BANNER_LINE_BYTES,
    MAX_SSH_PACKET_LENGTH,
    MAX_SSH_PREAUTH_TEXT_BYTES,
    BoundedPacketizer,
    BoundedSSHClient,
    BoundedSSHClientNoAuth,
    SSHBannerLimitError,
    SSHBinaryPacketLimitError,
    assert_paramiko_contract,
)


class FakeSocket:
    def __init__(self, data=b"", *, chunk=None, endless=False, error=None):
        self.data = data
        self.chunk = chunk
        self.endless = endless
        self.error = error
        self.requests = []
        self.acquired = 0
        self.sends = 0
        self.closed = False
        self.sent_data = b""

    def recv(self, size):
        self.requests.append(size)
        assert size <= 300_000, "unsafe SSH recv request in test"
        if self.error:
            raise self.error
        if self.data:
            take = min(size, self.chunk or size)
            result, self.data = self.data[:take], self.data[take:]
        elif self.endless:
            result = b"x" * min(size, self.chunk or 128)
        else:
            result = b""
        self.acquired += len(result)
        return result

    def send(self, data):
        self.sends += 1
        self.sent_data += data
        return len(data)

    def settimeout(self, timeout):
        self.timeout = timeout

    def close(self):
        self.closed = True


def packetizer(data=b"", **kwargs):
    sock = FakeSocket(data, **kwargs)
    return BoundedPacketizer(sock), sock


def test_dependency_contract_and_chain():
    assert_paramiko_contract()
    assert paramiko.__version__ == "4.0.0"
    assert netmiko.__version__ == "4.8.0"
    assert issubclass(BoundedPacketizer, Packetizer)
    assert issubclass(BoundedArubaConnection, netmiko.hp.hp_procurve.HPProcurveSSH)
    conn = BoundedArubaConnection.__new__(BoundedArubaConnection)
    conn.use_keys, conn.allow_agent, conn.password = False, False, "synthetic"
    assert isinstance(conn._get_ssh_client_instance(), BoundedSSHClient)
    conn.password = ""
    assert isinstance(conn._get_ssh_client_instance(), BoundedSSHClientNoAuth)
    assert BoundedSSHClientNoAuth._auth is netmiko.ssh_auth.SSHClient_noauth._auth
    assert "self._get_ssh_client_instance()" in inspect.getsource(
        BaseConnection._build_ssh_client
    )


def test_dependency_drift_fails_before_network(monkeypatch):
    monkeypatch.setattr(bounded_paramiko, "version", lambda name: "4.9.0")
    with pytest.raises(RuntimeError, match="review the bounded Paramiko transport"):
        assert_paramiko_contract()


def test_packet_parser_source_drift_fails_before_network(monkeypatch):
    monkeypatch.setattr(bounded_paramiko, "_READ_MESSAGE_SHA256", "0" * 64)
    with pytest.raises(RuntimeError, match="review the bounded Paramiko transport"):
        assert_paramiko_contract()


def _make_wire_packet(mode, payload):
    """Use Paramiko's real writer and genuine cipher/MAC implementations."""
    sock = FakeSocket()
    writer = Packetizer(sock)
    key, iv, mac_key = b"k" * 16, b"i" * 16, b"m" * 32
    if mode == "classic" or mode == "etm":
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        writer.set_outbound_cipher(
            cipher.encryptor(),
            16,
            hashlib.sha256,
            32,
            mac_key,
            sdctr=True,
            etm=mode == "etm",
        )
    elif mode == "aead":
        writer.set_outbound_cipher(
            AESGCM(key), 16, None, 16, None, aead=True, iv_out=b"i" * 12
        )
    writer.send_message(paramiko.Message(payload))
    return sock.sent_data


def _reader_for_mode(reader, mode):
    key, iv, mac_key = b"k" * 16, b"i" * 16, b"m" * 32
    if mode == "classic" or mode == "etm":
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        reader.set_inbound_cipher(
            cipher.decryptor(),
            16,
            hashlib.sha256,
            32,
            mac_key,
            etm=mode == "etm",
        )
    elif mode == "aead":
        reader.set_inbound_cipher(
            AESGCM(key), 16, None, 16, None, aead=True, iv_in=b"i" * 12
        )


def _packet_payload(size=24):
    return b"\x02" + b"x" * (size - 1)


@pytest.mark.parametrize("mode", ["plain", "classic", "etm", "aead"])
def test_real_packet_parser_matches_upstream_for_valid_packet(mode):
    wire = _make_wire_packet(mode, _packet_payload())
    results = []
    for cls in (Packetizer, BoundedPacketizer):
        sock = FakeSocket(wire, chunk=3)
        reader = cls(sock)
        _reader_for_mode(reader, mode)
        command, message = reader.read_message()
        results.append((command, message.get_remainder(), message.seqno))
        assert max(sock.requests) <= len(wire)
    assert results[0] == results[1] == (2, b"x" * 23, 0)


@pytest.mark.parametrize("mode", ["classic", "etm", "aead"])
def test_upstream_authentication_still_rejects_tampered_packet(mode):
    wire = bytearray(_make_wire_packet(mode, _packet_payload()))
    wire[-1] ^= 1  # MAC or GCM tag
    for cls in (Packetizer, BoundedPacketizer):
        reader = cls(FakeSocket(bytes(wire)))
        _reader_for_mode(reader, mode)
        with pytest.raises((paramiko.SSHException, InvalidTag)):
            reader.read_message()
        if isinstance(reader, BoundedPacketizer):
            assert not reader.binary_packet_limit_exceeded


@pytest.mark.parametrize("length", [0xFFFFFFFC, 0xFFFFFFFF])
def test_malicious_plain_header_never_reaches_large_recv(length):
    header = struct.pack(">I", length) + b"\x04\x00\x00\x00"
    reader, sock = packetizer(header)
    with pytest.raises((SSHBinaryPacketLimitError, paramiko.SSHException)):
        reader.read_message()
    assert sock.requests == [8]
    if length == 0xFFFFFFFC:
        assert reader.binary_packet_limit_exceeded
        assert sock.closed


@pytest.mark.parametrize(
    ("mode", "excess"),
    [("classic", 12), ("etm", 1), ("etm", 16), ("aead", 1)],
)
def test_encrypted_over_limit_rejected_before_body_recv(mode, excess):
    # A real encrypted first block is enough: the body is never supplied.
    wire = _make_wire_packet(mode, _packet_payload())
    reader, sock = packetizer(wire[:16])
    _reader_for_mode(reader, mode)
    if mode == "classic":
        # Encrypt a valid aligned over-limit field with the genuine CTR cipher.
        field = MAX_SSH_PACKET_LENGTH + excess
        plain = struct.pack(">I", field) + b"\x04" + b"\x00" * 11
        sock.data = (
            Cipher(algorithms.AES(b"k" * 16), modes.CTR(b"i" * 16))
            .encryptor()
            .update(plain)
        )
    else:
        field = MAX_SSH_PACKET_LENGTH + excess
        sock.data = struct.pack(">I", field) + wire[4:16]
    with pytest.raises(SSHBinaryPacketLimitError):
        reader.read_message()
    assert sock.requests == [16]
    assert reader.binary_packet_limit_exceeded


def test_exact_etm_field_limit_and_one_block_over():
    # EtM excludes the clear four-byte field from block alignment.
    payload = _packet_payload(MAX_SSH_PACKET_LENGTH - 5)
    wire = _make_wire_packet("etm", payload)
    field = int.from_bytes(wire[:4], "big")
    assert field == MAX_SSH_PACKET_LENGTH
    reader, sock = packetizer(wire, chunk=4096)
    _reader_for_mode(reader, "etm")
    command, message = reader.read_message()
    assert command == 2
    assert message.get_remainder() == payload[1:]
    assert reader._packet_phase is None
    assert not reader.binary_packet_limit_exceeded
    assert max(sock.requests) <= MAX_SSH_PACKET_LENGTH


@pytest.mark.parametrize(
    ("mode", "field"),
    [
        ("plain", MAX_SSH_PACKET_LENGTH - 4),
        ("classic", MAX_SSH_PACKET_LENGTH - 4),
        ("aead", MAX_SSH_PACKET_LENGTH),
    ],
)
def test_largest_aligned_classic_and_exact_aead_packets(mode, field):
    wire = _make_wire_packet(mode, _packet_payload(field - 5))
    if mode in ("plain", "aead"):
        assert int.from_bytes(wire[:4], "big") == field
    reader, sock = packetizer(wire, chunk=4096)
    _reader_for_mode(reader, mode)
    command, message = reader.read_message()
    assert command == 2
    assert len(message.get_remainder()) == field - 6
    assert not reader.binary_packet_limit_exceeded
    if mode == "aead":
        # Tag bytes are bounded overhead outside packet_length.
        assert sock.requests[1] == field - 16 + 4 + 16
        assert sock.requests[1] > MAX_SSH_PACKET_LENGTH
    if mode == "classic":
        # Classic's combined body/MAC request includes 32 MAC bytes.
        assert sock.requests[1] == field - 16 + 4 + 32


def test_two_plain_packets_reset_guard_and_sequence():
    wire = _make_wire_packet("plain", _packet_payload()) * 2
    reader, _ = packetizer(wire)
    first, first_message = reader.read_message()
    second, second_message = reader.read_message()
    assert (first, second) == (2, 2)
    assert (first_message.seqno, second_message.seqno) == (0, 1)
    assert reader._packet_phase is None


def test_truncated_body_and_socket_error_do_not_leave_guard_armed():
    wire = _make_wire_packet("plain", _packet_payload())
    reader, _ = packetizer(wire[:8])
    with pytest.raises(EOFError):
        reader.read_message()
    assert reader._packet_phase is None
    assert not reader.binary_packet_limit_exceeded

    reader, _ = packetizer(wire[:8], error=OSError("synthetic socket error"))
    with pytest.raises(OSError, match="synthetic socket error"):
        reader.read_message()
    assert reader._packet_phase is None


@pytest.mark.parametrize(
    "wire",
    [
        b"\x00\x00\x00\x04\x04\x02\x00\x00",  # too small for a payload
        b"\x00\x00\x00\x05\x04\x02\x00\x00",  # classic misalignment
        b"\x00\x00\x00\x0c\xff\x02\x00\x00" + b"\x00" * 8,
    ],
)
def test_malformed_packets_remain_rejected(wire):
    reader, sock = packetizer(wire)
    with pytest.raises((SSHBinaryPacketLimitError, paramiko.SSHException, IndexError)):
        reader.read_message()
    assert max(sock.requests) <= len(wire)


def test_packet_limit_exceeds_rfc_interoperability_floor():
    # RFC 4253 requires support for 35,000 total bytes including the length
    # field and MAC; the no-MAC field component can therefore be 34,996.
    assert MAX_SSH_PACKET_LENGTH >= 35_000 - 4


def test_binary_remainder_and_fragmented_header_are_bounded():
    identification = b"SSH-2.0-test\r\n"
    header = bytes.fromhex("ff ff ff fc 04 00 00 00")
    for prefix in (8, 3):
        reader, sock = packetizer(identification + header[:prefix])
        assert reader.readline(1) == "SSH-2.0-test"
        sock.data = header[prefix:]
        with pytest.raises(SSHBinaryPacketLimitError):
            reader.read_message()
        assert max(sock.requests) <= 128


def test_valid_packet_body_spans_banner_remainder_and_socket():
    identification = b"SSH-2.0-test\r\n"
    wire = _make_wire_packet("plain", _packet_payload())
    reader, sock = packetizer(identification + wire[:10])
    assert reader.readline(1) == "SSH-2.0-test"
    sock.data = wire[10:]
    command, message = reader.read_message()
    assert command == 2
    assert message.get_remainder() == b"x" * 23
    assert not reader.binary_packet_limit_exceeded


def test_unexpected_packet_read_pattern_fails_closed(monkeypatch):
    reader, sock = packetizer(b"\x00" * 8)
    monkeypatch.setattr(reader, "_packet_phase", "body")
    reader._packet_block = 8
    reader._packet_mac = 0
    reader._packet_mode = "classic"
    with pytest.raises(SSHBinaryPacketLimitError):
        reader.read_all(MAX_SSH_PACKET_LENGTH + 100)
    assert sock.requests == []
    assert reader.binary_packet_limit_exceeded

    reader, sock = packetizer(b"\x00" * 16)
    reader._packet_phase = "body"
    reader._packet_block = 8
    reader._packet_mac = 0
    with pytest.raises(SSHBinaryPacketLimitError):
        reader.read_all(16)
    assert sock.requests == []


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"hello\n", "hello"),
        (b"\n", ""),
        (b"hello\r\n", "hello"),
        (b"SSH-2.0-test\n", "SSH-2.0-test"),
        (b"SSH-2.0-test\r\n", "SSH-2.0-test"),
        (b"SSH-2.0-" + "é".encode() * 20 + b"\n", "SSH-2.0-" + "é" * 20),
    ],
)
def test_normal_lines(data, expected):
    reader, sock = packetizer(data, chunk=1)
    assert reader.readline(1) == expected
    assert reader.text_bytes == len(data)
    assert sock.acquired == len(data)
    assert max(sock.requests) <= 128


def test_immediate_eof_and_socket_error():
    reader, _ = packetizer()
    with pytest.raises(EOFError):
        reader.readline(1)
    reader, _ = packetizer(error=OSError("synthetic socket error"))
    with pytest.raises(OSError, match="synthetic socket error"):
        reader.readline(1)
    reader, _ = packetizer(error=TimeoutError())
    with pytest.raises(TimeoutError):
        reader.readline(0)


@pytest.mark.parametrize("chunk", [1, 128, None])
def test_exact_line_boundary_and_next_byte(chunk):
    line = b"SSH-2.0-" + b"x" * (MAX_SSH_BANNER_LINE_BYTES - 9) + b"\n"
    assert len(line) == MAX_SSH_BANNER_LINE_BYTES
    reader, sock = packetizer(line, chunk=chunk)
    assert reader.readline(1) == line[:-1].decode()
    assert reader.text_bytes == 255
    assert sock.acquired == 255

    crlf = b"SSH-2.0-" + b"x" * (MAX_SSH_BANNER_LINE_BYTES - 10) + b"\r\n"
    reader, _ = packetizer(crlf)
    assert reader.readline(1) == crlf[:-2].decode()

    reader, sock = packetizer(line[:-1], chunk=chunk, endless=True)
    with pytest.raises(SSHBannerLimitError) as error:
        reader.readline(1)
    assert str(error.value) == "SSH banner resource limit exceeded"
    assert reader.banner_limit_exceeded
    assert sock.acquired == 255
    assert max(sock.requests) <= 128
    assert sock.requests[-1] == 1


def test_256_byte_terminated_line_rejected_without_overread():
    reader, sock = packetizer(b"x" * 255 + b"\n", chunk=128)
    with pytest.raises(SSHBannerLimitError):
        reader.readline(1)
    assert sock.acquired == 255
    assert sock.data == b"\n"
    assert len(sock.requests) == 2


def test_endless_and_slow_drip_are_finite():
    for chunk in (None, 1):
        reader, sock = packetizer(endless=True, chunk=chunk)
        with pytest.raises(SSHBannerLimitError):
            reader.readline(1)
        assert sock.acquired == 255
        assert reader.text_bytes == 255
        assert all(1 <= size <= 128 for size in sock.requests)


def test_line_count_and_cumulative_boundary():
    line = b"x" * 254 + b"\n"
    identification = b"SSH-2.0-" + b"y" * 246 + b"\n"
    assert len(identification) == 255
    reader, sock = packetizer(line * 99 + identification)
    for _ in range(99):
        assert reader.readline(1) == "x" * 254
    assert reader.pre_identification_lines == 99
    assert reader.readline(1).startswith("SSH-2.0-")
    assert reader.text_bytes == MAX_SSH_PREAUTH_TEXT_BYTES
    assert sock.acquired == MAX_SSH_PREAUTH_TEXT_BYTES

    reader, sock = packetizer(line * 100 + identification)
    for _ in range(99):
        reader.readline(1)
    with pytest.raises(SSHBannerLimitError):
        reader.readline(1)
    assert reader.pre_identification_lines == 99
    assert sock.acquired <= MAX_SSH_PREAUTH_TEXT_BYTES


def test_cumulative_budget_is_not_reset_for_a_new_line():
    reader, sock = packetizer(b"first\nxy\n")
    assert reader.readline(1) == "first"
    reader.text_bytes = MAX_SSH_PREAUTH_TEXT_BYTES - 1
    with pytest.raises(SSHBannerLimitError):
        reader.readline(1)
    assert sock.acquired <= len(b"first\nxy\n")
    assert reader.banner_limit_exceeded


def test_text_and_binary_remainders_are_preserved():
    reader, sock = packetizer(b"hello\nSSH-2.0-test\r\n" + b"\x00\x00\x00\x08")
    assert reader.readline(1) == "hello"
    assert reader.readline(1) == "SSH-2.0-test"
    assert reader.text_bytes == len(b"hello\nSSH-2.0-test\r\n")
    assert reader.read_all(4) == b"\x00\x00\x00\x08"
    assert sock.acquired == len(b"hello\nSSH-2.0-test\r\n\x00\x00\x00\x08")


def test_identification_remainder_enters_real_binary_packet_reader():
    identification = b"SSH-2.0-test\r\n"
    # Unencrypted SSH_MSG_IGNORE with a five-byte string payload. Four bytes
    # of packet length plus the 20-byte packet make three eight-byte blocks;
    # the nine padding bytes satisfy SSH's minimum of four.
    payload = b"\x02" + struct.pack(">I", 5) + b"probe"
    binary_packet = struct.pack(">I", 20) + b"\x09" + payload + b"\x00" * 9
    assert len(binary_packet) == 24
    reader, sock = packetizer(identification + binary_packet)

    assert reader.readline(1) == "SSH-2.0-test"
    assert reader.text_bytes == len(identification)
    assert reader._Packetizer__remainder == binary_packet
    assert sock.requests == [128]

    command, message = reader.read_message()
    assert command == paramiko.common.MSG_IGNORE
    assert message.get_string() == b"probe"
    assert message.get_remainder() == b""
    assert reader._Packetizer__remainder == b""
    assert reader.text_bytes == len(identification)
    assert sock.acquired == len(identification + binary_packet)
    assert sock.requests == [128]


def test_invalid_utf8_is_charged_before_strict_decode():
    reader, _ = packetizer(b"\xff\n")
    with pytest.raises(UnicodeDecodeError):
        reader.readline(1)
    assert reader.text_bytes == 2


def test_nul_is_not_normalized():
    reader, _ = packetizer(b"SSH-2.0-\x00test\n")
    assert "\x00" in reader.readline(1)


def test_paramiko_still_rejects_incompatible_protocol_version():
    transport = Transport(
        FakeSocket(b"SSH-1.0-old\n"), packetizer_class=BoundedPacketizer
    )
    with pytest.raises(paramiko.IncompatiblePeer):
        transport._check_banner()


def test_transport_installs_packetizer_and_preserves_disabled_algorithms():
    sock = FakeSocket()
    policy = {"ciphers": ["aes128-cbc"]}
    transport = bounded_paramiko._transport_factory(
        sock, gss_kex=False, gss_deleg_creds=True, disabled_algorithms=policy
    )
    assert type(transport) is Transport
    assert type(transport.packetizer) is BoundedPacketizer
    assert transport.disabled_algorithms is policy
    assert transport.sock is sock


def test_competing_factory_rejected_before_socket_use():
    client = BoundedSSHClient()
    sock = FakeSocket()
    with pytest.raises(ValueError, match="competing SSH transport"):
        client.connect("switch.example", sock=sock, transport_factory=Transport)
    assert not sock.requests
    assert not sock.closed


def test_compression_cannot_be_enabled_without_review():
    client = BoundedSSHClient()
    sock = FakeSocket()
    with pytest.raises(
        ValueError, match="compression requires a resource-policy review"
    ):
        client.connect("switch.example", sock=sock, compress=True)
    assert not sock.requests
    assert not sock.closed


def test_wrapped_overflow_becomes_content_free_project_error_and_closes():
    sock = FakeSocket(b"x" * 1000, chunk=128)
    client = BoundedSSHClient()
    with pytest.raises(SSHBannerLimitError) as error:
        client.connect(
            "switch.example", sock=sock, username="synthetic", password="synthetic"
        )
    assert str(error.value) == "SSH banner resource limit exceeded"
    assert sock.closed
    assert client.get_transport() is None
    assert sock.acquired == 255
    assert max(sock.requests) <= 128


def test_netmiko_chain_overflow_never_opens_shell_or_reconnects(tmp_path, monkeypatch):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("")
    sock = FakeSocket(b"x" * 1000)
    monkeypatch.setattr(
        BoundedSSHClient,
        "invoke_shell",
        lambda *args, **kwargs: pytest.fail("A shell must not open"),
    )
    with pytest.raises(SSHBannerLimitError):
        BoundedArubaConnection(
            device_type="aruba_osswitch",
            host="switch.example",
            username="synthetic",
            password="synthetic",
            sock=sock,
            alt_host_keys=True,
            alt_key_file=str(known_hosts),
            system_host_keys=False,
            ssh_strict=True,
        )
    assert sock.closed
    assert sock.acquired == 255
    assert sock.sends == 1


def test_binary_overflow_through_client_and_netmiko_before_shell(tmp_path, monkeypatch):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("")
    header = bytes.fromhex("ff ff ff fc 04 00 00 00")
    sock = FakeSocket(b"SSH-2.0-synthetic\r\n" + header)
    monkeypatch.setattr(
        BoundedSSHClient,
        "invoke_shell",
        lambda *args, **kwargs: pytest.fail("A shell must not open"),
    )
    with pytest.raises(
        SSHBinaryPacketLimitError, match="SSH binary packet resource limit"
    ):
        BoundedArubaConnection(
            device_type="aruba_osswitch",
            host="switch.example",
            username="synthetic",
            password="synthetic",
            sock=sock,
            alt_host_keys=True,
            alt_key_file=str(known_hosts),
            system_host_keys=False,
            ssh_strict=True,
        )
    assert sock.closed
    assert max(sock.requests) <= 128
    # Identification and KEXINIT may both be sent before the peer packet.
    assert sock.sends == 2


class SyntheticServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, channel_id):
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session"
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        return True


def start_server(key, prelude=b""):
    client_sock, server_sock = socket.socketpair()
    observed = []
    done = threading.Event()

    def serve():
        transport = None
        try:
            if prelude:
                server_sock.sendall(prelude)
            transport = Transport(server_sock)
            transport.add_server_key(key)
            transport.start_server(server=SyntheticServer())
            channel = transport.accept(3)
            if channel is not None:
                observed.append("shell")
                done.wait(3)
        except (OSError, EOFError, paramiko.SSHException) as error:
            observed.append(f"{type(error).__name__}: {error}")
        finally:
            if transport is not None:
                transport.close()
            server_sock.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return client_sock, thread, observed, done


@pytest.mark.parametrize("trust", ["expected", "wrong", "unknown"])
def test_real_transport_host_key_and_shell_path(tmp_path, monkeypatch, trust):
    from netmiko.hp.hp_procurve import HPProcurveSSH

    key = paramiko.RSAKey.generate(2048)
    other_key = paramiko.RSAKey.generate(2048)
    known_hosts = tmp_path / "known_hosts"
    if trust != "unknown":
        trusted = key if trust == "expected" else other_key
        known_hosts.write_text(
            f"switch.example {trusted.get_name()} {trusted.get_base64()}\n"
        )
    else:
        known_hosts.write_text("")
    client_sock, thread, observed, done = start_server(key, b"information\r\n")
    monkeypatch.setattr(HPProcurveSSH, "session_preparation", lambda self: None)
    try:
        if trust == "expected":
            with BoundedArubaConnection(
                device_type="aruba_osswitch",
                host="switch.example",
                username="synthetic",
                password="synthetic",
                sock=client_sock,
                alt_host_keys=True,
                alt_key_file=str(known_hosts),
                system_host_keys=False,
                ssh_strict=True,
                disabled_algorithms={"ciphers": ["aes128-cbc"]},
            ) as conn:
                transport = conn.remote_conn_pre.get_transport()
                assert type(transport) is Transport
                assert type(transport.packetizer) is BoundedPacketizer
                assert transport.packetizer.pre_identification_lines == 1
                assert transport.disabled_algorithms == {"ciphers": ["aes128-cbc"]}
                assert transport.sock is client_sock
                assert isinstance(conn.remote_conn_pre._policy, paramiko.RejectPolicy)
                assert not conn.system_host_keys
                assert conn.alt_key_file == str(known_hosts)
        else:
            with pytest.raises(NetmikoTimeoutException) as error:
                BoundedArubaConnection(
                    device_type="aruba_osswitch",
                    host="switch.example",
                    username="synthetic",
                    password="synthetic",
                    sock=client_sock,
                    alt_host_keys=True,
                    alt_key_file=str(known_hosts),
                    system_host_keys=False,
                    ssh_strict=True,
                )
            if trust == "wrong":
                assert isinstance(error.value.__context__, paramiko.BadHostKeyException)
            else:
                assert isinstance(error.value.__context__, paramiko.SSHException)
    finally:
        done.set()
        client_sock.close()
        thread.join(timeout=3)
    assert not thread.is_alive()
    if trust == "expected":
        assert observed == ["shell"]
    else:
        assert "shell" not in observed
