"""Bound Paramiko's textual identification and binary transport packets."""

import hashlib
import inspect
import time
from contextlib import suppress
from functools import wraps
from importlib.metadata import version

from netmiko.base_connection import BaseConnection
from netmiko.hp.hp_procurve import HPProcurveSSH, SSHClient_noauth
from paramiko import SSHClient, Transport
from paramiko.packet import Packetizer
from paramiko.util import u

MAX_SSH_BANNER_LINE_BYTES = 255
MAX_SSH_PRE_IDENTIFICATION_LINES = 99
MAX_SSH_PREAUTH_TEXT_BYTES = 25_500
MAX_SSH_PACKET_LENGTH = 256 * 1024  # SSH uint32 packet_length field, excluding MAC
_TEXT_READ_CHUNK_BYTES = 128  # Paramiko 4.0.0 Packetizer._read_timeout()
_ERROR = "SSH banner resource limit exceeded"
_BINARY_ERROR = "SSH binary packet resource limit exceeded"
# Exact Paramiko 4.0.0 read_message() reviewed for its three body-read formulas.
_READ_MESSAGE_SHA256 = (
    "d5d2c6765cab09ef3037d96dfce77bb42698a829605ea3e18ec7cfdb84b31b33"
)
_READ_ALL_SHA256 = "d6eccad5d1d31e066f42a826c3c515f60752da456065085d32054f2c863cf86a"
_SET_INBOUND_CIPHER_SHA256 = (
    "6f797a65419ca6fa525a20464e42a7f4224c50413bf27e04dc4a6ea46e0bb0c4"
)


class SSHBannerLimitError(ValueError):
    """The peer exceeded a pre-authentication textual SSH resource limit."""


class SSHBinaryPacketLimitError(ValueError):
    """An SSH transport packet exceeded the project resource policy."""


def assert_paramiko_contract():
    """Reject dependency drift before a socket is opened."""
    message = "SSH transport changed; review the bounded Paramiko transport before use"
    if version("paramiko") != "4.0.0" or version("netmiko") != "4.8.0":
        raise RuntimeError(message)
    try:
        connect = inspect.getsource(SSHClient.connect)
        init = inspect.getsource(Transport.__init__)
        banner = inspect.getsource(Transport._check_banner)
        run = inspect.getsource(Transport.run)
        packet_init = inspect.getsource(Packetizer.__init__)
        read_all = inspect.getsource(Packetizer.read_all)
        read_message = inspect.getsource(Packetizer.read_message)
        inbound_cipher = inspect.getsource(Packetizer.set_inbound_cipher)
        read_timeout = inspect.getsource(Packetizer._read_timeout)
        noauth = inspect.getsource(SSHClient_noauth._auth)
        build_client = inspect.getsource(BaseConnection._build_ssh_client)
        procurve_client = inspect.getsource(HPProcurveSSH._get_ssh_client_instance)
    except (OSError, TypeError) as error:
        raise RuntimeError(message) from error
    if not (
        "transport_factory" in inspect.signature(SSHClient.connect).parameters
        and "packetizer_class" in inspect.signature(Transport.__init__).parameters
        and "transport_factory = Transport" in connect
        and "t = self._transport = transport_factory(" in connect
        and "gss_kex=gss_kex" in connect
        and "gss_deleg_creds=gss_deleg_creds" in connect
        and "disabled_algorithms=disabled_algorithms" in connect
        and "self._system_host_keys.get(server_hostkey_name)" in connect
        and "self._host_keys.get(server_hostkey_name)" in connect
        and "self._policy.missing_host_key(" in connect
        and "raise BadHostKeyException(" in connect
        and "self._auth(" in connect
        and "self.packetizer = (packetizer_class or Packetizer)(sock)" in init
        and "buf = self.packetizer.readline(timeout)" in banner
        and 'if buf[:4] == "SSH-":' in banner
        and "self._check_banner()" in run
        and "self.packetizer.read_message()" in run
        and "self.__socket = socket" in packet_init
        and "self.__remainder = bytes()" in packet_init
        and "self.__remainder[:n]" in read_all
        and "self.__remainder = self.__remainder[n:]" in read_all
        and "self.__socket.recv(128)" in read_timeout
        and hashlib.sha256(read_message.encode()).hexdigest() == _READ_MESSAGE_SHA256
        and hashlib.sha256(read_all.encode()).hexdigest() == _READ_ALL_SHA256
        and hashlib.sha256(inbound_cipher.encode()).hexdigest()
        == _SET_INBOUND_CIPHER_SHA256
        and "self.__socket.recv(n)" in read_all
        and "transport.auth_none(username)" in noauth
        and "self._get_ssh_client_instance()" in build_client
        and "remote_conn_pre.load_system_host_keys()" in build_client
        and "remote_conn_pre.load_host_keys(self.alt_key_file)" in build_client
        and "remote_conn_pre.set_missing_host_key_policy(self.key_policy)"
        in build_client
        and "return SSHClient_noauth()" in procurve_client
    ):
        raise RuntimeError(message)


class BoundedPacketizer(Packetizer):
    """Bound identification lines and every inbound transport packet."""

    def __init__(self, socket):
        super().__init__(socket)
        self.text_bytes = 0
        self.pre_identification_lines = 0
        self.banner_limit_exceeded = False
        self.binary_packet_limit_exceeded = False
        self._packet_phase = None
        self._packet_mode = None
        self._packet_block = None
        self._packet_mac = None
        self._packet_clear_length = None

    def _binary_limit(self):
        self.binary_packet_limit_exceeded = True
        # Transport.close() joins its thread; close the packetizer/socket here.
        with suppress(Exception):
            self.close()
        raise SSHBinaryPacketLimitError(_BINARY_ERROR)

    def read_message(self):
        if self.binary_packet_limit_exceeded or self._packet_phase is not None:
            self._binary_limit()
        self._packet_phase = "header"
        try:
            return super().read_message()
        finally:
            self._packet_phase = None
            self._packet_mode = None
            self._packet_block = None
            self._packet_mac = None
            self._packet_clear_length = None

    def read_all(self, n, check_rekey=False):
        """Check Paramiko's packet body request before it reaches socket.recv."""
        if self.binary_packet_limit_exceeded:
            self._binary_limit()
        # Other Paramiko reads are small; never delegate an unexplained large
        # request. The MAC allowance applies only to a reviewed packet mode.
        if not isinstance(n, int) or n < 0 or n > MAX_SSH_PACKET_LENGTH + 64:
            self._binary_limit()
        phase = self._packet_phase
        if phase == "header":
            block = self._Packetizer__block_size_in
            mac = self._Packetizer__mac_size_in
            etm = self._Packetizer__etm_in
            aead = self._Packetizer__aead_in
            if (
                not check_rekey
                or n != block
                or block not in (8, 16)
                or not isinstance(mac, int)
                or not 0 <= mac <= 64
                or not isinstance(etm, bool)
                or not isinstance(aead, bool)
                or (etm and aead)
                or (etm and mac == 0)
                or (aead and mac != 16)
            ):
                self._binary_limit()
            header = super().read_all(n, check_rekey=check_rekey)
            self._packet_block = block
            self._packet_mac = mac
            self._packet_mode = "etm" if etm else "aead" if aead else "classic"
            if etm or aead:
                self._packet_clear_length = int.from_bytes(header[:4], "big")
                if self._packet_clear_length > MAX_SSH_PACKET_LENGTH:
                    self._binary_limit()
            self._packet_phase = "body"
            return header
        if phase == "body":
            if (
                check_rekey
                or self._packet_mode not in ("classic", "etm", "aead")
                or not isinstance(self._packet_block, int)
                or not isinstance(self._packet_mac, int)
            ):
                self._binary_limit()
            # packet_length excludes its own four bytes and the MAC/tag.
            # Classic: n = field + MAC - (block - 4).
            # EtM:     n = field - (block - 4), then a separate MAC read.
            # GCM:     n = field + tag - (block - 4).
            overhead = 0 if self._packet_mode == "etm" else self._packet_mac
            field = n + self._packet_block - 4 - overhead
            if (
                field < 5
                or field > MAX_SSH_PACKET_LENGTH
                or (
                    self._packet_clear_length is not None
                    and field != self._packet_clear_length
                )
            ):
                self._binary_limit()
            body = super().read_all(n, check_rekey=False)
            self._packet_phase = "mac" if self._packet_mode == "etm" else "done"
            return body
        if phase == "mac":
            if check_rekey or n != self._packet_mac:
                self._binary_limit()
            mac = super().read_all(n, check_rekey=False)
            self._packet_phase = "done"
            return mac
        if phase is not None or check_rekey:
            self._binary_limit()
        return super().read_all(n, check_rekey=False)

    def _limit(self):
        self.banner_limit_exceeded = True
        raise SSHBannerLimitError(_ERROR)

    def readline(self, timeout):
        line = bytearray()
        remainder = self._Packetizer__remainder
        self._Packetizer__remainder = b""
        start = None
        while True:
            if remainder:
                newline = remainder.find(b"\n")
                length = len(remainder) if newline < 0 else newline + 1
                if (
                    length > MAX_SSH_BANNER_LINE_BYTES - len(line)
                    or length > MAX_SSH_PREAUTH_TEXT_BYTES - self.text_bytes
                ):
                    self._limit()
                line.extend(remainder[:length])
                self.text_bytes += length
                if newline >= 0:
                    self._Packetizer__remainder = remainder[length:]
                    break
                remainder = b""

            remaining = min(
                MAX_SSH_BANNER_LINE_BYTES - len(line),
                MAX_SSH_PREAUTH_TEXT_BYTES - self.text_bytes,
            )
            if remaining == 0:
                self._limit()
            # Mirror Packetizer._read_timeout's timeout handling, but bound
            # each recv to the allowance remaining in this textual line.
            if start is None:
                start = time.time()
            try:
                remainder = self._Packetizer__socket.recv(
                    min(_TEXT_READ_CHUNK_BYTES, remaining)
                )
                if not remainder:
                    raise EOFError()
                start = None
            except TimeoutError:
                if self._Packetizer__closed:
                    raise EOFError() from None
                if time.time() - start >= timeout:
                    raise
                continue
            if self._Packetizer__closed:
                raise EOFError()

        raw = bytes(line[:-1])
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        decoded = u(raw)
        if not decoded.startswith("SSH-"):
            if self.pre_identification_lines >= MAX_SSH_PRE_IDENTIFICATION_LINES:
                self._limit()
            self.pre_identification_lines += 1
        return decoded


def _transport_factory(sock, *, gss_kex, gss_deleg_creds, disabled_algorithms):
    return Transport(
        sock,
        gss_kex=gss_kex,
        gss_deleg_creds=gss_deleg_creds,
        disabled_algorithms=disabled_algorithms,
        packetizer_class=BoundedPacketizer,
    )


class BoundedSSHClient(SSHClient):
    """Use the bounded packetizer on Paramiko's ordinary connection path."""

    @wraps(SSHClient.connect)
    def connect(self, *args, **kwargs):
        assert_paramiko_contract()
        bound = inspect.signature(SSHClient.connect).bind(self, *args, **kwargs)
        if bound.arguments.get("transport_factory") is not None:
            raise ValueError("A competing SSH transport factory is not supported")
        if bound.arguments.get("compress", False) is not False:
            raise ValueError("SSH compression requires a resource-policy review")
        bound.arguments["transport_factory"] = _transport_factory
        try:
            return super().connect(*bound.args[1:], **bound.kwargs)
        except Exception:
            transport = self.get_transport()
            if not isinstance(
                getattr(transport, "packetizer", None), BoundedPacketizer
            ):
                raise
            packetizer = transport.packetizer
            if not (
                packetizer.banner_limit_exceeded
                or packetizer.binary_packet_limit_exceeded
            ):
                raise
            # The transport thread may still be unwinding _check_banner.
            # Close its socket directly; Transport.close() joins that thread.
            with suppress(Exception):
                transport.packetizer.close()
            with suppress(Exception):
                transport.sock.close()
            transport.active = False
            self._transport = None
            if packetizer.binary_packet_limit_exceeded:
                raise SSHBinaryPacketLimitError(_BINARY_ERROR) from None
            raise SSHBannerLimitError(_ERROR) from None


class BoundedSSHClientNoAuth(BoundedSSHClient, SSHClient_noauth):
    """Preserve Netmiko's no-auth path when a caller selects it."""
