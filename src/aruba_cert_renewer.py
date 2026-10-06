#!/usr/bin/env python3

import argparse
import errno
import getpass
import ipaddress
import logging
import math
import multiprocessing
import os
import re
import shutil
import socket
import ssl
import stat
import sys
import tempfile
import time
import tomllib
import warnings
from contextlib import contextmanager
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from types import MappingProxyType

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import (
    ExtendedKeyUsageOID,
    ExtensionOID,
    NameOID,
    SignatureAlgorithmOID,
)
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

from lifecycle_lock import LifecycleLockError, LifecycleLockReleaseError, lifecycle_lock
from opnsense_client import MAX_DESCRIPTION_CHARS, OPNsenseClient, validate_base_url
from output_policy import SanitizingFormatter, sanitize_terminal_text
from secure_file import open_secure_file
from tls_policy import create_client_tls_context

DEFAULT_CONFIG_FILE = Path(__file__).resolve().parent.parent / "config.toml"

EXIT_OK = 0
EXIT_WARNING = 1
EXIT_ERROR = 2

MAX_CERTIFICATE_INPUT_BYTES = 64 * 1024
MAX_CONFIG_FILE_BYTES = 1024 * 1024
MAX_KNOWN_HOSTS_FILE_BYTES = 256 * 1024
MAX_VERIFICATION_CA_FILE_BYTES = 1024 * 1024
MAX_PASSWORD_FILE_BYTES = 16 * 1024
MAX_ADDITIONAL_SANS = 100
HTTPS_VERIFICATION_WINDOW_SECONDS = 30
HTTPS_RETRY_DELAY_SECONDS = 2
HTTPS_SOCKET_TIMEOUT_SECONDS = 5
HTTPS_RESOLVER_CLEANUP_SECONDS = 0.1


@dataclass(frozen=True)
class VerificationCASnapshot:
    path: Path
    pem: bytes = dataclass_field(repr=False)


def capture_verification_ca(path):
    try:
        with open_secure_file(path, source_name="verification.ca_file") as ca_file:
            ca_bytes = ca_file.read(MAX_VERIFICATION_CA_FILE_BYTES + 1)
    except OSError:
        raise ValueError(f"verification.ca_file cannot be read: {path}") from None
    if len(ca_bytes) > MAX_VERIFICATION_CA_FILE_BYTES:
        raise ValueError(
            "verification.ca_file exceeds "
            f"{MAX_VERIFICATION_CA_FILE_BYTES} bytes: {path}"
        )
    if not ca_bytes:
        raise ValueError(
            f"verification.ca_file does not contain any trusted certificates: {path}"
        )
    return VerificationCASnapshot(Path(path), ca_bytes)


def require_verification_ca_snapshot(snapshot):
    if not isinstance(snapshot, VerificationCASnapshot):
        raise ValueError("A captured verification CA snapshot is required")
    return snapshot


def _ca_ssl_data(snapshot):
    try:
        return snapshot.pem.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError(
            f"verification.ca_file does not contain valid PEM certificates: {snapshot.path}"
        ) from None


CERTIFICATE_PASTE_PROMPT = "Paste the certificate here and enter:"
CERTIFICATE_REPLACEMENT_PROMPT = (
    "This certificate will replace an existing local certificate. Continue (y/n)?"
)

SSH_DISABLED_ALGORITHMS = MappingProxyType(
    {
        "ciphers": (
            "aes128-cbc",
            "aes192-cbc",
            "aes256-cbc",
            "3des-cbc",
        ),
        "macs": (
            "hmac-sha1",
            "hmac-sha1-96",
            "hmac-md5",
            "hmac-md5-96",
        ),
        "kex": (
            "diffie-hellman-group-exchange-sha1",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group1-sha1",
        ),
        "keys": ("ssh-rsa",),
        "pubkeys": ("ssh-rsa",),
    }
)


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Monitor and explicitly renew HTTPS certificates on ArubaOS-Switch devices."
        )
    )

    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_FILE,
        help=f"Configuration file (default: {DEFAULT_CONFIG_FILE})",
    )

    parser.add_argument(
        "--switch",
        dest="switch_name",
        metavar="NAME",
        help="Check only the named switch",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable Netmiko debug logging",
    )

    parser.add_argument(
        "--generate-csr",
        action="store_true",
        help="Generate and retrieve a CSR for one explicitly selected switch",
    )

    parser.add_argument(
        "--retrieve-csr",
        action="store_true",
        help="Retrieve and validate an existing pending CSR without modifying it",
    )

    parser.add_argument(
        "--sign-csr",
        action="store_true",
        help="Sign and validate an existing pending CSR using OPNsense",
    )

    parser.add_argument(
        "--install-certificate",
        action="store_true",
        help=(
            "Install a validated certificate onto an existing pending CSR and "
            "verify live HTTPS"
        ),
    )

    parser.add_argument(
        "--renew",
        action="store_true",
        help=(
            "Renew one explicitly selected switch now using automatic "
            "certificate naming"
        ),
    )

    parser.add_argument(
        "--renew-due",
        action="store_true",
        help=(
            "Check selected switches and renew only certificates at or beyond "
            "the configured warning threshold"
        ),
    )

    parser.add_argument(
        "--certificate-name",
        metavar="NAME",
        help="Certificate name to generate, retrieve, sign, or install",
    )

    parser.add_argument(
        "--csr-output",
        type=Path,
        metavar="FILE",
        help="Write the validated PEM CSR to this file instead of stdout",
    )

    parser.add_argument(
        "--certificate-output",
        type=Path,
        metavar="FILE",
        help="Write the validated signed PEM certificate to this file",
    )

    parser.add_argument(
        "--certificate-input",
        type=Path,
        metavar="FILE",
        help="Read the signed PEM certificate to install from this file",
    )

    return parser.parse_args()


def validate_cli_args(args):
    renew = getattr(args, "renew", False)
    renew_due = getattr(args, "renew_due", False)
    install_certificate = getattr(args, "install_certificate", False)
    certificate_input = getattr(args, "certificate_input", None)
    staged_operations = [
        args.generate_csr,
        args.retrieve_csr,
        args.sign_csr,
        install_certificate,
    ]
    operations = [*staged_operations, renew, renew_due]
    if sum(operations) > 1:
        raise ValueError(
            "--generate-csr, --retrieve-csr, --sign-csr, "
            "--install-certificate, --renew, and --renew-due are mutually exclusive"
        )

    staged_operation = any(staged_operations)
    if args.generate_csr:
        operation_name = "--generate-csr"
    elif args.retrieve_csr:
        operation_name = "--retrieve-csr"
    elif args.sign_csr:
        operation_name = "--sign-csr"
    else:
        operation_name = "--install-certificate"

    if renew and not args.switch_name:
        raise ValueError("--renew requires --switch")

    if staged_operation and not args.switch_name:
        raise ValueError(f"{operation_name} requires --switch")

    if staged_operation and not args.certificate_name:
        raise ValueError(f"{operation_name} requires --certificate-name")

    renewal_mode = "--renew-due" if renew_due else "--renew"

    if (renew or renew_due) and args.certificate_name:
        raise ValueError(f"{renewal_mode} does not accept --certificate-name")

    if not staged_operation and not renew and not renew_due and args.certificate_name:
        raise ValueError(
            "--certificate-name requires --generate-csr, --retrieve-csr, "
            "--sign-csr, or --install-certificate"
        )

    if (renew or renew_due) and args.csr_output:
        raise ValueError(f"{renewal_mode} does not accept --csr-output")

    if (
        not staged_operation or args.sign_csr or install_certificate
    ) and args.csr_output:
        raise ValueError("--csr-output requires --generate-csr or --retrieve-csr")

    if (renew or renew_due) and args.certificate_output:
        raise ValueError(f"{renewal_mode} does not accept --certificate-output")

    if not args.sign_csr and args.certificate_output:
        raise ValueError("--certificate-output requires --sign-csr")

    if args.sign_csr and not args.certificate_output:
        raise ValueError("--sign-csr requires --certificate-output")

    if install_certificate and not certificate_input:
        raise ValueError("--install-certificate requires --certificate-input")

    if (renew or renew_due) and certificate_input:
        raise ValueError(f"{renewal_mode} does not accept --certificate-input")

    if not install_certificate and not renew and not renew_due and certificate_input:
        raise ValueError("--certificate-input requires --install-certificate")

    if args.certificate_name:
        validate_cli_identifier(args.certificate_name, "certificate name")

    if args.csr_output and args.csr_output.exists():
        raise ValueError(f"CSR output file already exists: {args.csr_output}")

    if args.certificate_output and args.certificate_output.exists():
        raise ValueError(
            f"Certificate output file already exists: {args.certificate_output}"
        )


def configure_logging(debug):
    if not debug:
        return

    handler = logging.StreamHandler()
    handler.setFormatter(
        SanitizingFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logging.basicConfig(
        level=logging.DEBUG,
        handlers=[handler],
        force=True,
    )

    logging.getLogger("netmiko").setLevel(logging.DEBUG)

    # Paramiko's DEBUG output is extremely verbose and is usually not useful
    # when troubleshooting Netmiko command handling.
    logging.getLogger("paramiko").setLevel(logging.WARNING)


def print_terminal(value="", *, file=None):
    """Print one operator-facing line after escaping terminal controls."""
    print(sanitize_terminal_text(value), file=file)


def get_local_time():
    """Return the current timezone-aware local wall-clock time."""
    return datetime.now(UTC).astimezone()


def format_run_timestamp(value):
    """Format a timezone-aware time for operator-facing run output."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Run timestamp must be timezone-aware")
    return value.strftime("%Y-%m-%d %H:%M:%S %Z")


def print_run_start(title, started_at):
    print_terminal(title)
    print_terminal("=" * len(title))
    print_terminal(f"Check started:    {format_run_timestamp(started_at)}")


def print_switch_heading(switch):
    """Print a safe switch heading whose underline matches displayed text."""
    display_name = sanitize_terminal_text(switch["name"])
    print_terminal()
    print_terminal(display_name)
    print_terminal("-" * len(display_name))
    print_terminal(f"Host:             {switch['host']}")


def load_config(config_file):
    config_file = Path(config_file)
    try:
        with open_secure_file(config_file, source_name="Configuration file") as file:
            contents = file.read(MAX_CONFIG_FILE_BYTES + 1)
    except OSError:
        raise ValueError(f"Configuration file cannot be read: {config_file}") from None
    if len(contents) > MAX_CONFIG_FILE_BYTES:
        raise ValueError(
            f"Configuration file exceeds {MAX_CONFIG_FILE_BYTES} bytes: {config_file}"
        )
    try:
        return tomllib.loads(contents.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        raise ValueError(
            f"Invalid TOML or UTF-8 in configuration file {config_file}"
        ) from None


def resolve_config_relative_path(configured_path, config_file):
    path = Path(configured_path)
    if not path.is_absolute():
        config_directory = Path(config_file).parent.resolve()
        path = config_directory / path
    return Path(os.path.abspath(path))


def parse_identity(value, field_name="identity"):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 253
        or any(character.isspace() or ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{field_name} contains unsupported characters")

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        # Colons indicate an IPv6 literal or host:port, while an all-numeric,
        # dotted value is intended as IPv4. Neither may fall through and be
        # accepted as a DNS hostname when malformed.
        if ":" in value or re.fullmatch(r"[0-9.]+", value):
            raise ValueError(f"{field_name} is not a valid IP address") from None

        labels = value.split(".")
        if "*" in value or any(
            not re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
                label,
            )
            for label in labels
        ):
            raise ValueError(f"{field_name} is not a valid DNS hostname") from None

        canonical = value.lower()
        return {"kind": "dns", "value": canonical, "key": ("dns", canonical)}

    kind = "ipv4" if address.version == 4 else "ipv6"
    return {"kind": kind, "value": str(address), "key": ("ip", address)}


def get_certificate_identities(switch):
    identities = []
    seen = set()
    for value in [switch["host"], *switch.get("additional_sans", [])]:
        identity = parse_identity(value, "switch identity")
        if identity["key"] in seen:
            continue
        seen.add(identity["key"])
        identities.append(identity)

    host = identities[0]
    return {
        "common_name": host["value"],
        "dns_names": [
            identity["value"] for identity in identities if identity["kind"] == "dns"
        ],
        "ip_addresses": [
            identity["value"] for identity in identities if identity["kind"] != "dns"
        ],
    }


def get_ssh_known_hosts_file(config, config_file):
    settings = config.get("ssh")

    if not isinstance(settings, dict):
        raise ValueError("An [ssh] configuration section is required")

    configured_path = settings.get("known_hosts_file")
    if not isinstance(configured_path, str) or not configured_path.strip():
        raise ValueError("ssh.known_hosts_file must be configured")

    if "\x00" in configured_path:
        raise ValueError("ssh.known_hosts_file contains unsupported characters")

    known_hosts_file = resolve_config_relative_path(configured_path, config_file)
    with open_secure_file(
        known_hosts_file,
        source_name="ssh.known_hosts_file",
    ):
        pass

    return known_hosts_file


def validate_config(config, config_file=DEFAULT_CONFIG_FILE):
    known_hosts_file = get_ssh_known_hosts_file(config, config_file)
    settings = config.get("settings", {})
    warning_days = settings.get("warning_days", 30)

    if not isinstance(warning_days, int) or isinstance(warning_days, bool):
        raise ValueError("settings.warning_days must be an integer")

    if warning_days < 0:
        raise ValueError("settings.warning_days cannot be negative")

    switches = config.get("switches")

    if not isinstance(switches, list) or not switches:
        raise ValueError("At least one [[switches]] entry must be configured")

    required_fields = ("name", "host")
    seen_names = set()

    for index, switch in enumerate(switches, start=1):
        if not isinstance(switch, dict):
            raise ValueError(f"Switch entry {index} must be a TOML table")

        if "fqdn" in switch:
            raise ValueError(
                "switches.fqdn is no longer supported; use host and optional "
                "additional_sans"
            )

        if "password" in switch:
            raise ValueError(
                "switches.password is not supported; passwords must come from "
                "password_file, ARUBA_SSH_PASSWORD, or interactive input"
            )

        for field in required_fields:
            value = switch.get(field)

            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Switch entry {index} must contain a non-empty '{field}'"
                )

        switch["host"] = parse_identity(
            switch["host"],
            f"Switch entry {index} host",
        )["value"]

        additional_sans = switch.get("additional_sans", [])
        if not isinstance(additional_sans, list) or any(
            not isinstance(value, str) for value in additional_sans
        ):
            raise ValueError(
                f"Switch entry {index} additional_sans must be an array of strings"
            )
        if len(additional_sans) > MAX_ADDITIONAL_SANS:
            raise ValueError(
                f"Switch entry {index} additional_sans cannot contain more than "
                f"{MAX_ADDITIONAL_SANS} entries"
            )

        switch["additional_sans"] = [
            parse_identity(value, f"Switch entry {index} additional_sans item")["value"]
            for value in additional_sans
        ]
        switch["_ssh_known_hosts_file"] = known_hosts_file

        username = switch.get("username")
        if username is not None:
            validate_ssh_username(username, f"Switch entry {index} username")

        password_file = switch.get("password_file")
        if password_file is not None and (
            not isinstance(password_file, str)
            or not password_file
            or not password_file.strip()
            or "\x00" in password_file
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in password_file
            )
        ):
            raise ValueError(
                f"Switch entry {index} password_file must be a non-empty safe path"
            )

        normalized_name = switch["name"].casefold()

        if normalized_name in seen_names:
            raise ValueError(f"Duplicate switch name: {switch['name']}")

        seen_names.add(normalized_name)

    return warning_days, switches


def select_switches(switches, switch_name):
    if switch_name is None:
        return switches

    matches = [
        switch
        for switch in switches
        if switch["name"].casefold() == switch_name.casefold()
    ]

    if not matches:
        raise ValueError(f"Switch not found in configuration: {switch_name}")

    return matches


def validate_ssh_username(username, field_name="SSH username"):
    if (
        not isinstance(username, str)
        or not username
        or not username.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in username)
    ):
        raise ValueError(f"{field_name} must be a non-empty string without controls")
    return username


def read_password_file(configured_path, config_file):
    password_file = resolve_config_relative_path(configured_path, config_file)

    with open_secure_file(
        password_file,
        source_name="switches.password_file",
    ) as file:
        try:
            password_bytes = file.read(MAX_PASSWORD_FILE_BYTES + 1)
        except OSError:
            raise ValueError(
                f"switches.password_file cannot be read: {password_file}"
            ) from None

    if len(password_bytes) > MAX_PASSWORD_FILE_BYTES:
        raise ValueError(
            f"switches.password_file exceeds {MAX_PASSWORD_FILE_BYTES} bytes: "
            f"{password_file}"
        )
    if b"\x00" in password_bytes:
        raise ValueError(f"switches.password_file contains NUL: {password_file}")

    if password_bytes.endswith(b"\r\n"):
        password_bytes = password_bytes[:-2]
    elif password_bytes.endswith(b"\n"):
        password_bytes = password_bytes[:-1]

    if not password_bytes:
        raise ValueError(f"switches.password_file is empty: {password_file}")
    if b"\r" in password_bytes or b"\n" in password_bytes:
        raise ValueError(
            f"switches.password_file must contain exactly one line: {password_file}"
        )

    try:
        return password_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(
            f"switches.password_file must contain valid UTF-8: {password_file}"
        ) from None


def get_switch_credentials(switch, config_file):
    display_name = sanitize_terminal_text(switch["name"])
    username = switch.get("username") or os.environ.get("ARUBA_SSH_USERNAME")
    if not username:
        username = input(f"SSH username for {display_name}: ")
    username = validate_ssh_username(username)

    if "password_file" in switch:
        password = read_password_file(switch["password_file"], config_file)
    else:
        password = os.environ.get("ARUBA_SSH_PASSWORD")
        if not password:
            password = getpass.getpass(f"SSH password for {display_name}: ")

    if not password:
        raise ValueError(f"SSH password for {switch['name']} cannot be empty")

    return username, password


def parse_aos_version(output):
    match = re.search(r"\b[A-Z]{2}\.\d{2}\.\d{2}\.\d{4}\b", output)

    if match:
        return match.group(0)

    return "Unknown"


def parse_web_certificates(output):
    pattern = re.compile(
        r"^\s*"
        r"(?P<name>\S+)"
        r"\s+"
        r"(?P<usage>Web)"
        r"\s+"
        r"(?P<expiration>\d{4}/\d{2}/\d{2}|CSR)"
        r"\s+"
        r"(?P<profile>\S+)"
        r"\s*$",
        re.MULTILINE,
    )

    certificates = []

    for match in pattern.finditer(output):
        expiration_text = match.group("expiration")
        pending = expiration_text == "CSR"
        expiration = None

        if not pending:
            expiration = datetime.strptime(
                expiration_text,
                "%Y/%m/%d",
            ).date()

        certificates.append(
            {
                "name": match.group("name"),
                "expiration": expiration,
                "profile": match.group("profile"),
                "pending": pending,
            }
        )

    return certificates


def get_active_web_certificate(certificates):
    pending = [certificate for certificate in certificates if certificate["pending"]]

    if pending:
        names = ", ".join(certificate["name"] for certificate in pending)
        raise ValueError(f"Found pending Web CSR: {names}")

    installed = [
        certificate for certificate in certificates if not certificate["pending"]
    ]

    if not installed:
        raise ValueError("Could not find an installed Web certificate")

    if len(installed) != 1:
        raise ValueError(
            f"Found {len(installed)} installed Web certificates; expected 1"
        )

    return installed[0]


def certificate_name_exists(summary_output, certificate_name):
    certificate_name = validate_cli_identifier(
        certificate_name,
        "certificate name",
    )

    return (
        re.search(
            rf"^\s*{re.escape(certificate_name)}\s+",
            summary_output,
            re.MULTILINE | re.IGNORECASE,
        )
        is not None
    )


def choose_renewal_certificate_name(summary_output, *, now=None):
    """Choose the first unused UTC-dated renewal certificate name."""
    if now is None:
        now = datetime.now(UTC)

    if isinstance(now, datetime):
        if now.tzinfo is None:
            raise ValueError("Renewal naming time must be timezone-aware")
        renewal_date = now.astimezone(UTC).date()
    elif isinstance(now, date):
        renewal_date = now
    else:
        raise ValueError("Renewal naming time must be a date or datetime")

    prefix = f"webcert-{renewal_date:%Y%m%d}-"
    for sequence in range(1, 100):
        candidate = f"{prefix}{sequence:02d}"
        if not certificate_name_exists(summary_output, candidate):
            return validate_cli_identifier(candidate, "certificate name")

    raise ValueError(
        f"All 99 renewal certificate names for {renewal_date:%Y-%m-%d} "
        "already exist on the switch"
    )


def get_certificate_summary_entry(summary_output, certificate_name):
    certificate_name = validate_cli_identifier(
        certificate_name,
        "certificate name",
    )
    pattern = re.compile(
        rf"^\s*(?P<name>{re.escape(certificate_name)})"
        r"\s+(?P<usage>\S+)"
        r"\s+(?P<expiration>\d{4}/\d{2}/\d{2}|CSR)"
        r"\s+(?P<profile>\S+)\s*$",
        re.MULTILINE | re.IGNORECASE,
    )
    matches = list(pattern.finditer(summary_output))

    if not matches:
        raise ValueError(
            f"Certificate name not found on the switch: {certificate_name}"
        )

    if len(matches) != 1:
        raise ValueError(f"Certificate name is ambiguous: {certificate_name}")

    match = matches[0]
    return {
        "name": match.group("name"),
        "usage": match.group("usage"),
        "expiration": match.group("expiration"),
        "profile": match.group("profile"),
    }


def get_csr_settings(config):
    csr_settings = config.get("csr")

    if not isinstance(csr_settings, dict):
        raise ValueError("A [csr] configuration section is required")

    return validate_csr_settings(csr_settings)


def get_opnsense_settings(config):
    settings = config.get("opnsense")

    if not isinstance(settings, dict):
        raise ValueError("An [opnsense] configuration section is required")

    if "api_key" in settings or "api_secret" in settings:
        raise ValueError(
            "OPNsense API credentials must be supplied only through environment "
            "variables"
        )

    required_fields = ("base_url", "ca", "lifetime_days", "digest")
    for field in required_fields:
        if field not in settings:
            raise ValueError(f"opnsense.{field} must be configured")

    base_url = validate_base_url(settings["base_url"])
    ca_description = settings["ca"]
    lifetime_days = settings["lifetime_days"]
    digest = settings["digest"]

    if (
        not isinstance(ca_description, str)
        or not ca_description.strip()
        or len(ca_description) > 255
        or any(ord(character) < 32 for character in ca_description)
    ):
        raise ValueError("opnsense.ca must be a non-empty safe description")

    if (
        not isinstance(lifetime_days, int)
        or isinstance(lifetime_days, bool)
        or not 1 <= lifetime_days <= 3650
    ):
        raise ValueError("opnsense.lifetime_days must be between 1 and 3650")

    if digest not in {"sha256", "sha384", "sha512"}:
        raise ValueError("opnsense.digest must be sha256, sha384, or sha512")

    return {
        "base_url": base_url,
        "ca": ca_description.strip(),
        "lifetime_days": lifetime_days,
        "digest": digest,
    }


def get_verification_ca_file(config, config_file):
    settings = config.get("verification")

    if not isinstance(settings, dict):
        raise ValueError(
            "A [verification] configuration section is required for "
            "--install-certificate, --renew, or --renew-due"
        )

    configured_path = settings.get("ca_file")
    if not isinstance(configured_path, str) or not configured_path.strip():
        raise ValueError("verification.ca_file must be configured")

    if "\x00" in configured_path:
        raise ValueError("verification.ca_file contains unsupported characters")

    ca_file = resolve_config_relative_path(configured_path, config_file)
    snapshot = capture_verification_ca(ca_file)

    try:
        create_client_tls_context(cadata=_ca_ssl_data(snapshot))
    except (OSError, ssl.SSLError, ValueError):
        raise ValueError(
            f"verification.ca_file cannot be loaded as a CA file: {ca_file}"
        ) from None

    return snapshot


def validate_csr_settings(csr_settings):
    if not isinstance(csr_settings, dict):
        raise ValueError("CSR settings must be a table")

    required_fields = (
        "organization",
        "organizational_unit",
        "locality",
        "state",
        "country",
        "key_type",
        "key_size",
    )

    for field in required_fields:
        if field not in csr_settings:
            raise ValueError(f"csr.{field} must be configured")

    text_fields = (
        "organization",
        "organizational_unit",
        "locality",
        "state",
    )

    for field in text_fields:
        value = csr_settings[field]

        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"csr.{field} must be a non-empty string")

        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .,'()&/-]*", value):
            raise ValueError(f"csr.{field} contains unsupported characters")

    country = csr_settings["country"]

    if not isinstance(country, str) or not re.fullmatch(r"[A-Z]{2}", country):
        raise ValueError("csr.country must be a two-letter uppercase country code")

    if csr_settings["key_type"] != "rsa":
        raise ValueError("csr.key_type must currently be 'rsa'")

    if csr_settings["key_size"] != 2048:
        raise ValueError("csr.key_size must currently be 2048")

    return csr_settings


def validate_cli_identifier(value, field_name):
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]*",
        value,
    ):
        raise ValueError(f"{field_name} contains unsupported characters")

    return value


def quote_cli_subject_value(value):
    if any(character in value for character in ('"', "\r", "\n")):
        raise ValueError("CSR subject value contains unsupported characters")

    if " " in value:
        return f'"{value}"'

    return value


def build_csr_command(switch, certificate_name, ta_profile, csr_settings):
    csr_settings = validate_csr_settings(csr_settings)
    certificate_name = validate_cli_identifier(
        certificate_name,
        "certificate name",
    )
    ta_profile = validate_cli_identifier(
        ta_profile,
        "TA profile",
    )
    common_name = get_certificate_identities(switch)["common_name"]

    organization = quote_cli_subject_value(csr_settings["organization"])
    organizational_unit = quote_cli_subject_value(csr_settings["organizational_unit"])
    locality = quote_cli_subject_value(csr_settings["locality"])
    state = quote_cli_subject_value(csr_settings["state"])
    country = csr_settings["country"]

    return " ".join(
        [
            "crypto pki create-csr",
            f"certificate-name {certificate_name}",
            f"ta-profile {ta_profile}",
            "usage web",
            f"key-type {csr_settings['key_type']}",
            f"key-size {csr_settings['key_size']}",
            "subject",
            f"common-name {common_name}",
            f"org {organization}",
            f"org-unit {organizational_unit}",
            f"locality {locality}",
            f"state {state}",
            f"country {country}",
        ]
    )


def extract_csr_pem(output):
    match = re.search(
        r"-----BEGIN CERTIFICATE REQUEST-----"
        r".*?"
        r"-----END CERTIFICATE REQUEST-----",
        output,
        re.DOTALL,
    )

    if not match:
        raise ValueError("Could not find a PEM certificate signing request")

    return match.group(0).strip() + "\n"


def get_subject_value(subject, oid, field_name):
    attributes = subject.get_attributes_for_oid(oid)

    if len(attributes) != 1:
        raise ValueError(f"CSR must contain exactly one {field_name}")

    return attributes[0].value


def verify_csr_signature(csr, public_key):
    supported_algorithms = {
        # AOS-S WC.16.11.0015 emits RSA/SHA-1 PKCS#10 self-signatures. SHA-1 is
        # accepted only here as proof of possession; it is not acceptable for
        # an issued HTTPS certificate.
        SignatureAlgorithmOID.RSA_WITH_SHA1: hashes.SHA1(),
        SignatureAlgorithmOID.RSA_WITH_SHA256: hashes.SHA256(),
    }
    signature_hash = supported_algorithms.get(csr.signature_algorithm_oid)

    if signature_hash is None:
        raise ValueError(
            "Unsupported CSR signature algorithm: "
            f"{csr.signature_algorithm_oid.dotted_string}"
        )

    try:
        public_key.verify(
            csr.signature,
            csr.tbs_certrequest_bytes,
            padding.PKCS1v15(),
            signature_hash,
        )

    except InvalidSignature as error:
        raise ValueError("CSR signature is invalid") from error

    except UnsupportedAlgorithm as error:
        raise ValueError(
            f"CSR signature algorithm is unavailable: {signature_hash.name}"
        ) from error


def validate_csr_pem(csr_pem, switch, csr_settings):
    csr_settings = validate_csr_settings(csr_settings)

    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))

    except (ValueError, UnicodeEncodeError) as error:
        raise ValueError("Returned CSR is not valid PEM") from error

    public_key = csr.public_key()

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("CSR does not contain an RSA public key")

    if public_key.key_size != csr_settings["key_size"]:
        raise ValueError(
            f"CSR RSA key size is {public_key.key_size}; "
            f"expected {csr_settings['key_size']}"
        )

    verify_csr_signature(csr, public_key)

    expected_subject = {
        NameOID.COMMON_NAME: (
            "common name",
            get_certificate_identities(switch)["common_name"],
        ),
        NameOID.ORGANIZATION_NAME: (
            "organization",
            csr_settings["organization"],
        ),
        NameOID.ORGANIZATIONAL_UNIT_NAME: (
            "organizational unit",
            csr_settings["organizational_unit"],
        ),
        NameOID.LOCALITY_NAME: (
            "locality",
            csr_settings["locality"],
        ),
        NameOID.STATE_OR_PROVINCE_NAME: (
            "state",
            csr_settings["state"],
        ),
        NameOID.COUNTRY_NAME: (
            "country",
            csr_settings["country"],
        ),
    }

    for oid, (field_name, expected_value) in expected_subject.items():
        actual_value = get_subject_value(
            csr.subject,
            oid,
            field_name,
        )

        if actual_value != expected_value:
            raise ValueError(
                f"CSR {field_name} is {actual_value!r}; expected {expected_value!r}"
            )

    return csr


def validate_switch_signing_identity(switch):
    return get_certificate_identities(switch)


def _require_extension(certificate, extension_oid, name):
    with warnings.catch_warnings():
        # OPNsense-created self-signed internal CAs may have serial 0, which can
        # appear as authorityCertSerialNumber=0 in an issued certificate's AKI.
        # This intentionally narrow compatibility filter does not accept an
        # arbitrary malformed leaf certificate serial number as valid.
        # A future cryptography parser exception will still fail validation.
        warnings.filterwarnings(
            "ignore",
            message=(
                r"^Parsed a serial number which wasn't positive \(i\.e\., it was "
                r"negative or zero\), which is disallowed by RFC 5280\."
            ),
            category=CryptographyDeprecationWarning,
        )

        try:
            return certificate.extensions.get_extension_for_oid(extension_oid).value
        except x509.ExtensionNotFound as error:
            raise ValueError(f"Issued certificate is missing {name}") from error


def _public_key_bytes(public_key):
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


ISSUED_SIGNATURE_OIDS = {
    "sha256": frozenset(
        (SignatureAlgorithmOID.RSA_WITH_SHA256, SignatureAlgorithmOID.ECDSA_WITH_SHA256)
    ),
    "sha384": frozenset(
        (SignatureAlgorithmOID.RSA_WITH_SHA384, SignatureAlgorithmOID.ECDSA_WITH_SHA384)
    ),
    "sha512": frozenset(
        (SignatureAlgorithmOID.RSA_WITH_SHA512, SignatureAlgorithmOID.ECDSA_WITH_SHA512)
    ),
}
ISSUED_EKU_OIDS = (
    ExtendedKeyUsageOID.SERVER_AUTH,
    x509.ObjectIdentifier("1.3.6.1.5.5.8.2.2"),
)
ISSUANCE_FRESHNESS_WINDOW = timedelta(minutes=5)


def _validate_issued_signature(certificate, digest):
    allowed_oids = ISSUED_SIGNATURE_OIDS.get(digest)
    if allowed_oids is None:
        raise ValueError("Configured issued certificate digest is unsupported")

    try:
        signature_hash = certificate.signature_hash_algorithm
    except UnsupportedAlgorithm as error:
        raise ValueError(
            "Issued certificate signature hash algorithm is unsupported"
        ) from error

    if (
        signature_hash is None
        or signature_hash.name != digest
        or certificate.signature_algorithm_oid not in allowed_oids
    ):
        raise ValueError("Issued certificate signature does not match opnsense.digest")


def _require_current_certificate_validity(certificate, now, minimum_remaining_days):
    if certificate.not_valid_before_utc > now:
        raise ValueError("Issued certificate is not yet valid")
    if certificate.not_valid_after_utc <= now:
        raise ValueError("Issued certificate has expired")
    if minimum_remaining_days is not None and certificate.not_valid_after_utc <= (
        now + timedelta(days=minimum_remaining_days)
    ):
        raise ValueError(
            "Issued certificate does not have enough remaining validity "
            "to leave the renewal warning window"
        )


def validate_issued_certificate(
    certificate_pem,
    csr,
    switch,
    lifetime_days,
    *,
    digest,
    now=None,
    require_fresh_issuance=False,
    minimum_remaining_days=None,
):
    try:
        certificates = x509.load_pem_x509_certificates(certificate_pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise ValueError("Issued certificate is not valid PEM X.509") from error

    if len(certificates) != 1:
        raise ValueError(
            "Issued certificate response must contain exactly one certificate"
        )

    certificate = certificates[0]
    certificate_key = certificate.public_key()
    csr_key = csr.public_key()

    if not isinstance(certificate_key, rsa.RSAPublicKey):
        raise ValueError("Issued certificate does not contain an RSA public key")

    if certificate_key.key_size != 2048:
        raise ValueError(
            f"Issued certificate RSA key size is {certificate_key.key_size}; "
            "expected 2048"
        )

    if _public_key_bytes(certificate_key) != _public_key_bytes(csr_key):
        raise ValueError("Issued certificate public key does not match the CSR")

    identities = get_certificate_identities(switch)
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) != 1 or common_names[0].value != identities["common_name"]:
        raise ValueError(
            f"Issued certificate CN must equal switch host "
            f"{identities['common_name']!r}"
        )

    if certificate.subject != csr.subject:
        raise ValueError("Issued certificate subject does not match the CSR")

    subject_alt_name = _require_extension(
        certificate,
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        "Subject Alternative Name",
    )
    dns_names = subject_alt_name.get_values_for_type(x509.DNSName)
    ip_addresses = subject_alt_name.get_values_for_type(x509.IPAddress)
    if any(
        not isinstance(name, (x509.DNSName, x509.IPAddress))
        for name in subject_alt_name
    ):
        raise ValueError("Issued certificate SAN contains an unsupported identity type")
    expected_dns = {name.casefold() for name in identities["dns_names"]}
    actual_dns = {name.casefold() for name in dns_names}
    if len(dns_names) != len(expected_dns) or actual_dns != expected_dns:
        raise ValueError(
            "Issued certificate DNS SAN set does not exactly match configured "
            "identities"
        )

    expected_ips = {
        ipaddress.ip_address(address) for address in identities["ip_addresses"]
    }
    if len(ip_addresses) != len(expected_ips) or set(ip_addresses) != expected_ips:
        raise ValueError(
            "Issued certificate IP SAN set does not exactly match configured identities"
        )

    basic_constraints = _require_extension(
        certificate,
        ExtensionOID.BASIC_CONSTRAINTS,
        "Basic Constraints",
    )
    if basic_constraints.ca:
        raise ValueError("Issued certificate Basic Constraints must set CA to FALSE")

    extended_key_usage = _require_extension(
        certificate,
        ExtensionOID.EXTENDED_KEY_USAGE,
        "Extended Key Usage",
    )
    if len(extended_key_usage) != len(ISSUED_EKU_OIDS) or set(
        extended_key_usage
    ) != set(ISSUED_EKU_OIDS):
        raise ValueError(
            "Issued certificate Extended Key Usage must contain exactly "
            "serverAuth and 1.3.6.1.5.5.8.2.2"
        )

    key_usage = _require_extension(certificate, ExtensionOID.KEY_USAGE, "Key Usage")
    if not (
        key_usage.digital_signature
        and key_usage.key_encipherment
        and not key_usage.content_commitment
        and not key_usage.data_encipherment
        and not key_usage.key_agreement
        and not key_usage.key_cert_sign
        and not key_usage.crl_sign
    ):
        raise ValueError("Issued certificate Key Usage does not match server policy")

    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    if not_after <= not_before:
        raise ValueError("Issued certificate validity period is invalid")

    if now is None:
        now = datetime.now(UTC)
    elif now.tzinfo is None:
        raise ValueError("Certificate validation time must be timezone-aware")

    _require_current_certificate_validity(certificate, now, minimum_remaining_days)

    if require_fresh_issuance and not_before < now - ISSUANCE_FRESHNESS_WINDOW:
        raise ValueError(
            "Issued certificate is older than the issuance freshness window"
        )

    actual_lifetime = not_after - not_before
    expected_lifetime = timedelta(days=lifetime_days)
    if actual_lifetime != expected_lifetime:
        raise ValueError(
            "Issued certificate validity period is inconsistent with "
            "opnsense.lifetime_days"
        )

    _validate_issued_signature(certificate, digest)

    return certificate


def verify_issued_certificate_trust(certificate, switch, verification_ca_snapshot):
    """Verify an issued server certificate against the configured CA bundle."""
    snapshot = require_verification_ca_snapshot(verification_ca_snapshot)

    try:
        trusted_certificates = x509.load_pem_x509_certificates(snapshot.pem)
    except ValueError:
        raise ValueError(
            "verification.ca_file does not contain valid PEM certificates: "
            f"{snapshot.path}"
        ) from None

    if not trusted_certificates:
        raise ValueError(
            "verification.ca_file does not contain any trusted certificates: "
            f"{snapshot.path}"
        )

    host_identity = parse_identity(switch["host"], "switch host")
    if host_identity["kind"] == "dns":
        expected_identity = x509.DNSName(host_identity["value"])
    else:
        expected_identity = x509.IPAddress(ipaddress.ip_address(host_identity["value"]))

    verifier = (
        PolicyBuilder()
        .store(Store(trusted_certificates))
        .build_server_verifier(expected_identity)
    )

    try:
        verifier.verify(certificate, [])
    except VerificationError as error:
        raise ValueError(
            "Issued certificate failed pre-install trust verification against "
            f"verification.ca_file ({snapshot.path}): {error}"
        ) from error


def read_certificate_input(certificate_input):
    try:
        flags = os.O_RDONLY | os.O_NONBLOCK
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(certificate_input, flags)
        try:
            input_file = os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise
        with input_file:
            if not stat.S_ISREG(os.fstat(input_file.fileno()).st_mode):
                raise ValueError(
                    f"Certificate input is not a regular file: {certificate_input}"
                )

            certificate_bytes = input_file.read(MAX_CERTIFICATE_INPUT_BYTES + 1)

    except FileNotFoundError:
        raise ValueError(
            f"Certificate input file not found: {certificate_input}"
        ) from None
    except IsADirectoryError:
        raise ValueError(
            f"Certificate input is not a regular file: {certificate_input}"
        ) from None
    except OSError as error:
        raise ValueError(
            f"Certificate input could not be read: {certificate_input}: {error}"
        ) from error

    if len(certificate_bytes) > MAX_CERTIFICATE_INPUT_BYTES:
        raise ValueError(
            f"Certificate input exceeds {MAX_CERTIFICATE_INPUT_BYTES} bytes"
        )

    try:
        certificate_pem = certificate_bytes.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("Certificate input must be ASCII PEM") from error

    pem_match = re.fullmatch(
        r"[ \t\r\n]*"
        r"-----BEGIN CERTIFICATE-----\r?\n"
        r"(?:[A-Za-z0-9+/=]+\r?\n)+"
        r"-----END CERTIFICATE-----"
        r"[ \t\r\n]*",
        certificate_pem,
    )
    if pem_match is None:
        raise ValueError(
            "Certificate input must contain exactly one PEM X.509 certificate"
        )

    try:
        certificates = x509.load_pem_x509_certificates(certificate_bytes)
    except ValueError as error:
        raise ValueError("Certificate input is not valid PEM X.509") from error

    if len(certificates) != 1:
        raise ValueError("Certificate input must contain exactly one certificate")

    return certificate_pem


def build_opnsense_certificate_description(certificate_name, common_name):
    """Bound metadata built from the validated ASCII name and switch identity."""
    description = f"Aruba Web certificate {certificate_name} for {common_name}"
    return description[:MAX_DESCRIPTION_CHARS]


def sign_pending_csr(
    switch,
    username,
    password,
    certificate_name,
    csr_settings,
    opnsense_settings,
    *,
    minimum_remaining_days=None,
):
    identities = validate_switch_signing_identity(switch)
    description = build_opnsense_certificate_description(
        certificate_name, identities["common_name"]
    )
    csr_pem = retrieve_csr(
        switch,
        username,
        password,
        certificate_name,
        csr_settings,
    )
    csr = validate_csr_pem(csr_pem, switch, csr_settings)

    client = OPNsenseClient(opnsense_settings["base_url"])
    caref = client.resolve_ca(opnsense_settings["ca"])
    certificate_uuid = client.sign_csr(
        csr_pem,
        caref=caref,
        digest=opnsense_settings["digest"],
        lifetime_days=opnsense_settings["lifetime_days"],
        dns_names=identities["dns_names"],
        ip_addresses=identities["ip_addresses"],
        description=description,
    )
    certificate_pem = client.get_certificate(certificate_uuid)
    validate_issued_certificate(
        certificate_pem,
        csr,
        switch,
        opnsense_settings["lifetime_days"],
        digest=opnsense_settings["digest"],
        require_fresh_issuance=True,
        minimum_remaining_days=minimum_remaining_days,
    )
    return certificate_pem


@contextmanager
def snapshot_known_hosts(switch):
    try:
        known_hosts_file = switch["_ssh_known_hosts_file"]
    except KeyError:
        raise ValueError(
            "SSH known_hosts configuration was not validated for this switch"
        ) from None

    try:
        with open_secure_file(
            known_hosts_file, source_name="ssh.known_hosts_file"
        ) as source:
            contents = source.read(MAX_KNOWN_HOSTS_FILE_BYTES + 1)
    except OSError:
        raise ValueError(
            f"ssh.known_hosts_file cannot be read: {known_hosts_file}"
        ) from None
    if len(contents) > MAX_KNOWN_HOSTS_FILE_BYTES:
        raise ValueError(
            f"ssh.known_hosts_file exceeds {MAX_KNOWN_HOSTS_FILE_BYTES} bytes: {known_hosts_file}"
        )

    directory = tempfile.mkdtemp(prefix="aruba-known-hosts-")
    primary_error = False
    try:
        if stat.S_IMODE(os.stat(directory).st_mode) != 0o700:
            raise OSError("temporary directory permissions are unsafe")
        snapshot = Path(directory) / "known_hosts"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        with os.fdopen(os.open(snapshot, flags, 0o600), "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(contents)
        yield snapshot
    except BaseException:
        primary_error = True
        raise
    finally:
        try:
            shutil.rmtree(directory)
        except OSError:
            if not primary_error:
                raise ValueError(
                    "SSH known_hosts snapshot could not be removed"
                ) from None
            logging.warning("SSH known_hosts snapshot could not be removed")


def get_device_parameters(switch, username, password, snapshot):
    return {
        "device_type": "aruba_osswitch",
        "host": switch["host"],
        "username": username,
        "password": password,
        "conn_timeout": 10,
        "banner_timeout": 15,
        "auth_timeout": 15,
        "ssh_strict": True,
        "system_host_keys": False,
        "alt_host_keys": True,
        "alt_key_file": str(snapshot),
        "disabled_algorithms": {
            category: list(algorithms)
            for category, algorithms in SSH_DISABLED_ALGORITHMS.items()
        },
    }


@contextmanager
def ssh_connection(switch, username, password):
    with snapshot_known_hosts(switch) as snapshot:
        device = get_device_parameters(switch, username, password, snapshot)
        with ConnectHandler(**device) as connection:
            yield connection


class CSRGenerationError(ValueError):
    """An error after CSR creation was attempted on the switch."""


class CertificateInstallationAttemptError(ValueError):
    """An error after certificate installation was attempted on the switch."""


class RenewalPreflightError(ValueError):
    """A read-only renewal preflight failure."""


class CSRGenerationPreAttemptError(ValueError):
    """A renewal failure before CSR creation was attempted."""


class CSRSigningError(ValueError):
    """A renewal signing failure that leaves a pending CSR on the switch."""


class CertificatePreInstallationError(ValueError):
    """A renewal failure before certificate installation was attempted."""


class LiveHTTPSVerificationError(ValueError):
    """A renewal HTTPS failure after certificate installation completed."""


def renewal_preflight(switch, username, password, *, now=None):
    """Read switch certificate state and select a safe renewal name."""
    try:
        with ssh_connection(switch, username, password) as connection:
            summary_output = connection.send_command(
                "show crypto pki local-certificate summary"
            )

        certificates = parse_web_certificates(summary_output)
        pending = [
            certificate for certificate in certificates if certificate["pending"]
        ]
        if pending:
            names = ", ".join(certificate["name"] for certificate in pending)
            raise RenewalPreflightError(
                f"A pending Web CSR already exists ({names}). Use the explicit "
                "staged commands to inspect or recover it; --renew will not "
                "resume, replace, or clear it"
            )

        active_certificate = get_active_web_certificate(certificates)
        certificate_name = choose_renewal_certificate_name(
            summary_output,
            now=now,
        )
        return {
            "active_certificate_name": active_certificate["name"],
            "ta_profile": active_certificate["profile"],
            "new_certificate_name": certificate_name,
        }

    except RenewalPreflightError:
        raise
    except NetmikoAuthenticationException as error:
        raise RenewalPreflightError("SSH authentication failed") from error
    except NetmikoTimeoutException as error:
        raise RenewalPreflightError("SSH connection timed out") from error
    except (ValueError, OSError) as error:
        raise RenewalPreflightError(str(error)) from error


def renew_certificate(
    switch,
    username,
    password,
    csr_settings,
    opnsense_settings,
    verification_ca_snapshot,
    *,
    now=None,
    minimum_remaining_days=None,
):
    """Compose the proven staged functions into one explicit renewal."""
    require_verification_ca_snapshot(verification_ca_snapshot)
    preflight = renewal_preflight(
        switch,
        username,
        password,
        now=now,
    )
    certificate_name = preflight["new_certificate_name"]

    print_terminal(
        f"Current active Web certificate: {preflight['active_certificate_name']}"
    )
    print_terminal(f"Selected renewal certificate name: {certificate_name}")

    try:
        generate_csr(
            switch,
            username,
            password,
            certificate_name,
            csr_settings,
        )
    except CSRGenerationError:
        raise
    except (ValueError, OSError) as error:
        raise CSRGenerationPreAttemptError(str(error)) from error

    print_terminal("CSR generated and validated.")
    print_terminal("Signing CSR with OPNsense...")

    try:
        certificate_pem = sign_pending_csr(
            switch,
            username,
            password,
            certificate_name,
            csr_settings,
            opnsense_settings,
            minimum_remaining_days=minimum_remaining_days,
        )
    except (ValueError, OSError) as error:
        raise CSRSigningError(
            f"{error}. The pending CSR remains on the switch; use the explicit "
            "staged commands for diagnosis or recovery"
        ) from error

    print_terminal("Issued certificate validated.")
    print_terminal("Verifying issued certificate trust before installation...")

    try:
        certificate = install_pending_certificate(
            switch,
            username,
            password,
            certificate_name,
            certificate_pem,
            csr_settings,
            opnsense_settings["lifetime_days"],
            verification_ca_snapshot,
            digest=opnsense_settings["digest"],
            minimum_remaining_days=minimum_remaining_days,
        )
    except CertificateInstallationAttemptError:
        raise
    except (ValueError, OSError) as error:
        raise CertificatePreInstallationError(
            f"{error}. The pending CSR remains on the switch; use the explicit "
            "staged commands for diagnosis or recovery"
        ) from error

    print_terminal("Certificate installed and Aruba state verified.")
    print_terminal("Verifying live HTTPS...")

    try:
        verify_live_https_certificate(
            switch,
            verification_ca_snapshot,
            certificate,
        )
    except (ValueError, OSError, ssl.SSLError) as error:
        raise LiveHTTPSVerificationError(str(error)) from error

    print_terminal("Live HTTPS certificate chain and hostname verified.")
    print_terminal("Live HTTPS certificate matches the installed certificate.")
    print_terminal("Renewal completed successfully.")
    print_terminal(f"Active Web certificate: {certificate_name}")
    return certificate_name


def retrieve_and_validate_csr(connection, switch, certificate_name, csr_settings):
    csr_output = connection.send_command(
        f"show crypto pki local-certificate {certificate_name}",
        read_timeout=30,
    )
    csr_pem = extract_csr_pem(csr_output)
    validate_csr_pem(csr_pem, switch, csr_settings)
    return csr_pem


def generate_csr(
    switch,
    username,
    password,
    certificate_name,
    csr_settings,
):
    certificate_name = validate_cli_identifier(
        certificate_name,
        "certificate name",
    )
    csr_settings = validate_csr_settings(csr_settings)
    csr_creation_attempted = False

    try:
        with ssh_connection(switch, username, password) as connection:
            summary_output = connection.send_command(
                "show crypto pki local-certificate summary"
            )
            certificates = parse_web_certificates(summary_output)
            active_certificate = get_active_web_certificate(certificates)

            if certificate_name.casefold() == active_certificate["name"].casefold():
                raise ValueError(
                    "New certificate name must differ from the active Web "
                    "certificate name"
                )

            if certificate_name_exists(summary_output, certificate_name):
                raise ValueError(
                    f"Certificate name already exists on the switch: {certificate_name}"
                )

            csr_command = build_csr_command(
                switch,
                certificate_name,
                active_certificate["profile"],
                csr_settings,
            )

            print_terminal(
                f"Current active Web certificate: {active_certificate['name']}"
            )
            print_terminal(f"Discovered TA profile: {active_certificate['profile']}")
            print_terminal(f"Requested new certificate name: {certificate_name}")
            print_terminal("Generating CSR...")

            connection.config_mode()

            try:
                csr_creation_attempted = True
                connection.send_command_timing(
                    csr_command,
                    read_timeout=120,
                )
            finally:
                connection.exit_config_mode()

            try:
                return retrieve_and_validate_csr(
                    connection,
                    switch,
                    certificate_name,
                    csr_settings,
                )

            except ValueError as error:
                raise CSRGenerationError(
                    f"CSR retrieval or validation failed: {error}. "
                    "The pending CSR was not removed"
                ) from error

    except CSRGenerationError:
        raise

    except NetmikoAuthenticationException as error:
        if csr_creation_attempted:
            raise CSRGenerationError(
                "SSH authentication failed after CSR creation was attempted; "
                "a pending CSR may remain on the switch"
            ) from error

        raise ValueError("SSH authentication failed") from error

    except NetmikoTimeoutException as error:
        if csr_creation_attempted:
            raise CSRGenerationError(
                "SSH operation timed out after CSR creation was attempted; "
                "a pending CSR may remain on the switch"
            ) from error

        raise ValueError("SSH connection timed out") from error

    except Exception as error:
        if csr_creation_attempted:
            raise CSRGenerationError(
                "CSR creation was attempted, but the operation failed; "
                "a pending CSR may remain on the switch"
            ) from error

        raise


def retrieve_csr(
    switch,
    username,
    password,
    certificate_name,
    csr_settings,
):
    certificate_name = validate_cli_identifier(
        certificate_name,
        "certificate name",
    )
    csr_settings = validate_csr_settings(csr_settings)

    try:
        with ssh_connection(switch, username, password) as connection:
            summary_output = connection.send_command(
                "show crypto pki local-certificate summary"
            )
            entry = get_certificate_summary_entry(
                summary_output,
                certificate_name,
            )

            if entry["usage"].casefold() != "web":
                raise ValueError(
                    f"Certificate {certificate_name} has usage {entry['usage']}; "
                    "expected Web"
                )

            if entry["expiration"].casefold() != "csr":
                raise ValueError(
                    f"Certificate {certificate_name} is installed; expected a "
                    "pending CSR"
                )

            return retrieve_and_validate_csr(
                connection,
                switch,
                certificate_name,
                csr_settings,
            )

    except NetmikoAuthenticationException as error:
        raise ValueError("SSH authentication failed") from error

    except NetmikoTimeoutException as error:
        raise ValueError("SSH connection timed out") from error


def require_pending_web_certificate(summary_output, certificate_name):
    entry = get_certificate_summary_entry(summary_output, certificate_name)

    if entry["usage"].casefold() != "web":
        raise ValueError(
            f"Certificate {certificate_name} has usage {entry['usage']}; expected Web"
        )

    if entry["expiration"].casefold() != "csr":
        raise ValueError(
            f"Certificate {certificate_name} is installed; expected a pending CSR"
        )

    return entry


def _contains_obvious_cli_error(output):
    return (
        re.search(
            r"(?:^|\n)\s*(?:%\s*)?(?:invalid|unknown|error|failed)|not found",
            output,
            re.IGNORECASE,
        )
        is not None
    )


def _ends_with_expected_prompt(output, expected_prompt):
    return not _contains_obvious_cli_error(output) and output.rstrip().endswith(
        expected_prompt
    )


def _send_certificate_pem(connection, certificate_pem):
    previous_logging_disable = logging.root.manager.disable
    logging.disable(logging.DEBUG)
    try:
        connection.write_channel(certificate_pem)
        connection.write_channel("\n")
        return connection.read_channel_timing(read_timeout=60)
    finally:
        logging.disable(previous_logging_disable)


def install_signed_certificate(
    connection,
    certificate_name,
    certificate_pem,
    expected_profile,
):
    """Install one validated PEM certificate using the guarded AOS-S prompts."""
    installation_attempted = False
    installation_dialogue_completed = False
    entered_config_mode = False

    try:
        summary_output = connection.send_command(
            "show crypto pki local-certificate summary"
        )
        pending_entry = require_pending_web_certificate(
            summary_output,
            certificate_name,
        )
        if pending_entry["profile"].casefold() != expected_profile.casefold():
            raise ValueError(
                f"Certificate {certificate_name} TA profile changed before installation"
            )

        connection.config_mode()
        entered_config_mode = True

        installation_attempted = True
        paste_prompt = connection.send_command_timing(
            "crypto pki install-signed-certificate",
            read_timeout=30,
        )
        if not _ends_with_expected_prompt(paste_prompt, CERTIFICATE_PASTE_PROMPT):
            raise ValueError(
                "Switch did not return the expected certificate-paste prompt"
            )

        replacement_prompt = _send_certificate_pem(connection, certificate_pem)
        if not _ends_with_expected_prompt(
            replacement_prompt,
            CERTIFICATE_REPLACEMENT_PROMPT,
        ):
            raise ValueError(
                "Switch did not return the expected certificate-replacement prompt; "
                "confirmation was not sent"
            )

        confirmation_output = connection.send_command_timing(
            "y",
            read_timeout=60,
        )
        if _contains_obvious_cli_error(confirmation_output):
            raise ValueError(
                "Switch reported an error while installing the certificate"
            )
        installation_dialogue_completed = True

    except Exception as error:
        if installation_attempted:
            raise CertificateInstallationAttemptError(
                f"Certificate installation may already have changed the switch: {error}"
            ) from error
        raise

    finally:
        if entered_config_mode:
            try:
                connection.exit_config_mode()
            except Exception as exit_error:
                if installation_dialogue_completed:
                    raise CertificateInstallationAttemptError(
                        "Certificate installation may already have changed the switch, "
                        f"and config mode could not be exited: {exit_error}"
                    ) from exit_error

    try:
        summary_output = connection.send_command(
            "show crypto pki local-certificate summary"
        )
        installed_entry = get_certificate_summary_entry(
            summary_output,
            certificate_name,
        )
        if installed_entry["usage"].casefold() != "web":
            raise ValueError(
                f"Installed certificate has usage {installed_entry['usage']}; "
                "expected Web"
            )
        if installed_entry["expiration"].casefold() == "csr":
            raise ValueError("Certificate is still shown as a pending CSR")
        if installed_entry["profile"].casefold() != expected_profile.casefold():
            raise ValueError("Installed certificate TA profile changed")

        details_output = connection.send_command(
            f"show crypto pki local-certificate {certificate_name}",
            read_timeout=30,
        )
        if (
            _contains_obvious_cli_error(details_output)
            or re.search(
                r"(?:^|\n)\s*Certificate Detail:\s*(?:\n|$)",
                details_output,
            )
            is None
        ):
            raise ValueError(
                "Could not confirm the installed certificate in detailed switch output"
            )

    except CertificateInstallationAttemptError:
        raise
    except Exception as error:
        raise CertificateInstallationAttemptError(
            "Certificate installation may already have changed the switch, but "
            f"post-install Aruba verification failed: {error}"
        ) from error


def install_pending_certificate(
    switch,
    username,
    password,
    certificate_name,
    certificate_pem,
    csr_settings,
    lifetime_days,
    verification_ca_snapshot,
    *,
    digest,
    minimum_remaining_days=None,
):
    require_verification_ca_snapshot(verification_ca_snapshot)
    certificate_name = validate_cli_identifier(
        certificate_name,
        "certificate name",
    )
    csr_settings = validate_csr_settings(csr_settings)
    validate_switch_signing_identity(switch)
    installation_completed = False

    try:
        with ssh_connection(switch, username, password) as connection:
            summary_output = connection.send_command(
                "show crypto pki local-certificate summary"
            )
            pending_entry = require_pending_web_certificate(
                summary_output,
                certificate_name,
            )
            csr_pem = retrieve_and_validate_csr(
                connection,
                switch,
                certificate_name,
                csr_settings,
            )
            csr = validate_csr_pem(csr_pem, switch, csr_settings)
            certificate = validate_issued_certificate(
                certificate_pem,
                csr,
                switch,
                lifetime_days,
                digest=digest,
                minimum_remaining_days=minimum_remaining_days,
            )
            verify_issued_certificate_trust(
                certificate,
                switch,
                verification_ca_snapshot,
            )
            _require_current_certificate_validity(
                certificate, datetime.now(UTC), minimum_remaining_days
            )

            install_signed_certificate(
                connection,
                certificate_name,
                certificate_pem,
                pending_entry["profile"],
            )
            installation_completed = True
            return certificate

    except CertificateInstallationAttemptError:
        raise
    except NetmikoAuthenticationException as error:
        if installation_completed:
            raise CertificateInstallationAttemptError(
                "Certificate installation may already have changed the switch; "
                "SSH authentication failed while closing the connection"
            ) from error
        raise ValueError("SSH authentication failed") from error
    except NetmikoTimeoutException as error:
        if installation_completed:
            raise CertificateInstallationAttemptError(
                "Certificate installation may already have changed the switch; "
                "SSH timed out while closing the connection"
            ) from error
        raise ValueError("SSH connection timed out") from error
    except (ValueError, OSError) as error:
        if installation_completed:
            raise CertificateInstallationAttemptError(
                "Certificate installation may already have changed the switch; "
                "an error occurred while closing the SSH connection"
            ) from error
        raise
    except Exception as error:
        if installation_completed:
            raise CertificateInstallationAttemptError(
                "Certificate installation may already have changed the switch; "
                "an SSH error occurred while closing the connection"
            ) from error
        raise ValueError(
            "SSH operation failed before certificate installation was attempted"
        ) from error


def verify_live_https_certificate(
    switch,
    verification_ca_snapshot,
    expected_certificate,
    *,
    verification_window=HTTPS_VERIFICATION_WINDOW_SECONDS,
    retry_delay=HTTPS_RETRY_DELAY_SECONDS,
    socket_timeout=HTTPS_SOCKET_TIMEOUT_SECONDS,
):
    snapshot = require_verification_ca_snapshot(verification_ca_snapshot)
    for value, name, zero_allowed in (
        (verification_window, "verification window", False),
        (retry_delay, "retry delay", True),
        (socket_timeout, "socket timeout", False),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"Invalid live HTTPS {name}")
        try:
            finite = math.isfinite(value)
        except OverflowError:
            finite = False
        if not finite or value < 0 or (value == 0 and not zero_allowed):
            raise ValueError(f"Invalid live HTTPS {name}")

    host = validate_switch_signing_identity(switch)["common_name"]
    expected_der = expected_certificate.public_bytes(serialization.Encoding.DER)
    try:
        context = create_client_tls_context(cadata=_ca_ssl_data(snapshot))
    except (OSError, ssl.SSLError, ValueError):
        raise ValueError(
            f"verification.ca_file cannot be loaded as a CA file: {snapshot.path}"
        ) from None

    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise ValueError("TLS verification context is not securely configured")

    deadline = time.monotonic() + verification_window
    if not math.isfinite(deadline):
        raise ValueError("Invalid live HTTPS verification window")
    addresses = _resolve_live_https_addresses(host, deadline)
    last_error = "HTTPS endpoint did not become ready"

    while True:
        if deadline - time.monotonic() <= 0:
            break
        try:
            peer_der = _read_live_https_leaf(
                addresses, host, context, deadline, socket_timeout
            )
            if peer_der == expected_der:
                if deadline - time.monotonic() <= 0:
                    last_error = "HTTPS verification deadline expired"
                    break
                return
            last_error = "HTTPS service presented a different valid certificate"
        except ssl.SSLCertVerificationError:
            raise ValueError(
                "Live HTTPS certificate or hostname verification failed"
            ) from None
        except ssl.SSLError:
            raise ValueError("Live HTTPS TLS handshake failed") from None
        except OSError as error:
            if not _is_retryable_live_https_error(error):
                raise ValueError("Live HTTPS connection failed") from None
            last_error = "HTTPS endpoint did not become ready"

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(retry_delay, remaining))

    raise ValueError(
        "Expected certificate was not verified over live HTTPS within "
        f"{verification_window} seconds: {last_error}"
    )


def _resolve_hostname_worker(connection, host):
    try:
        # Only small numeric socket addresses cross the process boundary.
        results = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        addresses = []
        for family, socktype, _protocol, _canonical, sockaddr in results:
            if (
                family in (socket.AF_INET, socket.AF_INET6)
                and socktype == socket.SOCK_STREAM
            ):
                addresses.append((family, sockaddr))
                if len(addresses) == 16:
                    break
        connection.send(addresses)
    except (OSError, OverflowError):
        connection.send([])
    finally:
        connection.close()


def _resolve_live_https_addresses(host, deadline):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        sockaddr = (host, 443, 0, 0) if address.version == 6 else (host, 443)
        return [(family, sockaddr)]

    remaining = deadline - time.monotonic()
    if remaining <= HTTPS_RESOLVER_CLEANUP_SECONDS:
        raise ValueError("Live HTTPS hostname resolution exceeded verification window")

    context = multiprocessing.get_context("spawn")
    try:
        receiver, sender = context.Pipe(duplex=False)
    except OSError:
        raise ValueError("Live HTTPS hostname resolution could not start") from None
    try:
        process = context.Process(target=_resolve_hostname_worker, args=(sender, host))
    except OSError:
        receiver.close()
        sender.close()
        raise ValueError("Live HTTPS hostname resolution could not start") from None
    process.daemon = True
    try:
        try:
            process.start()
        except OSError:
            raise ValueError("Live HTTPS hostname resolution could not start") from None
        sender.close()
        wait = max(0.0, deadline - time.monotonic() - HTTPS_RESOLVER_CLEANUP_SECONDS)
        if not receiver.poll(wait):
            raise ValueError(
                "Live HTTPS hostname resolution exceeded verification window"
            )
        try:
            addresses = receiver.recv()
        except EOFError:
            addresses = []
        if not addresses:
            raise ValueError("Live HTTPS hostname resolution failed")
        if time.monotonic() >= deadline:
            raise ValueError(
                "Live HTTPS hostname resolution exceeded verification window"
            )
        return addresses
    finally:
        receiver.close()
        sender.close()
        if process.pid is not None:
            if process.is_alive():
                process.kill()
            process.join(timeout=HTTPS_RESOLVER_CLEANUP_SECONDS)
            if process.is_alive():
                raise ValueError("Live HTTPS hostname resolver could not stop")
            process.close()


def _read_live_https_leaf(addresses, host, context, deadline, socket_timeout):
    last_error = None
    for family, sockaddr in addresses:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as tcp_socket:
                tcp_socket.settimeout(_live_https_timeout(deadline, socket_timeout))
                tcp_socket.connect(sockaddr)
                tcp_socket.settimeout(_live_https_timeout(deadline, socket_timeout))
                with context.wrap_socket(
                    tcp_socket, server_hostname=host
                ) as tls_socket:
                    peer_der = tls_socket.getpeercert(binary_form=True)
            _live_https_timeout(deadline, socket_timeout)
            return peer_der
        except ssl.SSLError:
            raise
        except OSError as error:
            if not _is_retryable_live_https_error(error):
                raise
            last_error = error
            if deadline - time.monotonic() <= 0:
                break
    if last_error is not None:
        raise last_error
    raise TimeoutError


def _is_retryable_live_https_error(error):
    # ConnectionError and TimeoutError are OSError subclasses. SSL errors are
    # always handled separately as hard failures before this classification.
    return isinstance(error, (ConnectionError, TimeoutError)) or error.errno in {
        errno.ECONNREFUSED,
        errno.ECONNRESET,
        errno.ECONNABORTED,
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
        errno.ETIMEDOUT,
    }


def _live_https_timeout(deadline, socket_timeout):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return min(socket_timeout, remaining)


def check_switch(switch, username, password, warning_days):
    print_switch_heading(switch)

    try:
        with ssh_connection(switch, username, password) as connection:
            version_output = connection.send_command("show version")
            cert_output = connection.send_command(
                "show crypto pki local-certificate summary"
            )

    except NetmikoAuthenticationException:
        print_terminal("Status:           ERROR")
        print_terminal("Reason:           SSH authentication failed")
        return "error"

    except NetmikoTimeoutException:
        print_terminal("Status:           ERROR")
        print_terminal("Reason:           SSH connection timed out")
        return "error"

    except Exception as error:
        print_terminal("Status:           ERROR")
        print_terminal(f"Reason:           {error}")
        return "error"

    print_terminal(f"AOS-S version:    {parse_aos_version(version_output)}")

    try:
        certificate = get_active_web_certificate(parse_web_certificates(cert_output))

    except ValueError as error:
        print_terminal("Status:           ERROR")
        print_terminal(f"Reason:           {error}")
        return "error"

    days_remaining = (certificate["expiration"] - date.today()).days

    print_terminal(f"Certificate:      {certificate['name']}")
    print_terminal(f"TA profile:       {certificate['profile']}")
    print_terminal(f"Expires:          {certificate['expiration'].isoformat()}")
    print_terminal(f"Days remaining:   {days_remaining}")

    if days_remaining < 0:
        print_terminal("Status:           EXPIRED")
        return "expired"

    if days_remaining <= warning_days:
        print_terminal("Status:           RENEWAL DUE")
        return "renewal_due"

    print_terminal("Status:           OK")
    return "ok"


def print_summary(results, completed_at):
    print_terminal()
    print_terminal("Summary")
    print_terminal("-------")
    print_terminal(f"Switches checked: {len(results)}")
    print_terminal(f"OK:               {results.count('ok')}")
    print_terminal(f"Renewal due:      {results.count('renewal_due')}")
    print_terminal(f"Expired:          {results.count('expired')}")
    print_terminal(f"Errors:           {results.count('error')}")
    print_terminal()
    print_terminal(f"Check completed:  {format_run_timestamp(completed_at)}")


def print_renewal_summary(results, completed_at):
    print_terminal()
    print_terminal("Renewal summary")
    print_terminal("---------------")
    print_terminal(f"Switches processed: {len(results)}")
    print_terminal(f"Healthy:             {results.count('healthy')}")
    print_terminal(f"Renewed:             {results.count('renewed')}")
    print_terminal(f"Errors:              {results.count('error')}")
    print_terminal()
    print_terminal(f"Check completed:     {format_run_timestamp(completed_at)}")


def get_exit_code(results):
    if "error" in results:
        return EXIT_ERROR

    if "renewal_due" in results or "expired" in results:
        return EXIT_WARNING

    return EXIT_OK


def report_renewal_failure(error):
    """Print the established explicit-renewal safety message for an error."""
    if isinstance(error, RenewalPreflightError):
        print_terminal(
            "Error: Renewal preflight failed; no renewal change was "
            f"attempted: {error}",
            file=sys.stderr,
        )
    elif isinstance(error, CSRGenerationPreAttemptError):
        print_terminal(
            "Error: CSR generation failed before CSR creation was attempted; "
            f"no pending CSR was created: {error}",
            file=sys.stderr,
        )
    elif isinstance(error, CSRGenerationError):
        print_terminal(f"Error: {error}", file=sys.stderr)
        print_terminal(
            "CSR creation was attempted. No automatic cleanup was attempted; "
            "use the explicit staged commands for diagnosis or recovery.",
            file=sys.stderr,
        )
    elif isinstance(error, CSRSigningError):
        print_terminal(f"Error: CSR signing failed: {error}", file=sys.stderr)
        print_terminal(
            "No certificate installation or automatic OPNsense cleanup was attempted.",
            file=sys.stderr,
        )
    elif isinstance(error, CertificatePreInstallationError):
        print_terminal(
            f"Error: Certificate installation did not begin: {error}",
            file=sys.stderr,
        )
        print_terminal("No automatic rollback was attempted.", file=sys.stderr)
    elif isinstance(error, CertificateInstallationAttemptError):
        print_terminal(f"Error: Post-install failure: {error}", file=sys.stderr)
        print_terminal(
            "No automatic rollback was attempted; inspect the switch manually.",
            file=sys.stderr,
        )
    elif isinstance(error, LiveHTTPSVerificationError):
        print_terminal(
            "Error: Post-install HTTPS verification failed. The certificate "
            "may already be active and requires manual investigation: "
            f"{error}",
            file=sys.stderr,
        )
        print_terminal("No automatic rollback was attempted.", file=sys.stderr)


RENEWAL_FAILURE_TYPES = (
    RenewalPreflightError,
    CSRGenerationPreAttemptError,
    CSRGenerationError,
    CSRSigningError,
    CertificatePreInstallationError,
    CertificateInstallationAttemptError,
    LiveHTTPSVerificationError,
)


def validate_automatic_renewal_window(warning_days, opnsense_settings):
    if warning_days < 0 or warning_days >= opnsense_settings["lifetime_days"]:
        raise ValueError(
            "--renew-due requires settings.warning_days to be less than "
            "opnsense.lifetime_days"
        )


def renew_due_certificates(
    switches,
    config_file,
    warning_days,
    csr_settings,
    opnsense_settings,
    verification_ca_snapshot,
):
    require_verification_ca_snapshot(verification_ca_snapshot)
    validate_automatic_renewal_window(warning_days, opnsense_settings)
    print_run_start("Aruba certificate renewal check", get_local_time())
    results = []

    for switch in switches:
        username = password = None
        result = None
        try:
            try:
                username, password = get_switch_credentials(switch, config_file)
            except ValueError as error:
                print_switch_heading(switch)
                print_terminal("Status:           ERROR")
                print_terminal(f"Reason:           {error}")
                print_terminal("Action:           No renewal attempted")
                result = "error"
                continue
            except Exception:
                print_switch_heading(switch)
                print_terminal("Status:           ERROR")
                print_terminal(
                    "Reason:           Unexpected credential resolution failure"
                )
                print_terminal("Action:           No renewal attempted")
                result = "error"
                continue

            with lifecycle_lock(switch["host"]):
                try:
                    status = check_switch(switch, username, password, warning_days)
                except Exception as error:
                    print_terminal("Status:           ERROR")
                    print_terminal(f"Reason:           {error}")
                    print_terminal("Action:           No renewal attempted")
                    result = "error"
                    continue
                if status == "ok":
                    print_terminal("Action:           No renewal required")
                    result = "healthy"
                    continue

                if status not in {"renewal_due", "expired"}:
                    print_terminal("Action:           No renewal attempted")
                    result = "error"
                    continue

                print_terminal("Action:           Renewing certificate")
                try:
                    renew_certificate(
                        switch,
                        username,
                        password,
                        csr_settings,
                        opnsense_settings,
                        verification_ca_snapshot,
                        minimum_remaining_days=warning_days,
                    )
                except RENEWAL_FAILURE_TYPES as error:
                    report_renewal_failure(error)
                    result = "error"
                except Exception as error:
                    print_terminal(
                        "Error: Unexpected renewal failure "
                        f"({type(error).__name__}). Renewal state may be uncertain.",
                        file=sys.stderr,
                    )
                    print_terminal(
                        "No automatic retry, cleanup, or rollback was attempted; "
                        "inspect the switch and use the explicit staged commands "
                        "if necessary.",
                        file=sys.stderr,
                    )
                    result = "error"
                else:
                    result = "renewed"
        except LifecycleLockReleaseError:
            print_terminal("Status:           ERROR")
            if result == "renewed":
                print_terminal(
                    "Reason:           Lifecycle lock release failed after renewal. "
                    "Renewal may already have completed; inspect the switch manually"
                )
                print_terminal(
                    "Action:           No automatic retry, cleanup, or rollback"
                )
            elif result == "healthy":
                print_terminal(
                    "Reason:           Certificate check completed; no renewal was "
                    "required, but lifecycle lock release failed"
                )
                print_terminal(
                    "Action:           Inspect local lifecycle lock state before retry"
                )
            elif result == "error":
                print_terminal(
                    "Reason:           Switch check or renewal had already reported "
                    "an error; lifecycle lock release also failed"
                )
                print_terminal(
                    "Action:           Inspect switch and lifecycle lock state "
                    "manually before retry; no automatic retry, cleanup, or rollback"
                )
            else:
                print_terminal(
                    "Reason:           Lifecycle lock release failed; the protected "
                    "operation outcome could not be confirmed"
                )
                print_terminal(
                    "Action:           Inspect switch and lifecycle lock state "
                    "manually before retry; no automatic retry, cleanup, or rollback"
                )
            result = "error"
        except LifecycleLockError as error:
            print_switch_heading(switch)
            print_terminal("Status:           ERROR")
            print_terminal(f"Reason:           {error}")
            print_terminal("Action:           No renewal attempted")
            result = "error"
        finally:
            username = password = None
            if result is not None:
                results.append(result)

    print_renewal_summary(results, get_local_time())
    return EXIT_ERROR if "error" in results else EXIT_OK


def write_or_print_csr(csr_pem, output_path):
    if output_path:
        with output_path.open("x", encoding="ascii") as output_file:
            output_file.write(csr_pem)

        print_terminal(f"CSR written to {output_path}")
    else:
        print(csr_pem, end="")


def write_certificate(certificate_pem, output_path):
    with output_path.open("x", encoding="ascii") as output_file:
        output_file.write(certificate_pem)

    print_terminal(f"Certificate written to {output_path}")


def run_explicit_operation(
    args,
    switches,
    csr_settings,
    opnsense_settings,
    verification_ca_snapshot,
    certificate_pem,
):
    if args.renew or args.install_certificate:
        require_verification_ca_snapshot(verification_ca_snapshot)
    try:
        username, password = get_switch_credentials(switches[0], args.config)
    except ValueError as error:
        print_terminal(f"Error: {error}", file=sys.stderr)
        return EXIT_ERROR

    if args.renew:
        switch = switches[0]

        try:
            renew_certificate(
                switch,
                username,
                password,
                csr_settings,
                opnsense_settings,
                verification_ca_snapshot,
            )
            return EXIT_OK

        except RENEWAL_FAILURE_TYPES as error:
            report_renewal_failure(error)
            return EXIT_ERROR

    if args.install_certificate:
        switch = switches[0]

        try:
            certificate = install_pending_certificate(
                switch,
                username,
                password,
                args.certificate_name,
                certificate_pem,
                csr_settings,
                opnsense_settings["lifetime_days"],
                verification_ca_snapshot,
                digest=opnsense_settings["digest"],
            )

        except CertificateInstallationAttemptError as error:
            print_terminal(f"Error: Post-install failure: {error}", file=sys.stderr)
            print_terminal(
                "No automatic rollback was attempted; inspect the switch manually.",
                file=sys.stderr,
            )
            return EXIT_ERROR

        except (ValueError, OSError) as error:
            print_terminal(
                "Error: Pre-install failure; the switch has not been modified: "
                f"{error}",
                file=sys.stderr,
            )
            return EXIT_ERROR

        print_terminal(
            f"Certificate validated against pending CSR for {switch['name']}."
        )
        print_terminal(f"Signed certificate installed on {switch['name']}.")

        try:
            verify_live_https_certificate(
                switch,
                verification_ca_snapshot,
                certificate,
            )
        except (ValueError, OSError, ssl.SSLError) as error:
            print_terminal(
                "Error: Post-install HTTPS verification failed. The certificate "
                "may already be active and requires manual investigation: "
                f"{error}",
                file=sys.stderr,
            )
            print_terminal("No automatic rollback was attempted.", file=sys.stderr)
            return EXIT_ERROR

        print_terminal("Live HTTPS certificate chain and hostname verified.")
        print_terminal("Live HTTPS certificate matches the installed certificate.")
        print_terminal("Certificate installation verified successfully.")
        return EXIT_OK

    if args.sign_csr:
        switch = switches[0]

        try:
            certificate_pem = sign_pending_csr(
                switch,
                username,
                password,
                args.certificate_name,
                csr_settings,
                opnsense_settings,
            )
            write_certificate(certificate_pem, args.certificate_output)
            print_terminal(
                f"Pending CSR signed and issued certificate validated for "
                f"{switch['name']}."
            )
            print_terminal("The certificate has not been installed on the switch.")
            return EXIT_OK

        except (ValueError, OSError) as error:
            print_terminal(f"Error: {error}", file=sys.stderr)
            return EXIT_ERROR

    if args.generate_csr or args.retrieve_csr:
        switch = switches[0]

        try:
            if args.generate_csr:
                csr_pem = generate_csr(
                    switch,
                    username,
                    password,
                    args.certificate_name,
                    csr_settings,
                )
                print_terminal(f"CSR generated and validated for {switch['name']}.")
            else:
                csr_pem = retrieve_csr(
                    switch,
                    username,
                    password,
                    args.certificate_name,
                    csr_settings,
                )
                print_terminal(
                    f"Pending CSR retrieved and validated for {switch['name']}."
                )

            try:
                write_or_print_csr(csr_pem, args.csr_output)

            except OSError as error:
                if args.generate_csr:
                    raise CSRGenerationError(
                        f"CSR was generated and validated but could not be written "
                        f"to {args.csr_output}: {error}. The pending CSR remains on "
                        "the switch and can be retrieved again"
                    ) from error

                raise ValueError(
                    f"CSR was retrieved and validated but could not be written "
                    f"to {args.csr_output}: {error}"
                ) from error

            return EXIT_OK

        except (ValueError, OSError) as error:
            print_terminal(f"Error: {error}", file=sys.stderr)
            return EXIT_ERROR


def main():
    args = parse_args()
    configure_logging(args.debug)
    csr_settings = opnsense_settings = verification_ca_snapshot = certificate_pem = None

    try:
        validate_cli_args(args)
        config = load_config(args.config)
        warning_days, switches = validate_config(config, args.config)
        switches = select_switches(switches, args.switch_name)
        renew_due = getattr(args, "renew_due", False)

        if (
            args.generate_csr
            or args.retrieve_csr
            or args.sign_csr
            or args.install_certificate
            or args.renew
            or renew_due
        ):
            csr_settings = get_csr_settings(config)

        if args.sign_csr or args.install_certificate or args.renew or renew_due:
            opnsense_settings = get_opnsense_settings(config)
            if renew_due:
                validate_automatic_renewal_window(warning_days, opnsense_settings)
            for switch in switches if renew_due else switches[:1]:
                validate_switch_signing_identity(switch)

        if args.install_certificate or args.renew or renew_due:
            verification_ca_snapshot = get_verification_ca_file(config, args.config)

        if args.install_certificate:
            certificate_pem = read_certificate_input(args.certificate_input)

    except ValueError as error:
        print_terminal(f"Error: {error}", file=sys.stderr)
        return EXIT_ERROR

    explicit_operation = any(
        (
            args.generate_csr,
            args.retrieve_csr,
            args.sign_csr,
            args.install_certificate,
            args.renew,
        )
    )
    if renew_due:
        return renew_due_certificates(
            switches,
            args.config,
            warning_days,
            csr_settings,
            opnsense_settings,
            verification_ca_snapshot,
        )

    if explicit_operation:
        body_result = None
        try:
            if (
                args.renew
                or args.install_certificate
                or args.sign_csr
                or args.generate_csr
            ):
                with lifecycle_lock(switches[0]["host"]):
                    body_result = run_explicit_operation(
                        args,
                        switches,
                        csr_settings,
                        opnsense_settings,
                        verification_ca_snapshot,
                        certificate_pem,
                    )
                return body_result
            return run_explicit_operation(
                args,
                switches,
                csr_settings,
                opnsense_settings,
                verification_ca_snapshot,
                certificate_pem,
            )
        except LifecycleLockReleaseError:
            if body_result == EXIT_OK:
                print_terminal(
                    "Error: Command body completed before lifecycle lock release "
                    "failed. The operation may already have changed device state; "
                    "inspect it before retry. No automatic retry, cleanup, or "
                    "rollback was attempted.",
                    file=sys.stderr,
                )
            elif body_result == EXIT_ERROR:
                print_terminal(
                    "Error: Operation had already reported an error; lifecycle lock "
                    "release also failed. Inspect local lifecycle lock state before "
                    "retry. No automatic retry, cleanup, or rollback was attempted.",
                    file=sys.stderr,
                )
            else:
                print_terminal(
                    "Error: Lifecycle lock release failed; command body outcome "
                    "could not be confirmed. Inspect device state before retry. "
                    "No automatic retry, cleanup, or rollback was attempted.",
                    file=sys.stderr,
                )
            return EXIT_ERROR
        except LifecycleLockError as error:
            print_terminal(f"Error: {error}", file=sys.stderr)
            return EXIT_ERROR

    print_run_start("Aruba certificate check", get_local_time())
    results = []
    for switch in switches:
        try:
            username, password = get_switch_credentials(switch, args.config)
        except ValueError as error:
            print_switch_heading(switch)
            print_terminal("Status:           ERROR")
            print_terminal(f"Reason:           {error}")
            results.append("error")
            continue

        try:
            status = check_switch(switch, username, password, warning_days)
        except ValueError as error:
            print_switch_heading(switch)
            print_terminal("Status:           ERROR")
            print_terminal(f"Reason:           {error}")
            results.append("error")
            continue

        results.append(status)

    print_summary(results, get_local_time())

    return get_exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
