#!/usr/bin/env python3

import argparse
import getpass
import ipaddress
import logging
import os
import re
import socket
import ssl
import stat
import sys
import time
import tomllib
import warnings
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

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
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

from opnsense_client import OPNsenseClient, validate_base_url

DEFAULT_CONFIG_FILE = Path(__file__).resolve().parent.parent / "config.toml"

EXIT_OK = 0
EXIT_WARNING = 1
EXIT_ERROR = 2

MAX_CERTIFICATE_INPUT_BYTES = 64 * 1024
MAX_PASSWORD_FILE_BYTES = 16 * 1024
MAX_ADDITIONAL_SANS = 100
HTTPS_VERIFICATION_WINDOW_SECONDS = 30
HTTPS_RETRY_DELAY_SECONDS = 2
HTTPS_SOCKET_TIMEOUT_SECONDS = 5

CERTIFICATE_PASTE_PROMPT = "Paste the certificate here and enter:"
CERTIFICATE_REPLACEMENT_PROMPT = (
    "This certificate will replace an existing local certificate. Continue (y/n)?"
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

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    logging.getLogger("netmiko").setLevel(logging.DEBUG)

    # Paramiko's DEBUG output is extremely verbose and is usually not useful
    # when troubleshooting Netmiko command handling.
    logging.getLogger("paramiko").setLevel(logging.WARNING)


def load_config(config_file):
    try:
        with config_file.open("rb") as file:
            return tomllib.load(file)

    except FileNotFoundError:
        raise ValueError(f"Configuration file not found: {config_file}") from None

    except tomllib.TOMLDecodeError as error:
        raise ValueError(
            f"Invalid TOML in configuration file {config_file}: {error}"
        ) from error


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


def validate_config(config):
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
    password_file = Path(configured_path)
    if not password_file.is_absolute():
        password_file = config_file.resolve().parent / password_file

    try:
        with password_file.open("rb") as file:
            if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                raise ValueError(
                    f"switches.password_file is not a regular file: {password_file}"
                )
            password_bytes = file.read(MAX_PASSWORD_FILE_BYTES + 1)
    except FileNotFoundError:
        raise ValueError(f"switches.password_file not found: {password_file}") from None
    except IsADirectoryError:
        raise ValueError(
            f"switches.password_file is not a regular file: {password_file}"
        ) from None
    except OSError as error:
        raise ValueError(
            f"switches.password_file cannot be read: {password_file}: {error}"
        ) from error

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
    username = switch.get("username") or os.environ.get("ARUBA_SSH_USERNAME")
    if not username:
        username = input(f"SSH username for {switch['name']}: ")
    username = validate_ssh_username(username)

    if "password_file" in switch:
        password = read_password_file(switch["password_file"], config_file)
    else:
        password = os.environ.get("ARUBA_SSH_PASSWORD")
        if not password:
            password = getpass.getpass(f"SSH password for {switch['name']}: ")

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

    ca_file = Path(configured_path)
    if not ca_file.is_absolute():
        ca_file = config_file.resolve().parent / ca_file

    try:
        with ca_file.open("rb") as file:
            if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
                raise ValueError(
                    f"verification.ca_file is not a regular file: {ca_file}"
                )

    except FileNotFoundError:
        raise ValueError(f"verification.ca_file not found: {ca_file}") from None
    except IsADirectoryError:
        raise ValueError(
            f"verification.ca_file is not a regular file: {ca_file}"
        ) from None
    except OSError as error:
        raise ValueError(
            f"verification.ca_file cannot be read: {ca_file}: {error}"
        ) from error

    try:
        ssl.create_default_context(cafile=str(ca_file))
    except (OSError, ssl.SSLError) as error:
        raise ValueError(
            f"verification.ca_file cannot be loaded as a CA file: {ca_file}: {error}"
        ) from error

    return ca_file


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


def validate_issued_certificate(
    certificate_pem,
    csr,
    switch,
    lifetime_days,
    *,
    now=None,
    clock_skew=timedelta(minutes=5),
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
    if actual_dns != expected_dns:
        raise ValueError(
            "Issued certificate DNS SAN set does not exactly match configured "
            "identities"
        )

    expected_ips = {
        ipaddress.ip_address(address) for address in identities["ip_addresses"]
    }
    if set(ip_addresses) != expected_ips:
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
    if ExtendedKeyUsageOID.SERVER_AUTH not in extended_key_usage:
        raise ValueError(
            "Issued certificate Extended Key Usage must contain serverAuth"
        )

    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    if not_after <= not_before:
        raise ValueError("Issued certificate validity period is invalid")

    if now is None:
        now = datetime.now(UTC)
    elif now.tzinfo is None:
        raise ValueError("Certificate validation time must be timezone-aware")

    if not_before > now + clock_skew:
        raise ValueError("Issued certificate is not yet valid")

    if not_after <= now:
        raise ValueError("Issued certificate has expired")

    actual_lifetime = not_after - not_before
    expected_lifetime = timedelta(days=lifetime_days)
    lifetime_tolerance = timedelta(days=1)
    if not (
        expected_lifetime - lifetime_tolerance
        <= actual_lifetime
        <= expected_lifetime + lifetime_tolerance
    ):
        raise ValueError(
            "Issued certificate validity period is inconsistent with "
            "opnsense.lifetime_days"
        )

    try:
        signature_hash = certificate.signature_hash_algorithm
    except UnsupportedAlgorithm as error:
        raise ValueError(
            "Issued certificate signature hash algorithm is unsupported"
        ) from error

    if signature_hash is None or signature_hash.digest_size < 32:
        raise ValueError(
            "Issued certificate signature hash must be SHA-256 or stronger"
        )

    return certificate


def read_certificate_input(certificate_input):
    try:
        with certificate_input.open("rb") as input_file:
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


def sign_pending_csr(
    switch,
    username,
    password,
    certificate_name,
    csr_settings,
    opnsense_settings,
):
    identities = validate_switch_signing_identity(switch)
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
        description=(
            f"Aruba Web certificate {certificate_name} for {identities['common_name']}"
        ),
    )
    certificate_pem = client.get_certificate(certificate_uuid)
    validate_issued_certificate(
        certificate_pem,
        csr,
        switch,
        opnsense_settings["lifetime_days"],
    )
    return certificate_pem


def get_device_parameters(switch, username, password):
    return {
        "device_type": "aruba_osswitch",
        "host": switch["host"],
        "username": username,
        "password": password,
        "conn_timeout": 10,
        "banner_timeout": 15,
        "auth_timeout": 15,
    }


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
    device = get_device_parameters(switch, username, password)

    try:
        with ConnectHandler(**device) as connection:
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
    verification_ca_file,
    *,
    now=None,
):
    """Compose the proven staged functions into one explicit renewal."""
    preflight = renewal_preflight(
        switch,
        username,
        password,
        now=now,
    )
    certificate_name = preflight["new_certificate_name"]

    print(f"Current active Web certificate: {preflight['active_certificate_name']}")
    print(f"Selected renewal certificate name: {certificate_name}")

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

    print("CSR generated and validated.")
    print("Signing CSR with OPNsense...")

    try:
        certificate_pem = sign_pending_csr(
            switch,
            username,
            password,
            certificate_name,
            csr_settings,
            opnsense_settings,
        )
    except (ValueError, OSError) as error:
        raise CSRSigningError(
            f"{error}. The pending CSR remains on the switch; use the explicit "
            "staged commands for diagnosis or recovery"
        ) from error

    print("Issued certificate validated.")
    print("Installing signed certificate...")

    try:
        certificate = install_pending_certificate(
            switch,
            username,
            password,
            certificate_name,
            certificate_pem,
            csr_settings,
            opnsense_settings["lifetime_days"],
        )
    except CertificateInstallationAttemptError:
        raise
    except (ValueError, OSError) as error:
        raise CertificatePreInstallationError(
            f"{error}. The pending CSR remains on the switch; use the explicit "
            "staged commands for diagnosis or recovery"
        ) from error

    print("Certificate installed and Aruba state verified.")
    print("Verifying live HTTPS...")

    try:
        verify_live_https_certificate(
            switch,
            verification_ca_file,
            certificate,
        )
    except (ValueError, OSError, ssl.SSLError) as error:
        raise LiveHTTPSVerificationError(str(error)) from error

    print("Live HTTPS certificate chain and hostname verified.")
    print("Live HTTPS certificate matches the installed certificate.")
    print("Renewal completed successfully.")
    print(f"Active Web certificate: {certificate_name}")
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
    device = get_device_parameters(switch, username, password)
    csr_creation_attempted = False

    try:
        with ConnectHandler(**device) as connection:
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

            print(f"Current active Web certificate: {active_certificate['name']}")
            print(f"Discovered TA profile: {active_certificate['profile']}")
            print(f"Requested new certificate name: {certificate_name}")
            print("Generating CSR...")

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
    device = get_device_parameters(switch, username, password)

    try:
        with ConnectHandler(**device) as connection:
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
                if sys.exc_info()[0] is None:
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
):
    certificate_name = validate_cli_identifier(
        certificate_name,
        "certificate name",
    )
    csr_settings = validate_csr_settings(csr_settings)
    validate_switch_signing_identity(switch)
    device = get_device_parameters(switch, username, password)
    installation_completed = False

    try:
        with ConnectHandler(**device) as connection:
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
    ca_file,
    expected_certificate,
    *,
    verification_window=HTTPS_VERIFICATION_WINDOW_SECONDS,
    retry_delay=HTTPS_RETRY_DELAY_SECONDS,
    socket_timeout=HTTPS_SOCKET_TIMEOUT_SECONDS,
):
    host = validate_switch_signing_identity(switch)["common_name"]
    expected_der = expected_certificate.public_bytes(serialization.Encoding.DER)
    context = ssl.create_default_context(cafile=str(ca_file))

    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise ValueError("TLS verification context is not securely configured")

    deadline = time.monotonic() + verification_window
    last_error = None

    while True:
        try:
            with (
                socket.create_connection(
                    (host, 443),
                    timeout=socket_timeout,
                ) as tcp_socket,
                context.wrap_socket(
                    tcp_socket,
                    server_hostname=host,
                ) as tls_socket,
            ):
                peer_der = tls_socket.getpeercert(binary_form=True)

            if peer_der == expected_der:
                return

            last_error = ValueError(
                "Live HTTPS service presented a different valid certificate"
            )

        except (OSError, ssl.SSLError) as error:
            last_error = error

        now = time.monotonic()
        if now >= deadline:
            raise ValueError(
                "Expected certificate was not verified over live HTTPS within "
                f"{verification_window} seconds: {last_error}"
            ) from last_error

        time.sleep(min(retry_delay, deadline - now))


def check_switch(switch, username, password, warning_days):
    device = get_device_parameters(switch, username, password)

    print()
    print(switch["name"])
    print("-" * len(switch["name"]))
    print(f"Host:             {switch['host']}")

    try:
        with ConnectHandler(**device) as connection:
            version_output = connection.send_command("show version")
            cert_output = connection.send_command(
                "show crypto pki local-certificate summary"
            )

    except NetmikoAuthenticationException:
        print("Status:           ERROR")
        print("Reason:           SSH authentication failed")
        return "error"

    except NetmikoTimeoutException:
        print("Status:           ERROR")
        print("Reason:           SSH connection timed out")
        return "error"

    except Exception as error:
        print("Status:           ERROR")
        print(f"Reason:           {error}")
        return "error"

    print(f"AOS-S version:    {parse_aos_version(version_output)}")

    try:
        certificate = get_active_web_certificate(parse_web_certificates(cert_output))

    except ValueError as error:
        print("Status:           ERROR")
        print(f"Reason:           {error}")
        return "error"

    days_remaining = (certificate["expiration"] - date.today()).days

    print(f"Certificate:      {certificate['name']}")
    print(f"TA profile:       {certificate['profile']}")
    print(f"Expires:          {certificate['expiration'].isoformat()}")
    print(f"Days remaining:   {days_remaining}")

    if days_remaining < 0:
        print("Status:           EXPIRED")
        return "expired"

    if days_remaining <= warning_days:
        print("Status:           RENEWAL DUE")
        return "renewal_due"

    print("Status:           OK")
    return "ok"


def print_summary(results):
    print()
    print("Summary")
    print("-------")
    print(f"Switches checked: {len(results)}")
    print(f"OK:               {results.count('ok')}")
    print(f"Renewal due:      {results.count('renewal_due')}")
    print(f"Expired:          {results.count('expired')}")
    print(f"Errors:           {results.count('error')}")


def print_renewal_summary(results):
    print()
    print("Renewal summary")
    print("---------------")
    print(f"Switches processed: {len(results)}")
    print(f"Healthy:             {results.count('healthy')}")
    print(f"Renewed:             {results.count('renewed')}")
    print(f"Errors:              {results.count('error')}")


def get_exit_code(results):
    if "error" in results:
        return EXIT_ERROR

    if "renewal_due" in results or "expired" in results:
        return EXIT_WARNING

    return EXIT_OK


def report_renewal_failure(error):
    """Print the established explicit-renewal safety message for an error."""
    if isinstance(error, RenewalPreflightError):
        print(
            "Error: Renewal preflight failed; no renewal change was "
            f"attempted: {error}",
            file=sys.stderr,
        )
    elif isinstance(error, CSRGenerationPreAttemptError):
        print(
            "Error: CSR generation failed before CSR creation was attempted; "
            f"no pending CSR was created: {error}",
            file=sys.stderr,
        )
    elif isinstance(error, CSRGenerationError):
        print(f"Error: {error}", file=sys.stderr)
        print(
            "CSR creation was attempted. No automatic cleanup was attempted; "
            "use the explicit staged commands for diagnosis or recovery.",
            file=sys.stderr,
        )
    elif isinstance(error, CSRSigningError):
        print(f"Error: CSR signing failed: {error}", file=sys.stderr)
        print(
            "No certificate installation or automatic OPNsense cleanup was attempted.",
            file=sys.stderr,
        )
    elif isinstance(error, CertificatePreInstallationError):
        print(
            f"Error: Certificate installation did not begin: {error}",
            file=sys.stderr,
        )
        print("No automatic rollback was attempted.", file=sys.stderr)
    elif isinstance(error, CertificateInstallationAttemptError):
        print(f"Error: Post-install failure: {error}", file=sys.stderr)
        print(
            "No automatic rollback was attempted; inspect the switch manually.",
            file=sys.stderr,
        )
    elif isinstance(error, LiveHTTPSVerificationError):
        print(
            "Error: Post-install HTTPS verification failed. The certificate "
            "may already be active and requires manual investigation: "
            f"{error}",
            file=sys.stderr,
        )
        print("No automatic rollback was attempted.", file=sys.stderr)


RENEWAL_FAILURE_TYPES = (
    RenewalPreflightError,
    CSRGenerationPreAttemptError,
    CSRGenerationError,
    CSRSigningError,
    CertificatePreInstallationError,
    CertificateInstallationAttemptError,
    LiveHTTPSVerificationError,
)


def renew_due_certificates(
    switches,
    config_file,
    warning_days,
    csr_settings,
    opnsense_settings,
    verification_ca_file,
):
    results = []

    for switch in switches:
        username = password = None
        try:
            try:
                username, password = get_switch_credentials(switch, config_file)
            except ValueError as error:
                print()
                print(switch["name"])
                print("-" * len(switch["name"]))
                print(f"Host:             {switch['host']}")
                print("Status:           ERROR")
                print(f"Reason:           {error}")
                print("Action:           No renewal attempted")
                results.append("error")
                continue
            except Exception:
                print()
                print(switch["name"])
                print("-" * len(switch["name"]))
                print(f"Host:             {switch['host']}")
                print("Status:           ERROR")
                print("Reason:           Unexpected credential resolution failure")
                print("Action:           No renewal attempted")
                results.append("error")
                continue

            try:
                status = check_switch(switch, username, password, warning_days)
            except Exception as error:
                print("Status:           ERROR")
                print(f"Reason:           {error}")
                print("Action:           No renewal attempted")
                results.append("error")
                continue
            if status == "ok":
                print("Action:           No renewal required")
                results.append("healthy")
                continue

            if status not in {"renewal_due", "expired"}:
                print("Action:           No renewal attempted")
                results.append("error")
                continue

            print("Action:           Renewing certificate")
            try:
                renew_certificate(
                    switch,
                    username,
                    password,
                    csr_settings,
                    opnsense_settings,
                    verification_ca_file,
                )
            except RENEWAL_FAILURE_TYPES as error:
                report_renewal_failure(error)
                results.append("error")
            except Exception as error:
                print(
                    "Error: Unexpected renewal failure "
                    f"({type(error).__name__}). Renewal state may be uncertain.",
                    file=sys.stderr,
                )
                print(
                    "No automatic retry, cleanup, or rollback was attempted; "
                    "inspect the switch and use the explicit staged commands "
                    "if necessary.",
                    file=sys.stderr,
                )
                results.append("error")
            else:
                results.append("renewed")
        finally:
            username = password = None

    print_renewal_summary(results)
    return EXIT_ERROR if "error" in results else EXIT_OK


def write_or_print_csr(csr_pem, output_path):
    if output_path:
        with output_path.open("x", encoding="ascii") as output_file:
            output_file.write(csr_pem)

        print(f"CSR written to {output_path}")
    else:
        print(csr_pem, end="")


def write_certificate(certificate_pem, output_path):
    with output_path.open("x", encoding="ascii") as output_file:
        output_file.write(certificate_pem)

    print(f"Certificate written to {output_path}")


def main():
    args = parse_args()
    configure_logging(args.debug)

    try:
        validate_cli_args(args)
        config = load_config(args.config)
        warning_days, switches = validate_config(config)
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
            for switch in switches if renew_due else switches[:1]:
                validate_switch_signing_identity(switch)

        if args.install_certificate or args.renew or renew_due:
            verification_ca_file = get_verification_ca_file(config, args.config)

        if args.install_certificate:
            certificate_pem = read_certificate_input(args.certificate_input)

    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
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
    if explicit_operation:
        try:
            username, password = get_switch_credentials(switches[0], args.config)
        except ValueError as error:
            print(f"Error: {error}", file=sys.stderr)
            return EXIT_ERROR

    if renew_due:
        return renew_due_certificates(
            switches,
            args.config,
            warning_days,
            csr_settings,
            opnsense_settings,
            verification_ca_file,
        )

    if args.renew:
        switch = switches[0]

        try:
            renew_certificate(
                switch,
                username,
                password,
                csr_settings,
                opnsense_settings,
                verification_ca_file,
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
            )

        except CertificateInstallationAttemptError as error:
            print(f"Error: Post-install failure: {error}", file=sys.stderr)
            print(
                "No automatic rollback was attempted; inspect the switch manually.",
                file=sys.stderr,
            )
            return EXIT_ERROR

        except (ValueError, OSError) as error:
            print(
                "Error: Pre-install failure; the switch has not been modified: "
                f"{error}",
                file=sys.stderr,
            )
            return EXIT_ERROR

        print(f"Certificate validated against pending CSR for {switch['name']}.")
        print(f"Signed certificate installed on {switch['name']}.")

        try:
            verify_live_https_certificate(
                switch,
                verification_ca_file,
                certificate,
            )
        except (ValueError, OSError, ssl.SSLError) as error:
            print(
                "Error: Post-install HTTPS verification failed. The certificate "
                "may already be active and requires manual investigation: "
                f"{error}",
                file=sys.stderr,
            )
            print("No automatic rollback was attempted.", file=sys.stderr)
            return EXIT_ERROR

        print("Live HTTPS certificate chain and hostname verified.")
        print("Live HTTPS certificate matches the installed certificate.")
        print("Certificate installation verified successfully.")
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
            print(
                f"Pending CSR signed and issued certificate validated for "
                f"{switch['name']}."
            )
            print("The certificate has not been installed on the switch.")
            return EXIT_OK

        except (ValueError, OSError) as error:
            print(f"Error: {error}", file=sys.stderr)
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
                print(f"CSR generated and validated for {switch['name']}.")
            else:
                csr_pem = retrieve_csr(
                    switch,
                    username,
                    password,
                    args.certificate_name,
                    csr_settings,
                )
                print(f"Pending CSR retrieved and validated for {switch['name']}.")

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

        except ValueError as error:
            print(f"Error: {error}", file=sys.stderr)
            return EXIT_ERROR

    results = []
    for switch in switches:
        try:
            username, password = get_switch_credentials(switch, args.config)
        except ValueError as error:
            print()
            print(switch["name"])
            print("-" * len(switch["name"]))
            print(f"Host:             {switch['host']}")
            print("Status:           ERROR")
            print(f"Reason:           {error}")
            results.append("error")
            continue

        results.append(check_switch(switch, username, password, warning_days))

    print_summary(results)

    return get_exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
