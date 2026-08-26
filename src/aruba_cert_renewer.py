#!/usr/bin/env python3

import argparse
import getpass
import ipaddress
import logging
import os
import re
import sys
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


def parse_args():
    parser = argparse.ArgumentParser(
        description="Check HTTPS certificate expiry on ArubaOS-Switch devices."
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
        "--certificate-name",
        metavar="NAME",
        help="Certificate name to generate, retrieve, or sign",
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

    return parser.parse_args()


def validate_cli_args(args):
    operations = [args.generate_csr, args.retrieve_csr, args.sign_csr]
    if sum(operations) > 1:
        raise ValueError(
            "--generate-csr, --retrieve-csr, and --sign-csr are mutually exclusive"
        )

    csr_operation = any(operations)
    if args.generate_csr:
        operation_name = "--generate-csr"
    elif args.retrieve_csr:
        operation_name = "--retrieve-csr"
    else:
        operation_name = "--sign-csr"

    if csr_operation and not args.switch_name:
        raise ValueError(f"{operation_name} requires --switch")

    if csr_operation and not args.certificate_name:
        raise ValueError(f"{operation_name} requires --certificate-name")

    if not csr_operation and args.certificate_name:
        raise ValueError(
            "--certificate-name requires --generate-csr, --retrieve-csr, or --sign-csr"
        )

    if (not csr_operation or args.sign_csr) and args.csr_output:
        raise ValueError("--csr-output requires --generate-csr or --retrieve-csr")

    if not args.sign_csr and args.certificate_output:
        raise ValueError("--certificate-output requires --sign-csr")

    if args.sign_csr and not args.certificate_output:
        raise ValueError("--sign-csr requires --certificate-output")

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

    required_fields = ("name", "host", "fqdn")
    seen_names = set()

    for index, switch in enumerate(switches, start=1):
        if not isinstance(switch, dict):
            raise ValueError(f"Switch entry {index} must be a TOML table")

        for field in required_fields:
            value = switch.get(field)

            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Switch entry {index} must contain a non-empty '{field}'"
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


def get_credentials():
    username = os.environ.get("ARUBA_SSH_USERNAME")
    password = os.environ.get("ARUBA_SSH_PASSWORD")

    if not username:
        username = input("SSH username: ")

    if not password:
        password = getpass.getpass("SSH password: ")

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


def validate_fqdn(value):
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError("switch FQDN contains unsupported characters")

    labels = value.split(".")

    if any(
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("switch FQDN contains unsupported characters")

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
    common_name = validate_fqdn(switch["fqdn"])

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
        NameOID.COMMON_NAME: ("common name", switch["fqdn"]),
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
    fqdn = validate_fqdn(switch["fqdn"])

    try:
        management_ip = ipaddress.IPv4Address(switch["host"])
    except ipaddress.AddressValueError as error:
        raise ValueError(
            "switch host must be a management IPv4 address for --sign-csr"
        ) from error

    return fqdn, management_ip


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

    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) != 1 or common_names[0].value != switch["fqdn"]:
        raise ValueError(
            f"Issued certificate CN must equal switch FQDN {switch['fqdn']!r}"
        )

    if certificate.subject != csr.subject:
        raise ValueError("Issued certificate subject does not match the CSR")

    subject_alt_name = _require_extension(
        certificate,
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        "Subject Alternative Name",
    )
    dns_names = subject_alt_name.get_values_for_type(x509.DNSName)
    if switch["fqdn"].casefold() not in {name.casefold() for name in dns_names}:
        raise ValueError("Issued certificate is missing the switch DNS SAN")

    expected_ip = ipaddress.IPv4Address(switch["host"])
    ip_addresses = subject_alt_name.get_values_for_type(x509.IPAddress)
    if expected_ip not in ip_addresses:
        raise ValueError("Issued certificate is missing the switch IP SAN")

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


def sign_pending_csr(
    switch,
    username,
    password,
    certificate_name,
    csr_settings,
    opnsense_settings,
):
    fqdn, management_ip = validate_switch_signing_identity(switch)
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
        dns_name=fqdn,
        ip_address=str(management_ip),
        description=f"Aruba Web certificate {certificate_name} for {fqdn}",
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

    except NetmikoAuthenticationException as error:
        raise ValueError("SSH authentication failed") from error

    except NetmikoTimeoutException as error:
        if csr_creation_attempted:
            raise CSRGenerationError(
                "SSH operation timed out after CSR creation was attempted; "
                "a pending CSR may remain on the switch"
            ) from error

        raise ValueError("SSH connection timed out") from error


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


def check_switch(switch, username, password, warning_days):
    device = get_device_parameters(switch, username, password)

    print()
    print(switch["name"])
    print("-" * len(switch["name"]))
    print(f"Address:          {switch['host']}")
    print(f"FQDN:             {switch['fqdn']}")

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


def get_exit_code(results):
    if "error" in results:
        return EXIT_ERROR

    if "renewal_due" in results or "expired" in results:
        return EXIT_WARNING

    return EXIT_OK


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

        if args.generate_csr or args.retrieve_csr or args.sign_csr:
            csr_settings = get_csr_settings(config)
            validate_fqdn(switches[0]["fqdn"])

        if args.sign_csr:
            opnsense_settings = get_opnsense_settings(config)
            validate_switch_signing_identity(switches[0])

    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_ERROR

    username, password = get_credentials()

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

    results = [
        check_switch(switch, username, password, warning_days) for switch in switches
    ]

    print_summary(results)

    return get_exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
