#!/usr/bin/env python3

import argparse
import getpass
import logging
import os
import re
import sys
import tomllib
from datetime import date, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

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
        "--certificate-name",
        metavar="NAME",
        help="New certificate name to use when generating a CSR",
    )

    parser.add_argument(
        "--csr-output",
        type=Path,
        metavar="FILE",
        help="Write the generated PEM CSR to this file instead of stdout",
    )

    return parser.parse_args()


def validate_cli_args(args):
    if args.generate_csr and not args.switch_name:
        raise ValueError("--generate-csr requires --switch")

    if args.generate_csr and not args.certificate_name:
        raise ValueError("--generate-csr requires --certificate-name")

    if not args.generate_csr and args.certificate_name:
        raise ValueError("--certificate-name requires --generate-csr")

    if not args.generate_csr and args.csr_output:
        raise ValueError("--csr-output requires --generate-csr")

    if args.certificate_name:
        validate_cli_identifier(args.certificate_name, "certificate name")

    if args.csr_output and args.csr_output.exists():
        raise ValueError(f"CSR output file already exists: {args.csr_output}")


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


def get_csr_settings(config):
    csr_settings = config.get("csr")

    if not isinstance(csr_settings, dict):
        raise ValueError("A [csr] configuration section is required")

    return validate_csr_settings(csr_settings)


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


def validate_csr_pem(csr_pem, switch, csr_settings):
    csr_settings = validate_csr_settings(csr_settings)

    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))

    except (ValueError, UnicodeEncodeError) as error:
        raise ValueError("Returned CSR is not valid PEM") from error

    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")

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

    public_key = csr.public_key()

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("CSR does not contain an RSA public key")

    if public_key.key_size != csr_settings["key_size"]:
        raise ValueError(
            f"CSR RSA key size is {public_key.key_size}; "
            f"expected {csr_settings['key_size']}"
        )

    return csr


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

            csr_output = connection.send_command(
                f"show crypto pki local-certificate {certificate_name}",
                read_timeout=30,
            )

    except NetmikoAuthenticationException as error:
        raise ValueError("SSH authentication failed") from error

    except NetmikoTimeoutException as error:
        if csr_creation_attempted:
            raise CSRGenerationError(
                "SSH operation timed out after CSR creation was attempted; "
                "a pending CSR may remain on the switch"
            ) from error

        raise ValueError("SSH connection timed out") from error

    try:
        csr_pem = extract_csr_pem(csr_output)
        validate_csr_pem(csr_pem, switch, csr_settings)

    except ValueError as error:
        raise CSRGenerationError(
            f"CSR retrieval or validation failed: {error}. "
            "The pending CSR was not removed"
        ) from error

    return csr_pem


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


def main():
    args = parse_args()
    configure_logging(args.debug)

    try:
        validate_cli_args(args)
        config = load_config(args.config)
        warning_days, switches = validate_config(config)
        switches = select_switches(switches, args.switch_name)

        if args.generate_csr:
            csr_settings = get_csr_settings(config)
            validate_fqdn(switches[0]["fqdn"])

    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_ERROR

    username, password = get_credentials()

    if args.generate_csr:
        switch = switches[0]

        try:
            csr_pem = generate_csr(
                switch,
                username,
                password,
                args.certificate_name,
                csr_settings,
            )

            print(f"CSR generated and validated for {switch['name']}.")

            if args.csr_output:
                try:
                    with args.csr_output.open("x", encoding="ascii") as output_file:
                        output_file.write(csr_pem)

                except OSError as error:
                    raise CSRGenerationError(
                        f"CSR was generated and validated but could not be written "
                        f"to {args.csr_output}: {error}. The pending CSR remains on "
                        "the switch and can be retrieved again"
                    ) from error

                print(f"CSR written to {args.csr_output}")
            else:
                print(csr_pem, end="")

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
