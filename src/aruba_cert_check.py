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

    return parser.parse_args()


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
        r"(?P<expiration>\d{4}/\d{2}/\d{2})"
        r"\s+"
        r"(?P<profile>\S+)"
        r"\s*$",
        re.MULTILINE,
    )

    certificates = []

    for match in pattern.finditer(output):
        expiration = datetime.strptime(
            match.group("expiration"),
            "%Y/%m/%d",
        ).date()

        certificates.append(
            {
                "name": match.group("name"),
                "expiration": expiration,
                "profile": match.group("profile"),
            }
        )

    return certificates


def check_switch(switch, username, password, warning_days):
    device = {
        "device_type": "aruba_osswitch",
        "host": switch["host"],
        "username": username,
        "password": password,
        "conn_timeout": 10,
        "banner_timeout": 15,
        "auth_timeout": 15,
    }

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

    certificates = parse_web_certificates(cert_output)

    if not certificates:
        print("Status:           ERROR")
        print("Reason:           Could not find a Web certificate")
        return "error"

    if len(certificates) != 1:
        print("Status:           ERROR")
        print(
            f"Reason:           Found {len(certificates)} Web certificates; expected 1"
        )
        return "error"

    certificate = certificates[0]
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
        config = load_config(args.config)
        warning_days, switches = validate_config(config)
        switches = select_switches(switches, args.switch_name)

    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_ERROR

    username, password = get_credentials()

    results = [
        check_switch(switch, username, password, warning_days) for switch in switches
    ]

    print_summary(results)

    return get_exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
