#!/usr/bin/env python3

import getpass
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


CONFIG_FILE = Path(__file__).parent.parent / "config.toml"


def load_config():
    with CONFIG_FILE.open("rb") as file:
        return tomllib.load(file)


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


def parse_web_certificate(output):
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

    match = pattern.search(output)

    if not match:
        return None

    expiration = datetime.strptime(
        match.group("expiration"),
        "%Y/%m/%d",
    ).date()

    return {
        "name": match.group("name"),
        "expiration": expiration,
        "profile": match.group("profile"),
    }


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

    certificate = parse_web_certificate(cert_output)

    if certificate is None:
        print("Status:           ERROR")
        print("Reason:           Could not find a Web certificate")
        return "error"

    days_remaining = (certificate["expiration"] - date.today()).days

    print(f"Certificate:      {certificate['name']}")
    print(f"TA profile:       {certificate['profile']}")
    print(f"Expires:          {certificate['expiration'].isoformat()}")
    print(f"Days remaining:   {days_remaining}")

    if days_remaining < 0:
        print("Status:           EXPIRED")
        return "warning"

    if days_remaining <= warning_days:
        print("Status:           RENEWAL DUE")
        return "warning"

    print("Status:           OK")
    return "ok"


def main():
    config = load_config()

    warning_days = config.get("settings", {}).get("warning_days", 30)
    switches = config.get("switches", [])

    if not switches:
        print("No switches configured.")
        return 2

    username, password = get_credentials()

    results = [
        check_switch(switch, username, password, warning_days)
        for switch in switches
    ]

    print()
    print("Summary")
    print("-------")
    print(f"Switches checked: {len(results)}")
    print(f"OK:               {results.count('ok')}")
    print(f"Renewal due:      {results.count('warning')}")
    print(f"Errors:           {results.count('error')}")

    if "error" in results:
        return 2

    if "warning" in results:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())