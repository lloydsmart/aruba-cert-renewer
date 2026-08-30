import base64
import ipaddress
import re
import warnings
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import (
    ExtendedKeyUsageOID,
    ExtensionOID,
    NameOID,
    SignatureAlgorithmOID,
)
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

import aruba_cert_renewer as checker

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def make_config():
    return {
        "settings": {
            "warning_days": 30,
        },
        "switches": [
            {
                "name": "EXAMPLE-SWITCH",
                "host": "switch.example.com",
                "additional_sans": ["192.0.2.10"],
            }
        ],
    }


def make_certificate_summary(
    expiration,
    name="webcert2026",
    profile="webprofile2026",
):
    return f"{name} Web {expiration:%Y/%m/%d} {profile}\n"


class FakeConnection:
    def __init__(self, version_output, certificate_output):
        self.version_output = version_output
        self.certificate_output = certificate_output

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def send_command(self, command):
        outputs = {
            "show version": self.version_output,
            "show crypto pki local-certificate summary": self.certificate_output,
        }

        return outputs[command]


def test_parse_aos_version():
    output = "Software revision : WC.16.11.0015"

    assert checker.parse_aos_version(output) == "WC.16.11.0015"


def test_parse_aos_version_returns_unknown():
    assert checker.parse_aos_version("No version here") == "Unknown"


def test_parse_web_certificate():
    output = "webcert2026 Web 2027/09/27 webprofile2026"

    certificates = checker.parse_web_certificates(output)

    assert certificates == [
        {
            "name": "webcert2026",
            "expiration": date(2027, 9, 27),
            "profile": "webprofile2026",
            "pending": False,
        }
    ]


def test_parse_pending_web_csr():
    output = "webcert2027 Web CSR webprofile2026"

    certificates = checker.parse_web_certificates(output)

    assert certificates == [
        {
            "name": "webcert2027",
            "expiration": None,
            "profile": "webprofile2026",
            "pending": True,
        }
    ]


def test_parse_web_certificates_returns_empty_list():
    assert checker.parse_web_certificates("No certificates") == []


def test_parse_multiple_web_certificates():
    output = "\n".join(
        [
            "webcert2026 Web 2027/09/27 webprofile2026",
            "webcert2027 Web 2028/09/27 webprofile2026",
        ]
    )

    certificates = checker.parse_web_certificates(output)

    assert len(certificates) == 2
    assert certificates[0]["name"] == "webcert2026"
    assert certificates[1]["name"] == "webcert2027"


def test_get_active_web_certificate():
    certificates = checker.parse_web_certificates(
        "webcert2026 Web 2027/09/27 webprofile2026"
    )

    assert checker.get_active_web_certificate(certificates)["name"] == "webcert2026"


def test_get_active_web_certificate_rejects_pending_csr():
    certificates = checker.parse_web_certificates(
        "\n".join(
            [
                "webcert2026 Web 2027/09/27 webprofile2026",
                "webcert2027 Web CSR webprofile2026",
            ]
        )
    )

    with pytest.raises(ValueError, match="pending Web CSR"):
        checker.get_active_web_certificate(certificates)


def test_get_active_web_certificate_rejects_no_installed_certificate():
    with pytest.raises(ValueError, match="installed Web certificate"):
        checker.get_active_web_certificate([])


def test_get_active_web_certificate_rejects_multiple_installed_certificates():
    certificates = checker.parse_web_certificates(
        "\n".join(
            [
                "webcert2026 Web 2027/09/27 webprofile2026",
                "webcert2027 Web 2028/09/27 webprofile2026",
            ]
        )
    )

    with pytest.raises(ValueError, match="2 installed Web certificates"):
        checker.get_active_web_certificate(certificates)


def test_certificate_name_exists_for_any_usage():
    output = "clientcert Client 2027/09/27 clientprofile\n"

    assert checker.certificate_name_exists(output, "clientcert")
    assert not checker.certificate_name_exists(output, "webcert2027")


def test_certificate_name_exists_is_case_insensitive():
    output = "WebCert2027 Web CSR webprofile2026\n"

    assert checker.certificate_name_exists(output, "webcert2027")


def test_validate_config():
    warning_days, switches = checker.validate_config(make_config())

    assert warning_days == 30
    assert len(switches) == 1
    assert switches[0]["name"] == "EXAMPLE-SWITCH"


@pytest.mark.parametrize(
    "warning_days",
    [
        -1,
        True,
        "30",
    ],
)
def test_validate_config_rejects_invalid_warning_days(warning_days):
    config = make_config()
    config["settings"]["warning_days"] = warning_days

    with pytest.raises(ValueError):
        checker.validate_config(config)


def test_validate_config_rejects_missing_switch_field():
    config = make_config()
    del config["switches"][0]["host"]

    with pytest.raises(ValueError, match="host"):
        checker.validate_config(config)


def test_validate_config_rejects_removed_fqdn_field():
    config = make_config()
    config["switches"][0]["fqdn"] = "old.example.com"

    with pytest.raises(ValueError, match="fqdn is no longer supported"):
        checker.validate_config(config)


@pytest.mark.parametrize("host", ["switch.example.com", "192.0.2.10", "2001:db8::10"])
def test_validate_config_accepts_dns_ipv4_and_ipv6_hosts(host):
    config = make_config()
    config["switches"][0] = {"name": "EXAMPLE-SWITCH", "host": host}

    _, switches = checker.validate_config(config)

    assert switches[0]["host"] == host
    assert switches[0]["additional_sans"] == []


def test_validate_config_accepts_optional_switch_fields():
    config = make_config()
    config["switches"][0].update(
        username="cert-renewer",
        password_file="secrets/switch-password",
    )

    _, switches = checker.validate_config(config)

    assert switches[0]["username"] == "cert-renewer"
    assert switches[0]["password_file"] == "secrets/switch-password"


def test_validate_config_rejects_literal_password_without_exposing_it():
    config = make_config()
    config["switches"][0]["password"] = "never-print-this"

    with pytest.raises(ValueError, match="password_file") as raised:
        checker.validate_config(config)

    assert "never-print-this" not in str(raised.value)


@pytest.mark.parametrize(
    "additional_sans",
    ["alias.example.com", ["alias.example.com", 123]],
)
def test_validate_config_requires_additional_sans_array_of_strings(additional_sans):
    config = make_config()
    config["switches"][0]["additional_sans"] = additional_sans

    with pytest.raises(ValueError, match="array of strings"):
        checker.validate_config(config)


@pytest.mark.parametrize(
    "identity",
    [
        "https://switch.example.com",
        "switch.example.com:443",
        "[2001:db8::10]",
        "*.example.com",
        "bad_name.example.com",
        "999.0.2.10",
        "2001:db8::gg",
        "switch.example.com/path",
        "switch.example.com\nreload",
        "",
    ],
)
def test_validate_config_rejects_malformed_host(identity):
    config = make_config()
    config["switches"][0]["host"] = identity

    with pytest.raises(ValueError, match="host"):
        checker.validate_config(config)


def test_validate_config_rejects_malformed_additional_san():
    config = make_config()
    config["switches"][0]["additional_sans"] = ["2001:db8::gg"]

    with pytest.raises(ValueError, match="additional_sans"):
        checker.validate_config(config)


def test_validate_config_bounds_additional_sans():
    config = make_config()
    config["switches"][0]["additional_sans"] = [
        f"alias-{index}.example.com" for index in range(checker.MAX_ADDITIONAL_SANS + 1)
    ]

    with pytest.raises(ValueError, match="cannot contain more"):
        checker.validate_config(config)


@pytest.mark.parametrize("username", ["", "   ", "user\nname", "user\x7fname"])
def test_validate_config_rejects_invalid_username(username):
    config = make_config()
    config["switches"][0]["username"] = username

    with pytest.raises(ValueError, match="username"):
        checker.validate_config(config)


def test_validate_config_rejects_duplicate_switch_names():
    config = make_config()
    config["switches"].append(
        {
            "name": "example-switch",
            "host": "192.0.2.11",
        }
    )

    with pytest.raises(ValueError, match="Duplicate switch name"):
        checker.validate_config(config)


def test_select_switches_is_case_insensitive():
    switches = make_config()["switches"]

    selected = checker.select_switches(switches, "example-switch")

    assert len(selected) == 1
    assert selected[0]["name"] == "EXAMPLE-SWITCH"


def test_select_switches_rejects_unknown_switch():
    switches = make_config()["switches"]

    with pytest.raises(ValueError, match="Switch not found"):
        checker.select_switches(switches, "DOES-NOT-EXIST")


@pytest.mark.parametrize(
    ("host", "dns_names", "ip_addresses"),
    [
        ("Switch.Example.COM", ["switch.example.com"], []),
        ("192.0.2.10", [], ["192.0.2.10"]),
        ("2001:0db8:0:0::10", [], ["2001:db8::10"]),
    ],
)
def test_certificate_identities_classify_and_canonicalize_host(
    host, dns_names, ip_addresses
):
    identities = checker.get_certificate_identities({"host": host})

    assert identities == {
        "common_name": dns_names[0] if dns_names else ip_addresses[0],
        "dns_names": dns_names,
        "ip_addresses": ip_addresses,
    }


def test_certificate_identities_mix_types_deduplicate_and_preserve_order():
    identities = checker.get_certificate_identities(
        {
            "host": "Switch.Example.COM",
            "additional_sans": [
                "192.0.2.10",
                "switch.example.com",
                "alias.example.com",
                "2001:0db8:0:0::10",
                "2001:db8::10",
            ],
        }
    )

    assert identities == {
        "common_name": "switch.example.com",
        "dns_names": ["switch.example.com", "alias.example.com"],
        "ip_addresses": ["192.0.2.10", "2001:db8::10"],
    }


def test_switch_credentials_prefer_switch_username_and_password_file(
    monkeypatch, tmp_path
):
    config_file = tmp_path / "config.toml"
    secret_file = tmp_path / "switch.secret"
    secret_file.write_bytes(b"  switch password  \n")
    monkeypatch.setenv("ARUBA_SSH_USERNAME", "global-user")
    monkeypatch.setenv("ARUBA_SSH_PASSWORD", "global-password")

    credentials = checker.get_switch_credentials(
        {
            "name": "EXAMPLE-SWITCH",
            "host": "switch.example.com",
            "username": "switch-user",
            "password_file": "switch.secret",
        },
        config_file,
    )

    assert credentials == ("switch-user", "  switch password  ")


def test_switch_credentials_use_global_environment_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("ARUBA_SSH_USERNAME", "global-user")
    monkeypatch.setenv("ARUBA_SSH_PASSWORD", "global-password")

    credentials = checker.get_switch_credentials(
        {"name": "EXAMPLE-SWITCH", "host": "switch.example.com"},
        tmp_path / "config.toml",
    )

    assert credentials == ("global-user", "global-password")


def test_switch_credentials_use_identified_interactive_prompts(monkeypatch, tmp_path):
    prompts = []
    monkeypatch.delenv("ARUBA_SSH_USERNAME", raising=False)
    monkeypatch.delenv("ARUBA_SSH_PASSWORD", raising=False)
    monkeypatch.setattr(
        "builtins.input", lambda prompt: prompts.append(prompt) or "prompt-user"
    )
    monkeypatch.setattr(
        checker.getpass,
        "getpass",
        lambda prompt: prompts.append(prompt) or "prompt-password",
    )

    credentials = checker.get_switch_credentials(
        {"name": "EXAMPLE-SWITCH", "host": "switch.example.com"},
        tmp_path / "config.toml",
    )

    assert credentials == ("prompt-user", "prompt-password")
    assert prompts == [
        "SSH username for EXAMPLE-SWITCH: ",
        "SSH password for EXAMPLE-SWITCH: ",
    ]


@pytest.mark.parametrize(
    ("contents", "expected"),
    [
        (b"password", "password"),
        (b"password\n", "password"),
        (b"password\r\n", "password"),
        (b" password ", " password "),
    ],
)
def test_read_password_file_accepts_one_bounded_line(tmp_path, contents, expected):
    secret_file = tmp_path / "secret"
    secret_file.write_bytes(contents)

    assert (
        checker.read_password_file(str(secret_file), tmp_path / "config.toml")
        == expected
    )


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        (b"", "empty"),
        (b"one\ntwo", "exactly one line"),
        (b"secret\x00value", "NUL"),
        (b"secret-\xff-value", "valid UTF-8"),
        (b"x" * (checker.MAX_PASSWORD_FILE_BYTES + 1), "exceeds"),
    ],
)
def test_read_password_file_rejects_unsafe_content_without_exposure(
    tmp_path, contents, message
):
    secret_file = tmp_path / "secret"
    secret_file.write_bytes(contents)

    with pytest.raises(ValueError, match=message) as raised:
        checker.read_password_file(str(secret_file), tmp_path / "config.toml")

    assert "secret" not in str(raised.value).replace(str(secret_file), "")
    assert raised.value.__cause__ is None


def test_read_password_file_rejects_missing_file_and_directory(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        checker.read_password_file("missing", tmp_path / "config.toml")

    with pytest.raises(ValueError, match="not a regular file"):
        checker.read_password_file(str(tmp_path), tmp_path / "config.toml")


@pytest.mark.parametrize(
    ("results", "expected"),
    [
        (["ok"], checker.EXIT_OK),
        (["ok", "renewal_due"], checker.EXIT_WARNING),
        (["expired"], checker.EXIT_WARNING),
        (["ok", "error"], checker.EXIT_ERROR),
    ],
)
def test_get_exit_code(results, expected):
    assert checker.get_exit_code(results) == expected


@pytest.mark.parametrize(
    ("days_remaining", "expected"),
    [
        (31, "ok"),
        (30, "renewal_due"),
        (-1, "expired"),
    ],
)
def test_check_switch_certificate_status(
    monkeypatch,
    days_remaining,
    expected,
):
    expiration = date.today() + timedelta(days=days_remaining)

    connection = FakeConnection(
        version_output="Software revision : WC.16.11.0015",
        certificate_output=make_certificate_summary(expiration),
    )

    monkeypatch.setattr(
        checker,
        "ConnectHandler",
        lambda **kwargs: connection,
    )

    switch = make_config()["switches"][0]

    result = checker.check_switch(
        switch,
        "username",
        "password",
        warning_days=30,
    )

    assert result == expected


def test_check_switch_rejects_multiple_web_certificates(monkeypatch):
    expiration = date.today() + timedelta(days=365)

    certificate_output = make_certificate_summary(
        expiration, name="webcert2026"
    ) + make_certificate_summary(expiration, name="webcert2027")

    connection = FakeConnection(
        version_output="Software revision : WC.16.11.0015",
        certificate_output=certificate_output,
    )

    monkeypatch.setattr(
        checker,
        "ConnectHandler",
        lambda **kwargs: connection,
    )

    switch = make_config()["switches"][0]

    result = checker.check_switch(
        switch,
        "username",
        "password",
        warning_days=30,
    )

    assert result == "error"


def test_check_switch_rejects_pending_web_csr(monkeypatch):
    expiration = date.today() + timedelta(days=365)
    certificate_output = make_certificate_summary(expiration)
    certificate_output += "webcert2027 Web CSR webprofile2026\n"
    connection = FakeConnection(
        version_output="Software revision : WC.16.11.0015",
        certificate_output=certificate_output,
    )
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    result = checker.check_switch(
        make_config()["switches"][0],
        "username",
        "password",
        warning_days=30,
    )

    assert result == "error"


def test_monitoring_resolves_credentials_for_each_switch(monkeypatch, tmp_path):
    (tmp_path / "a.secret").write_text("password-a\n", encoding="utf-8")
    (tmp_path / "b.secret").write_text("password-b\n", encoding="utf-8")
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[[switches]]
name = "SWITCH-A"
host = "switch-a.example.com"
username = "user-a"
password_file = "a.secret"

[[switches]]
name = "SWITCH-B"
host = "switch-b.example.com"
username = "user-b"
password_file = "b.secret"
""".strip(),
        encoding="utf-8",
    )
    calls = []
    monkeypatch.setattr(
        checker.sys, "argv", ["aruba_cert_renewer.py", "--config", str(config_file)]
    )
    monkeypatch.setattr(
        checker,
        "check_switch",
        lambda switch, username, password, warning_days: (
            calls.append((switch["name"], username, password)) or "ok"
        ),
    )

    assert checker.main() == checker.EXIT_OK
    assert calls == [
        ("SWITCH-A", "user-a", "password-a"),
        ("SWITCH-B", "user-b", "password-b"),
    ]


def test_monitoring_reports_one_switch_credential_failure_and_continues(
    monkeypatch, tmp_path, capsys
):
    (tmp_path / "b.secret").write_text("password-b\n", encoding="utf-8")
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[[switches]]
name = "SWITCH-A"
host = "switch-a.example.com"
username = "user-a"
password_file = "missing.secret"

[[switches]]
name = "SWITCH-B"
host = "switch-b.example.com"
username = "user-b"
password_file = "b.secret"
""".strip(),
        encoding="utf-8",
    )
    calls = []
    monkeypatch.setattr(
        checker.sys, "argv", ["aruba_cert_renewer.py", "--config", str(config_file)]
    )
    monkeypatch.setattr(
        checker,
        "check_switch",
        lambda switch, *args: calls.append(switch["name"]) or "ok",
    )

    assert checker.main() == checker.EXIT_ERROR
    assert calls == ["SWITCH-B"]
    assert "SWITCH-A" in capsys.readouterr().out


def test_unknown_switch_fails_before_credentials(
    monkeypatch,
    tmp_path,
):
    config_file = tmp_path / "config.toml"

    config_file.write_text(
        """
[settings]
warning_days = 30

[[switches]]
name = "EXAMPLE-SWITCH"
host = "switch.example.com"
additional_sans = ["192.0.2.10"]
""".strip(),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_renewer.py",
            "--config",
            str(config_file),
            "--switch",
            "DOES-NOT-EXIST",
        ],
    )

    def unexpected_credentials_request(*args):
        pytest.fail("Credentials should not be requested")

    monkeypatch.setattr(
        checker,
        "get_switch_credentials",
        unexpected_credentials_request,
    )

    assert checker.main() == checker.EXIT_ERROR


@pytest.mark.parametrize(
    "argv",
    [
        ["aruba_cert_renewer.py", "--generate-csr", "--certificate-name", "newcert"],
        ["aruba_cert_renewer.py", "--generate-csr", "--switch", "EXAMPLE-SWITCH"],
        ["aruba_cert_renewer.py", "--retrieve-csr", "--certificate-name", "newcert"],
        ["aruba_cert_renewer.py", "--retrieve-csr", "--switch", "EXAMPLE-SWITCH"],
    ],
)
def test_csr_operations_require_arguments_before_credentials(monkeypatch, argv):
    monkeypatch.setattr(checker.sys, "argv", argv)

    def unexpected_credentials_request(*args):
        pytest.fail("Credentials should not be requested")

    monkeypatch.setattr(
        checker, "get_switch_credentials", unexpected_credentials_request
    )

    assert checker.main() == checker.EXIT_ERROR


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("certificate_name", "webcert2027"),
        ("csr_output", "request.pem"),
    ],
)
def test_csr_only_options_require_generate_csr(field, value):
    args = SimpleNamespace(
        generate_csr=False,
        retrieve_csr=False,
        sign_csr=False,
        switch_name=None,
        certificate_name=None,
        csr_output=None,
        certificate_output=None,
    )
    setattr(args, field, value)

    with pytest.raises(ValueError, match="requires --generate-csr"):
        checker.validate_cli_args(args)


def test_generate_and_retrieve_csr_are_mutually_exclusive():
    args = SimpleNamespace(
        generate_csr=True,
        retrieve_csr=True,
        sign_csr=False,
        switch_name="EXAMPLE-SWITCH",
        certificate_name="webcert2027",
        csr_output=None,
        certificate_output=None,
    )

    with pytest.raises(ValueError, match="mutually exclusive"):
        checker.validate_cli_args(args)


def test_mutually_exclusive_csr_operations_fail_before_credentials(monkeypatch):
    calls = []
    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_renewer.py",
            "--generate-csr",
            "--retrieve-csr",
            "--switch",
            "EXAMPLE-SWITCH",
            "--certificate-name",
            "webcert2027",
        ],
    )
    monkeypatch.setattr(
        checker,
        "get_switch_credentials",
        lambda *args: calls.append("credentials"),
    )

    assert checker.main() == checker.EXIT_ERROR
    assert calls == []


def test_generate_csr_main_writes_validated_pem(monkeypatch, tmp_path):
    config_file = tmp_path / "config.toml"
    output_file = tmp_path / "request.pem"
    config_file.write_text(
        """
[settings]
warning_days = 30

[csr]
organization = "Example Organization"
organizational_unit = "Infrastructure"
locality = "Example City"
state = "Example State"
country = "GB"
key_type = "rsa"
key_size = 2048

[[switches]]
name = "EXAMPLE-SWITCH"
host = "switch.example.com"
additional_sans = ["192.0.2.10"]
""".strip(),
        encoding="utf-8",
    )
    argv = [
        "aruba_cert_renewer.py",
        "--config",
        str(config_file),
        "--generate-csr",
        "--switch",
        "EXAMPLE-SWITCH",
        "--certificate-name",
        "webcert2027",
        "--csr-output",
        str(output_file),
    ]
    csr_pem = make_test_csr()
    credential_calls = []
    monkeypatch.setattr(checker.sys, "argv", argv)
    monkeypatch.setattr(
        checker,
        "get_switch_credentials",
        lambda *args: credential_calls.append(args) or ("username", "password"),
    )
    monkeypatch.setattr(checker, "generate_csr", lambda *args, **kwargs: csr_pem)

    assert checker.main() == checker.EXIT_OK
    assert len(credential_calls) == 1
    assert output_file.read_text(encoding="ascii") == csr_pem


def test_retrieve_csr_main_writes_validated_pem(monkeypatch, tmp_path):
    config_file = tmp_path / "config.toml"
    output_file = tmp_path / "request.pem"
    config_file.write_text(
        """
[csr]
organization = "Example Organization"
organizational_unit = "Infrastructure"
locality = "Example City"
state = "Example State"
country = "GB"
key_type = "rsa"
key_size = 2048

[[switches]]
name = "EXAMPLE-SWITCH"
host = "switch.example.com"
additional_sans = ["192.0.2.10"]
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_renewer.py",
            "--config",
            str(config_file),
            "--retrieve-csr",
            "--switch",
            "EXAMPLE-SWITCH",
            "--certificate-name",
            "webcert2027",
            "--csr-output",
            str(output_file),
        ],
    )
    csr_pem = make_test_csr()
    monkeypatch.setattr(
        checker, "get_switch_credentials", lambda *args: ("username", "password")
    )
    monkeypatch.setattr(checker, "retrieve_csr", lambda *args, **kwargs: csr_pem)

    def unexpected_generation(*args, **kwargs):
        pytest.fail("generate_csr must not be called during retrieval")

    monkeypatch.setattr(checker, "generate_csr", unexpected_generation)

    assert checker.main() == checker.EXIT_OK
    assert output_file.read_text(encoding="ascii") == csr_pem


@pytest.mark.parametrize("operation", ["--generate-csr", "--retrieve-csr"])
def test_existing_csr_output_fails_before_credentials_or_ssh(
    monkeypatch, tmp_path, operation
):
    output_file = tmp_path / "request.pem"
    output_file.write_text("existing CSR", encoding="ascii")
    calls = []
    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_renewer.py",
            "--config",
            str(tmp_path / "not-needed.toml"),
            operation,
            "--switch",
            "EXAMPLE-SWITCH",
            "--certificate-name",
            "webcert2027",
            "--csr-output",
            str(output_file),
        ],
    )
    monkeypatch.setattr(
        checker,
        "get_switch_credentials",
        lambda *args: calls.append("credentials"),
    )
    monkeypatch.setattr(
        checker,
        "generate_csr",
        lambda *args, **kwargs: calls.append("generate_csr"),
    )
    monkeypatch.setattr(
        checker,
        "retrieve_csr",
        lambda *args, **kwargs: calls.append("retrieve_csr"),
    )

    assert checker.main() == checker.EXIT_ERROR
    assert calls == []
    assert output_file.read_text(encoding="ascii") == "existing CSR"


def test_generate_csr_config_validation_fails_before_credentials(monkeypatch, tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        """
[csr]
organization = "Example; reload"
organizational_unit = "Infrastructure"
locality = "Example City"
state = "Example State"
country = "GB"
key_type = "rsa"
key_size = 2048

[[switches]]
name = "EXAMPLE-SWITCH"
host = "switch.example.com"
additional_sans = ["192.0.2.10"]
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_renewer.py",
            "--config",
            str(config_file),
            "--generate-csr",
            "--switch",
            "EXAMPLE-SWITCH",
            "--certificate-name",
            "webcert2027",
        ],
    )

    def unexpected_credentials_request(*args):
        pytest.fail("Credentials should not be requested")

    monkeypatch.setattr(
        checker, "get_switch_credentials", unexpected_credentials_request
    )

    assert checker.main() == checker.EXIT_ERROR


def make_csr_settings():
    return {
        "organization": "Example Organization",
        "organizational_unit": "Infrastructure",
        "locality": "Example City",
        "state": "Example State",
        "country": "GB",
        "key_type": "rsa",
        "key_size": 2048,
    }


def make_test_csr(
    common_name="switch.example.com",
    organization="Example Organization",
    organizational_unit="Infrastructure",
    locality="Example City",
    state="Example State",
    country="GB",
    key_size=2048,
    key_type="rsa",
    signature_hash=None,
):
    if signature_hash is None:
        signature_hash = hashes.SHA256()

    if key_type == "rsa":
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
    else:
        key = ec.generate_private_key(ec.SECP256R1())

    common_names = common_name if isinstance(common_name, list) else [common_name]
    subject = x509.Name(
        [
            *[x509.NameAttribute(NameOID.COMMON_NAME, value) for value in common_names],
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                organization,
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME,
                organizational_unit,
            ),
            x509.NameAttribute(
                NameOID.LOCALITY_NAME,
                locality,
            ),
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME,
                state,
            ),
            x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                country,
            ),
        ]
    )

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(
            key,
            signature_hash,
        )
    )

    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


class FakeCSRConnection:
    def __init__(
        self,
        csr_pem,
        summary_output=("webcert2026 Web 2027/09/27 webprofile2026\n"),
        generation_error=None,
        config_mode_error=None,
        exit_config_mode_error=None,
    ):
        self.csr_pem = csr_pem
        self.summary_output = summary_output
        self.generation_error = generation_error
        self.config_mode_error = config_mode_error
        self.exit_config_mode_error = exit_config_mode_error
        self.commands = []
        self.entered_config_mode = False
        self.exited_config_mode = False
        self.timing_kwargs = None
        self.retrieval_kwargs = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def send_command(self, command, **kwargs):
        self.commands.append(command)

        if command == "show crypto pki local-certificate summary":
            return self.summary_output

        self.retrieval_kwargs = kwargs
        return f"Certificate request:\n{self.csr_pem}"

    def config_mode(self):
        self.entered_config_mode = True
        if self.config_mode_error:
            raise self.config_mode_error

    def send_command_timing(self, command, **kwargs):
        self.commands.append(command)
        self.timing_kwargs = kwargs

        if self.generation_error:
            raise self.generation_error

        return "Generating RSA key and certificate request"

    def exit_config_mode(self):
        self.exited_config_mode = True
        if self.exit_config_mode_error:
            raise self.exit_config_mode_error


def test_get_csr_settings():
    config = make_config()
    config["csr"] = make_csr_settings()

    assert checker.get_csr_settings(config) == make_csr_settings()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("organization", ""),
        ("organizational_unit", "Infrastructure; reload"),
        ("locality", "Example\nCity"),
        ("state", 'Example "State"'),
        ("country", "gb"),
        ("country", "GBR"),
        ("key_type", "ecdsa"),
        ("key_size", 4096),
    ],
)
def test_get_csr_settings_rejects_invalid_values(field, value):
    config = make_config()
    config["csr"] = make_csr_settings()
    config["csr"][field] = value

    with pytest.raises(ValueError, match=f"csr.{field}"):
        checker.get_csr_settings(config)


def test_get_csr_settings_rejects_missing_field():
    config = make_config()
    config["csr"] = make_csr_settings()
    del config["csr"]["organization"]

    with pytest.raises(ValueError, match="csr.organization"):
        checker.get_csr_settings(config)


def test_build_csr_command():
    switch = make_config()["switches"][0]

    command = checker.build_csr_command(
        switch,
        "webcert2027",
        "webprofile2026",
        make_csr_settings(),
    )

    assert command == (
        "crypto pki create-csr "
        "certificate-name webcert2027 "
        "ta-profile webprofile2026 "
        "usage web "
        "key-type rsa "
        "key-size 2048 "
        "subject "
        "common-name switch.example.com "
        'org "Example Organization" '
        "org-unit Infrastructure "
        'locality "Example City" '
        'state "Example State" '
        "country GB"
    )


@pytest.mark.parametrize("host", ["switch.example.com", "192.0.2.10", "2001:db8::10"])
def test_build_csr_command_uses_host_as_common_name(host):
    switch = {"name": "EXAMPLE-SWITCH", "host": host}

    command = checker.build_csr_command(
        switch,
        "webcert2027",
        "webprofile2026",
        make_csr_settings(),
    )

    assert f"common-name {host} " in command


@pytest.mark.parametrize(
    "certificate_name",
    [
        "webcert;reload",
        "webcert\nreload",
        'webcert"bad',
        "",
    ],
)
def test_build_csr_command_rejects_unsafe_certificate_name(certificate_name):
    switch = make_config()["switches"][0]

    with pytest.raises(ValueError):
        checker.build_csr_command(
            switch,
            certificate_name,
            "webprofile2026",
            make_csr_settings(),
        )


@pytest.mark.parametrize(
    "ta_profile",
    ["webprofile;reload", "webprofile\nreload", 'webprofile"bad', ""],
)
def test_build_csr_command_rejects_unsafe_ta_profile(ta_profile):
    with pytest.raises(ValueError, match="TA profile"):
        checker.build_csr_command(
            make_config()["switches"][0],
            "webcert2027",
            ta_profile,
            make_csr_settings(),
        )


@pytest.mark.parametrize(
    "host",
    [
        "switch.example.com; reload",
        "switch.example.com\nreload",
        'bad"host',
        "bad_host.example.com",
        "-switch.example.com",
    ],
)
def test_build_csr_command_rejects_unsafe_host(host):
    switch = make_config()["switches"][0]
    switch["host"] = host

    with pytest.raises(ValueError, match="switch identity"):
        checker.build_csr_command(
            switch,
            "webcert2027",
            "webprofile2026",
            make_csr_settings(),
        )


def test_build_csr_command_revalidates_subject_settings():
    settings = make_csr_settings()
    settings["organization"] = "Example; reload"

    with pytest.raises(ValueError, match="csr.organization"):
        checker.build_csr_command(
            make_config()["switches"][0],
            "webcert2027",
            "webprofile2026",
            settings,
        )


def test_generate_csr_uses_active_ta_profile_and_retrieves_new_name(
    monkeypatch, capsys
):
    connection = FakeCSRConnection(make_test_csr())
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    csr_pem = checker.generate_csr(
        make_config()["switches"][0],
        "username",
        "password",
        "webcert2027",
        make_csr_settings(),
    )

    assert csr_pem == connection.csr_pem
    generation_command = connection.commands[1]
    assert "certificate-name webcert2027" in generation_command
    assert "ta-profile webprofile2026" in generation_command
    assert connection.commands[2] == ("show crypto pki local-certificate webcert2027")
    assert connection.timing_kwargs["read_timeout"] == 120
    assert connection.retrieval_kwargs["read_timeout"] == 30
    assert connection.entered_config_mode
    assert connection.exited_config_mode
    output = capsys.readouterr().out
    assert "Current active Web certificate: webcert2026" in output
    assert "Discovered TA profile: webprofile2026" in output
    assert "Requested new certificate name: webcert2027" in output
    assert "Generating CSR..." in output
    assert "crypto pki create-csr" not in output


def test_generate_csr_sends_no_save_install_or_delete_commands(monkeypatch):
    connection = FakeCSRConnection(make_test_csr())
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    checker.generate_csr(
        make_config()["switches"][0],
        "username",
        "password",
        "webcert2027",
        make_csr_settings(),
    )

    commands = "\n".join(connection.commands).casefold()
    assert "write memory" not in commands
    assert "install" not in commands
    assert "delete" not in commands
    assert "clear" not in commands


def test_generate_csr_rejects_active_certificate_name_collision(monkeypatch):
    connection = FakeCSRConnection(make_test_csr())
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(ValueError, match="must differ"):
        checker.generate_csr(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2026",
            make_csr_settings(),
        )

    assert not connection.entered_config_mode


def test_generate_csr_rejects_existing_non_web_certificate_name(monkeypatch):
    summary = "\n".join(
        [
            "webcert2026 Web 2027/09/27 webprofile2026",
            "clientcert Client 2027/09/27 clientprofile",
        ]
    )
    connection = FakeCSRConnection(make_test_csr(), summary_output=summary)
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(ValueError, match="already exists"):
        checker.generate_csr(
            make_config()["switches"][0],
            "username",
            "password",
            "clientcert",
            make_csr_settings(),
        )

    assert not connection.entered_config_mode


def test_generate_csr_rejects_pending_csr_before_config_mode(monkeypatch):
    summary = "\n".join(
        [
            "webcert2026 Web 2027/09/27 webprofile2026",
            "webcert2027 Web CSR webprofile2026",
        ]
    )
    connection = FakeCSRConnection(make_test_csr(), summary_output=summary)
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(ValueError, match="pending Web CSR"):
        checker.generate_csr(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2028",
            make_csr_settings(),
        )

    assert not connection.entered_config_mode


def test_generate_csr_classifies_runtime_error_after_attempt_and_exits_config_mode(
    monkeypatch,
):
    connection = FakeCSRConnection(
        make_test_csr(),
        generation_error=RuntimeError("generation failed"),
    )
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(checker.CSRGenerationError, match="pending CSR may remain"):
        checker.generate_csr(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            make_csr_settings(),
        )

    assert connection.exited_config_mode


def test_generate_csr_classifies_oserror_from_send_after_attempt(monkeypatch):
    connection = FakeCSRConnection(
        make_test_csr(),
        generation_error=OSError("channel failed"),
    )
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(checker.CSRGenerationError, match="pending CSR may remain"):
        checker.generate_csr(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            make_csr_settings(),
        )

    assert connection.exited_config_mode


@pytest.mark.parametrize(
    "exit_error",
    [OSError("channel failed"), RuntimeError("transport failed")],
    ids=["oserror", "runtimeerror"],
)
def test_generate_csr_classifies_config_exit_error_after_attempt(
    monkeypatch, exit_error
):
    connection = FakeCSRConnection(
        make_test_csr(),
        exit_config_mode_error=exit_error,
    )
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(checker.CSRGenerationError, match="pending CSR may remain"):
        checker.generate_csr(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            make_csr_settings(),
        )

    assert connection.commands[1].startswith("crypto pki create-csr")
    assert connection.exited_config_mode


@pytest.mark.parametrize(
    "pre_attempt_error",
    [OSError("config mode failed"), RuntimeError("config mode failed")],
    ids=["oserror", "runtimeerror"],
)
def test_generate_csr_preserves_errors_before_attempt(monkeypatch, pre_attempt_error):
    connection = FakeCSRConnection(
        make_test_csr(),
        config_mode_error=pre_attempt_error,
    )
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(type(pre_attempt_error), match="config mode failed") as raised:
        checker.generate_csr(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            make_csr_settings(),
        )

    assert not isinstance(raised.value, checker.CSRGenerationError)
    assert connection.commands == ["show crypto pki local-certificate summary"]
    assert not connection.exited_config_mode


def test_generate_csr_reports_post_creation_validation_failure(monkeypatch):
    connection = FakeCSRConnection(make_test_csr(common_name="wrong.example.com"))
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(checker.CSRGenerationError, match="pending CSR was not removed"):
        checker.generate_csr(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            make_csr_settings(),
        )


@pytest.mark.parametrize(
    ("exception", "message"),
    [
        (NetmikoAuthenticationException("denied"), "authentication failed"),
        (NetmikoTimeoutException("timeout"), "connection timed out"),
    ],
)
def test_generate_csr_translates_expected_connection_errors(
    monkeypatch, exception, message
):
    def fail_connection(**kwargs):
        raise exception

    monkeypatch.setattr(checker, "ConnectHandler", fail_connection)

    with pytest.raises(ValueError, match=message):
        checker.generate_csr(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            make_csr_settings(),
        )


def test_generate_csr_warns_if_timeout_follows_creation_attempt(monkeypatch):
    connection = FakeCSRConnection(
        make_test_csr(),
        generation_error=NetmikoTimeoutException("timeout"),
    )
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(checker.CSRGenerationError, match="pending CSR may remain"):
        checker.generate_csr(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            make_csr_settings(),
        )


def test_retrieve_csr_finds_and_validates_requested_pending_web_csr(monkeypatch):
    summary = "\n".join(
        [
            "webcert2026 Web 2027/09/27 webprofile2026",
            "webcert2027 Web CSR webprofile2026",
        ]
    )
    connection = FakeCSRConnection(make_test_csr(), summary_output=summary)
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    csr_pem = checker.retrieve_csr(
        make_config()["switches"][0],
        "username",
        "password",
        "webcert2027",
        make_csr_settings(),
    )

    assert csr_pem == connection.csr_pem
    assert connection.commands == [
        "show crypto pki local-certificate summary",
        "show crypto pki local-certificate webcert2027",
    ]
    assert connection.retrieval_kwargs["read_timeout"] == 30
    assert not connection.entered_config_mode
    assert not connection.exited_config_mode
    assert connection.timing_kwargs is None


def test_retrieve_csr_sends_only_read_only_show_commands(monkeypatch):
    summary = "webcert2027 Web CSR webprofile2026\n"
    connection = FakeCSRConnection(make_test_csr(), summary_output=summary)
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    checker.retrieve_csr(
        make_config()["switches"][0],
        "username",
        "password",
        "webcert2027",
        make_csr_settings(),
    )

    commands = "\n".join(connection.commands).casefold()
    assert all(command.startswith("show ") for command in connection.commands)
    assert "write memory" not in commands
    assert "install" not in commands
    assert "delete" not in commands
    assert "clear" not in commands
    assert "create-csr" not in commands


def test_retrieve_csr_rejects_installed_web_certificate(monkeypatch):
    summary = "webcert2027 Web 2028/09/27 webprofile2026\n"
    connection = FakeCSRConnection(make_test_csr(), summary_output=summary)
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(ValueError, match="installed; expected a pending CSR"):
        checker.retrieve_csr(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            make_csr_settings(),
        )

    assert connection.commands == ["show crypto pki local-certificate summary"]
    assert not connection.entered_config_mode


def test_retrieve_csr_rejects_non_web_pending_certificate(monkeypatch):
    summary = "webcert2027 Client CSR webprofile2026\n"
    connection = FakeCSRConnection(make_test_csr(), summary_output=summary)
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(ValueError, match="usage Client; expected Web"):
        checker.retrieve_csr(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            make_csr_settings(),
        )

    assert connection.commands == ["show crypto pki local-certificate summary"]


def test_retrieve_csr_rejects_wrong_certificate_name(monkeypatch):
    summary = "othercert Web CSR webprofile2026\n"
    connection = FakeCSRConnection(make_test_csr(), summary_output=summary)
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(ValueError, match="not found"):
        checker.retrieve_csr(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            make_csr_settings(),
        )

    assert connection.commands == ["show crypto pki local-certificate summary"]


def test_write_or_print_csr_uses_exclusive_file_creation(tmp_path):
    output_file = tmp_path / "request.pem"
    csr_pem = make_test_csr()

    checker.write_or_print_csr(csr_pem, output_file)

    assert output_file.read_text(encoding="ascii") == csr_pem

    with pytest.raises(FileExistsError):
        checker.write_or_print_csr("replacement", output_file)

    assert output_file.read_text(encoding="ascii") == csr_pem


def test_extract_csr_pem():
    csr_pem = make_test_csr()

    output = f"""
Generating certificate request...

{csr_pem}
HOUSE-SWITCH(config)#
"""

    assert checker.extract_csr_pem(output) == csr_pem


def test_extract_csr_pem_rejects_missing_csr():
    with pytest.raises(ValueError, match="Could not find"):
        checker.extract_csr_pem("No CSR here")


def test_validate_csr_pem():
    switch = make_config()["switches"][0]

    csr = checker.validate_csr_pem(
        make_test_csr(),
        switch,
        make_csr_settings(),
    )

    assert csr.signature_algorithm_oid == SignatureAlgorithmOID.RSA_WITH_SHA256
    assert csr.public_key().key_size == 2048


def test_explicit_verification_accepts_rsa_sha1_when_property_reports_false():
    csr_pem = (FIXTURES_DIR / "rsa_sha1_csr.pem").read_text(encoding="ascii")
    parsed_csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))

    assert not parsed_csr.is_signature_valid

    csr = checker.validate_csr_pem(
        csr_pem,
        make_config()["switches"][0],
        make_csr_settings(),
    )

    assert csr.signature_algorithm_oid == SignatureAlgorithmOID.RSA_WITH_SHA1


def test_validate_csr_pem_rejects_unsupported_rsa_signature_algorithm():
    with pytest.raises(ValueError, match="Unsupported CSR signature algorithm"):
        checker.validate_csr_pem(
            make_test_csr(signature_hash=hashes.SHA384()),
            make_config()["switches"][0],
            make_csr_settings(),
        )


def test_validate_csr_pem_rejects_wrong_common_name():
    switch = make_config()["switches"][0]

    with pytest.raises(ValueError, match="common name"):
        checker.validate_csr_pem(
            make_test_csr(common_name="wrong.example.com"),
            switch,
            make_csr_settings(),
        )


def test_validate_csr_pem_rejects_multiple_common_names():
    with pytest.raises(ValueError, match="exactly one common name"):
        checker.validate_csr_pem(
            make_test_csr(common_name=["switch.example.com", "other.example.com"]),
            make_config()["switches"][0],
            make_csr_settings(),
        )


@pytest.mark.parametrize(
    ("keyword", "value", "message"),
    [
        ("organization", "Wrong Organization", "organization"),
        ("organizational_unit", "Wrong Unit", "organizational unit"),
        ("locality", "Wrong City", "locality"),
        ("state", "Wrong State", "state"),
        ("country", "US", "country"),
    ],
)
def test_validate_csr_pem_rejects_wrong_subject(keyword, value, message):
    with pytest.raises(ValueError, match=message):
        checker.validate_csr_pem(
            make_test_csr(**{keyword: value}),
            make_config()["switches"][0],
            make_csr_settings(),
        )


def test_validate_csr_pem_rejects_wrong_rsa_key_size():
    with pytest.raises(ValueError, match="RSA key size is 1024"):
        checker.validate_csr_pem(
            make_test_csr(key_size=1024),
            make_config()["switches"][0],
            make_csr_settings(),
        )


def test_validate_csr_pem_rejects_non_rsa_key():
    with pytest.raises(ValueError, match="does not contain an RSA"):
        checker.validate_csr_pem(
            make_test_csr(key_type="ec"),
            make_config()["switches"][0],
            make_csr_settings(),
        )


def test_validate_csr_pem_rejects_invalid_signature():
    csr = x509.load_pem_x509_csr(make_test_csr().encode("ascii"))
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 1
    invalid_pem = (
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        + base64.encodebytes(bytes(der)).decode("ascii")
        + "-----END CERTIFICATE REQUEST-----\n"
    )

    with pytest.raises(ValueError, match="signature is invalid"):
        checker.validate_csr_pem(
            invalid_pem,
            make_config()["switches"][0],
            make_csr_settings(),
        )


def make_opnsense_settings():
    return {
        "base_url": "https://opnsense.example.com:8443",
        "ca": "internal-ca",
        "lifetime_days": 397,
        "digest": "sha256",
    }


def make_test_identity_and_certificate(
    *,
    common_name="switch.example.com",
    dns_names=("switch.example.com",),
    ip_addresses=("192.0.2.10",),
    ca=False,
    eku=(ExtendedKeyUsageOID.SERVER_AUTH,),
    certificate_key_matches=True,
    not_before=None,
    not_after=None,
    lifetime_days=397,
    signature_hash=None,
    authority_cert_serial_number=None,
):
    if not_before is None:
        not_before = datetime(2026, 1, 1, tzinfo=UTC) - timedelta(minutes=1)
    if not_after is None:
        not_after = not_before + timedelta(days=lifetime_days)
    if signature_hash is None:
        signature_hash = hashes.SHA256()

    csr_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Organization"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Infrastructure"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Example City"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Example State"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        ]
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(csr_subject)
        .sign(csr_key, hashes.SHA256())
    )
    certificate_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            *list(csr_subject)[1:],
        ]
    )
    certificate_key = csr_key
    if not certificate_key_matches:
        certificate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    issuer_subject = certificate_subject
    signing_key = certificate_key
    if authority_cert_serial_number is not None:
        issuer_subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Test CA")]
        )
        signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    builder = (
        x509.CertificateBuilder()
        .subject_name(certificate_subject)
        .issuer_name(issuer_subject)
        .public_key(certificate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    *[x509.DNSName(name) for name in dns_names],
                    *[
                        x509.IPAddress(ipaddress.ip_address(address))
                        for address in ip_addresses
                    ],
                ]
            ),
            critical=False,
        )
    )
    if ca is not None:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=None), critical=True
        )
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)

    if authority_cert_serial_number is not None:
        issuer_key_identifier = x509.SubjectKeyIdentifier.from_public_key(
            signing_key.public_key()
        ).digest
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=issuer_key_identifier,
                authority_cert_issuer=[x509.DirectoryName(issuer_subject)],
                authority_cert_serial_number=authority_cert_serial_number,
            ),
            critical=False,
        )

    certificate = builder.sign(signing_key, signature_hash)
    return (
        csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        csr,
        certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    )


def test_get_opnsense_settings_validates_configuration():
    config = make_config()
    config["opnsense"] = make_opnsense_settings()

    assert checker.get_opnsense_settings(config) == make_opnsense_settings()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("base_url", "http://opnsense.example.com"),
        ("ca", ""),
        ("ca", "internal-ca\nother"),
        ("lifetime_days", True),
        ("lifetime_days", 0),
        ("lifetime_days", 3651),
        ("digest", "sha1"),
        ("digest", "SHA256"),
    ],
)
def test_get_opnsense_settings_rejects_invalid_values(field, value):
    config = make_config()
    config["opnsense"] = make_opnsense_settings()
    config["opnsense"][field] = value

    with pytest.raises(ValueError, match=f"opnsense.{field}"):
        checker.get_opnsense_settings(config)


@pytest.mark.parametrize("field", ["api_key", "api_secret"])
def test_get_opnsense_settings_rejects_credentials(field):
    config = make_config()
    config["opnsense"] = make_opnsense_settings()
    config["opnsense"][field] = "must-not-be-accepted"

    with pytest.raises(
        ValueError, match="only through environment variables"
    ) as raised:
        checker.get_opnsense_settings(config)

    assert "must-not-be-accepted" not in str(raised.value)


def test_validate_switch_signing_identity_accepts_dns_host():
    switch = make_config()["switches"][0]
    switch["host"] = "switch-management.example.com"

    identities = checker.validate_switch_signing_identity(switch)

    assert identities["common_name"] == "switch-management.example.com"


def test_validate_issued_certificate():
    _, csr, certificate_pem = make_test_identity_and_certificate()

    certificate = checker.validate_issued_certificate(
        certificate_pem,
        csr,
        make_config()["switches"][0],
        397,
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert certificate.public_key().key_size == 2048


@pytest.mark.parametrize(
    ("switch", "common_name", "dns_names", "ip_addresses"),
    [
        (
            {"host": "switch.example.com"},
            "switch.example.com",
            ("SWITCH.EXAMPLE.COM",),
            (),
        ),
        ({"host": "192.0.2.10"}, "192.0.2.10", (), ("192.0.2.10",)),
        ({"host": "2001:db8::10"}, "2001:db8::10", (), ("2001:0db8::10",)),
        (
            {
                "host": "switch.example.com",
                "additional_sans": ["alias.example.com", "192.0.2.10", "2001:db8::10"],
            },
            "switch.example.com",
            ("switch.example.com", "alias.example.com"),
            ("192.0.2.10", "2001:0db8::10"),
        ),
    ],
)
def test_validate_issued_certificate_accepts_exact_configured_identity_sets(
    switch, common_name, dns_names, ip_addresses
):
    _, csr, certificate_pem = make_test_identity_and_certificate(
        common_name=common_name,
        dns_names=dns_names,
        ip_addresses=ip_addresses,
    )

    checker.validate_issued_certificate(
        certificate_pem,
        csr,
        switch,
        397,
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )


@pytest.mark.parametrize(
    ("dns_names", "ip_addresses", "message"),
    [
        (("switch.example.com", "extra.example.com"), ("192.0.2.10",), "DNS SAN"),
        (("switch.example.com",), ("192.0.2.10", "192.0.2.11"), "IP SAN"),
    ],
)
def test_validate_issued_certificate_rejects_unexpected_sans(
    dns_names, ip_addresses, message
):
    _, csr, certificate_pem = make_test_identity_and_certificate(
        dns_names=dns_names,
        ip_addresses=ip_addresses,
    )

    with pytest.raises(ValueError, match=message):
        checker.validate_issued_certificate(
            certificate_pem,
            csr,
            make_config()["switches"][0],
            397,
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_validate_issued_certificate_contains_zero_aki_serial_warning():
    _, csr, certificate_pem = make_test_identity_and_certificate(
        authority_cert_serial_number=0
    )
    parsed_certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))

    assert parsed_certificate.serial_number > 0
    with warnings.catch_warnings():
        warnings.simplefilter("error", CryptographyDeprecationWarning)
        with pytest.raises(
            CryptographyDeprecationWarning,
            match="Parsed a serial number which wasn't positive",
        ):
            _ = parsed_certificate.extensions

    with warnings.catch_warnings():
        warnings.simplefilter("error", CryptographyDeprecationWarning)
        certificate = checker.validate_issued_certificate(
            certificate_pem,
            csr,
            make_config()["switches"][0],
            397,
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )
        authority_key_identifier = checker._require_extension(
            certificate,
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            "Authority Key Identifier",
        )

    assert authority_key_identifier.authority_cert_serial_number == 0


def test_validate_issued_certificate_rejects_public_key_mismatch():
    _, csr, certificate_pem = make_test_identity_and_certificate(
        certificate_key_matches=False
    )

    with pytest.raises(ValueError, match="public key does not match"):
        checker.validate_issued_certificate(
            certificate_pem,
            csr,
            make_config()["switches"][0],
            397,
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_validate_issued_certificate_rejects_incorrect_cn():
    _, csr, certificate_pem = make_test_identity_and_certificate(
        common_name="wrong.example.com"
    )

    with pytest.raises(ValueError, match="CN must equal"):
        checker.validate_issued_certificate(
            certificate_pem,
            csr,
            make_config()["switches"][0],
            397,
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"dns_names": ()}, "DNS SAN"),
        ({"ip_addresses": ()}, "IP SAN"),
        ({"ca": None}, "missing Basic Constraints"),
        ({"ca": True}, "CA to FALSE"),
        ({"eku": None}, "missing Extended Key Usage"),
        ({"eku": (ExtendedKeyUsageOID.CLIENT_AUTH,)}, "serverAuth"),
    ],
)
def test_validate_issued_certificate_rejects_required_extension_errors(kwargs, message):
    _, csr, certificate_pem = make_test_identity_and_certificate(**kwargs)

    with pytest.raises(ValueError, match=message):
        checker.validate_issued_certificate(
            certificate_pem,
            csr,
            make_config()["switches"][0],
            397,
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    ("not_before", "not_after", "message"),
    [
        (
            datetime(2026, 1, 1, 0, 10, tzinfo=UTC),
            datetime(2027, 2, 2, 0, 10, tzinfo=UTC),
            "not yet valid",
        ),
        (
            datetime(2024, 1, 1, tzinfo=UTC),
            datetime(2025, 2, 1, tzinfo=UTC),
            "expired",
        ),
        (
            datetime(2026, 1, 1, tzinfo=UTC),
            datetime(2026, 2, 1, tzinfo=UTC),
            "inconsistent",
        ),
    ],
)
def test_validate_issued_certificate_rejects_invalid_validity(
    not_before, not_after, message
):
    _, csr, certificate_pem = make_test_identity_and_certificate(
        not_before=not_before,
        not_after=not_after,
    )

    with pytest.raises(ValueError, match=message):
        checker.validate_issued_certificate(
            certificate_pem,
            csr,
            make_config()["switches"][0],
            397,
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_validate_issued_certificate_rejects_malformed_pem():
    _, csr, _ = make_test_identity_and_certificate()

    with pytest.raises(ValueError, match="not valid PEM"):
        checker.validate_issued_certificate(
            "not a certificate",
            csr,
            make_config()["switches"][0],
            397,
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_validate_issued_certificate_rejects_sha1_signature():
    csr_pem = (FIXTURES_DIR / "rsa_sha1_certificate_csr.pem").read_text(
        encoding="ascii"
    )
    certificate_pem = (FIXTURES_DIR / "rsa_sha1_certificate.pem").read_text(
        encoding="ascii"
    )
    csr = checker.validate_csr_pem(
        csr_pem,
        make_config()["switches"][0],
        make_csr_settings(),
    )
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))

    assert certificate.signature_hash_algorithm.name == "sha1"
    with pytest.raises(ValueError, match="SHA-256 or stronger"):
        checker.validate_issued_certificate(
            certificate_pem,
            csr,
            make_config()["switches"][0],
            397,
            now=certificate.not_valid_before_utc + timedelta(minutes=1),
        )


@pytest.mark.parametrize(
    "argv",
    [
        ["aruba_cert_renewer.py", "--sign-csr", "--certificate-name", "newcert"],
        ["aruba_cert_renewer.py", "--sign-csr", "--switch", "EXAMPLE-SWITCH"],
        [
            "aruba_cert_renewer.py",
            "--sign-csr",
            "--switch",
            "EXAMPLE-SWITCH",
            "--certificate-name",
            "newcert",
        ],
    ],
)
def test_sign_csr_requires_arguments_before_credentials(monkeypatch, argv):
    monkeypatch.setattr(checker.sys, "argv", argv)
    monkeypatch.setattr(
        checker,
        "get_switch_credentials",
        lambda *args: pytest.fail("Credentials should not be requested"),
    )

    assert checker.main() == checker.EXIT_ERROR


def test_sign_pending_csr_retrieves_existing_csr_and_never_generates(monkeypatch):
    csr_pem, _, certificate_pem = make_test_identity_and_certificate(
        not_before=datetime.now(UTC) - timedelta(minutes=1)
    )
    calls = []

    def fake_retrieve(*args, **kwargs):
        calls.append("retrieve")
        return csr_pem

    class FakeOPNsenseClient:
        def __init__(self, base_url):
            calls.append(("client", base_url))

        def resolve_ca(self, description):
            calls.append(("resolve", description))
            return "0123456789abc"

        def sign_csr(self, supplied_csr, **kwargs):
            calls.append(("sign", supplied_csr, kwargs))
            return "12345678-1234-4234-9234-123456789abc"

        def get_certificate(self, certificate_uuid):
            calls.append(("get", certificate_uuid))
            return certificate_pem

    monkeypatch.setattr(checker, "retrieve_csr", fake_retrieve)
    monkeypatch.setattr(
        checker,
        "generate_csr",
        lambda *args, **kwargs: pytest.fail("CSR generation must not be invoked"),
    )
    monkeypatch.setattr(checker, "OPNsenseClient", FakeOPNsenseClient)

    result = checker.sign_pending_csr(
        make_config()["switches"][0],
        "username",
        "password",
        "webcert2027",
        make_csr_settings(),
        make_opnsense_settings(),
    )

    assert result == certificate_pem
    assert calls[0] == "retrieve"
    sign_call = next(
        call for call in calls if isinstance(call, tuple) and call[0] == "sign"
    )
    assert sign_call[2]["dns_names"] == ["switch.example.com"]
    assert sign_call[2]["ip_addresses"] == ["192.0.2.10"]


def signing_config_text():
    return """
[csr]
organization = "Example Organization"
organizational_unit = "Infrastructure"
locality = "Example City"
state = "Example State"
country = "GB"
key_type = "rsa"
key_size = 2048

[opnsense]
base_url = "https://opnsense.example.com:8443"
ca = "internal-ca"
lifetime_days = 397
digest = "sha256"

[[switches]]
name = "EXAMPLE-SWITCH"
host = "switch.example.com"
additional_sans = ["192.0.2.10"]
""".strip()


def test_sign_csr_main_writes_validated_certificate(monkeypatch, tmp_path):
    config_file = tmp_path / "config.toml"
    output_file = tmp_path / "certificate.pem"
    config_file.write_text(signing_config_text(), encoding="utf-8")
    certificate_pem = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"
    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_renewer.py",
            "--config",
            str(config_file),
            "--sign-csr",
            "--switch",
            "EXAMPLE-SWITCH",
            "--certificate-name",
            "webcert2027",
            "--certificate-output",
            str(output_file),
        ],
    )
    monkeypatch.setattr(
        checker, "get_switch_credentials", lambda *args: ("username", "password")
    )
    monkeypatch.setattr(
        checker, "sign_pending_csr", lambda *args, **kwargs: certificate_pem
    )

    assert checker.main() == checker.EXIT_OK
    assert output_file.read_text(encoding="ascii") == certificate_pem


def test_sign_csr_does_not_write_output_when_validation_fails(monkeypatch, tmp_path):
    config_file = tmp_path / "config.toml"
    output_file = tmp_path / "certificate.pem"
    config_file.write_text(signing_config_text(), encoding="utf-8")
    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_renewer.py",
            "--config",
            str(config_file),
            "--sign-csr",
            "--switch",
            "EXAMPLE-SWITCH",
            "--certificate-name",
            "webcert2027",
            "--certificate-output",
            str(output_file),
        ],
    )
    monkeypatch.setattr(
        checker, "get_switch_credentials", lambda *args: ("username", "password")
    )
    monkeypatch.setattr(
        checker,
        "sign_pending_csr",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            ValueError("issued certificate validation failed")
        ),
    )

    assert checker.main() == checker.EXIT_ERROR
    assert not output_file.exists()


def test_existing_certificate_output_is_not_overwritten(monkeypatch, tmp_path):
    output_file = tmp_path / "certificate.pem"
    output_file.write_text("existing certificate", encoding="ascii")
    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_renewer.py",
            "--sign-csr",
            "--switch",
            "EXAMPLE-SWITCH",
            "--certificate-name",
            "webcert2027",
            "--certificate-output",
            str(output_file),
        ],
    )
    monkeypatch.setattr(
        checker,
        "get_switch_credentials",
        lambda *args: pytest.fail("Credentials should not be requested"),
    )

    assert checker.main() == checker.EXIT_ERROR
    assert output_file.read_text(encoding="ascii") == "existing certificate"


def make_install_args(**overrides):
    values = {
        "generate_csr": False,
        "retrieve_csr": False,
        "sign_csr": False,
        "install_certificate": True,
        "switch_name": "EXAMPLE-SWITCH",
        "certificate_name": "webcert2027",
        "csr_output": None,
        "certificate_output": None,
        "certificate_input": Path("certificate.pem"),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"switch_name": None}, "requires --switch"),
        ({"certificate_name": None}, "requires --certificate-name"),
        ({"certificate_input": None}, "requires --certificate-input"),
    ],
)
def test_install_certificate_requires_explicit_arguments(overrides, message):
    with pytest.raises(ValueError, match=message):
        checker.validate_cli_args(make_install_args(**overrides))


@pytest.mark.parametrize(
    "other_operation", ["generate_csr", "retrieve_csr", "sign_csr"]
)
def test_install_certificate_is_mutually_exclusive(other_operation):
    args = make_install_args()
    setattr(args, other_operation, True)

    with pytest.raises(ValueError, match="mutually exclusive"):
        checker.validate_cli_args(args)


def test_certificate_input_is_install_only():
    args = make_install_args(
        install_certificate=False,
        switch_name=None,
        certificate_name=None,
    )

    with pytest.raises(ValueError, match="requires --install-certificate"):
        checker.validate_cli_args(args)


def test_read_certificate_input_preserves_complete_pem(tmp_path):
    _, _, certificate_pem = make_test_identity_and_certificate()
    certificate_file = tmp_path / "certificate.pem"
    certificate_file.write_text(certificate_pem, encoding="ascii")

    assert checker.read_certificate_input(certificate_file) == certificate_pem


@pytest.mark.parametrize(
    "contents",
    [
        b"not a certificate",
        b"\xff-----BEGIN CERTIFICATE-----\n",
        (b"-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----\n"),
    ],
)
def test_read_certificate_input_rejects_malformed_or_non_certificate_input(
    tmp_path, contents
):
    certificate_file = tmp_path / "certificate.pem"
    certificate_file.write_bytes(contents)

    with pytest.raises(ValueError):
        checker.read_certificate_input(certificate_file)


def test_read_certificate_input_rejects_a_certificate_bundle(tmp_path):
    _, _, certificate_pem = make_test_identity_and_certificate()
    certificate_file = tmp_path / "certificate.pem"
    certificate_file.write_text(certificate_pem + certificate_pem, encoding="ascii")

    with pytest.raises(ValueError, match="exactly one"):
        checker.read_certificate_input(certificate_file)


def test_read_certificate_input_is_bounded(tmp_path):
    certificate_file = tmp_path / "certificate.pem"
    certificate_file.write_bytes(b"A" * (checker.MAX_CERTIFICATE_INPUT_BYTES + 1))

    with pytest.raises(ValueError, match="exceeds"):
        checker.read_certificate_input(certificate_file)


def test_get_verification_ca_file_resolves_relative_to_config(monkeypatch, tmp_path):
    config_file = tmp_path / "config.toml"
    ca_file = tmp_path / "ca" / "internal-ca.pem"
    ca_file.parent.mkdir()
    ca_file.write_text("public CA placeholder", encoding="ascii")
    calls = []

    monkeypatch.setattr(
        checker.ssl,
        "create_default_context",
        lambda *, cafile: calls.append(cafile) or object(),
    )

    result = checker.get_verification_ca_file(
        {"verification": {"ca_file": "ca/internal-ca.pem"}},
        config_file,
    )

    assert result == ca_file
    assert calls == [str(ca_file)]


def test_get_verification_ca_file_rejects_missing_file(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        checker.get_verification_ca_file(
            {"verification": {"ca_file": "missing.pem"}},
            tmp_path / "config.toml",
        )


def test_invalid_install_config_fails_before_credentials(monkeypatch, tmp_path):
    config_file = tmp_path / "config.toml"
    certificate_file = tmp_path / "certificate.pem"
    _, _, certificate_pem = make_test_identity_and_certificate()
    certificate_file.write_text(certificate_pem, encoding="ascii")
    config_file.write_text(signing_config_text(), encoding="utf-8")
    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_renewer.py",
            "--config",
            str(config_file),
            "--install-certificate",
            "--switch",
            "EXAMPLE-SWITCH",
            "--certificate-name",
            "webcert2027",
            "--certificate-input",
            str(certificate_file),
        ],
    )
    monkeypatch.setattr(
        checker,
        "get_switch_credentials",
        lambda *args: pytest.fail("Credentials should not be requested"),
    )

    assert checker.main() == checker.EXIT_ERROR


def test_malformed_certificate_input_fails_before_credentials(monkeypatch, tmp_path):
    config_file = tmp_path / "config.toml"
    certificate_file = tmp_path / "certificate.pem"
    certificate_file.write_text("not a certificate", encoding="ascii")
    config_file.write_text(
        signing_config_text() + '\n\n[verification]\nca_file = "public-ca.pem"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_renewer.py",
            "--config",
            str(config_file),
            "--install-certificate",
            "--switch",
            "EXAMPLE-SWITCH",
            "--certificate-name",
            "webcert2027",
            "--certificate-input",
            str(certificate_file),
        ],
    )
    monkeypatch.setattr(
        checker,
        "get_verification_ca_file",
        lambda *args: tmp_path / "public-ca.pem",
    )
    monkeypatch.setattr(
        checker,
        "get_switch_credentials",
        lambda *args: pytest.fail("Credentials should not be requested"),
    )

    assert checker.main() == checker.EXIT_ERROR


class FakeInstallConnection:
    def __init__(
        self,
        csr_pem,
        *,
        paste_prompt=checker.CERTIFICATE_PASTE_PROMPT,
        replacement_prompt=checker.CERTIFICATE_REPLACEMENT_PROMPT,
        post_summary="webcert2027 Web 2027/02/02 webprofile2026\n",
        details_output=(
            "Certificate Detail:\n"
            "Version: 3 (0x2)\n"
            "Serial Number: 01:23:45:67\n"
            "Signature Algorithm: sha256WithRSAEncryption\n"
        ),
        context_exit_error=None,
    ):
        self.csr_pem = csr_pem
        self.paste_prompt = paste_prompt
        self.replacement_prompt = replacement_prompt
        self.post_summary = post_summary
        self.details_output = details_output
        self.context_exit_error = context_exit_error
        self.commands = []
        self.interactions = []
        self.channel_writes = []
        self.channel_output = ""
        self.summary_calls = 0
        self.entered_config_mode = False
        self.exited_config_mode = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.context_exit_error is not None:
            raise self.context_exit_error
        return False

    def send_command(self, command, **kwargs):
        self.commands.append(command)
        if command == "show crypto pki local-certificate summary":
            self.summary_calls += 1
            if self.summary_calls <= 2:
                return "webcert2027 Web CSR webprofile2026\n"
            return self.post_summary
        if command == "show crypto pki local-certificate webcert2027":
            if self.summary_calls == 1:
                return f"Certificate request:\n{self.csr_pem}"
            return self.details_output
        raise AssertionError(f"Unexpected command: {command}")

    def config_mode(self):
        self.entered_config_mode = True

    def exit_config_mode(self):
        self.exited_config_mode = True

    def send_command_timing(self, command, **kwargs):
        self.commands.append(command)
        self.interactions.append(("send_command_timing", command))
        if command == "crypto pki install-signed-certificate":
            return self.paste_prompt
        if command == "y":
            return "Certificate installed"
        raise AssertionError(f"Unexpected timing command: {command}")

    def write_channel(self, data):
        self.commands.append(data)
        self.interactions.append(("write_channel", data))
        self.channel_writes.append(data)

        if len(self.channel_writes) == 1:
            self.channel_output = ""
        elif len(self.channel_writes) == 2 and data == "\n":
            self.channel_output = self.replacement_prompt
        else:
            raise AssertionError(f"Unexpected channel write: {data!r}")

    def read_channel_timing(self, **kwargs):
        output = self.channel_output
        self.interactions.append(("read_channel_timing", output))
        self.channel_output = ""
        return output


def test_fake_aruba_requires_blank_line_after_normally_terminated_pem():
    csr_pem, _, certificate_pem = make_test_identity_and_certificate()
    connection = FakeInstallConnection(csr_pem)

    assert certificate_pem.endswith("\n")
    assert not certificate_pem.endswith("\n\n")

    connection.write_channel(certificate_pem)

    assert connection.read_channel_timing() == ""

    connection.write_channel("\n")

    assert connection.read_channel_timing() == checker.CERTIFICATE_REPLACEMENT_PROMPT


def test_install_pending_certificate_accepts_real_detail_shape_and_uses_guarded_interaction(
    monkeypatch,
):
    csr_pem, _, certificate_pem = make_test_identity_and_certificate(
        not_before=datetime.now(UTC) - timedelta(minutes=1)
    )
    connection = FakeInstallConnection(csr_pem)
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    checker.install_pending_certificate(
        make_config()["switches"][0],
        "username",
        "password",
        "webcert2027",
        certificate_pem,
        make_csr_settings(),
        397,
    )

    assert connection.entered_config_mode
    assert connection.exited_config_mode
    assert "Certificate Detail:" in connection.details_output
    assert "webcert2027" not in connection.details_output
    assert connection.commands == [
        "show crypto pki local-certificate summary",
        "show crypto pki local-certificate webcert2027",
        "show crypto pki local-certificate summary",
        "crypto pki install-signed-certificate",
        certificate_pem,
        "\n",
        "y",
        "show crypto pki local-certificate summary",
        "show crypto pki local-certificate webcert2027",
    ]
    assert connection.channel_writes == [certificate_pem, "\n"]
    assert connection.interactions[1:5] == [
        ("write_channel", certificate_pem),
        ("write_channel", "\n"),
        ("read_channel_timing", checker.CERTIFICATE_REPLACEMENT_PROMPT),
        ("send_command_timing", "y"),
    ]
    forbidden_patterns = (
        r"\bwrite\s+memory\b",
        r"\bsave\b",
        r"\breboot\b",
        r"\breload\b",
        r"\bclear\b",
        r"\bdelete\b",
        r"\bcreate-csr\b",
    )
    commands_without_pem = [
        command for command in connection.commands if command != certificate_pem
    ]
    for command in commands_without_pem:
        assert all(
            re.search(pattern, command, re.IGNORECASE) is None
            for pattern in forbidden_patterns
        )


@pytest.mark.parametrize(
    "expected_prompt",
    [checker.CERTIFICATE_PASTE_PROMPT, checker.CERTIFICATE_REPLACEMENT_PROMPT],
)
def test_expected_prompt_accepts_command_echo_and_trailing_whitespace(expected_prompt):
    response = f"command echo\r\nInformational text\r\n{expected_prompt}\r\n\r\n"

    assert checker._ends_with_expected_prompt(response, expected_prompt)


@pytest.mark.parametrize(
    "paste_prompt",
    [
        f"Error: rejected input\n{checker.CERTIFICATE_PASTE_PROMPT}",
        f"{checker.CERTIFICATE_PASTE_PROMPT}\nUnexpected follow-up text",
    ],
)
def test_bad_paste_prompt_never_sends_certificate(monkeypatch, paste_prompt):
    csr_pem, _, certificate_pem = make_test_identity_and_certificate(
        not_before=datetime.now(UTC) - timedelta(minutes=1)
    )
    connection = FakeInstallConnection(csr_pem, paste_prompt=paste_prompt)
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(
        checker.CertificateInstallationAttemptError,
        match="certificate-paste prompt",
    ):
        checker.install_pending_certificate(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            certificate_pem,
            make_csr_settings(),
            397,
        )

    assert connection.exited_config_mode
    assert certificate_pem not in connection.commands
    assert connection.channel_writes == []
    assert "y" not in connection.commands


@pytest.mark.parametrize(
    "replacement_prompt",
    [
        "",
        f"Error: rejected certificate\n{checker.CERTIFICATE_REPLACEMENT_PROMPT}",
        f"{checker.CERTIFICATE_REPLACEMENT_PROMPT}\nUnexpected follow-up text",
    ],
)
def test_bad_replacement_prompt_never_sends_confirmation(
    monkeypatch, replacement_prompt
):
    csr_pem, _, certificate_pem = make_test_identity_and_certificate(
        not_before=datetime.now(UTC) - timedelta(minutes=1)
    )
    connection = FakeInstallConnection(
        csr_pem,
        replacement_prompt=replacement_prompt,
    )
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(
        checker.CertificateInstallationAttemptError,
        match="confirmation was not sent",
    ):
        checker.install_pending_certificate(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            certificate_pem,
            make_csr_settings(),
            397,
        )

    assert connection.exited_config_mode
    assert certificate_pem in connection.commands
    assert connection.channel_writes == [certificate_pem, "\n"]
    assert "y" not in connection.commands


@pytest.mark.parametrize(
    "certificate_kwargs",
    [
        {"certificate_key_matches": False},
        {"common_name": "wrong.example.com"},
        {"dns_names": ()},
    ],
)
def test_certificate_validation_failure_sends_no_configuration_command(
    monkeypatch, certificate_kwargs
):
    csr_pem, _, certificate_pem = make_test_identity_and_certificate(
        not_before=datetime.now(UTC) - timedelta(minutes=1),
        **certificate_kwargs,
    )
    connection = FakeInstallConnection(csr_pem)
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(ValueError):
        checker.install_pending_certificate(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            certificate_pem,
            make_csr_settings(),
            397,
        )

    assert not connection.entered_config_mode
    assert all(command.startswith("show ") for command in connection.commands)


def test_installed_certificate_name_is_rejected_before_config_mode(monkeypatch):
    csr_pem, _, certificate_pem = make_test_identity_and_certificate(
        not_before=datetime.now(UTC) - timedelta(minutes=1)
    )
    connection = FakeInstallConnection(csr_pem)
    connection.summary_calls = 2
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(ValueError, match="installed; expected a pending CSR"):
        checker.install_pending_certificate(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            certificate_pem,
            make_csr_settings(),
            397,
        )

    assert not connection.entered_config_mode


@pytest.mark.parametrize(
    ("post_summary", "message"),
    [
        ("webcert2027 Web CSR webprofile2026\n", "still shown"),
        ("webcert2027 Client 2027/02/02 webprofile2026\n", "usage Client"),
        ("webcert2027 Web 2027/02/02 changedprofile\n", "profile changed"),
    ],
)
def test_post_install_summary_must_show_installed_web_certificate(
    monkeypatch, post_summary, message
):
    csr_pem, _, certificate_pem = make_test_identity_and_certificate(
        not_before=datetime.now(UTC) - timedelta(minutes=1)
    )
    connection = FakeInstallConnection(csr_pem, post_summary=post_summary)
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(checker.CertificateInstallationAttemptError, match=message):
        checker.install_pending_certificate(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            certificate_pem,
            make_csr_settings(),
            397,
        )


@pytest.mark.parametrize(
    "details_output",
    [
        "Error: certificate unavailable\nCertificate Detail:\n",
        "Version: 3 (0x2)\nSerial Number: 01:23:45:67\n",
    ],
)
def test_post_install_detail_rejects_cli_errors_or_missing_success_marker(
    monkeypatch, details_output
):
    csr_pem, _, certificate_pem = make_test_identity_and_certificate(
        not_before=datetime.now(UTC) - timedelta(minutes=1)
    )
    connection = FakeInstallConnection(csr_pem, details_output=details_output)
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(
        checker.CertificateInstallationAttemptError,
        match="detailed switch output",
    ):
        checker.install_pending_certificate(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            certificate_pem,
            make_csr_settings(),
            397,
        )


@pytest.mark.parametrize(
    "context_exit_error",
    [OSError("SSH close failed"), ValueError("SSH close failed")],
    ids=["oserror", "valueerror"],
)
def test_context_exit_error_after_install_is_post_install_failure(
    monkeypatch, context_exit_error
):
    csr_pem, _, certificate_pem = make_test_identity_and_certificate(
        not_before=datetime.now(UTC) - timedelta(minutes=1)
    )
    connection = FakeInstallConnection(
        csr_pem,
        context_exit_error=context_exit_error,
    )
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(checker.CertificateInstallationAttemptError) as raised:
        checker.install_pending_certificate(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            certificate_pem,
            make_csr_settings(),
            397,
        )

    assert "may already have changed the switch" in str(raised.value)
    assert "y" in connection.commands
    assert connection.summary_calls == 3


def test_context_exit_oserror_cannot_reach_main_pre_install_path(
    monkeypatch, tmp_path, capsys
):
    config_file = tmp_path / "config.toml"
    certificate_file = tmp_path / "certificate.pem"
    csr_pem, _, certificate_pem = make_test_identity_and_certificate(
        not_before=datetime.now(UTC) - timedelta(minutes=1)
    )
    certificate_file.write_text(certificate_pem, encoding="ascii")
    config_file.write_text(
        signing_config_text() + '\n\n[verification]\nca_file = "public-ca.pem"\n',
        encoding="utf-8",
    )
    connection = FakeInstallConnection(
        csr_pem,
        context_exit_error=OSError("SSH close failed"),
    )
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)
    monkeypatch.setattr(
        checker,
        "get_verification_ca_file",
        lambda *args: tmp_path / "public-ca.pem",
    )
    monkeypatch.setattr(
        checker, "get_switch_credentials", lambda *args: ("username", "password")
    )
    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_renewer.py",
            "--config",
            str(config_file),
            "--install-certificate",
            "--switch",
            "EXAMPLE-SWITCH",
            "--certificate-name",
            "webcert2027",
            "--certificate-input",
            str(certificate_file),
        ],
    )

    assert checker.main() == checker.EXIT_ERROR
    error_output = capsys.readouterr().err
    assert "Post-install failure" in error_output
    assert "may already have changed the switch" in error_output
    assert "Pre-install failure" not in error_output


@pytest.mark.parametrize(
    "pre_install_error",
    [OSError("SSH open failed"), ValueError("SSH open failed")],
    ids=["oserror", "valueerror"],
)
def test_pre_install_valueerror_and_oserror_remain_safe(monkeypatch, pre_install_error):
    def fail_connection(**kwargs):
        raise pre_install_error

    monkeypatch.setattr(checker, "ConnectHandler", fail_connection)

    with pytest.raises(type(pre_install_error)) as raised:
        checker.install_pending_certificate(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            "not reached",
            make_csr_settings(),
            397,
        )

    assert not isinstance(raised.value, checker.CertificateInstallationAttemptError)


class FakeTLSSocket:
    def __init__(self, peer_der=None):
        self.peer_der = peer_der

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def getpeercert(self, *, binary_form):
        assert binary_form is True
        return self.peer_der


class FakeVerifyingSSLContext:
    check_hostname = True
    verify_mode = checker.ssl.CERT_REQUIRED

    def __init__(self, tls_results):
        self.tls_results = iter(tls_results)
        self.wrap_calls = []

    def wrap_socket(self, tcp_socket, *, server_hostname):
        self.wrap_calls.append((tcp_socket, server_hostname))
        result = next(self.tls_results)
        if isinstance(result, Exception):
            raise result
        return FakeTLSSocket(result)


def test_verify_live_https_uses_verified_hostname_and_exact_der(monkeypatch):
    _, _, certificate_pem = make_test_identity_and_certificate()
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    expected_der = certificate.public_bytes(serialization.Encoding.DER)
    context = FakeVerifyingSSLContext([expected_der])
    tcp_socket = FakeTLSSocket()
    context_calls = []
    connection_calls = []
    monkeypatch.setattr(
        checker.ssl,
        "create_default_context",
        lambda *, cafile: context_calls.append(cafile) or context,
    )
    monkeypatch.setattr(
        checker.socket,
        "create_connection",
        lambda address, *, timeout: (
            connection_calls.append((address, timeout)) or tcp_socket
        ),
    )

    checker.verify_live_https_certificate(
        make_config()["switches"][0],
        Path("public-ca.pem"),
        certificate,
    )

    assert context_calls == ["public-ca.pem"]
    assert connection_calls == [(("switch.example.com", 443), 5)]
    assert context.wrap_calls == [(tcp_socket, "switch.example.com")]
    assert context.check_hostname is True
    assert context.verify_mode == checker.ssl.CERT_REQUIRED


@pytest.mark.parametrize("host", ["192.0.2.10", "2001:db8::10"])
def test_verify_live_https_uses_ip_host_for_connection_and_identity(monkeypatch, host):
    _, _, certificate_pem = make_test_identity_and_certificate()
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    expected_der = certificate.public_bytes(serialization.Encoding.DER)
    context = FakeVerifyingSSLContext([expected_der])
    connection_calls = []
    monkeypatch.setattr(
        checker.ssl, "create_default_context", lambda *, cafile: context
    )
    monkeypatch.setattr(
        checker.socket,
        "create_connection",
        lambda address, *, timeout: (
            connection_calls.append((address, timeout)) or FakeTLSSocket()
        ),
    )

    checker.verify_live_https_certificate(
        {"host": host, "additional_sans": ["alias.example.com"]},
        Path("public-ca.pem"),
        certificate,
    )

    assert connection_calls == [((host, 443), 5)]
    assert context.wrap_calls[0][1] == host


def test_verify_live_https_retries_until_expected_certificate_appears(monkeypatch):
    _, _, certificate_pem = make_test_identity_and_certificate()
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    expected_der = certificate.public_bytes(serialization.Encoding.DER)
    context = FakeVerifyingSSLContext([b"previous certificate", expected_der])
    connection_calls = []
    sleep_calls = []
    monotonic_values = iter([0, 1])
    monkeypatch.setattr(
        checker.ssl, "create_default_context", lambda *, cafile: context
    )
    monkeypatch.setattr(
        checker.socket,
        "create_connection",
        lambda address, *, timeout: (
            connection_calls.append((address, timeout)) or FakeTLSSocket()
        ),
    )
    monkeypatch.setattr(checker.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(checker.time, "sleep", sleep_calls.append)

    checker.verify_live_https_certificate(
        make_config()["switches"][0],
        Path("public-ca.pem"),
        certificate,
        verification_window=30,
        retry_delay=2,
    )

    assert len(connection_calls) == 2
    assert sleep_calls == [2]


@pytest.mark.parametrize(
    "tls_result",
    [
        b"another valid certificate",
        checker.ssl.SSLCertVerificationError(1, "hostname or CA verification failed"),
    ],
)
def test_verify_live_https_rejects_wrong_or_unverified_certificate(
    monkeypatch, tls_result
):
    _, _, certificate_pem = make_test_identity_and_certificate()
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    context = FakeVerifyingSSLContext([tls_result])
    monotonic_values = iter([0, 0])
    monkeypatch.setattr(
        checker.ssl, "create_default_context", lambda *, cafile: context
    )
    monkeypatch.setattr(
        checker.socket,
        "create_connection",
        lambda address, *, timeout: FakeTLSSocket(),
    )
    monkeypatch.setattr(checker.time, "monotonic", lambda: next(monotonic_values))

    with pytest.raises(ValueError, match="not verified"):
        checker.verify_live_https_certificate(
            make_config()["switches"][0],
            Path("public-ca.pem"),
            certificate,
            verification_window=0,
        )


def test_verify_live_https_retries_transient_connection_failure(monkeypatch):
    _, _, certificate_pem = make_test_identity_and_certificate()
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    expected_der = certificate.public_bytes(serialization.Encoding.DER)
    context = FakeVerifyingSSLContext([expected_der])
    results = iter([ConnectionRefusedError("restarting"), FakeTLSSocket()])
    monotonic_values = iter([0, 1])
    monkeypatch.setattr(
        checker.ssl, "create_default_context", lambda *, cafile: context
    )

    def create_connection(address, *, timeout):
        result = next(results)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(checker.socket, "create_connection", create_connection)
    monkeypatch.setattr(checker.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(checker.time, "sleep", lambda seconds: None)

    checker.verify_live_https_certificate(
        make_config()["switches"][0],
        Path("public-ca.pem"),
        certificate,
    )


def make_renew_args(**overrides):
    values = {
        "generate_csr": False,
        "retrieve_csr": False,
        "sign_csr": False,
        "install_certificate": False,
        "renew": True,
        "switch_name": "EXAMPLE-SWITCH",
        "certificate_name": None,
        "csr_output": None,
        "certificate_output": None,
        "certificate_input": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_renew_requires_switch():
    with pytest.raises(ValueError, match="--renew requires --switch"):
        checker.validate_cli_args(make_renew_args(switch_name=None))


@pytest.mark.parametrize(
    "staged_operation",
    ["generate_csr", "retrieve_csr", "sign_csr", "install_certificate"],
)
def test_renew_is_mutually_exclusive_with_staged_operations(staged_operation):
    args = make_renew_args()
    setattr(args, staged_operation, True)

    with pytest.raises(ValueError, match="mutually exclusive"):
        checker.validate_cli_args(args)


@pytest.mark.parametrize(
    ("field", "value", "option"),
    [
        ("certificate_name", "manual-name", "--certificate-name"),
        ("csr_output", Path("request.pem"), "--csr-output"),
        ("certificate_output", Path("certificate.pem"), "--certificate-output"),
        ("certificate_input", Path("certificate.pem"), "--certificate-input"),
    ],
)
def test_renew_rejects_staged_file_and_name_options(field, value, option):
    with pytest.raises(ValueError, match=f"does not accept {option}"):
        checker.validate_cli_args(make_renew_args(**{field: value}))


def make_renew_due_args(**overrides):
    values = {
        "generate_csr": False,
        "retrieve_csr": False,
        "sign_csr": False,
        "install_certificate": False,
        "renew": False,
        "renew_due": True,
        "switch_name": None,
        "certificate_name": None,
        "csr_output": None,
        "certificate_output": None,
        "certificate_input": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.mark.parametrize("switch_name", [None, "EXAMPLE-SWITCH"])
def test_renew_due_accepts_with_or_without_switch(switch_name):
    checker.validate_cli_args(make_renew_due_args(switch_name=switch_name))


@pytest.mark.parametrize(
    "other_operation",
    [
        "renew",
        "generate_csr",
        "retrieve_csr",
        "sign_csr",
        "install_certificate",
    ],
)
def test_renew_due_is_mutually_exclusive_with_other_operations(other_operation):
    args = make_renew_due_args()
    setattr(args, other_operation, True)

    with pytest.raises(ValueError, match="mutually exclusive"):
        checker.validate_cli_args(args)


@pytest.mark.parametrize(
    ("field", "value", "option"),
    [
        ("certificate_name", "manual-name", "--certificate-name"),
        ("csr_output", Path("request.pem"), "--csr-output"),
        ("certificate_output", Path("certificate.pem"), "--certificate-output"),
        ("certificate_input", Path("certificate.pem"), "--certificate-input"),
    ],
)
def test_renew_due_rejects_staged_file_and_name_options(field, value, option):
    with pytest.raises(ValueError, match=f"--renew-due does not accept {option}"):
        checker.validate_cli_args(make_renew_due_args(**{field: value}))


def test_choose_renewal_name_starts_at_01_and_is_a_valid_identifier():
    result = checker.choose_renewal_certificate_name(
        "webcert-20260828-01 Web 2027/09/27 profile\n",
        now=datetime(2026, 8, 29, 12, tzinfo=UTC),
    )

    assert result == "webcert-20260829-01"
    assert checker.validate_cli_identifier(result, "certificate name") == result


def test_choose_renewal_name_skips_case_insensitive_non_web_collision():
    result = checker.choose_renewal_certificate_name(
        "WEBCERT-20260829-01 Client 2027/09/27 clientprofile\n",
        now=date(2026, 8, 29),
    )

    assert result == "webcert-20260829-02"


def test_choose_renewal_name_can_select_sequence_99():
    summary = "".join(
        f"webcert-20260829-{sequence:02d} Client 2027/09/27 profile\n"
        for sequence in range(1, 99)
    )

    assert (
        checker.choose_renewal_certificate_name(
            summary,
            now=date(2026, 8, 29),
        )
        == "webcert-20260829-99"
    )


def test_choose_renewal_name_fails_when_all_99_names_exist():
    summary = "".join(
        f"webcert-20260829-{sequence:02d} Any 2027/09/27 profile\n"
        for sequence in range(1, 100)
    )

    with pytest.raises(ValueError, match="All 99 renewal certificate names"):
        checker.choose_renewal_certificate_name(
            summary,
            now=date(2026, 8, 29),
        )


def test_choose_renewal_name_uses_utc_for_datetime_dependency():
    result = checker.choose_renewal_certificate_name(
        "",
        now=datetime.fromisoformat("2026-08-30T00:30:00+01:00"),
    )

    assert result == "webcert-20260829-01"


def test_renewal_preflight_is_read_only_and_records_state(monkeypatch):
    summary = "".join(
        [
            "webcert2026 Web 2027/09/27 webprofile2026\n",
            "webcert-20260829-01 Client 2027/09/27 clientprofile\n",
        ]
    )
    connection = FakeCSRConnection(make_test_csr(), summary_output=summary)
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    result = checker.renewal_preflight(
        make_config()["switches"][0],
        "username",
        "password",
        now=date(2026, 8, 29),
    )

    assert result == {
        "active_certificate_name": "webcert2026",
        "ta_profile": "webprofile2026",
        "new_certificate_name": "webcert-20260829-02",
    }
    assert connection.commands == ["show crypto pki local-certificate summary"]
    assert not connection.entered_config_mode
    assert connection.timing_kwargs is None


def test_renewal_preflight_rejects_pending_web_csr(monkeypatch):
    summary = "".join(
        [
            "webcert2026 Web 2027/09/27 webprofile2026\n",
            "webcert2027 Web CSR webprofile2026\n",
        ]
    )
    connection = FakeCSRConnection(make_test_csr(), summary_output=summary)
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(checker.RenewalPreflightError, match="staged commands"):
        checker.renewal_preflight(
            make_config()["switches"][0],
            "username",
            "password",
            now=date(2026, 8, 29),
        )

    assert connection.commands == ["show crypto pki local-certificate summary"]
    assert not connection.entered_config_mode


def test_renewal_preflight_rejects_multiple_installed_web_certificates(monkeypatch):
    summary = "".join(
        [
            "webcert2026 Web 2027/09/27 webprofile2026\n",
            "webcert2027 Web 2028/09/27 webprofile2026\n",
        ]
    )
    connection = FakeCSRConnection(make_test_csr(), summary_output=summary)
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(checker.RenewalPreflightError, match="2 installed"):
        checker.renewal_preflight(
            make_config()["switches"][0],
            "username",
            "password",
            now=date(2026, 8, 29),
        )

    assert not connection.entered_config_mode


def test_renew_certificate_composes_stages_in_order_without_files(monkeypatch):
    calls = []
    switch = make_config()["switches"][0]
    csr_settings = make_csr_settings()
    opnsense_settings = make_opnsense_settings()
    certificate_pem = "issued certificate PEM"
    certificate = object()
    ca_file = Path("public-ca.pem")

    monkeypatch.setattr(
        checker,
        "renewal_preflight",
        lambda *args, **kwargs: (
            calls.append(("preflight", args, kwargs))
            or {
                "active_certificate_name": "webcert2026",
                "ta_profile": "webprofile2026",
                "new_certificate_name": "webcert-20260829-01",
            }
        ),
    )
    monkeypatch.setattr(
        checker,
        "generate_csr",
        lambda *args: calls.append(("generate", args)) or "unpersisted CSR",
    )
    monkeypatch.setattr(
        checker,
        "sign_pending_csr",
        lambda *args: calls.append(("sign", args)) or certificate_pem,
    )
    monkeypatch.setattr(
        checker,
        "install_pending_certificate",
        lambda *args: calls.append(("install", args)) or certificate,
    )
    monkeypatch.setattr(
        checker,
        "verify_live_https_certificate",
        lambda *args: calls.append(("https", args)),
    )
    monkeypatch.setattr(
        checker,
        "write_or_print_csr",
        lambda *args: pytest.fail("CSR must not be written"),
    )
    monkeypatch.setattr(
        checker,
        "write_certificate",
        lambda *args: pytest.fail("certificate must not be written"),
    )

    result = checker.renew_certificate(
        switch,
        "username",
        "password",
        csr_settings,
        opnsense_settings,
        ca_file,
        now=date(2026, 8, 29),
    )

    assert result == "webcert-20260829-01"
    assert [call[0] for call in calls] == [
        "preflight",
        "generate",
        "sign",
        "install",
        "https",
    ]
    assert calls[0][1] == (switch, "username", "password")
    assert calls[0][2] == {"now": date(2026, 8, 29)}
    for call in calls[1:4]:
        assert call[1][0:4] == (
            switch,
            "username",
            "password",
            "webcert-20260829-01",
        )
    assert calls[3][1][4] == certificate_pem
    assert calls[4][1] == (switch, ca_file, certificate)


@pytest.mark.parametrize(
    ("failing_stage", "exception_type", "expected_calls"),
    [
        ("generate", checker.CSRGenerationError, ["preflight", "generate"]),
        ("sign", checker.CSRSigningError, ["preflight", "generate", "sign"]),
        (
            "install",
            checker.CertificateInstallationAttemptError,
            ["preflight", "generate", "sign", "install"],
        ),
        (
            "https",
            checker.LiveHTTPSVerificationError,
            ["preflight", "generate", "sign", "install", "https"],
        ),
    ],
)
def test_renew_certificate_stops_after_failed_stage(
    monkeypatch, failing_stage, exception_type, expected_calls
):
    calls = []

    def stage(name, result=None):
        def invoke(*args, **kwargs):
            calls.append(name)
            if name == failing_stage:
                if name == "generate":
                    raise checker.CSRGenerationError("generation failed")
                if name == "install":
                    raise checker.CertificateInstallationAttemptError(
                        "installation failed"
                    )
                raise ValueError(f"{name} failed")
            return result

        return invoke

    monkeypatch.setattr(
        checker,
        "renewal_preflight",
        stage(
            "preflight",
            {
                "active_certificate_name": "webcert2026",
                "ta_profile": "webprofile2026",
                "new_certificate_name": "webcert-20260829-01",
            },
        ),
    )
    monkeypatch.setattr(checker, "generate_csr", stage("generate", "CSR"))
    monkeypatch.setattr(checker, "sign_pending_csr", stage("sign", "certificate"))
    monkeypatch.setattr(
        checker, "install_pending_certificate", stage("install", object())
    )
    monkeypatch.setattr(checker, "verify_live_https_certificate", stage("https"))

    with pytest.raises(exception_type):
        checker.renew_certificate(
            make_config()["switches"][0],
            "username",
            "password",
            make_csr_settings(),
            make_opnsense_settings(),
            Path("public-ca.pem"),
        )

    assert calls == expected_calls


def test_renew_certificate_preflight_failure_attempts_no_stage(monkeypatch):
    monkeypatch.setattr(
        checker,
        "renewal_preflight",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            checker.RenewalPreflightError("pending CSR exists")
        ),
    )
    for stage_name in (
        "generate_csr",
        "sign_pending_csr",
        "install_pending_certificate",
        "verify_live_https_certificate",
    ):
        monkeypatch.setattr(
            checker,
            stage_name,
            lambda *args, _stage_name=stage_name: pytest.fail(
                f"{_stage_name} must not run after a preflight failure"
            ),
        )

    with pytest.raises(checker.RenewalPreflightError):
        checker.renew_certificate(
            make_config()["switches"][0],
            "username",
            "password",
            make_csr_settings(),
            make_opnsense_settings(),
            Path("public-ca.pem"),
        )


def test_renew_signing_failure_reports_that_pending_csr_remains(monkeypatch):
    monkeypatch.setattr(
        checker,
        "renewal_preflight",
        lambda *args, **kwargs: {
            "active_certificate_name": "webcert2026",
            "ta_profile": "webprofile2026",
            "new_certificate_name": "webcert-20260829-01",
        },
    )
    monkeypatch.setattr(checker, "generate_csr", lambda *args: "CSR")
    monkeypatch.setattr(
        checker,
        "sign_pending_csr",
        lambda *args: (_ for _ in ()).throw(ValueError("OPNsense unavailable")),
    )
    monkeypatch.setattr(
        checker,
        "install_pending_certificate",
        lambda *args: pytest.fail("installation must not be attempted"),
    )

    with pytest.raises(checker.CSRSigningError, match="pending CSR remains"):
        checker.renew_certificate(
            make_config()["switches"][0],
            "username",
            "password",
            make_csr_settings(),
            make_opnsense_settings(),
            Path("public-ca.pem"),
        )


def renewal_config_text():
    return signing_config_text() + '\n\n[verification]\nca_file = "public-ca.pem"\n'


def test_renew_invalid_config_fails_before_credentials(monkeypatch, tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        renewal_config_text().replace('digest = "sha256"', 'digest = "sha1"'),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_renewer.py",
            "--config",
            str(config_file),
            "--switch",
            "EXAMPLE-SWITCH",
            "--renew",
        ],
    )
    monkeypatch.setattr(
        checker,
        "get_switch_credentials",
        lambda *args: pytest.fail("Credentials should not be requested"),
    )

    assert checker.main() == checker.EXIT_ERROR


def test_renew_verification_ca_is_validated_before_credentials(monkeypatch, tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text(renewal_config_text(), encoding="utf-8")
    calls = []
    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_renewer.py",
            "--config",
            str(config_file),
            "--switch",
            "EXAMPLE-SWITCH",
            "--renew",
        ],
    )
    monkeypatch.setattr(
        checker,
        "get_verification_ca_file",
        lambda *args: calls.append("verification") or Path("public-ca.pem"),
    )
    monkeypatch.setattr(
        checker,
        "get_switch_credentials",
        lambda *args: calls.append("credentials") or ("username", "password"),
    )
    monkeypatch.setattr(
        checker,
        "renew_certificate",
        lambda *args: calls.append("renewal"),
    )

    assert checker.main() == checker.EXIT_OK
    assert calls == ["verification", "credentials", "renewal"]


def test_renew_https_failure_returns_error_with_post_install_warning(
    monkeypatch, tmp_path, capsys
):
    config_file = tmp_path / "config.toml"
    config_file.write_text(renewal_config_text(), encoding="utf-8")
    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_renewer.py",
            "--config",
            str(config_file),
            "--switch",
            "EXAMPLE-SWITCH",
            "--renew",
        ],
    )
    monkeypatch.setattr(
        checker,
        "get_verification_ca_file",
        lambda *args: Path("public-ca.pem"),
    )
    monkeypatch.setattr(
        checker, "get_switch_credentials", lambda *args: ("username", "password")
    )
    monkeypatch.setattr(
        checker,
        "renew_certificate",
        lambda *args: (_ for _ in ()).throw(
            checker.LiveHTTPSVerificationError("verification timed out")
        ),
    )

    assert checker.main() == checker.EXIT_ERROR
    error_output = capsys.readouterr().err
    assert "may already be active" in error_output
    assert "No automatic rollback" in error_output


def test_renew_post_attempt_generation_oserror_never_claims_no_pending_csr(
    monkeypatch, tmp_path, capsys
):
    config_file = tmp_path / "config.toml"
    config_file.write_text(renewal_config_text(), encoding="utf-8")
    connection = FakeCSRConnection(
        make_test_csr(),
        generation_error=OSError("channel failed"),
    )
    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_renewer.py",
            "--config",
            str(config_file),
            "--switch",
            "EXAMPLE-SWITCH",
            "--renew",
        ],
    )
    monkeypatch.setattr(
        checker,
        "get_verification_ca_file",
        lambda *args: Path("public-ca.pem"),
    )
    monkeypatch.setattr(
        checker, "get_switch_credentials", lambda *args: ("username", "password")
    )
    monkeypatch.setattr(
        checker,
        "renewal_preflight",
        lambda *args, **kwargs: {
            "active_certificate_name": "webcert2026",
            "ta_profile": "webprofile2026",
            "new_certificate_name": "webcert-20260829-01",
        },
    )
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)
    monkeypatch.setattr(
        checker,
        "sign_pending_csr",
        lambda *args: pytest.fail("signing must not be attempted"),
    )

    assert checker.main() == checker.EXIT_ERROR
    error_output = capsys.readouterr().err
    assert "CSR creation was attempted" in error_output
    assert "pending CSR may remain" in error_output
    assert "no pending CSR was created" not in error_output


def make_multi_switch_config():
    config = make_config()
    config["switches"] = [
        {
            "name": "SWITCH-A",
            "host": "switch-a.example.com",
            "additional_sans": [],
        },
        {
            "name": "SWITCH-B",
            "host": "switch-b.example.com",
            "additional_sans": [],
        },
    ]
    config["csr"] = make_csr_settings()
    config["opnsense"] = make_opnsense_settings()
    config["verification"] = {"ca_file": "public-ca.pem"}
    return config


@pytest.mark.parametrize(
    ("exception", "expected_error"),
    [
        (
            checker.RenewalPreflightError("pending CSR"),
            "Error: Renewal preflight failed; no renewal change was attempted: "
            "pending CSR\n",
        ),
        (
            checker.CSRGenerationPreAttemptError("invalid settings"),
            "Error: CSR generation failed before CSR creation was attempted; no "
            "pending CSR was created: invalid settings\n",
        ),
        (
            checker.CSRGenerationError("pending CSR may remain"),
            "Error: pending CSR may remain\n"
            "CSR creation was attempted. No automatic cleanup was attempted; use "
            "the explicit staged commands for diagnosis or recovery.\n",
        ),
        (
            checker.CSRSigningError("signing failed"),
            "Error: CSR signing failed: signing failed\n"
            "No certificate installation or automatic OPNsense cleanup was "
            "attempted.\n",
        ),
        (
            checker.CertificatePreInstallationError("validation failed"),
            "Error: Certificate installation did not begin: validation failed\n"
            "No automatic rollback was attempted.\n",
        ),
        (
            checker.CertificateInstallationAttemptError("channel failed"),
            "Error: Post-install failure: channel failed\n"
            "No automatic rollback was attempted; inspect the switch manually.\n",
        ),
        (
            checker.LiveHTTPSVerificationError("timed out"),
            "Error: Post-install HTTPS verification failed. The certificate may "
            "already be active and requires manual investigation: timed out\n"
            "No automatic rollback was attempted.\n",
        ),
    ],
)
def test_explicit_renew_preserves_safety_messages(
    monkeypatch, capsys, exception, expected_error
):
    config = make_config()
    config["csr"] = make_csr_settings()
    config["opnsense"] = make_opnsense_settings()
    config["verification"] = {"ca_file": "public-ca.pem"}
    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_renewer.py",
            "--switch",
            "EXAMPLE-SWITCH",
            "--renew",
        ],
    )
    monkeypatch.setattr(checker, "load_config", lambda config_file: config)
    monkeypatch.setattr(
        checker,
        "get_verification_ca_file",
        lambda config, config_file: Path("public-ca.pem"),
    )
    monkeypatch.setattr(
        checker,
        "get_switch_credentials",
        lambda switch, config_file: ("user", "password"),
    )
    monkeypatch.setattr(
        checker,
        "renew_certificate",
        lambda *args: (_ for _ in ()).throw(exception),
    )

    assert checker.main() == checker.EXIT_ERROR
    assert capsys.readouterr().err == expected_error


@pytest.mark.parametrize(
    ("statuses", "renewed_names", "exit_code", "summary_counts"),
    [
        ({"SWITCH-A": "ok", "SWITCH-B": "ok"}, [], checker.EXIT_OK, (2, 0, 0)),
        (
            {"SWITCH-A": "ok", "SWITCH-B": "renewal_due"},
            ["SWITCH-B"],
            checker.EXIT_OK,
            (1, 1, 0),
        ),
        (
            {"SWITCH-A": "renewal_due", "SWITCH-B": "ok"},
            ["SWITCH-A"],
            checker.EXIT_OK,
            (1, 1, 0),
        ),
        (
            {"SWITCH-A": "renewal_due", "SWITCH-B": "expired"},
            ["SWITCH-A", "SWITCH-B"],
            checker.EXIT_OK,
            (0, 2, 0),
        ),
        (
            {"SWITCH-A": "error", "SWITCH-B": "ok"},
            [],
            checker.EXIT_ERROR,
            (1, 0, 1),
        ),
    ],
)
def test_renew_due_orchestrates_and_summarizes_switches(
    monkeypatch,
    capsys,
    statuses,
    renewed_names,
    exit_code,
    summary_counts,
):
    switches = make_multi_switch_config()["switches"]
    credentials_calls = []
    check_calls = []
    renewal_calls = []

    def credentials(switch, config_file):
        credentials_calls.append(switch["name"])
        return f"user-{switch['name']}", f"password-{switch['name']}"

    def check(switch, username, password, warning_days):
        check_calls.append(switch["name"])
        assert username == f"user-{switch['name']}"
        assert password == f"password-{switch['name']}"
        assert warning_days == 30
        return statuses[switch["name"]]

    def renew(switch, username, password, *settings):
        renewal_calls.append(switch["name"])
        assert username == f"user-{switch['name']}"
        assert password == f"password-{switch['name']}"

    monkeypatch.setattr(checker, "get_switch_credentials", credentials)
    monkeypatch.setattr(checker, "check_switch", check)
    monkeypatch.setattr(checker, "renew_certificate", renew)

    result = checker.renew_due_certificates(
        switches,
        Path("config.toml"),
        30,
        make_csr_settings(),
        make_opnsense_settings(),
        Path("public-ca.pem"),
    )

    assert result == exit_code
    assert credentials_calls == ["SWITCH-A", "SWITCH-B"]
    assert check_calls == ["SWITCH-A", "SWITCH-B"]
    assert renewal_calls == renewed_names
    healthy, renewed, errors = summary_counts
    output = capsys.readouterr().out
    assert "Renewal summary" in output
    assert "Switches processed: 2" in output
    assert f"Healthy:             {healthy}" in output
    assert f"Renewed:             {renewed}" in output
    assert f"Errors:              {errors}" in output


def test_renew_due_credential_failure_does_not_stop_later_switch(monkeypatch, capsys):
    switches = make_multi_switch_config()["switches"]
    checked = []
    renewed = []

    def credentials(switch, config_file):
        if switch["name"] == "SWITCH-A":
            raise ValueError("missing password file")
        return "user-b", "password-b"

    monkeypatch.setattr(checker, "get_switch_credentials", credentials)
    monkeypatch.setattr(
        checker,
        "check_switch",
        lambda switch, *args: checked.append(switch["name"]) or "renewal_due",
    )
    monkeypatch.setattr(
        checker,
        "renew_certificate",
        lambda switch, *args: renewed.append(switch["name"]),
    )

    result = checker.renew_due_certificates(
        switches,
        Path("config.toml"),
        30,
        make_csr_settings(),
        make_opnsense_settings(),
        Path("public-ca.pem"),
    )

    assert result == checker.EXIT_ERROR
    assert checked == ["SWITCH-B"]
    assert renewed == ["SWITCH-B"]
    output = capsys.readouterr().out
    assert "Switches processed: 2" in output
    assert "Renewed:             1" in output
    assert "Errors:              1" in output


def test_renew_due_unexpected_credential_failure_is_sanitized_and_isolated(
    monkeypatch, capsys
):
    switches = make_multi_switch_config()["switches"]
    checked = []

    def credentials(switch, config_file):
        if switch["name"] == "SWITCH-A":
            raise EOFError("synthetic input failure")
        return "user-b", "password-b"

    monkeypatch.setattr(checker, "get_switch_credentials", credentials)
    monkeypatch.setattr(
        checker,
        "check_switch",
        lambda switch, *args: checked.append(switch["name"]) or "ok",
    )
    monkeypatch.setattr(
        checker,
        "renew_certificate",
        lambda *args: pytest.fail("A healthy switch must not be renewed"),
    )

    result = checker.renew_due_certificates(
        switches,
        Path("config.toml"),
        30,
        make_csr_settings(),
        make_opnsense_settings(),
        Path("public-ca.pem"),
    )

    assert result == checker.EXIT_ERROR
    assert checked == ["SWITCH-B"]
    captured = capsys.readouterr()
    assert "Unexpected credential resolution failure" in captured.out
    assert "Action:           No renewal attempted" in captured.out
    assert "synthetic input failure" not in captured.out + captured.err
    assert "Renewal summary" in captured.out
    assert "Healthy:             1" in captured.out
    assert "Errors:              1" in captured.out


def test_renew_due_credential_keyboard_interrupt_propagates(monkeypatch):
    switches = make_multi_switch_config()["switches"]
    monkeypatch.setattr(
        checker,
        "get_switch_credentials",
        lambda *args: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    monkeypatch.setattr(
        checker,
        "check_switch",
        lambda *args: pytest.fail("No check should follow interrupted credentials"),
    )

    with pytest.raises(KeyboardInterrupt):
        checker.renew_due_certificates(
            switches,
            Path("config.toml"),
            30,
            make_csr_settings(),
            make_opnsense_settings(),
            Path("public-ca.pem"),
        )


@pytest.mark.parametrize(
    ("exception", "message"),
    [
        (checker.RenewalPreflightError("pending CSR"), "no renewal change"),
        (
            checker.CSRGenerationPreAttemptError("invalid settings"),
            "before CSR creation was attempted",
        ),
        (
            checker.CSRGenerationError("pending CSR may remain"),
            "pending CSR may remain",
        ),
        (checker.CSRSigningError("signing failed"), "CSR signing failed"),
        (
            checker.CertificatePreInstallationError("validation failed"),
            "installation did not begin",
        ),
        (
            checker.CertificateInstallationAttemptError("channel failed"),
            "inspect the switch manually",
        ),
        (
            checker.LiveHTTPSVerificationError("timed out"),
            "may already be active",
        ),
    ],
)
def test_renew_due_failure_class_continues_without_retry(
    monkeypatch, capsys, exception, message
):
    switches = make_multi_switch_config()["switches"]
    renewal_calls = []

    monkeypatch.setattr(
        checker, "get_switch_credentials", lambda switch, config_file: ("user", "pass")
    )
    monkeypatch.setattr(checker, "check_switch", lambda *args: "renewal_due")

    def renew(switch, *args):
        renewal_calls.append(switch["name"])
        if switch["name"] == "SWITCH-A":
            raise exception

    monkeypatch.setattr(checker, "renew_certificate", renew)

    result = checker.renew_due_certificates(
        switches,
        Path("config.toml"),
        30,
        make_csr_settings(),
        make_opnsense_settings(),
        Path("public-ca.pem"),
    )

    assert result == checker.EXIT_ERROR
    assert renewal_calls == ["SWITCH-A", "SWITCH-B"]
    captured = capsys.readouterr()
    assert message in captured.err
    assert "Renewed:             1" in captured.out
    assert "Errors:              1" in captured.out


def test_renew_due_unexpected_renewal_failure_is_sanitized_and_isolated(
    monkeypatch, capsys
):
    switches = make_multi_switch_config()["switches"]
    renewal_calls = []

    monkeypatch.setattr(
        checker, "get_switch_credentials", lambda switch, config_file: ("user", "pass")
    )
    monkeypatch.setattr(checker, "check_switch", lambda *args: "renewal_due")

    def renew(switch, *args):
        renewal_calls.append(switch["name"])
        if switch["name"] == "SWITCH-A":
            raise RuntimeError("synthetic unexpected failure")

    monkeypatch.setattr(checker, "renew_certificate", renew)

    result = checker.renew_due_certificates(
        switches,
        Path("config.toml"),
        30,
        make_csr_settings(),
        make_opnsense_settings(),
        Path("public-ca.pem"),
    )

    assert result == checker.EXIT_ERROR
    assert renewal_calls == ["SWITCH-A", "SWITCH-B"]
    captured = capsys.readouterr()
    combined_output = captured.out + captured.err
    assert "Unexpected renewal failure (RuntimeError)" in captured.err
    assert "Renewal state may be uncertain" in captured.err
    assert "No automatic retry, cleanup, or rollback was attempted" in captured.err
    assert "synthetic unexpected failure" not in combined_output
    assert "no pending CSR was created" not in combined_output
    assert "no renewal change was attempted" not in combined_output
    assert "installation did not begin" not in combined_output
    assert "Renewal summary" in captured.out
    assert "Renewed:             1" in captured.out
    assert "Errors:              1" in captured.out


def test_renew_due_renewal_keyboard_interrupt_propagates(monkeypatch):
    switches = make_multi_switch_config()["switches"]
    monkeypatch.setattr(
        checker, "get_switch_credentials", lambda switch, config_file: ("user", "pass")
    )
    monkeypatch.setattr(checker, "check_switch", lambda *args: "renewal_due")
    monkeypatch.setattr(
        checker,
        "renew_certificate",
        lambda *args: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    with pytest.raises(KeyboardInterrupt):
        checker.renew_due_certificates(
            switches,
            Path("config.toml"),
            30,
            make_csr_settings(),
            make_opnsense_settings(),
            Path("public-ca.pem"),
        )


def test_renew_due_monitor_exception_does_not_stop_later_switch(monkeypatch):
    switches = make_multi_switch_config()["switches"]
    renewed = []

    monkeypatch.setattr(
        checker, "get_switch_credentials", lambda switch, config_file: ("user", "pass")
    )

    def check(switch, *args):
        if switch["name"] == "SWITCH-A":
            raise OSError("SSH channel failed")
        return "renewal_due"

    monkeypatch.setattr(checker, "check_switch", check)
    monkeypatch.setattr(
        checker,
        "renew_certificate",
        lambda switch, *args: renewed.append(switch["name"]),
    )

    assert (
        checker.renew_due_certificates(
            switches,
            Path("config.toml"),
            30,
            make_csr_settings(),
            make_opnsense_settings(),
            Path("public-ca.pem"),
        )
        == checker.EXIT_ERROR
    )
    assert renewed == ["SWITCH-B"]


@pytest.mark.parametrize(
    ("missing_section", "message"),
    [
        ("csr", r"\[csr\]"),
        ("opnsense", r"\[opnsense\]"),
        ("verification", r"\[verification\]"),
    ],
)
def test_renew_due_validates_renewal_config_before_credentials(
    monkeypatch, capsys, missing_section, message
):
    config = make_multi_switch_config()
    del config[missing_section]
    monkeypatch.setattr(checker.sys, "argv", ["aruba_cert_renewer.py", "--renew-due"])
    monkeypatch.setattr(checker, "load_config", lambda config_file: config)
    monkeypatch.setattr(
        checker,
        "get_switch_credentials",
        lambda *args: pytest.fail("Credentials should not be requested"),
    )

    assert checker.main() == checker.EXIT_ERROR
    assert re.search(message, capsys.readouterr().err)


def test_renew_due_selected_switch_fails_before_credentials(monkeypatch):
    monkeypatch.setattr(
        checker.sys,
        "argv",
        ["aruba_cert_renewer.py", "--renew-due", "--switch", "UNKNOWN"],
    )
    monkeypatch.setattr(
        checker, "load_config", lambda config_file: make_multi_switch_config()
    )
    monkeypatch.setattr(
        checker,
        "get_switch_credentials",
        lambda *args: pytest.fail("Credentials should not be requested"),
    )

    assert checker.main() == checker.EXIT_ERROR


@pytest.mark.parametrize(
    ("switch_args", "expected_switch"),
    [
        ([], ["SWITCH-A", "SWITCH-B"]),
        (["--switch", "SWITCH-B"], ["SWITCH-B"]),
    ],
)
def test_renew_due_main_healthy_run_uses_selection_without_opnsense_contact(
    monkeypatch, capsys, switch_args, expected_switch
):
    for variable in (
        "OPNSENSE_API_KEY",
        "OPNSENSE_API_SECRET",
        "OPNSENSE_API_KEY_FILE",
        "OPNSENSE_API_SECRET_FILE",
    ):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(
        checker.sys,
        "argv",
        ["aruba_cert_renewer.py", "--renew-due", *switch_args],
    )
    monkeypatch.setattr(
        checker, "load_config", lambda config_file: make_multi_switch_config()
    )
    monkeypatch.setattr(
        checker,
        "get_verification_ca_file",
        lambda config, config_file: Path("public-ca.pem"),
    )
    monkeypatch.setattr(
        checker,
        "get_switch_credentials",
        lambda switch, config_file: ("user", "password"),
    )
    checked = []
    monkeypatch.setattr(
        checker,
        "check_switch",
        lambda switch, *args: checked.append(switch["name"]) or "ok",
    )
    monkeypatch.setattr(
        checker,
        "renew_certificate",
        lambda *args: pytest.fail("Healthy certificates must not be renewed"),
    )
    monkeypatch.setattr(
        checker,
        "OPNsenseClient",
        lambda *args, **kwargs: pytest.fail("Healthy run must not contact OPNsense"),
    )

    assert checker.main() == checker.EXIT_OK
    assert checked == expected_switch
    assert f"Switches processed: {len(expected_switch)}" in capsys.readouterr().out
