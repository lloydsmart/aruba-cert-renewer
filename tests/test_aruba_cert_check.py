from datetime import date, timedelta

import pytest

import aruba_cert_check as checker


def make_config():
    return {
        "settings": {
            "warning_days": 30,
        },
        "switches": [
            {
                "name": "EXAMPLE-SWITCH",
                "host": "192.0.2.10",
                "fqdn": "switch.example.com",
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
    del config["switches"][0]["fqdn"]

    with pytest.raises(ValueError, match="fqdn"):
        checker.validate_config(config)


def test_validate_config_rejects_duplicate_switch_names():
    config = make_config()
    config["switches"].append(
        {
            "name": "example-switch",
            "host": "192.0.2.11",
            "fqdn": "switch2.example.com",
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
host = "192.0.2.10"
fqdn = "switch.example.com"
""".strip(),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        checker.sys,
        "argv",
        [
            "aruba_cert_check.py",
            "--config",
            str(config_file),
            "--switch",
            "DOES-NOT-EXIST",
        ],
    )

    def unexpected_credentials_request():
        pytest.fail("Credentials should not be requested")

    monkeypatch.setattr(
        checker,
        "get_credentials",
        unexpected_credentials_request,
    )

    assert checker.main() == checker.EXIT_ERROR
