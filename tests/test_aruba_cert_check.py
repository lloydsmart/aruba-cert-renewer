from datetime import date, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

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


def make_test_csr(common_name="switch.example.com"):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                "Example Organization",
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME,
                "Infrastructure",
            ),
            x509.NameAttribute(
                NameOID.LOCALITY_NAME,
                "Example City",
            ),
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME,
                "Example State",
            ),
            x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                "GB",
            ),
        ]
    )

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(
            key,
            hashes.SHA256(),
        )
    )

    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def test_get_csr_settings():
    config = make_config()
    config["csr"] = make_csr_settings()

    assert checker.get_csr_settings(config) == make_csr_settings()


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

    assert csr.is_signature_valid
    assert csr.public_key().key_size == 2048


def test_validate_csr_pem_rejects_wrong_common_name():
    switch = make_config()["switches"][0]

    with pytest.raises(ValueError, match="common name"):
        checker.validate_csr_pem(
            make_test_csr(common_name="wrong.example.com"),
            switch,
            make_csr_settings(),
        )
