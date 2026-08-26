import base64
import ipaddress
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import (
    ExtendedKeyUsageOID,
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
            "aruba_cert_renewer.py",
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

    def unexpected_credentials_request():
        pytest.fail("Credentials should not be requested")

    monkeypatch.setattr(checker, "get_credentials", unexpected_credentials_request)

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
        "get_credentials",
        lambda: calls.append("credentials"),
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
host = "192.0.2.10"
fqdn = "switch.example.com"
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
    monkeypatch.setattr(checker.sys, "argv", argv)
    monkeypatch.setattr(checker, "get_credentials", lambda: ("username", "password"))
    monkeypatch.setattr(checker, "generate_csr", lambda *args, **kwargs: csr_pem)

    assert checker.main() == checker.EXIT_OK
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
host = "192.0.2.10"
fqdn = "switch.example.com"
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
    monkeypatch.setattr(checker, "get_credentials", lambda: ("username", "password"))
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
        "get_credentials",
        lambda: calls.append("credentials"),
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
host = "192.0.2.10"
fqdn = "switch.example.com"
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

    def unexpected_credentials_request():
        pytest.fail("Credentials should not be requested")

    monkeypatch.setattr(checker, "get_credentials", unexpected_credentials_request)

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
    ):
        self.csr_pem = csr_pem
        self.summary_output = summary_output
        self.generation_error = generation_error
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

    def send_command_timing(self, command, **kwargs):
        self.commands.append(command)
        self.timing_kwargs = kwargs

        if self.generation_error:
            raise self.generation_error

        return "Generating RSA key and certificate request"

    def exit_config_mode(self):
        self.exited_config_mode = True


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
    "fqdn",
    [
        "switch.example.com; reload",
        "switch.example.com\nreload",
        'bad"fqdn',
        "bad_fqdn.example.com",
        "-switch.example.com",
    ],
)
def test_build_csr_command_rejects_unsafe_fqdn(fqdn):
    switch = make_config()["switches"][0]
    switch["fqdn"] = fqdn

    with pytest.raises(ValueError, match="switch FQDN"):
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


def test_generate_csr_exits_config_mode_when_generation_raises(monkeypatch):
    connection = FakeCSRConnection(
        make_test_csr(),
        generation_error=RuntimeError("generation failed"),
    )
    monkeypatch.setattr(checker, "ConnectHandler", lambda **kwargs: connection)

    with pytest.raises(RuntimeError, match="generation failed"):
        checker.generate_csr(
            make_config()["switches"][0],
            "username",
            "password",
            "webcert2027",
            make_csr_settings(),
        )

    assert connection.exited_config_mode


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
            x509.NameAttribute(NameOID.COMMON_NAME, "switch.example.com"),
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

    builder = (
        x509.CertificateBuilder()
        .subject_name(certificate_subject)
        .issuer_name(certificate_subject)
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

    certificate = builder.sign(certificate_key, signature_hash)
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


def test_validate_switch_signing_identity_requires_ipv4():
    switch = make_config()["switches"][0]
    switch["host"] = "switch-management.example.com"

    with pytest.raises(ValueError, match="management IPv4"):
        checker.validate_switch_signing_identity(switch)


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
        "get_credentials",
        lambda: pytest.fail("Credentials should not be requested"),
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
    assert sign_call[2]["dns_name"] == "switch.example.com"
    assert sign_call[2]["ip_address"] == "192.0.2.10"


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
host = "192.0.2.10"
fqdn = "switch.example.com"
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
    monkeypatch.setattr(checker, "get_credentials", lambda: ("username", "password"))
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
    monkeypatch.setattr(checker, "get_credentials", lambda: ("username", "password"))
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
        "get_credentials",
        lambda: pytest.fail("Credentials should not be requested"),
    )

    assert checker.main() == checker.EXIT_ERROR
    assert output_file.read_text(encoding="ascii") == "existing certificate"
