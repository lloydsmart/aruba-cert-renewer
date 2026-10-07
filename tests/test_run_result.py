"""Structured CLI results use synthetic switches and no network access."""

import json
import logging
import re
from contextlib import contextmanager
from datetime import UTC, datetime
from io import BytesIO
from types import SimpleNamespace
from urllib.error import URLError
from uuid import UUID

import pytest

import aruba_cert_renewer as checker
import opnsense_client
from run_result import (
    Change,
    Milestone,
    Outcome,
    Reason,
    RunResult,
    Stage,
    SwitchResult,
)

REAL_GET_SWITCH_CREDENTIALS = checker.get_switch_credentials


@pytest.fixture
def json_environment(monkeypatch):
    switches = [
        {"name": "SWITCH-A", "host": "192.0.2.1"},
        {"name": "SWITCH-B", "host": "192.0.2.2"},
    ]
    monkeypatch.setattr(checker, "load_config", lambda path: {})
    monkeypatch.setattr(checker, "validate_config", lambda config, path: (30, switches))
    monkeypatch.setattr(checker, "get_csr_settings", lambda config: {})
    monkeypatch.setattr(
        checker,
        "get_opnsense_settings",
        lambda config: {"lifetime_days": 90, "digest": "sha256"},
    )
    monkeypatch.setattr(
        checker, "validate_switch_signing_identity", lambda switch: None
    )
    monkeypatch.setattr(checker, "get_verification_ca_file", lambda *args: object())
    monkeypatch.setattr(
        checker,
        "get_switch_credentials",
        lambda *args, **kwargs: ("synthetic", "synthetic"),
    )

    @contextmanager
    def unlocked(host):
        yield

    monkeypatch.setattr(checker, "lifecycle_lock", unlocked)
    return switches


def invoke(monkeypatch, capsys, *args):
    monkeypatch.setattr(
        checker.sys, "argv", ["aruba_cert_renewer.py", "--output", "json", *args]
    )
    code = checker.main()
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.endswith("\n")
    assert not captured.out.endswith("\n\n")
    decoder = json.JSONDecoder()
    result, end = decoder.raw_decode(captured.out)
    assert captured.out[end:] == "\n"
    assert result["schema_version"] == 1
    assert result["product"] == "aruba"
    assert UUID(result["attempt_id"]).version == 4
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", result["started_at"])
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", result["finished_at"])
    assert set(result) == {
        "schema_version",
        "product",
        "operation",
        "attempt_id",
        "started_at",
        "finished_at",
        "outcome",
        "stage",
        "manual_recovery_required",
        "reason_code",
        "message",
        "results",
    }
    for item in result["results"]:
        assert set(item) == {
            "target",
            "outcome",
            "stage",
            "renewal_due",
            "change",
            "manual_recovery_required",
            "reason_code",
            "message",
            "certificate",
            "milestones",
        }
        assert set(item["milestones"]) == {
            "csr",
            "issuance",
            "installation",
            "activation",
            "live_tls",
        }
        assert item["outcome"] in {value.value for value in Outcome}
        assert item["stage"] in {value.value for value in Stage}
        assert item["change"] in {value.value for value in Change}
        assert item["reason_code"] is None or item["reason_code"] in {
            value.value for value in Reason
        }
        assert set(item["milestones"].values()) <= {value.value for value in Milestone}
        mutation = item["milestones"]
        uncertain = any(
            mutation[name] == "uncertain"
            for name in ("csr", "issuance", "installation")
        )
        new_change_confirmed = item["change"] == "confirmed" or any(
            mutation[name] == "confirmed"
            for name in ("issuance", "installation", "activation")
        )
        if item["outcome"] == "failure_ambiguous":
            assert uncertain or item["change"] == "possible"
        elif item["outcome"] == "failure_partial":
            assert new_change_confirmed
        elif item["outcome"] == "failure_pre_attempt":
            assert not uncertain
            assert item["change"] == "none"
        if item["change"] == "confirmed":
            assert any(
                mutation[name] == "confirmed"
                for name in ("csr", "issuance", "installation", "activation")
            )
    for marker in (
        "-----BEGIN CERTIFICATE-----",
        "-----BEGIN CERTIFICATE REQUEST-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    ):
        assert marker not in captured.out
    return code, result, captured.out


def test_json_noop_and_attention(monkeypatch, capsys, json_environment):
    monkeypatch.setattr(checker, "check_switch", lambda *args: "ok")
    monkeypatch.setattr(
        checker, "renew_certificate", lambda *args, **kwargs: pytest.fail("No renewal")
    )
    monkeypatch.setattr(
        checker, "OPNsenseClient", lambda *args: pytest.fail("No signing")
    )
    code, result, _ = invoke(monkeypatch, capsys, "--renew-due")
    assert code == 0
    assert result["outcome"] == "success_no_change"
    assert all(item["renewal_due"] is False for item in result["results"])
    assert all(item["change"] == "none" for item in result["results"])
    assert all(
        set(item["milestones"].values()) == {"not_attempted"}
        for item in result["results"]
    )

    monkeypatch.setattr(
        checker,
        "check_switch",
        lambda switch, *args: "renewal_due" if switch["name"] == "SWITCH-B" else "ok",
    )
    code, result, _ = invoke(monkeypatch, capsys)
    assert code == 1
    assert result["outcome"] == "attention_due"
    assert result["results"][1]["renewal_due"] is True


@pytest.mark.parametrize(
    ("failure", "outcome", "stage", "milestone", "change", "recovery"),
    [
        (
            checker.PendingCSRPreflightError("secret"),
            "failure_pre_attempt",
            "preflight",
            "not_attempted",
            "none",
            True,
        ),
        (
            checker.CSRGenerationPreAttemptError("secret"),
            "failure_pre_attempt",
            "csr_generation",
            "not_attempted",
            "none",
            False,
        ),
        (
            checker.CSRGenerationError("secret"),
            "failure_ambiguous",
            "csr_generation",
            "uncertain",
            "possible",
            True,
        ),
        (
            checker.CSRSigningError("secret"),
            "failure_partial",
            "signing",
            "confirmed",
            "confirmed",
            True,
        ),
        (
            checker.CertificatePreInstallationError("secret"),
            "failure_partial",
            "installation",
            "confirmed",
            "confirmed",
            True,
        ),
        (
            checker.CertificateInstallationAttemptError("secret"),
            "failure_ambiguous",
            "installation",
            "confirmed",
            "possible",
            True,
        ),
        (
            checker.LiveHTTPSVerificationError("secret"),
            "failure_partial",
            "live_verification",
            "confirmed",
            "confirmed",
            True,
        ),
    ],
)
def test_renewal_failure_mapping(
    monkeypatch,
    capsys,
    json_environment,
    failure,
    outcome,
    stage,
    milestone,
    change,
    recovery,
):
    def fail(*args, **kwargs):
        progress = kwargs["progress"]
        if isinstance(failure, checker.CSRSigningError):
            progress("csr_confirmed")
            progress("signing_preparation")
        elif isinstance(
            failure,
            (
                checker.CertificatePreInstallationError,
                checker.CertificateInstallationAttemptError,
                checker.LiveHTTPSVerificationError,
            ),
        ):
            progress("csr_confirmed")
            progress("issuance_confirmed")
        if isinstance(failure, checker.LiveHTTPSVerificationError):
            certificate = SimpleNamespace(
                fingerprint=lambda algorithm: bytes(32),
                not_valid_after_utc=datetime(2027, 1, 1, tzinfo=UTC),
            )
            progress("installation_confirmed", certificate)
        raise failure

    monkeypatch.setattr(checker, "renew_certificate", fail)
    code, result, output = invoke(
        monkeypatch, capsys, "--renew", "--switch", "SWITCH-A"
    )
    item = result["results"][0]
    assert code == 2
    assert (item["outcome"], item["stage"], item["change"]) == (outcome, stage, change)
    assert item["milestones"]["csr"] == milestone
    assert item["manual_recovery_required"] is recovery
    if isinstance(failure, checker.LiveHTTPSVerificationError):
        assert item["milestones"]["installation"] == "confirmed"
        assert item["milestones"]["activation"] == "confirmed"
        assert item["milestones"]["live_tls"] == "failed"
        assert item["certificate"]["expiry_date"] == "2027-01-01"
    assert "secret" not in output


def test_signing_dispatch_is_uncertain(monkeypatch, capsys, json_environment):
    def fail(*args, **kwargs):
        kwargs["progress"]("csr_confirmed")
        kwargs["progress"]("issuance_dispatched")
        raise checker.CSRSigningError("API\nsecret\x1b[31m")

    monkeypatch.setattr(checker, "renew_certificate", fail)
    code, result, output = invoke(
        monkeypatch, capsys, "--renew", "--switch", "SWITCH-A"
    )
    assert code == 2
    assert result["outcome"] == "failure_ambiguous"
    assert result["results"][0]["milestones"]["issuance"] == "uncertain"
    assert "secret" not in output


def test_validated_issuance_failure_keeps_stage(monkeypatch, capsys, json_environment):
    def fail(*args, **kwargs):
        progress = kwargs["progress"]
        progress("csr_confirmed")
        progress("issuance_dispatched")
        progress("issuance_confirmed")
        progress("certificate_retrieved")
        raise checker.CSRSigningError("untrusted certificate text")

    monkeypatch.setattr(checker, "renew_certificate", fail)
    code, result, output = invoke(
        monkeypatch, capsys, "--renew", "--switch", "SWITCH-A"
    )
    assert code == 2
    assert result["outcome"] == "failure_partial"
    assert result["stage"] == "issued_validation"
    assert result["reason_code"] == "validation_failed"
    assert result["results"][0]["milestones"]["issuance"] == "confirmed"
    assert "untrusted certificate text" not in output


def test_json_success_tracks_confirmed_install_and_live_tls(
    monkeypatch, capsys, json_environment
):
    certificate = SimpleNamespace(
        fingerprint=lambda algorithm: bytes.fromhex("ab" * 32),
        not_valid_after_utc=datetime(2027, 1, 5, tzinfo=UTC),
    )

    def renew(*args, **kwargs):
        for event in (
            "csr_confirmed",
            "issuance_dispatched",
            "issuance_confirmed",
            "certificate_retrieved",
            "issued_validated",
        ):
            kwargs["progress"](event)
        kwargs["progress"]("installation_confirmed", certificate)
        kwargs["progress"]("live_tls_confirmed")
        return "webcert2027"

    monkeypatch.setattr(checker, "renew_certificate", renew)
    code, result, _ = invoke(monkeypatch, capsys, "--renew", "--switch", "SWITCH-A")
    assert code == 0
    assert result["outcome"] == "success_changed"
    assert result["stage"] == "completed"
    assert result["manual_recovery_required"] is False
    item = result["results"][0]
    assert set(item["milestones"].values()) == {"confirmed"}
    assert item["certificate"] == {
        "fingerprint_sha256": "ab" * 32,
        "expiry_date": "2027-01-05",
    }


def test_signed_certificate_file_failure_keeps_confirmed_issuance(
    monkeypatch, capsys, tmp_path, json_environment
):
    def sign(*args, **kwargs):
        for event in (
            "csr_retrieved",
            "issuance_dispatched",
            "issuance_confirmed",
            "issued_validated",
        ):
            kwargs["progress"](event)
        return "synthetic validated certificate"

    certificate = SimpleNamespace(
        fingerprint=lambda algorithm: bytes(32),
        not_valid_after_utc=datetime(2027, 1, 5, tzinfo=UTC),
    )
    monkeypatch.setattr(checker, "sign_pending_csr", sign)
    monkeypatch.setattr(
        checker.x509, "load_pem_x509_certificate", lambda data: certificate
    )
    monkeypatch.setattr(
        checker,
        "write_certificate",
        lambda *args: (_ for _ in ()).throw(OSError("secret")),
    )
    code, result, output = invoke(
        monkeypatch,
        capsys,
        "--sign-csr",
        "--switch",
        "SWITCH-A",
        "--certificate-name",
        "webcert2027",
        "--certificate-output",
        str(tmp_path / "signed.pem"),
    )
    assert code == 2
    assert result["outcome"] == "failure_partial"
    assert result["stage"] == "finalization"
    assert result["reason_code"] == "recovery_required"
    assert result["results"][0]["milestones"]["issuance"] == "confirmed"
    assert result["manual_recovery_required"] is True
    assert "secret" not in output


def test_json_csr_conflict_precedes_contact(monkeypatch, capsys, json_environment):
    monkeypatch.setattr(
        checker, "load_config", lambda *args: pytest.fail("Config read")
    )
    for operation in ("--generate-csr", "--retrieve-csr"):
        code, result, _ = invoke(
            monkeypatch,
            capsys,
            operation,
            "--switch",
            "SWITCH-A",
            "--certificate-name",
            "webcert2027",
        )
        assert code == 2
        assert result["results"] == []
        assert result["reason_code"] == "config_invalid"


@pytest.mark.parametrize("missing", ["username", "password"])
def test_json_missing_switch_credentials_never_prompt_or_connect(
    monkeypatch, capsys, json_environment, missing
):
    switch = json_environment[0]
    if missing == "password":
        switch["username"] = "synthetic-user"
    monkeypatch.setattr(checker, "get_switch_credentials", REAL_GET_SWITCH_CREDENTIALS)
    monkeypatch.delenv("ARUBA_SSH_USERNAME", raising=False)
    monkeypatch.delenv("ARUBA_SSH_PASSWORD", raising=False)
    monkeypatch.setattr("builtins.input", lambda *args: pytest.fail("input called"))
    monkeypatch.setattr(
        checker.getpass, "getpass", lambda *args: pytest.fail("getpass called")
    )
    monkeypatch.setattr(checker, "check_switch", lambda *args: pytest.fail("network"))

    code, result, _ = invoke(monkeypatch, capsys, "--switch", "SWITCH-A")
    item = result["results"][0]
    assert code == 2
    assert item["stage"] == "configuration"
    assert item["outcome"] == "failure_pre_attempt"
    assert item["reason_code"] == "config_invalid"
    assert item["change"] == "none"
    assert item["manual_recovery_required"] is False


@pytest.mark.parametrize("source", ["file", "environment"])
def test_json_accepts_noninteractive_switch_credentials(
    monkeypatch, capsys, tmp_path, json_environment, source
):
    switch = json_environment[0]
    monkeypatch.setattr(checker, "get_switch_credentials", REAL_GET_SWITCH_CREDENTIALS)
    monkeypatch.delenv("ARUBA_SSH_USERNAME", raising=False)
    monkeypatch.delenv("ARUBA_SSH_PASSWORD", raising=False)
    monkeypatch.setattr("builtins.input", lambda *args: pytest.fail("input called"))
    monkeypatch.setattr(
        checker.getpass, "getpass", lambda *args: pytest.fail("getpass called")
    )
    if source == "file":
        secret = tmp_path / "switch.secret"
        secret.write_text("synthetic-file-password\n")
        secret.chmod(0o600)
        switch.update(username="synthetic-file-user", password_file=str(secret))
        expected = ("synthetic-file-user", "synthetic-file-password")
    else:
        monkeypatch.setenv("ARUBA_SSH_USERNAME", "synthetic-env-user")
        monkeypatch.setenv("ARUBA_SSH_PASSWORD", "synthetic-env-password")
        expected = ("synthetic-env-user", "synthetic-env-password")

    def check_switch(switch, username, password, warning_days):
        assert (username, password) == expected
        return "ok"

    monkeypatch.setattr(checker, "check_switch", check_switch)
    code, result, output = invoke(monkeypatch, capsys, "--switch", "SWITCH-A")
    assert code == 0
    assert result["results"][0]["outcome"] == "success_no_change"
    assert all(value not in output for value in expected)


def test_json_missing_credentials_only_fail_affected_switch(
    monkeypatch, capsys, tmp_path, json_environment
):
    secret = tmp_path / "switch.secret"
    secret.write_text("synthetic-password\n")
    secret.chmod(0o600)
    json_environment[1].update(username="synthetic-user", password_file=str(secret))
    monkeypatch.setattr(checker, "get_switch_credentials", REAL_GET_SWITCH_CREDENTIALS)
    monkeypatch.delenv("ARUBA_SSH_USERNAME", raising=False)
    monkeypatch.delenv("ARUBA_SSH_PASSWORD", raising=False)
    monkeypatch.setattr("builtins.input", lambda *args: pytest.fail("input called"))
    monkeypatch.setattr(
        checker.getpass, "getpass", lambda *args: pytest.fail("getpass called")
    )
    checked = []

    def check_switch(switch, username, password, warning_days):
        checked.append(switch["name"])
        return "ok"

    monkeypatch.setattr(checker, "check_switch", check_switch)
    code, result, _ = invoke(monkeypatch, capsys)
    assert code == 2
    assert checked == ["SWITCH-B"]
    assert [item["outcome"] for item in result["results"]] == [
        "failure_pre_attempt",
        "success_no_change",
    ]


def test_json_csr_file_and_output_purity(
    monkeypatch, capsys, tmp_path, json_environment
):
    monkeypatch.setattr(
        checker,
        "generate_csr",
        lambda *args: "-----BEGIN CERTIFICATE REQUEST-----\nPUBLIC\n",
    )
    path = tmp_path / "csr.pem"
    code, result, output = invoke(
        monkeypatch,
        capsys,
        "--generate-csr",
        "--switch",
        "SWITCH-A",
        "--certificate-name",
        "webcert2027",
        "--csr-output",
        str(path),
    )
    assert code == 0
    assert result["outcome"] == "success_prepared"
    assert path.read_text() == "-----BEGIN CERTIFICATE REQUEST-----\nPUBLIC\n"
    assert "PUBLIC" not in output


def test_json_retrieved_csr_uses_only_requested_file(
    monkeypatch, capsys, tmp_path, json_environment
):
    csr = "-----BEGIN CERTIFICATE REQUEST-----\nPUBLIC\n"
    monkeypatch.setattr(checker, "retrieve_csr", lambda *args, **kwargs: csr)
    path = tmp_path / "retrieved.pem"
    code, result, output = invoke(
        monkeypatch,
        capsys,
        "--retrieve-csr",
        "--switch",
        "SWITCH-A",
        "--certificate-name",
        "webcert2027",
        "--csr-output",
        str(path),
    )
    assert code == 0
    assert result["outcome"] == "success_no_change"
    assert result["results"][0]["milestones"]["csr"] == "confirmed"
    assert path.read_text() == csr
    assert "PUBLIC" not in output


@pytest.mark.parametrize(
    ("phase", "expected_csr", "recovery", "expected_code"),
    [
        ("no_pending", "failed", False, 2),
        ("malformed", "failed", True, 2),
        ("read_failure", "failed", True, 2),
        ("success", "confirmed", False, 0),
        ("write_failure", "confirmed", True, 2),
    ],
)
def test_json_retrieve_csr_preserves_pending_evidence(
    monkeypatch,
    capsys,
    tmp_path,
    json_environment,
    phase,
    expected_csr,
    recovery,
    expected_code,
):
    csr = "-----BEGIN CERTIFICATE REQUEST-----\nU1lOVEhFVElD\n-----END CERTIFICATE REQUEST-----\n"
    commands = []

    @contextmanager
    def connection(*args):
        yield object()

    def send_command(connection, command, limit, **kwargs):
        commands.append(command)
        if command == "show crypto pki local-certificate summary":
            expiration = "2028/09/27" if phase == "no_pending" else "CSR"
            return f"webcert2027 Web {expiration} webprofile2026\n"
        if phase == "read_failure":
            raise OSError("synthetic SSH read failure")
        if phase == "malformed":
            return "malformed CSR detail"
        return csr

    monkeypatch.setattr(checker, "validate_csr_settings", lambda settings: settings)
    monkeypatch.setattr(checker, "validate_csr_pem", lambda *args: object())
    monkeypatch.setattr(checker, "ssh_connection", connection)
    monkeypatch.setattr(checker, "_send_command", send_command)
    monkeypatch.setattr(
        checker, "OPNsenseClient", lambda *args: pytest.fail("signer contacted")
    )
    monkeypatch.setattr(
        checker, "install_pending_certificate", lambda *args: pytest.fail("install")
    )
    output_path = tmp_path / "retrieved.pem"
    if phase == "write_failure":
        original_write = checker.write_or_print_csr

        def output_race(csr_pem, path):
            output_path.write_text("existing")
            return original_write(csr_pem, path)

        monkeypatch.setattr(checker, "write_or_print_csr", output_race)

    code, result, _ = invoke(
        monkeypatch,
        capsys,
        "--retrieve-csr",
        "--switch",
        "SWITCH-A",
        "--certificate-name",
        "webcert2027",
        "--csr-output",
        str(output_path),
    )
    item = result["results"][0]
    assert code == expected_code
    assert item["outcome"] == (
        "success_no_change" if phase == "success" else "failure_pre_attempt"
    )
    assert item["stage"] == ("completed" if phase == "success" else "csr_retrieval")
    assert item["reason_code"] == (None if phase == "success" else "csr_failed")
    assert item["change"] == "none"
    assert item["milestones"]["csr"] == expected_csr
    assert item["milestones"]["issuance"] == "not_attempted"
    assert item["manual_recovery_required"] is recovery
    assert commands == ["show crypto pki local-certificate summary"] + (
        []
        if phase == "no_pending"
        else ["show crypto pki local-certificate webcert2027"]
    )
    if phase == "success":
        assert output_path.read_text() == csr
    elif phase == "write_failure":
        assert output_path.read_text() == "existing"
    else:
        assert not output_path.exists()


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        (None, None, "success_no_change"),
        (None, checker.CSRGenerationPreAttemptError("x"), "failure_pre_attempt"),
        (None, checker.CSRSigningError("x"), "failure_partial"),
        (None, checker.CSRGenerationError("x"), "failure_ambiguous"),
        (
            checker.CSRSigningError("x"),
            checker.CSRGenerationError("x"),
            "failure_ambiguous",
        ),
    ],
)
def test_json_multi_switch_aggregation(
    monkeypatch, capsys, json_environment, first, second, expected
):
    monkeypatch.setattr(
        checker,
        "check_switch",
        lambda switch, *args: (
            "ok"
            if (switch["name"] == "SWITCH-A" and first is None)
            or (switch["name"] == "SWITCH-B" and second is None)
            else "renewal_due"
        ),
    )

    def renew(switch, *args, **kwargs):
        failure = first if switch["name"] == "SWITCH-A" else second
        if isinstance(failure, checker.CSRSigningError):
            kwargs["progress"]("csr_confirmed")
        raise failure

    monkeypatch.setattr(checker, "renew_certificate", renew)
    code, result, _ = invoke(monkeypatch, capsys, "--renew-due")
    assert result["outcome"] == expected
    assert len(result["results"]) == 2
    assert result["manual_recovery_required"] is (
        expected in {"failure_partial", "failure_ambiguous"}
    )
    assert code == (0 if expected == "success_no_change" else 2)


def test_json_lock_busy_and_release_after_change(monkeypatch, capsys, json_environment):
    @contextmanager
    def busy(host):
        raise checker.LifecycleLockBusy("secret\n\x1b")
        yield

    monkeypatch.setattr(checker, "lifecycle_lock", busy)
    monkeypatch.setattr(
        checker, "renew_certificate", lambda *args, **kwargs: pytest.fail("No contact")
    )
    code, result, output = invoke(
        monkeypatch, capsys, "--renew", "--switch", "SWITCH-A"
    )
    assert code == 2
    assert result["outcome"] == "failure_pre_attempt"
    assert result["reason_code"] == "lock_busy"
    assert "secret" not in output

    @contextmanager
    def bad_release(host):
        yield
        raise checker.LifecycleLockReleaseError("secret")

    def completed(*args, **kwargs):
        kwargs["progress"]("csr_confirmed")
        kwargs["progress"]("issuance_confirmed")
        return "webcert2027"

    monkeypatch.setattr(checker, "lifecycle_lock", bad_release)
    monkeypatch.setattr(checker, "renew_certificate", completed)
    code, result, output = invoke(
        monkeypatch, capsys, "--renew", "--switch", "SWITCH-A"
    )
    assert code == 2
    assert result["outcome"] == "failure_partial"
    assert result["stage"] == "lock"
    assert result["manual_recovery_required"] is True
    assert result["results"][0]["milestones"]["issuance"] == "confirmed"
    assert "secret" not in output


def test_aggregate_severity_and_control_escaping():
    run = RunResult(operation="inspect")
    run.results = [
        SwitchResult(target="one", outcome=Outcome.SUCCESS_CHANGED),
        SwitchResult(
            target="two\n\r\t\x1b\x00",
            outcome=Outcome.FAILURE_PARTIAL,
            stage=Stage.LIVE_VERIFICATION,
            manual_recovery_required=True,
        ),
        SwitchResult(
            target="three",
            outcome=Outcome.FAILURE_AMBIGUOUS,
            stage=Stage.INSTALLATION,
            reason_code=Reason.INSTALLATION_FAILED,
        ),
    ]
    run.finish()
    data = json.loads(run.to_json())
    assert data["outcome"] == "failure_ambiguous"
    assert data["stage"] == "installation"
    assert data["manual_recovery_required"] is True
    assert "two\\n\\r\\t\\u001b\\u0000" in run.to_json()


def test_json_debug_does_not_emit_secret(monkeypatch, capsys, caplog, json_environment):
    marker = "API_SENTINEL_7391"

    def fail(*args):
        logging.error("%s\n\r\t\x1b\x01", marker)
        print(marker)
        raise ValueError(marker)

    monkeypatch.setattr(checker, "check_switch", fail)
    code, result, output = invoke(monkeypatch, capsys, "--debug")
    assert code == 2
    assert result["outcome"] == "failure_pre_attempt"
    assert marker not in output
    assert marker not in caplog.text


@pytest.mark.parametrize("source", ["config", "credentials", "ssh", "api"])
def test_json_drops_untrusted_exception_and_secret_text(
    monkeypatch, capsys, caplog, json_environment, source
):
    markers = (
        "API_KEY_SENTINEL_48291",
        "API_SECRET_SENTINEL_15673",
        "SSH_SECRET_SENTINEL_90642",
        "CONFIG_SECRET_SENTINEL_64723",
        "PROTOCOL_SENTINEL_30518",
    )
    for name, marker in zip(
        ("OPNSENSE_API_KEY", "OPNSENSE_API_SECRET", "ARUBA_SSH_PASSWORD"),
        markers,
        strict=False,
    ):
        monkeypatch.setenv(name, marker)

    def poison(*args, **kwargs):
        logging.error("%s\r\n\t\x1b\x00", markers[4])
        print(markers[4])
        try:
            raise RuntimeError(markers[0] + markers[1])
        except RuntimeError as cause:
            raise ValueError("/".join(markers)) from cause

    if source == "config":
        monkeypatch.setattr(checker, "load_config", poison)
        args = ()
    elif source == "credentials":
        monkeypatch.setattr(checker, "get_switch_credentials", poison)
        args = ()
    elif source == "ssh":
        monkeypatch.setattr(checker, "check_switch", poison)
        args = ()
    else:

        def signing_failure(*args, **kwargs):
            kwargs["progress"]("csr_confirmed")
            kwargs["progress"]("issuance_dispatched")
            try:
                poison()
            except ValueError as cause:
                raise checker.CSRSigningError(markers[4]) from cause

        monkeypatch.setattr(checker, "renew_certificate", signing_failure)
        args = ("--renew", "--switch", "SWITCH-A")

    code, result, output = invoke(monkeypatch, capsys, "--debug", *args)
    assert code == 2
    assert result["reason_code"] is not None
    assert not any(marker in output or marker in caplog.text for marker in markers)


def _prepare_real_staged_sign(monkeypatch):
    csr_pem = (
        "-----BEGIN CERTIFICATE REQUEST-----\nQUJD\n-----END CERTIFICATE REQUEST-----\n"
    )
    monkeypatch.setattr(
        checker,
        "validate_switch_signing_identity",
        lambda switch: {
            "common_name": "switch.example.invalid",
            "dns_names": ("switch.example.invalid",),
            "ip_addresses": (),
        },
    )

    def retrieve(*args, **kwargs):
        kwargs["progress"]("pending_csr_observed")
        return csr_pem

    monkeypatch.setattr(checker, "retrieve_csr", retrieve)
    monkeypatch.setattr(
        checker,
        "validate_csr_pem",
        lambda *args: SimpleNamespace(public_bytes=lambda encoding: csr_pem.encode()),
    )
    monkeypatch.setattr(
        opnsense_client.OPNsenseClient,
        "resolve_ca",
        lambda self, description: "123456789abcd",
    )
    monkeypatch.setenv("OPNSENSE_API_KEY", "synthetic-key")
    monkeypatch.setenv("OPNSENSE_API_SECRET", "synthetic-secret")
    monkeypatch.delenv("OPNSENSE_API_KEY_FILE", raising=False)
    monkeypatch.delenv("OPNSENSE_API_SECRET_FILE", raising=False)


def test_staged_sign_csr_retrieval_failure_precedes_ca_contact(
    monkeypatch, capsys, tmp_path, json_environment
):
    monkeypatch.setattr(
        checker,
        "validate_switch_signing_identity",
        lambda switch: {"common_name": "switch.example.invalid"},
    )
    monkeypatch.setattr(
        checker,
        "retrieve_csr",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("untrusted CSR text")),
    )
    monkeypatch.setattr(
        checker,
        "OPNsenseClient",
        lambda *args: pytest.fail("CA must not be contacted before a valid CSR"),
    )
    code, result, output = invoke(
        monkeypatch,
        capsys,
        "--sign-csr",
        "--switch",
        "SWITCH-A",
        "--certificate-name",
        "webcert2027",
        "--certificate-output",
        str(tmp_path / "signed.pem"),
    )
    item = result["results"][0]
    assert code == 2
    assert result["outcome"] == "failure_pre_attempt"
    assert item["stage"] == "csr_retrieval"
    assert item["reason_code"] == "csr_failed"
    assert item["change"] == "none"
    assert item["milestones"]["csr"] == "failed"
    assert item["milestones"]["issuance"] == "not_attempted"
    assert item["manual_recovery_required"] is False
    assert "untrusted CSR text" not in output


def test_staged_sign_malformed_observed_pending_csr_requires_recovery(
    monkeypatch, capsys, tmp_path, json_environment
):
    commands = []

    @contextmanager
    def connection(*args):
        yield object()

    def send_command(connection, command, limit, **kwargs):
        commands.append(command)
        if command == "show crypto pki local-certificate summary":
            return "webcert2027 Web CSR webprofile2026\n"
        return "malformed CSR detail"

    monkeypatch.setattr(
        checker,
        "validate_switch_signing_identity",
        lambda switch: {"common_name": "switch.example.invalid"},
    )
    monkeypatch.setattr(checker, "validate_csr_settings", lambda settings: settings)
    monkeypatch.setattr(checker, "ssh_connection", connection)
    monkeypatch.setattr(checker, "_send_command", send_command)
    monkeypatch.setattr(
        checker,
        "OPNsenseClient",
        lambda *args: pytest.fail("CA must not be contacted for a malformed CSR"),
    )
    code, result, _ = invoke(
        monkeypatch,
        capsys,
        "--sign-csr",
        "--switch",
        "SWITCH-A",
        "--certificate-name",
        "webcert2027",
        "--certificate-output",
        str(tmp_path / "signed.pem"),
    )
    item = result["results"][0]
    assert code == 2
    assert commands == [
        "show crypto pki local-certificate summary",
        "show crypto pki local-certificate webcert2027",
    ]
    assert item["outcome"] == "failure_pre_attempt"
    assert item["stage"] == "csr_retrieval"
    assert item["reason_code"] == "csr_failed"
    assert item["change"] == "none"
    assert item["milestones"]["csr"] == "failed"
    assert item["milestones"]["issuance"] == "not_attempted"
    assert item["manual_recovery_required"] is True


@pytest.mark.parametrize(
    ("phase", "expected_outcome", "expected_issuance", "expected_change", "calls"),
    [
        ("local_validation", "failure_pre_attempt", "not_attempted", "none", 0),
        ("opener_construction", "failure_pre_attempt", "not_attempted", "none", 0),
        ("transport", "failure_ambiguous", "uncertain", "possible", 1),
        ("certificate_fetch", "failure_partial", "confirmed", "confirmed", 2),
    ],
)
def test_staged_sign_real_request_boundary(
    monkeypatch,
    capsys,
    tmp_path,
    json_environment,
    phase,
    expected_outcome,
    expected_issuance,
    expected_change,
    calls,
):
    _prepare_real_staged_sign(monkeypatch)
    monkeypatch.setattr(
        checker,
        "get_opnsense_settings",
        lambda config: {
            "base_url": "https://ca.example.invalid",
            "ca": "Synthetic CA",
            "digest": "sha1" if phase == "local_validation" else "sha256",
            "lifetime_days": 90,
        },
    )
    requests = []

    class FakeOpener:
        def open(self, request, *, timeout):
            requests.append(request.full_url)
            if phase == "certificate_fetch" and len(requests) == 1:
                return BytesIO(
                    b'{"result":"saved","uuid":"9a2b1234-5678-4abc-9def-1234567890ab"}'
                )
            raise URLError("untrusted transport text")

    def fake_build_opener(*handlers):
        if phase == "opener_construction":
            raise OSError("local opener construction failed")
        return FakeOpener()

    monkeypatch.setattr(opnsense_client, "build_opener", fake_build_opener)
    code, result, output = invoke(
        monkeypatch,
        capsys,
        "--sign-csr",
        "--switch",
        "SWITCH-A",
        "--certificate-name",
        "webcert2027",
        "--certificate-output",
        str(tmp_path / "signed.pem"),
    )
    item = result["results"][0]
    assert code == 2
    assert len(requests) == calls
    assert item["outcome"] == expected_outcome
    assert item["milestones"]["csr"] == "confirmed"
    assert item["milestones"]["issuance"] == expected_issuance
    assert item["change"] == expected_change
    assert item["manual_recovery_required"] is True
    assert "untrusted transport text" not in output


def test_staged_sign_success_preserves_staged_milestones(
    monkeypatch, capsys, tmp_path, json_environment
):
    _prepare_real_staged_sign(monkeypatch)
    monkeypatch.setattr(
        checker,
        "get_opnsense_settings",
        lambda config: {
            "base_url": "https://ca.example.invalid",
            "ca": "Synthetic CA",
            "digest": "sha256",
            "lifetime_days": 90,
        },
    )
    certificate_pem = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
    requests = []

    class FakeOpener:
        def open(self, request, *, timeout):
            requests.append(request.full_url)
            if len(requests) == 1:
                return BytesIO(
                    b'{"result":"saved","uuid":"9a2b1234-5678-4abc-9def-1234567890ab"}'
                )
            return BytesIO(
                json.dumps({"status": "ok", "payload": certificate_pem}).encode()
            )

    certificate = SimpleNamespace(
        fingerprint=lambda algorithm: bytes(32),
        not_valid_after_utc=datetime(2027, 1, 5, tzinfo=UTC),
    )
    monkeypatch.setattr(opnsense_client, "build_opener", lambda *handlers: FakeOpener())
    monkeypatch.setattr(checker, "validate_issued_certificate", lambda *a, **k: None)
    monkeypatch.setattr(
        checker.x509, "load_pem_x509_certificate", lambda data: certificate
    )
    output_path = tmp_path / "signed.pem"
    code, result, _ = invoke(
        monkeypatch,
        capsys,
        "--sign-csr",
        "--switch",
        "SWITCH-A",
        "--certificate-name",
        "webcert2027",
        "--certificate-output",
        str(output_path),
    )
    item = result["results"][0]
    assert code == 0
    assert len(requests) == 2
    assert item["outcome"] == "success_prepared"
    assert item["change"] == "confirmed"
    assert item["milestones"]["csr"] == "confirmed"
    assert item["milestones"]["issuance"] == "confirmed"
    assert all(
        item["milestones"][name] == "not_attempted"
        for name in ("installation", "activation", "live_tls")
    )
    assert output_path.read_text() == certificate_pem


def test_staged_install_observes_existing_csr_before_mutation(
    monkeypatch, capsys, tmp_path, json_environment
):
    @contextmanager
    def connection(*args):
        yield object()

    certificate = SimpleNamespace(
        fingerprint=lambda algorithm: bytes(32),
        not_valid_after_utc=datetime(2027, 1, 5, tzinfo=UTC),
    )
    monkeypatch.setattr(checker, "read_certificate_input", lambda path: "synthetic PEM")
    monkeypatch.setattr(checker, "require_verification_ca_snapshot", lambda ca: ca)
    monkeypatch.setattr(checker, "validate_csr_settings", lambda settings: settings)
    monkeypatch.setattr(checker, "ssh_connection", connection)
    monkeypatch.setattr(checker, "_send_command", lambda *args, **kwargs: "summary")
    monkeypatch.setattr(checker, "_check_summary_size", lambda output: None)
    monkeypatch.setattr(
        checker,
        "require_pending_web_certificate",
        lambda *args: {"profile": "synthetic-profile"},
    )
    monkeypatch.setattr(
        checker, "retrieve_and_validate_csr", lambda *args: "synthetic CSR"
    )
    monkeypatch.setattr(checker, "validate_csr_pem", lambda *args: object())
    monkeypatch.setattr(
        checker,
        "verify_issued_certificate_trust",
        lambda *args: None,
    )
    monkeypatch.setattr(
        checker,
        "_require_current_certificate_validity",
        lambda *args: None,
    )
    install_calls = []
    monkeypatch.setattr(
        checker,
        "install_signed_certificate",
        lambda *args: install_calls.append("install"),
    )
    live_calls = []
    monkeypatch.setattr(
        checker,
        "verify_live_https_certificate",
        lambda *args: live_calls.append("live"),
    )

    def reject_leaf(*args, **kwargs):
        raise ValueError("synthetic validation failure")

    monkeypatch.setattr(checker, "validate_issued_certificate", reject_leaf)
    arguments = (
        "--install-certificate",
        "--switch",
        "SWITCH-A",
        "--certificate-name",
        "webcert2027",
        "--certificate-input",
        str(tmp_path / "signed.pem"),
    )
    code, result, _ = invoke(monkeypatch, capsys, *arguments)
    item = result["results"][0]
    assert code == 2
    assert item["outcome"] == "failure_pre_attempt"
    assert item["stage"] == "issued_validation"
    assert item["milestones"]["csr"] == "confirmed"
    assert item["milestones"]["installation"] == "not_attempted"
    assert item["change"] == "none"
    assert item["manual_recovery_required"] is True
    assert install_calls == []

    monkeypatch.setattr(
        checker, "validate_issued_certificate", lambda *args, **kwargs: certificate
    )
    code, result, _ = invoke(monkeypatch, capsys, *arguments)
    item = result["results"][0]
    assert code == 0
    assert item["outcome"] == "success_changed"
    assert item["milestones"]["csr"] == "confirmed"
    assert item["milestones"]["issuance"] == "not_attempted"
    assert item["milestones"]["installation"] == "confirmed"
    assert item["milestones"]["activation"] == "confirmed"
    assert item["milestones"]["live_tls"] == "confirmed"
    assert item["change"] == "confirmed"
    assert install_calls == ["install"]
    assert live_calls == ["live"]


@pytest.mark.parametrize(
    ("events", "expected_outcome", "expected_change", "expected_issuance"),
    [
        ((), "failure_pre_attempt", "none", "not_attempted"),
        (
            ("csr_confirmed", "issuance_confirmed"),
            "failure_partial",
            "confirmed",
            "confirmed",
        ),
        (
            ("csr_confirmed", "issuance_dispatched"),
            "failure_ambiguous",
            "possible",
            "uncertain",
        ),
    ],
)
def test_unexpected_failure_uses_recorded_mutation_evidence(
    monkeypatch,
    capsys,
    json_environment,
    events,
    expected_outcome,
    expected_change,
    expected_issuance,
):
    def fail(*args, **kwargs):
        for event in events:
            kwargs["progress"](event)
        raise RuntimeError("untrusted later error")

    monkeypatch.setattr(checker, "renew_certificate", fail)
    code, result, output = invoke(
        monkeypatch, capsys, "--renew", "--switch", "SWITCH-A"
    )
    item = result["results"][0]
    assert code == 2
    assert item["outcome"] == expected_outcome
    assert item["change"] == expected_change
    assert item["milestones"]["issuance"] == expected_issuance
    assert item["manual_recovery_required"] is (
        expected_outcome != "failure_pre_attempt"
    )
    assert "untrusted later error" not in output


def test_staged_sign_unexpected_error_after_observing_csr_is_pre_attempt(
    monkeypatch, capsys, tmp_path, json_environment
):
    def fail(*args, **kwargs):
        kwargs["progress"]("csr_retrieved")
        kwargs["progress"]("signing_preparation")
        raise RuntimeError("untrusted later error")

    monkeypatch.setattr(checker, "sign_pending_csr", fail)
    code, result, output = invoke(
        monkeypatch,
        capsys,
        "--sign-csr",
        "--switch",
        "SWITCH-A",
        "--certificate-name",
        "webcert2027",
        "--certificate-output",
        str(tmp_path / "signed.pem"),
    )
    item = result["results"][0]
    assert code == 2
    assert item["outcome"] == "failure_pre_attempt"
    assert item["change"] == "none"
    assert item["milestones"]["csr"] == "confirmed"
    assert item["milestones"]["issuance"] == "not_attempted"
    assert item["manual_recovery_required"] is True
    assert "untrusted later error" not in output


def test_opnsense_dispatch_hook_follows_local_request_bounds(monkeypatch):
    monkeypatch.setenv("OPNSENSE_API_KEY", "synthetic-key")
    monkeypatch.setenv("OPNSENSE_API_SECRET", "synthetic-secret")
    monkeypatch.delenv("OPNSENSE_API_KEY_FILE", raising=False)
    monkeypatch.delenv("OPNSENSE_API_SECRET_FILE", raising=False)
    client = opnsense_client.OPNsenseClient("https://ca.example.invalid")
    events = []

    class FakeOpener:
        def open(self, request, *, timeout):
            events.append("transport")
            raise URLError("synthetic transport failure")

    def fake_build_opener(*handlers):
        events.append("build")
        return FakeOpener()

    monkeypatch.setattr(opnsense_client, "build_opener", fake_build_opener)
    with pytest.raises(opnsense_client.OPNsenseAPIError):
        client._request_json(
            "POST",
            opnsense_client.CERT_ADD_PATH,
            {
                "cert": {
                    "csr_payload": "x" * opnsense_client.MAX_OPNSENSE_SIGN_REQUEST_BYTES
                }
            },
            on_dispatch=lambda: events.append("dispatch"),
        )
    assert events == []

    with pytest.raises(TypeError):
        client._request_json(
            "POST",
            opnsense_client.CERT_ADD_PATH,
            {"cert": {"action": object()}},
            on_dispatch=lambda: events.append("dispatch"),
        )
    assert events == []

    original_request = opnsense_client.Request
    monkeypatch.setattr(
        opnsense_client,
        "Request",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("bad request")),
    )
    with pytest.raises(ValueError, match="bad request"):
        client._request_json(
            "POST",
            opnsense_client.CERT_ADD_PATH,
            {"cert": {"action": "sign_csr"}},
            on_dispatch=lambda: events.append("dispatch"),
        )
    assert events == []
    monkeypatch.setattr(opnsense_client, "Request", original_request)

    def fail_build_opener(*handlers):
        events.append("build")
        raise OSError("opener setup failed")

    monkeypatch.setattr(opnsense_client, "build_opener", fail_build_opener)
    with pytest.raises(opnsense_client.OPNsenseAPIError):
        client._request_json(
            "POST",
            opnsense_client.CERT_ADD_PATH,
            {"cert": {"action": "sign_csr"}},
            on_dispatch=lambda: events.append("dispatch"),
        )
    assert events == ["build"]
    events.clear()
    monkeypatch.setattr(opnsense_client, "build_opener", fake_build_opener)

    def callback_failure():
        events.append("dispatch")
        raise RuntimeError("bookkeeping failed")

    with pytest.raises(RuntimeError, match="bookkeeping failed"):
        client._request_json(
            "POST",
            opnsense_client.CERT_ADD_PATH,
            {"cert": {"action": "sign_csr"}},
            on_dispatch=callback_failure,
        )
    assert events == ["build", "dispatch"]
    events.clear()

    with pytest.raises(opnsense_client.OPNsenseAPIError):
        client._request_json(
            "POST",
            opnsense_client.CERT_ADD_PATH,
            {"cert": {"action": "sign_csr"}},
            on_dispatch=lambda: events.append("dispatch"),
        )
    assert events == ["build", "dispatch", "transport"]
