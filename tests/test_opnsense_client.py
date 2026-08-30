import base64
import json
from email.message import Message
from io import BytesIO
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler
from urllib.response import addinfourl

import pytest

import opnsense_client

BASE_URL = "https://opnsense.example.com:8443"
CA_REF = "0123456789abc"
CERTIFICATE_UUID = "12345678-1234-4234-9234-123456789abc"


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self, size=-1):
        return self.payload


@pytest.fixture(autouse=True)
def api_credentials(monkeypatch):
    monkeypatch.setenv("OPNSENSE_API_KEY", "test-api-key")
    monkeypatch.setenv("OPNSENSE_API_SECRET", "test-api-secret")
    monkeypatch.delenv("OPNSENSE_API_KEY_FILE", raising=False)
    monkeypatch.delenv("OPNSENSE_API_SECRET_FILE", raising=False)


def json_response(payload):
    return FakeResponse(json.dumps(payload).encode())


def install_redirecting_https_handler(monkeypatch, location):
    requests = []

    class RedirectingHTTPSHandler(HTTPSHandler):
        def https_open(self, request):
            requests.append(request)
            headers = Message()
            headers["Location"] = location
            response = addinfourl(
                BytesIO(b"redirected"),
                headers,
                request.full_url,
                302,
            )
            response.msg = "Found"
            return response

    monkeypatch.setattr(
        opnsense_client,
        "HTTPSHandler",
        RedirectingHTTPSHandler,
    )
    return requests


def test_resolve_ca(monkeypatch):
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: json_response(
            {"rows": [{"caref": CA_REF, "descr": "internal-ca"}], "count": 1}
        ),
    )

    client = opnsense_client.OPNsenseClient(BASE_URL)

    assert client.resolve_ca("internal-ca") == CA_REF


def test_resolve_ca_rejects_missing_ca(monkeypatch):
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: json_response({"rows": [], "count": 0}),
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError, match="was not found"):
        opnsense_client.OPNsenseClient(BASE_URL).resolve_ca("internal-ca")


def test_resolve_ca_rejects_duplicate_descriptions(monkeypatch):
    payload = {
        "rows": [
            {"caref": CA_REF, "descr": "internal-ca"},
            {"caref": "fedcba9876543", "descr": "internal-ca"},
        ],
        "count": 2,
    }
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: json_response(payload),
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError, match="not unique"):
        opnsense_client.OPNsenseClient(BASE_URL).resolve_ca("internal-ca")


def test_resolve_ca_rejects_malformed_list(monkeypatch):
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: json_response({"rows": [], "count": 1}),
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError, match="malformed"):
        opnsense_client.OPNsenseClient(BASE_URL).resolve_ca("internal-ca")


def test_resolve_ca_rejects_invalid_caref(monkeypatch):
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: json_response(
            {"rows": [{"caref": "not-a-ref", "descr": "internal-ca"}], "count": 1}
        ),
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError, match="invalid CA reference"):
        opnsense_client.OPNsenseClient(BASE_URL).resolve_ca("internal-ca")


def test_malformed_json_is_rejected(monkeypatch):
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: FakeResponse(b"not JSON"),
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError, match="malformed JSON"):
        opnsense_client.OPNsenseClient(BASE_URL).resolve_ca("internal-ca")


def test_ca_list_redirect_is_rejected_without_following_authorization(monkeypatch):
    redirect_url = "https://attacker.example/collect"
    requests = install_redirecting_https_handler(monkeypatch, redirect_url)

    with pytest.raises(opnsense_client.OPNsenseAPIError, match="HTTP 302"):
        opnsense_client.OPNsenseClient(BASE_URL).resolve_ca("internal-ca")

    assert len(requests) == 1
    assert requests[0].full_url == BASE_URL + opnsense_client.CA_LIST_PATH
    assert requests[0].get_header("Authorization").startswith("Basic ")
    assert all(request.full_url != redirect_url for request in requests)


def test_post_redirect_is_rejected_without_following_authorization(monkeypatch):
    redirect_url = "https://attacker.example/collect"
    requests = install_redirecting_https_handler(monkeypatch, redirect_url)

    with pytest.raises(opnsense_client.OPNsenseAPIError, match="HTTP 302"):
        opnsense_client.OPNsenseClient(BASE_URL).sign_csr(
            "CSR",
            caref=CA_REF,
            digest="sha256",
            lifetime_days=397,
            dns_names=["switch.example.com"],
            ip_addresses=["192.0.2.10"],
            description="Aruba certificate",
        )

    assert len(requests) == 1
    assert requests[0].method == "POST"
    assert requests[0].full_url == BASE_URL + opnsense_client.CERT_ADD_PATH
    assert requests[0].get_header("Authorization").startswith("Basic ")
    assert all(request.full_url != redirect_url for request in requests)


@pytest.mark.parametrize("status", [401, 403, 500])
def test_http_errors_are_safely_reported(monkeypatch, tmp_path, status):
    key_file = tmp_path / "api-key"
    secret_file = tmp_path / "api-secret"
    key_file.write_bytes(b"super-secret-api-key")
    secret_file.write_bytes(b"super-secret-api-secret")
    monkeypatch.setenv("OPNSENSE_API_KEY_FILE", str(key_file))
    monkeypatch.setenv("OPNSENSE_API_SECRET_FILE", str(secret_file))

    def fail(*args, **kwargs):
        raise HTTPError(BASE_URL, status, "failure", {}, None)

    monkeypatch.setattr(opnsense_client, "_open_url", fail)

    with pytest.raises(
        opnsense_client.OPNsenseAPIError, match=f"HTTP {status}"
    ) as raised:
        opnsense_client.OPNsenseClient(BASE_URL).resolve_ca("internal-ca")

    assert "super-secret-api-secret" not in str(raised.value)
    assert "super-secret-api-key" not in str(raised.value)


def test_connection_errors_do_not_expose_credentials(monkeypatch, tmp_path):
    key_file = tmp_path / "api-key"
    secret_file = tmp_path / "api-secret"
    key_file.write_bytes(b"super-secret-api-key")
    secret_file.write_bytes(b"super-secret-api-secret")
    monkeypatch.setenv("OPNSENSE_API_KEY_FILE", str(key_file))
    monkeypatch.setenv("OPNSENSE_API_SECRET_FILE", str(secret_file))

    def fail(*args, **kwargs):
        raise URLError("super-secret-api-key:super-secret-api-secret")

    monkeypatch.setattr(opnsense_client, "_open_url", fail)

    with pytest.raises(opnsense_client.OPNsenseAPIError) as raised:
        opnsense_client.OPNsenseClient(BASE_URL).resolve_ca("internal-ca")

    assert "super-secret-api-secret" not in str(raised.value)
    assert "super-secret-api-key" not in str(raised.value)


@pytest.mark.parametrize(
    ("direct_name", "file_name"),
    [
        ("OPNSENSE_API_KEY", "OPNSENSE_API_KEY_FILE"),
        ("OPNSENSE_API_SECRET", "OPNSENSE_API_SECRET_FILE"),
    ],
)
def test_missing_api_credentials_are_rejected(monkeypatch, direct_name, file_name):
    monkeypatch.delenv(direct_name)

    with pytest.raises(
        opnsense_client.OPNsenseAPIError,
        match=rf"{direct_name} or {file_name} must be set",
    ):
        opnsense_client.OPNsenseClient(BASE_URL)


def test_key_and_secret_can_be_loaded_from_files(monkeypatch, tmp_path):
    captured = {}
    key_file = tmp_path / "api-key"
    secret_file = tmp_path / "api-secret"
    key_file.write_bytes(b"file-api-key\n")
    secret_file.write_bytes(b"file-api-secret\r\n")
    monkeypatch.setenv("OPNSENSE_API_KEY_FILE", str(key_file))
    monkeypatch.setenv("OPNSENSE_API_SECRET_FILE", str(secret_file))

    def fake_open_url(request, **kwargs):
        captured["request"] = request
        return json_response({"rows": [], "count": 0})

    monkeypatch.setattr(opnsense_client, "_open_url", fake_open_url)

    client = opnsense_client.OPNsenseClient(BASE_URL)
    with pytest.raises(opnsense_client.OPNsenseAPIError, match="was not found"):
        client.resolve_ca("internal-ca")

    expected = base64.b64encode(b"file-api-key:file-api-secret").decode()
    assert captured["request"].get_header("Authorization") == f"Basic {expected}"


@pytest.mark.parametrize(
    ("contents", "expected"),
    [
        (b"unterminated", "unterminated"),
        (b"terminated-with-lf\n", "terminated-with-lf"),
        (b"terminated-with-crlf\r\n", "terminated-with-crlf"),
        (b"  spaces are credentials  \n", "  spaces are credentials  "),
    ],
)
def test_secret_file_accepts_one_utf8_line_and_preserves_spaces(
    monkeypatch, tmp_path, contents, expected
):
    key_file = tmp_path / "api-key"
    key_file.write_bytes(contents)
    monkeypatch.setenv("OPNSENSE_API_KEY_FILE", str(key_file))

    client = opnsense_client.OPNsenseClient(BASE_URL)

    encoded = base64.b64encode(f"{expected}:test-api-secret".encode()).decode()
    assert client._authorization == f"Basic {encoded}"


@pytest.mark.parametrize(
    ("file_name", "direct_name", "expected_credentials"),
    [
        (
            "OPNSENSE_API_KEY_FILE",
            "OPNSENSE_API_KEY",
            b"file-value:test-api-secret",
        ),
        (
            "OPNSENSE_API_SECRET_FILE",
            "OPNSENSE_API_SECRET",
            b"test-api-key:file-value",
        ),
    ],
)
def test_secret_file_overrides_corresponding_direct_environment_value(
    monkeypatch,
    tmp_path,
    file_name,
    direct_name,
    expected_credentials,
):
    secret_file = tmp_path / "credential"
    secret_file.write_bytes(b"file-value")
    monkeypatch.setenv(file_name, str(secret_file))
    monkeypatch.setenv(direct_name, "unused-direct-value")

    client = opnsense_client.OPNsenseClient(BASE_URL)

    encoded_credentials = client._authorization.removeprefix("Basic ")
    decoded_credentials = base64.b64decode(encoded_credentials)
    assert decoded_credentials == expected_credentials
    assert b"unused-direct-value" not in decoded_credentials


@pytest.mark.parametrize(
    ("file_name", "direct_name"),
    [
        ("OPNSENSE_API_KEY_FILE", "OPNSENSE_API_KEY"),
        ("OPNSENSE_API_SECRET_FILE", "OPNSENSE_API_SECRET"),
    ],
)
def test_invalid_secret_file_fails_closed_without_direct_fallback(
    monkeypatch, tmp_path, file_name, direct_name
):
    direct_value = f"super-secret-{direct_name.casefold()}"
    monkeypatch.setenv(direct_name, direct_value)
    monkeypatch.setenv(file_name, str(tmp_path / "missing-secret"))

    with pytest.raises(opnsense_client.OPNsenseAPIError) as raised:
        opnsense_client.OPNsenseClient(BASE_URL)

    assert file_name in str(raised.value)
    assert direct_value not in str(raised.value)


@pytest.mark.parametrize(
    ("key_from_file", "secret_from_file"),
    [(True, False), (False, True)],
)
def test_key_and_secret_can_use_mixed_sources(
    monkeypatch, tmp_path, key_from_file, secret_from_file
):
    if key_from_file:
        key_file = tmp_path / "api-key"
        key_file.write_bytes(b"mixed-api-key")
        monkeypatch.setenv("OPNSENSE_API_KEY_FILE", str(key_file))
    else:
        monkeypatch.setenv("OPNSENSE_API_KEY", "mixed-api-key")

    if secret_from_file:
        secret_file = tmp_path / "api-secret"
        secret_file.write_bytes(b"mixed-api-secret")
        monkeypatch.setenv("OPNSENSE_API_SECRET_FILE", str(secret_file))
    else:
        monkeypatch.setenv("OPNSENSE_API_SECRET", "mixed-api-secret")

    client = opnsense_client.OPNsenseClient(BASE_URL)

    expected = base64.b64encode(b"mixed-api-key:mixed-api-secret").decode()
    assert client._authorization == f"Basic {expected}"


@pytest.mark.parametrize(
    "file_name", ["OPNSENSE_API_KEY_FILE", "OPNSENSE_API_SECRET_FILE"]
)
@pytest.mark.parametrize("unsafe_path", ["", "   ", "bad\x1fpath"])
def test_secret_file_rejects_empty_or_unsafe_path(monkeypatch, file_name, unsafe_path):
    monkeypatch.setenv(file_name, unsafe_path)

    with pytest.raises(
        opnsense_client.OPNsenseAPIError,
        match=rf"{file_name} must be a non-empty safe path",
    ):
        opnsense_client.OPNsenseClient(BASE_URL)


@pytest.mark.parametrize(
    "file_name", ["OPNSENSE_API_KEY_FILE", "OPNSENSE_API_SECRET_FILE"]
)
def test_secret_file_reader_rejects_nul_path_before_open(file_name):
    with pytest.raises(
        opnsense_client.OPNsenseAPIError,
        match=rf"{file_name} must be a non-empty safe path",
    ):
        opnsense_client._read_secret_file("bad\x00path", file_name)


@pytest.mark.parametrize(
    "file_name", ["OPNSENSE_API_KEY_FILE", "OPNSENSE_API_SECRET_FILE"]
)
def test_secret_file_rejects_missing_file_without_exposing_path(
    monkeypatch, tmp_path, file_name
):
    sensitive_path = tmp_path / "super-secret-api-key"
    monkeypatch.setenv(file_name, str(sensitive_path))

    with pytest.raises(
        opnsense_client.OPNsenseAPIError,
        match=rf"{file_name} could not be read",
    ) as raised:
        opnsense_client.OPNsenseClient(BASE_URL)

    assert "super-secret-api-key" not in str(raised.value)


@pytest.mark.parametrize(
    "file_name", ["OPNSENSE_API_KEY_FILE", "OPNSENSE_API_SECRET_FILE"]
)
def test_secret_file_rejects_directory(monkeypatch, tmp_path, file_name):
    monkeypatch.setenv(file_name, str(tmp_path))

    with pytest.raises(
        opnsense_client.OPNsenseAPIError,
        match=rf"{file_name} is not a regular file",
    ):
        opnsense_client.OPNsenseClient(BASE_URL)


@pytest.mark.parametrize(
    "file_name", ["OPNSENSE_API_KEY_FILE", "OPNSENSE_API_SECRET_FILE"]
)
def test_secret_file_rejects_non_regular_opened_file(monkeypatch, tmp_path, file_name):
    secret_file = tmp_path / "credential"
    secret_file.write_bytes(b"secret")
    monkeypatch.setenv(file_name, str(secret_file))
    monkeypatch.setattr(
        opnsense_client.os,
        "fstat",
        lambda file_descriptor: type("StatResult", (), {"st_mode": 0})(),
    )

    with pytest.raises(
        opnsense_client.OPNsenseAPIError,
        match=rf"{file_name} is not a regular file",
    ):
        opnsense_client.OPNsenseClient(BASE_URL)


@pytest.mark.parametrize(
    "file_name", ["OPNSENSE_API_KEY_FILE", "OPNSENSE_API_SECRET_FILE"]
)
def test_unreadable_secret_file_does_not_expose_underlying_error(
    monkeypatch, tmp_path, file_name
):
    monkeypatch.setenv(file_name, str(tmp_path / "credential"))

    def fail_open(*args, **kwargs):
        raise PermissionError("super-secret-api-secret")

    monkeypatch.setattr(opnsense_client, "open", fail_open, raising=False)

    with pytest.raises(
        opnsense_client.OPNsenseAPIError,
        match=rf"{file_name} could not be read",
    ) as raised:
        opnsense_client.OPNsenseClient(BASE_URL)

    assert "super-secret-api-secret" not in str(raised.value)


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        (b"", "is empty"),
        (b"super-secret-api-key\x00", "contains NUL"),
        (b"super-secret-api-key\nsecond-line", "must contain exactly one line"),
        (b"super-secret-api-key\rsecond-line", "must contain exactly one line"),
        (b"super-secret-api-key\xff", "must contain valid UTF-8"),
        (
            b"x" * (opnsense_client.MAX_SECRET_FILE_BYTES + 1),
            f"exceeds {opnsense_client.MAX_SECRET_FILE_BYTES} bytes",
        ),
    ],
)
@pytest.mark.parametrize(
    "file_name", ["OPNSENSE_API_KEY_FILE", "OPNSENSE_API_SECRET_FILE"]
)
def test_secret_file_rejects_unsafe_content_without_exposure(
    monkeypatch, tmp_path, file_name, contents, message
):
    secret_file = tmp_path / "credential"
    secret_file.write_bytes(contents)
    monkeypatch.setenv(file_name, str(secret_file))

    with pytest.raises(
        opnsense_client.OPNsenseAPIError,
        match=message,
    ) as raised:
        opnsense_client.OPNsenseClient(BASE_URL)

    assert "super-secret-api-key" not in str(raised.value)


def test_file_and_direct_credentials_produce_identical_authorization(
    monkeypatch, tmp_path
):
    key = "equivalent-api-key"
    secret = "equivalent-api-secret"
    monkeypatch.setenv("OPNSENSE_API_KEY", key)
    monkeypatch.setenv("OPNSENSE_API_SECRET", secret)
    direct_authorization = opnsense_client.OPNsenseClient(BASE_URL)._authorization

    key_file = tmp_path / "api-key"
    secret_file = tmp_path / "api-secret"
    key_file.write_text(key, encoding="utf-8")
    secret_file.write_text(secret, encoding="utf-8")
    monkeypatch.setenv("OPNSENSE_API_KEY_FILE", str(key_file))
    monkeypatch.setenv("OPNSENSE_API_SECRET_FILE", str(secret_file))

    file_authorization = opnsense_client.OPNsenseClient(BASE_URL)._authorization

    assert file_authorization == direct_authorization


def test_basic_authentication_and_tls_context_are_used(monkeypatch):
    captured = {}

    def fake_open_url(request, **kwargs):
        captured["request"] = request
        captured.update(kwargs)
        return json_response({"rows": [], "count": 0})

    monkeypatch.setattr(opnsense_client, "_open_url", fake_open_url)
    client = opnsense_client.OPNsenseClient(BASE_URL)

    with pytest.raises(opnsense_client.OPNsenseAPIError, match="was not found"):
        client.resolve_ca("internal-ca")

    expected = base64.b64encode(b"test-api-key:test-api-secret").decode()
    assert captured["request"].get_header("Authorization") == f"Basic {expected}"
    assert captured["request"].full_url == BASE_URL + opnsense_client.CA_LIST_PATH
    assert captured["ssl_context"].check_hostname
    assert captured["ssl_context"].verify_mode.name == "CERT_REQUIRED"


def test_sign_csr_sends_nested_model_payload(monkeypatch):
    captured = {}

    def fake_open_url(request, **kwargs):
        captured["request"] = request
        return json_response({"result": "saved", "uuid": CERTIFICATE_UUID})

    monkeypatch.setattr(opnsense_client, "_open_url", fake_open_url)
    csr_pem = (
        "-----BEGIN CERTIFICATE REQUEST-----\nTEST\n-----END CERTIFICATE REQUEST-----\n"
    )

    result = opnsense_client.OPNsenseClient(BASE_URL).sign_csr(
        csr_pem,
        caref=CA_REF,
        digest="sha256",
        lifetime_days=397,
        dns_names=["switch.example.com"],
        ip_addresses=["192.0.2.10"],
        description="Aruba certificate",
    )

    assert result == CERTIFICATE_UUID
    request = captured["request"]
    assert request.method == "POST"
    assert request.full_url == BASE_URL + opnsense_client.CERT_ADD_PATH
    assert set(json.loads(request.data)) == {"cert"}
    cert = json.loads(request.data)["cert"]
    assert cert == {
        "action": "sign_csr",
        "caref": CA_REF,
        "digest": "sha256",
        "cert_type": "server_cert",
        "lifetime": 397,
        "key_type": "2048",
        "csr_payload": csr_pem,
        "altnames_dns": "switch.example.com",
        "altnames_ip": "192.0.2.10",
        "descr": "Aruba certificate",
    }


@pytest.mark.parametrize(
    ("dns_names", "ip_addresses", "expected_dns", "expected_ip"),
    [
        (["switch.example.com"], [], "switch.example.com", ""),
        ([], ["192.0.2.10"], "", "192.0.2.10"),
        ([], ["2001:db8::10"], "", "2001:db8::10"),
        (
            ["switch.example.com", "alias.example.com"],
            ["192.0.2.10", "2001:db8::10"],
            "switch.example.com\nalias.example.com",
            "192.0.2.10\n2001:db8::10",
        ),
    ],
)
def test_sign_csr_serializes_typed_san_lists(
    monkeypatch, dns_names, ip_addresses, expected_dns, expected_ip
):
    captured = {}

    def fake_open_url(request, **kwargs):
        captured["request"] = request
        return json_response({"result": "saved", "uuid": CERTIFICATE_UUID})

    monkeypatch.setattr(opnsense_client, "_open_url", fake_open_url)

    opnsense_client.OPNsenseClient(BASE_URL).sign_csr(
        "CSR",
        caref=CA_REF,
        digest="sha256",
        lifetime_days=397,
        dns_names=dns_names,
        ip_addresses=ip_addresses,
        description="Aruba certificate",
    )

    payload = json.loads(captured["request"].data)
    assert set(payload) == {"cert"}
    assert payload["cert"]["altnames_dns"] == expected_dns
    assert payload["cert"]["altnames_ip"] == expected_ip


@pytest.mark.parametrize(
    "response",
    [
        {"result": "failed", "uuid": CERTIFICATE_UUID},
        {"result": "saved"},
        {"result": "saved", "uuid": "not-a-uuid"},
        {"result": "saved", "uuid": 123},
    ],
)
def test_sign_csr_rejects_failed_or_invalid_uuid_response(monkeypatch, response):
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: json_response(response),
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError):
        opnsense_client.OPNsenseClient(BASE_URL).sign_csr(
            "CSR",
            caref=CA_REF,
            digest="sha256",
            lifetime_days=397,
            dns_names=["switch.example.com"],
            ip_addresses=["192.0.2.10"],
            description="Aruba certificate",
        )


def test_get_certificate_extracts_public_pem(monkeypatch):
    certificate_pem = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"
    captured = {}

    def fake_open_url(request, **kwargs):
        captured["request"] = request
        return json_response({"status": "ok", "payload": certificate_pem})

    monkeypatch.setattr(opnsense_client, "_open_url", fake_open_url)

    result = opnsense_client.OPNsenseClient(BASE_URL).get_certificate(CERTIFICATE_UUID)

    assert result == certificate_pem
    request = captured["request"]
    expected_path = opnsense_client.CERTIFICATE_PATH.format(uuid=CERTIFICATE_UUID)
    assert request.full_url == BASE_URL + expected_path
    assert request.method == "POST"
    assert json.loads(request.data) == {}


@pytest.mark.parametrize(
    "response",
    [
        {"status": "failed", "payload": "certificate"},
        {"status": "ok"},
        {"status": "ok", "payload": ""},
        {"status": "ok", "payload": 123},
    ],
)
def test_get_certificate_rejects_malformed_response(monkeypatch, response):
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: json_response(response),
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError, match="malformed"):
        opnsense_client.OPNsenseClient(BASE_URL).get_certificate(CERTIFICATE_UUID)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://opnsense.example.com",
        "https://user:password@opnsense.example.com",
        "https://opnsense.example.com?query=yes",
        "https://opnsense.example.com/unexpected/path",
        "not a URL",
    ],
)
def test_base_url_requires_safe_verified_https(base_url):
    with pytest.raises(ValueError, match="opnsense.base_url"):
        opnsense_client.OPNsenseClient(base_url)
