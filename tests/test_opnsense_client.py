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
            dns_name="switch.example.com",
            ip_address="192.0.2.10",
            description="Aruba certificate",
        )

    assert len(requests) == 1
    assert requests[0].method == "POST"
    assert requests[0].full_url == BASE_URL + opnsense_client.CERT_ADD_PATH
    assert requests[0].get_header("Authorization").startswith("Basic ")
    assert all(request.full_url != redirect_url for request in requests)


@pytest.mark.parametrize("status", [401, 403, 500])
def test_http_errors_are_safely_reported(monkeypatch, status):
    def fail(*args, **kwargs):
        raise HTTPError(BASE_URL, status, "failure", {}, None)

    monkeypatch.setattr(opnsense_client, "_open_url", fail)

    with pytest.raises(
        opnsense_client.OPNsenseAPIError, match=f"HTTP {status}"
    ) as raised:
        opnsense_client.OPNsenseClient(BASE_URL).resolve_ca("internal-ca")

    assert "test-api-secret" not in str(raised.value)
    assert "test-api-key" not in str(raised.value)


def test_connection_errors_do_not_expose_credentials(monkeypatch):
    def fail(*args, **kwargs):
        raise URLError("test-api-key:test-api-secret")

    monkeypatch.setattr(opnsense_client, "_open_url", fail)

    with pytest.raises(opnsense_client.OPNsenseAPIError) as raised:
        opnsense_client.OPNsenseClient(BASE_URL).resolve_ca("internal-ca")

    assert "test-api-secret" not in str(raised.value)
    assert "test-api-key" not in str(raised.value)


@pytest.mark.parametrize("missing", ["OPNSENSE_API_KEY", "OPNSENSE_API_SECRET"])
def test_missing_api_credentials_are_rejected(monkeypatch, missing):
    monkeypatch.delenv(missing)

    with pytest.raises(opnsense_client.OPNsenseAPIError, match=missing):
        opnsense_client.OPNsenseClient(BASE_URL)


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
        dns_name="switch.example.com",
        ip_address="192.0.2.10",
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
            dns_name="switch.example.com",
            ip_address="192.0.2.10",
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
