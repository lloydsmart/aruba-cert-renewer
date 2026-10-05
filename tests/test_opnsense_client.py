import base64
import json
import ssl
import sys
import urllib.request as urllib_request
from email.message import Message
from io import BytesIO
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request
from urllib.response import addinfourl

import pytest

import opnsense_client
from secure_file import SecureFileError

BASE_URL = "https://opnsense.example.com:8443"
CA_REF = "0123456789abc"
CERTIFICATE_UUID = "12345678-1234-4234-9234-123456789abc"
CSR_PEM = (
    "-----BEGIN CERTIFICATE REQUEST-----\nTEST\n-----END CERTIFICATE REQUEST-----\n"
)


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


@pytest.mark.parametrize("response", [b"not JSON", b"\xff"])
def test_malformed_json_is_rejected(monkeypatch, response):
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: FakeResponse(response),
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError, match="malformed JSON"):
        opnsense_client.OPNsenseClient(BASE_URL).resolve_ca("internal-ca")


def test_json_integer_limit_is_safely_reported(monkeypatch):
    previous_limit = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(sys.int_info.str_digits_check_threshold)
        response = b'{"count":' + b"9" * (sys.get_int_max_str_digits() + 1) + b"}"
        assert len(response) < opnsense_client.MAX_RESPONSE_BYTES
        with pytest.raises(ValueError):
            json.loads(response)

        monkeypatch.setattr(
            opnsense_client,
            "_open_url",
            lambda *args, **kwargs: FakeResponse(response),
        )
        with pytest.raises(opnsense_client.OPNsenseAPIError) as raised:
            opnsense_client.OPNsenseClient(BASE_URL)._request_json(
                "GET", opnsense_client.CA_LIST_PATH
            )
        assert str(raised.value) == "OPNsense API returned malformed JSON"
    finally:
        sys.set_int_max_str_digits(previous_limit)


def test_json_parser_recursion_error_is_safely_reported(monkeypatch):
    response = b'{"rows":[]}'

    def fail_parser(*args, **kwargs):
        raise RecursionError("synthetic parser detail")

    monkeypatch.setattr(
        opnsense_client, "_open_url", lambda *args, **kwargs: FakeResponse(response)
    )
    monkeypatch.setattr(opnsense_client.json, "loads", fail_parser)
    with pytest.raises(opnsense_client.OPNsenseAPIError) as raised:
        opnsense_client.OPNsenseClient(BASE_URL)._request_json(
            "GET", opnsense_client.CA_LIST_PATH
        )
    assert str(raised.value) == "OPNsense API returned malformed JSON"
    assert "synthetic parser detail" not in str(raised.value)
    assert "rows" not in str(raised.value)


def test_json_response_size_is_checked_before_parsing(monkeypatch):
    response = b"{" * (opnsense_client.MAX_RESPONSE_BYTES + 1)
    monkeypatch.setattr(
        opnsense_client, "_open_url", lambda *args, **kwargs: FakeResponse(response)
    )
    with pytest.raises(opnsense_client.OPNsenseAPIError, match="too large"):
        opnsense_client.OPNsenseClient(BASE_URL)._request_json(
            "GET", opnsense_client.CA_LIST_PATH
        )


def test_non_parser_valueerror_is_not_reclassified(monkeypatch):
    def fail_before_parsing(*args, **kwargs):
        raise ValueError("local programming error")

    monkeypatch.setattr(opnsense_client, "_open_url", fail_before_parsing)
    with pytest.raises(ValueError, match="local programming error") as raised:
        opnsense_client.OPNsenseClient(BASE_URL)._request_json(
            "GET", opnsense_client.CA_LIST_PATH
        )
    assert type(raised.value) is ValueError


@pytest.mark.parametrize(
    "response",
    [
        b'{"rows":[],"count":0,"count":1}',
        b'{"rows":[{"descr":"a","descr":"b"}],"count":1}',
        b'{"outer":[{"key":1,"key":2}]}',
    ],
)
def test_duplicate_json_keys_are_rejected_at_every_depth(monkeypatch, response):
    monkeypatch.setattr(
        opnsense_client, "_open_url", lambda *args, **kwargs: FakeResponse(response)
    )

    with pytest.raises(
        opnsense_client.OPNsenseAPIError, match="malformed JSON"
    ) as raised:
        opnsense_client.OPNsenseClient(BASE_URL)._request_json(
            "GET", opnsense_client.CA_LIST_PATH
        )
    assert "descr" not in str(raised.value)


def test_unique_nested_json_and_arrays_are_accepted(monkeypatch):
    payload = {"rows": [{"descr": "internal-ca", "caref": CA_REF}], "count": 1}
    monkeypatch.setattr(
        opnsense_client, "_open_url", lambda *args, **kwargs: json_response(payload)
    )
    assert (
        opnsense_client.OPNsenseClient(BASE_URL)._request_json(
            "GET", opnsense_client.CA_LIST_PATH
        )
        == payload
    )


@pytest.mark.parametrize("response", [b"[]", b"null", b'"text"'])
def test_non_object_json_root_is_rejected(monkeypatch, response):
    monkeypatch.setattr(
        opnsense_client, "_open_url", lambda *args, **kwargs: FakeResponse(response)
    )
    with pytest.raises(opnsense_client.OPNsenseAPIError, match="invalid JSON response"):
        opnsense_client.OPNsenseClient(BASE_URL)._request_json(
            "GET", opnsense_client.CA_LIST_PATH
        )


@pytest.mark.parametrize("timeout", [1, 0.5])
def test_positive_finite_timeout_is_accepted(timeout):
    assert opnsense_client.OPNsenseClient(BASE_URL, timeout=timeout).timeout == timeout


@pytest.mark.parametrize(
    "timeout",
    [0, -1, True, False, float("nan"), float("inf"), -float("inf"), "1", None, 10**400],
)
def test_invalid_timeout_is_rejected_before_credentials(monkeypatch, timeout):
    monkeypatch.delenv("OPNSENSE_API_KEY")
    with pytest.raises(ValueError, match="positive finite"):
        opnsense_client.OPNsenseClient(BASE_URL, timeout=timeout)


@pytest.mark.parametrize("description", ["CA with spaces", "Café authority", "x" * 255])
def test_resolve_ca_accepts_safe_description(monkeypatch, description):
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: json_response(
            {"rows": [{"descr": description, "caref": CA_REF}], "count": 1}
        ),
    )
    assert opnsense_client.OPNsenseClient(BASE_URL).resolve_ca(description) == CA_REF


@pytest.mark.parametrize(
    "description",
    [
        None,
        7,
        "",
        "   ",
        "x" * 256,
        "hidden\nvalue",
        "bad\x7f",
        "bad\u200e",
        "bad\ud800",
        "bad\u2028",
        "bad\u2029",
    ],
)
def test_resolve_ca_rejects_unsafe_description_before_request(monkeypatch, description):
    calls = []
    client = opnsense_client.OPNsenseClient(BASE_URL)
    monkeypatch.setattr(client, "_request_json", lambda *args: calls.append(args))
    with pytest.raises(opnsense_client.OPNsenseAPIError) as raised:
        client.resolve_ca(description)
    assert calls == []
    assert "hidden" not in str(raised.value)
    assert "value" not in str(raised.value)


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
            CSR_PEM,
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
@pytest.mark.parametrize(
    ("mode", "message"),
    [(0o620, "group-writable"), (0o602, "world-writable")],
)
def test_secret_file_rejects_unsafe_write_permissions(
    monkeypatch, tmp_path, file_name, mode, message
):
    secret_file = tmp_path / "credential"
    secret_file.write_bytes(b"super-secret-credential")
    secret_file.chmod(mode)
    monkeypatch.setenv(file_name, str(secret_file))

    with pytest.raises(opnsense_client.OPNsenseAPIError, match=message) as raised:
        opnsense_client.OPNsenseClient(BASE_URL)

    assert "super-secret-credential" not in str(raised.value)


@pytest.mark.parametrize(
    "file_name", ["OPNSENSE_API_KEY_FILE", "OPNSENSE_API_SECRET_FILE"]
)
def test_secret_file_rejects_symlink_without_exposing_path(
    monkeypatch, tmp_path, file_name
):
    target = tmp_path / "super-secret-target"
    target.write_bytes(b"credential")
    link = tmp_path / "super-secret-link"
    link.symlink_to(target)
    monkeypatch.setenv(file_name, str(link))

    with pytest.raises(
        opnsense_client.OPNsenseAPIError,
        match=rf"{file_name} is a symbolic link",
    ) as raised:
        opnsense_client.OPNsenseClient(BASE_URL)

    assert "super-secret-link" not in str(raised.value)


@pytest.mark.parametrize(
    "file_name", ["OPNSENSE_API_KEY_FILE", "OPNSENSE_API_SECRET_FILE"]
)
def test_secret_file_rejects_non_regular_opened_file(monkeypatch, tmp_path, file_name):
    secret_file = tmp_path / "credential"
    secret_file.write_bytes(b"secret")
    monkeypatch.setenv(file_name, str(secret_file))
    monkeypatch.setattr(
        opnsense_client,
        "open_secure_file",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            SecureFileError(f"{file_name} is not a regular file")
        ),
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
        raise SecureFileError(f"{file_name} could not be read")

    monkeypatch.setattr(opnsense_client, "open_secure_file", fail_open)

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


@pytest.mark.parametrize("name", ["OPNSENSE_API_KEY", "OPNSENSE_API_SECRET"])
@pytest.mark.parametrize("value", ["x" * 16384, "é" * 8192])
def test_direct_credential_accepts_exact_utf8_limit(monkeypatch, name, value):
    monkeypatch.setenv(name, value)

    client = opnsense_client.OPNsenseClient(BASE_URL)

    decoded = base64.b64decode(client._authorization.removeprefix("Basic "))
    assert value.encode("utf-8") in decoded


@pytest.mark.parametrize("name", ["OPNSENSE_API_KEY", "OPNSENSE_API_SECRET"])
@pytest.mark.parametrize("value", ["x" * 16385, "é" * 8192 + "x"])
def test_direct_credential_rejects_overlong_utf8_without_disclosure(
    monkeypatch, name, value
):
    monkeypatch.setenv(name, value)

    with pytest.raises(
        opnsense_client.OPNsenseAPIError, match="exceeds 16384 bytes"
    ) as raised:
        opnsense_client.OPNsenseClient(BASE_URL)

    assert name in str(raised.value)
    assert value not in str(raised.value)
    assert "Basic " not in str(raised.value)


@pytest.mark.parametrize("name", ["OPNSENSE_API_KEY", "OPNSENSE_API_SECRET"])
@pytest.mark.parametrize(
    ("value", "message"),
    [("", "is empty"), ("secret\nvalue", "one line")],
)
def test_direct_credential_shares_file_content_rules_without_disclosure(
    monkeypatch, name, value, message
):
    monkeypatch.setenv(name, value)

    with pytest.raises(opnsense_client.OPNsenseAPIError, match=message) as raised:
        opnsense_client.OPNsenseClient(BASE_URL)

    assert value not in str(raised.value) or not value


def test_shared_credential_content_validator_rejects_nul_without_disclosure():
    with pytest.raises(
        opnsense_client.OPNsenseAPIError, match="contains NUL"
    ) as raised:
        opnsense_client._validate_credential_content(
            "secret\x00value", "OPNSENSE_API_KEY"
        )

    assert "secret" not in str(raised.value)


def test_direct_credential_rejects_invalid_utf8_without_disclosure(monkeypatch):
    monkeypatch.setenv("OPNSENSE_API_KEY", "secret\udcffvalue")

    with pytest.raises(opnsense_client.OPNsenseAPIError, match="valid UTF-8") as raised:
        opnsense_client.OPNsenseClient(BASE_URL)

    assert "secret" not in str(raised.value)


@pytest.mark.parametrize("name", ["OPNSENSE_API_KEY_FILE", "OPNSENSE_API_SECRET_FILE"])
def test_secret_file_accepts_exact_size_limit(monkeypatch, tmp_path, name):
    path = tmp_path / "credential"
    path.write_bytes(b"x" * opnsense_client.MAX_SECRET_FILE_BYTES)
    monkeypatch.setenv(name, str(path))

    client = opnsense_client.OPNsenseClient(BASE_URL)

    assert b"x" * opnsense_client.MAX_SECRET_FILE_BYTES in base64.b64decode(
        client._authorization.removeprefix("Basic ")
    )


@pytest.mark.parametrize(
    ("file_name", "direct_name"),
    [
        ("OPNSENSE_API_KEY_FILE", "OPNSENSE_API_KEY"),
        ("OPNSENSE_API_SECRET_FILE", "OPNSENSE_API_SECRET"),
    ],
)
def test_secret_file_precedence_skips_oversized_direct_value(
    monkeypatch, tmp_path, file_name, direct_name
):
    path = tmp_path / "credential"
    path.write_bytes(b"file-value")
    monkeypatch.setenv(file_name, str(path))
    monkeypatch.setenv(direct_name, "x" * 16385)

    client = opnsense_client.OPNsenseClient(BASE_URL)

    assert b"file-value" in base64.b64decode(
        client._authorization.removeprefix("Basic ")
    )


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
    assert captured["ssl_context"].verify_mode == ssl.CERT_REQUIRED
    assert captured["ssl_context"].minimum_version == ssl.TLSVersion.TLSv1_2
    assert captured["ssl_context"].maximum_version == ssl.TLSVersion.MAXIMUM_SUPPORTED


def test_opnsense_client_uses_shared_tls_context_policy(monkeypatch):
    context = object()
    calls = []
    monkeypatch.setattr(
        opnsense_client,
        "create_client_tls_context",
        lambda: calls.append(True) or context,
    )

    client = opnsense_client.OPNsenseClient(BASE_URL)

    assert calls == [True]
    assert client._ssl_context is context


def test_sign_csr_sends_nested_model_payload(monkeypatch):
    captured = {}

    def fake_open_url(request, **kwargs):
        captured["request"] = request
        return json_response({"result": "saved", "uuid": CERTIFICATE_UUID})

    monkeypatch.setattr(opnsense_client, "_open_url", fake_open_url)
    csr_pem = CSR_PEM

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
        CSR_PEM,
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


def signing_arguments(**changes):
    arguments = {
        "caref": CA_REF,
        "digest": "sha256",
        "lifetime_days": 397,
        "dns_names": ["switch.example.com"],
        "ip_addresses": ["192.0.2.10"],
        "description": "Aruba certificate",
    }
    arguments.update(changes)
    return arguments


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"caref": "0123456789ABC"}, "CA reference"),
        ({"caref": "0123456789ab"}, "CA reference"),
        ({"caref": None}, "CA reference"),
        ({"digest": "sha1"}, "digest"),
        ({"digest": "SHA256"}, "digest"),
        ({"digest": []}, "digest"),
        ({"lifetime_days": 0}, "lifetime"),
        ({"lifetime_days": 3651}, "lifetime"),
        ({"lifetime_days": True}, "lifetime"),
        ({"lifetime_days": 1.0}, "lifetime"),
        ({"description": ""}, "description"),
        ({"description": "x" * 256}, "description"),
        ({"description": "bad\u200e"}, "description"),
        ({"description": "bad\nvalue"}, "description"),
        ({"dns_names": "switch.example.com"}, "SANs"),
        ({"ip_addresses": "192.0.2.10"}, "SANs"),
        ({"dns_names": [], "ip_addresses": []}, "SAN count"),
        ({"dns_names": ["*.example.com"]}, "DNS SAN"),
        ({"dns_names": ["999.999.999.999"]}, "DNS SAN"),
        ({"dns_names": ["bad..example.com"]}, "DNS SAN"),
        ({"dns_names": ["bad\n.example.com"]}, "DNS SAN"),
        ({"dns_names": ["tést.example.com"]}, "DNS SAN"),
        ({"dns_names": [42]}, "DNS SAN"),
        ({"dns_names": ["Switch.example.com", "switch.example.com"]}, "duplicate"),
        ({"ip_addresses": ["999.999.999.999"]}, "IP SAN"),
        ({"ip_addresses": ["fe80::1%eth0"]}, "IP SAN"),
        ({"ip_addresses": ["bad\nip"]}, "IP SAN"),
        ({"ip_addresses": [42]}, "IP SAN"),
        ({"ip_addresses": ["2001:0db8::1", "2001:db8::1"]}, "duplicate"),
        ({"csr_pem": b"not text"}, "CSR PEM"),
        (
            {
                "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nTÉST\n-----END CERTIFICATE REQUEST-----\n"
            },
            "ASCII",
        ),
        ({"csr_pem": "not a CSR"}, "CSR PEM"),
    ],
)
def test_sign_csr_rejects_invalid_arguments_before_network(
    monkeypatch, changes, message
):
    calls = []
    client = opnsense_client.OPNsenseClient(BASE_URL)
    monkeypatch.setattr(client, "_request_json", lambda *args: calls.append(args))
    arguments = signing_arguments(
        **{key: value for key, value in changes.items() if key != "csr_pem"}
    )
    with pytest.raises(opnsense_client.OPNsenseAPIError, match=message) as raised:
        client.sign_csr(changes.get("csr_pem", CSR_PEM), **arguments)
    assert calls == []
    assert "bad\nvalue" not in str(raised.value)


@pytest.mark.parametrize("lifetime_days", [1, 3650])
def test_sign_csr_accepts_aruba_lifetime_boundaries(monkeypatch, lifetime_days):
    payloads = []
    client = opnsense_client.OPNsenseClient(BASE_URL)
    monkeypatch.setattr(
        client,
        "_request_json",
        lambda method, path, payload: (
            payloads.append(payload) or {"result": "saved", "uuid": CERTIFICATE_UUID}
        ),
    )
    assert (
        client.sign_csr(CSR_PEM, **signing_arguments(lifetime_days=lifetime_days))
        == CERTIFICATE_UUID
    )
    assert payloads[0]["cert"]["lifetime"] == lifetime_days


def test_sign_csr_accepts_maximum_safe_description_and_crlf_pem(monkeypatch):
    payloads = []
    client = opnsense_client.OPNsenseClient(BASE_URL)
    monkeypatch.setattr(
        client,
        "_request_json",
        lambda method, path, payload: (
            payloads.append(payload) or {"result": "saved", "uuid": CERTIFICATE_UUID}
        ),
    )
    description = "x" * 255
    crlf_pem = CSR_PEM.replace("\n", "\r\n")
    assert (
        client.sign_csr(crlf_pem, **signing_arguments(description=description))
        == CERTIFICATE_UUID
    )
    assert payloads[0]["cert"]["descr"] == description
    assert payloads[0]["cert"]["csr_payload"] == crlf_pem


def test_sign_csr_preserves_dns_case_and_canonicalizes_ip(monkeypatch):
    payloads = []
    client = opnsense_client.OPNsenseClient(BASE_URL)
    monkeypatch.setattr(
        client,
        "_request_json",
        lambda method, path, payload: (
            payloads.append(payload) or {"result": "saved", "uuid": CERTIFICATE_UUID}
        ),
    )
    client.sign_csr(
        CSR_PEM,
        **signing_arguments(
            dns_names=["Switch.Example.com", "alias.example.com"],
            ip_addresses=["192.0.2.10", "2001:0db8::0010"],
        ),
    )
    assert (
        payloads[0]["cert"]["altnames_dns"] == "Switch.Example.com\nalias.example.com"
    )
    assert payloads[0]["cert"]["altnames_ip"] == "192.0.2.10\n2001:db8::10"


@pytest.mark.parametrize("count", [101, 102])
def test_sign_csr_san_count_boundary(monkeypatch, count):
    calls = []
    client = opnsense_client.OPNsenseClient(BASE_URL)
    monkeypatch.setattr(
        client,
        "_request_json",
        lambda method, path, payload: (
            calls.append(payload) or {"result": "saved", "uuid": CERTIFICATE_UUID}
        ),
    )
    names = [f"switch-{index}.example.com" for index in range(count)]
    if count == 101:
        assert (
            client.sign_csr(
                CSR_PEM, **signing_arguments(dns_names=names, ip_addresses=[])
            )
            == CERTIFICATE_UUID
        )
        assert len(calls) == 1
    else:
        with pytest.raises(opnsense_client.OPNsenseAPIError, match="SAN count"):
            client.sign_csr(
                CSR_PEM, **signing_arguments(dns_names=names, ip_addresses=[])
            )
        assert calls == []


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
            CSR_PEM,
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


@pytest.mark.parametrize("payload", ["PÉM", " CERTIFICATE\u2003"])
def test_get_certificate_rejects_non_ascii_payload(monkeypatch, payload):
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: json_response({"status": "ok", "payload": payload}),
    )
    with pytest.raises(opnsense_client.OPNsenseAPIError, match="not ASCII") as raised:
        opnsense_client.OPNsenseClient(BASE_URL).get_certificate(CERTIFICATE_UUID)
    assert payload not in str(raised.value)


@pytest.mark.parametrize(
    "size",
    [
        opnsense_client.MAX_CERTIFICATE_PEM_BYTES,
        opnsense_client.MAX_CERTIFICATE_PEM_BYTES + 1,
    ],
)
def test_get_certificate_pem_size_boundary(monkeypatch, size):
    payload = "A" * (size - 1)
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: json_response({"status": "ok", "payload": payload}),
    )
    client = opnsense_client.OPNsenseClient(BASE_URL)
    if size == opnsense_client.MAX_CERTIFICATE_PEM_BYTES:
        assert len(client.get_certificate(CERTIFICATE_UUID)) == size
    else:
        with pytest.raises(opnsense_client.OPNsenseAPIError, match="size limit"):
            client.get_certificate(CERTIFICATE_UUID)


@pytest.mark.parametrize(
    ("base_url", "expected"),
    [
        ("https://opnsense.example.com", "https://opnsense.example.com"),
        ("https://opnsense.example.com/", "https://opnsense.example.com"),
        ("https://OpnSense.Example.COM", "https://OpnSense.Example.COM"),
        ("https://xn--fa-hia.de", "https://xn--fa-hia.de"),
        ("https://xn--bcher-kva.example", "https://xn--bcher-kva.example"),
        ("https://XN--BCHER-KVA.example", "https://XN--BCHER-KVA.example"),
        ("https://opnsense.123.example", "https://opnsense.123.example"),
        ("https://192.0.2.10", "https://192.0.2.10"),
        ("https://[2001:db8::10]", "https://[2001:db8::10]"),
        ("https://[2001:db8::10]/", "https://[2001:db8::10]"),
        ("https://opnsense.example.com:1", "https://opnsense.example.com:1"),
        ("https://opnsense.example.com:65535/", "https://opnsense.example.com:65535"),
        ("https://[2001:db8::10]:8443", "https://[2001:db8::10]:8443"),
    ],
)
def test_base_url_accepts_only_normalized_https_origins(base_url, expected):
    assert opnsense_client.validate_base_url(base_url) == expected


def test_ascii_xn_label_is_preserved_without_unicode_conversion():
    assert (
        opnsense_client.validate_base_url("https://xn--fa-hia.de")
        == "https://xn--fa-hia.de"
    )


@pytest.mark.parametrize(
    "base_url",
    [
        None,
        123,
        "",
        " \t ",
        " https://opnsense.example.com",
        "https://opnsense.example.com ",
        "https://opn sense.example.com",
        "https://opnsense.example.com\n",
        "https://opnsense.example.com\x00",
        "https://opnsense.example.com\x7f",
        "https://opnsense.example.com\x85",
        "https://opnsense.example.com\u200e",
        "http://opnsense.example.com",
        "https://",
        "https:///missing-host",
        "https://@opnsense.example.com",
        "https://user@opnsense.example.com",
        "https://user:password@opnsense.example.com",
        "https://opnsense.example.com:",
        "https://opnsense.example.com:0",
        "https://opnsense.example.com:65536",
        "https://opnsense.example.com:-1",
        "https://opnsense.example.com:+1",
        "https://opnsense.example.com:abc",
        "https://opnsense.example.com:1.5",
        "https://opnsense.example.com:１２",
        "https://opnsense.example.com//",
        "https://opnsense.example.com///",
        "https://opnsense.example.com/unexpected/path",
        "https://opnsense.example.com?",
        "https://opnsense.example.com?query=yes",
        "https://opnsense.example.com#",
        "https://opnsense.example.com#fragment",
        "https://fa\u00df.de",
        "https://b\u00fccher.example",
        "https://\u212a.example",
        "https://\u00e9.example",
        "https://[fe80::1%25eth0]",
        "https://2130706433",
        "https://0x7f.0.0.1",
        "https://127.1",
        "https://0177.0.0.1",
        "https://999.999.999.999",
        "https://[192.0.2.10]",
        "https://2001:db8::10",
        "https://*.example.com",
        "https://opnsense..example.com",
        "https://-opnsense.example.com",
        "https://opnsense-.example.com",
        f"https://{'a' * 64}.example.com",
        f"https://{'a' * 63}.{'b' * 63}.{'c' * 63}.{'d' * 62}",
        "not a URL",
    ],
)
def test_base_url_rejects_ambiguous_or_unsafe_origins(base_url):
    with pytest.raises(ValueError, match="opnsense.base_url"):
        opnsense_client.validate_base_url(base_url)


@pytest.mark.parametrize(
    "base_url",
    ["https://fa\u00df.de", "https://b\u00fccher.example", "https://\u212a.example"],
)
def test_unicode_origin_rejected_before_credentials_are_loaded(monkeypatch, base_url):
    monkeypatch.setattr(
        opnsense_client.OPNsenseClient,
        "_load_authorization",
        staticmethod(lambda: pytest.fail("credentials must not be loaded")),
    )

    with pytest.raises(ValueError, match="opnsense.base_url"):
        opnsense_client.OPNsenseClient(base_url)


def test_opener_ignores_ambient_and_platform_proxies(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.setenv(name, "http://hostile-proxy.example:8080")

    discovery_calls = []

    def hostile_platform_proxies():
        discovery_calls.append(True)
        return {"https": "http://platform-proxy.example:8080"}

    monkeypatch.setattr(urllib_request, "getproxies", hostile_platform_proxies)
    original_build_opener = opnsense_client.build_opener
    captured = {}

    def capture_opener(*handlers):
        captured["passed_handlers"] = handlers
        opener = original_build_opener(*handlers)
        captured["handlers"] = opener.handlers
        opener.open = lambda request, timeout: captured.update(
            request=request, timeout=timeout
        )
        return opener

    monkeypatch.setattr(opnsense_client, "build_opener", capture_opener)
    context = ssl.create_default_context()
    request = Request(BASE_URL + opnsense_client.CA_LIST_PATH)

    opnsense_client._open_url(request, timeout=30, ssl_context=context)

    assert discovery_calls == []
    proxy_handlers = [
        handler
        for handler in captured["passed_handlers"]
        if isinstance(handler, ProxyHandler)
    ]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {}
    assert not hasattr(proxy_handlers[0], "https_open")
    assert not any(
        isinstance(handler, ProxyHandler) for handler in captured["handlers"]
    )
    assert any(
        isinstance(handler, opnsense_client.RejectRedirectHandler)
        for handler in captured["handlers"]
    )
    assert any(
        isinstance(handler, HTTPSHandler) and handler._context is context
        for handler in captured["handlers"]
    )
    assert captured["request"] is request
    assert captured["timeout"] == 30
