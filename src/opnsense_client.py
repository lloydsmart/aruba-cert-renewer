"""Narrow HTTPS client for the OPNsense Trust certificate API."""

import base64
import json
import os
import re
import ssl
import unicodedata
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

from secure_file import SecureFileError, open_secure_file

CA_LIST_PATH = "/api/trust/cert/ca_list"
CERT_ADD_PATH = "/api/trust/cert/add"
CERTIFICATE_PATH = "/api/trust/cert/generate_file/{uuid}/crt"
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_SECRET_FILE_BYTES = 16 * 1024


class OPNsenseAPIError(ValueError):
    """A safe-to-display OPNsense API or response error."""


class RejectRedirectHandler(HTTPRedirectHandler):
    """Leave redirects unhandled so urllib raises the original HTTP error."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_url(request, *, timeout, ssl_context):
    opener = build_opener(
        RejectRedirectHandler(),
        HTTPSHandler(context=ssl_context),
    )
    return opener.open(request, timeout=timeout)


def validate_base_url(base_url):
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("opnsense.base_url must be a non-empty HTTPS URL")

    base_url = base_url.strip().rstrip("/")
    parsed = urlsplit(base_url)

    if parsed.scheme.casefold() != "https" or not parsed.hostname:
        raise ValueError("opnsense.base_url must be a valid HTTPS URL")

    if parsed.username or parsed.password:
        raise ValueError("opnsense.base_url must not contain credentials")

    if parsed.query or parsed.fragment:
        raise ValueError("opnsense.base_url must not contain a query or fragment")

    if parsed.path not in {"", "/"}:
        raise ValueError("opnsense.base_url must not contain a path")

    if any(ord(character) < 32 for character in base_url):
        raise ValueError("opnsense.base_url contains unsupported characters")

    try:
        _ = parsed.port
    except ValueError as error:
        raise ValueError("opnsense.base_url contains an invalid port") from error

    return base_url


def _read_secret_file(configured_path, source_name):
    if (
        not configured_path
        or not configured_path.strip()
        or any(unicodedata.category(character) == "Cc" for character in configured_path)
    ):
        raise OPNsenseAPIError(f"{source_name} must be a non-empty safe path")

    try:
        with open_secure_file(
            configured_path,
            source_name=source_name,
            disclose_path=False,
        ) as secret_file:
            secret_bytes = secret_file.read(MAX_SECRET_FILE_BYTES + 1)
    except SecureFileError as error:
        raise OPNsenseAPIError(str(error)) from None
    except OSError:
        raise OPNsenseAPIError(f"{source_name} could not be read") from None

    if len(secret_bytes) > MAX_SECRET_FILE_BYTES:
        raise OPNsenseAPIError(f"{source_name} exceeds {MAX_SECRET_FILE_BYTES} bytes")

    if b"\x00" in secret_bytes:
        raise OPNsenseAPIError(f"{source_name} contains NUL")

    try:
        secret = secret_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise OPNsenseAPIError(f"{source_name} must contain valid UTF-8") from None

    if secret.endswith("\r\n"):
        secret = secret[:-2]
    elif secret.endswith("\n"):
        secret = secret[:-1]

    if "\r" in secret or "\n" in secret:
        raise OPNsenseAPIError(f"{source_name} must contain exactly one line")

    if not secret:
        raise OPNsenseAPIError(f"{source_name} is empty")

    return secret


def _load_credential(direct_name, file_name):
    if file_name in os.environ:
        return _read_secret_file(os.environ[file_name], file_name)

    credential = os.environ.get(direct_name)
    if not credential:
        raise OPNsenseAPIError(f"{direct_name} or {file_name} must be set")

    return credential


class OPNsenseClient:
    """Access only the Trust API routes needed to sign and fetch a certificate."""

    def __init__(self, base_url, *, timeout=30):
        self.base_url = validate_base_url(base_url)
        self.timeout = timeout
        self._authorization = self._load_authorization()
        self._ssl_context = ssl.create_default_context()

    @staticmethod
    def _load_authorization():
        api_key = _load_credential(
            "OPNSENSE_API_KEY",
            "OPNSENSE_API_KEY_FILE",
        )
        api_secret = _load_credential(
            "OPNSENSE_API_SECRET",
            "OPNSENSE_API_SECRET_FILE",
        )

        credentials = f"{api_key}:{api_secret}".encode()
        return "Basic " + base64.b64encode(credentials).decode("ascii")

    def _request_json(self, method, path, payload=None):
        headers = {
            "Accept": "application/json",
            "Authorization": self._authorization,
        }
        data = None

        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode("utf-8")

        request = Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )

        try:
            with _open_url(
                request,
                timeout=self.timeout,
                ssl_context=self._ssl_context,
            ) as response:
                response_data = response.read(MAX_RESPONSE_BYTES + 1)

        except HTTPError as error:
            raise OPNsenseAPIError(
                f"OPNsense API request failed with HTTP {error.code}"
            ) from None
        except (URLError, TimeoutError, OSError):
            raise OPNsenseAPIError("OPNsense API connection failed") from None

        if len(response_data) > MAX_RESPONSE_BYTES:
            raise OPNsenseAPIError("OPNsense API response is too large")

        try:
            result = json.loads(response_data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise OPNsenseAPIError("OPNsense API returned malformed JSON") from None

        if not isinstance(result, dict):
            raise OPNsenseAPIError("OPNsense API returned an invalid JSON response")

        return result

    def resolve_ca(self, description):
        response = self._request_json("GET", CA_LIST_PATH)
        rows = response.get("rows")
        count = response.get("count")

        if (
            not isinstance(rows, list)
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count != len(rows)
        ):
            raise OPNsenseAPIError("OPNsense CA list response is malformed")

        matches = []
        for row in rows:
            if not isinstance(row, dict):
                raise OPNsenseAPIError("OPNsense CA list response is malformed")

            descr = row.get("descr")
            caref = row.get("caref")
            if not isinstance(descr, str) or not isinstance(caref, str):
                raise OPNsenseAPIError("OPNsense CA list response is malformed")

            if descr == description:
                matches.append(caref)

        if not matches:
            raise OPNsenseAPIError(
                f"OPNsense CA description was not found: {description}"
            )

        if len(matches) != 1:
            raise OPNsenseAPIError(
                f"OPNsense CA description is not unique: {description}"
            )

        caref = matches[0]
        if not re.fullmatch(r"[0-9a-f]{13}", caref):
            raise OPNsenseAPIError("OPNsense returned an invalid CA reference")

        return caref

    def sign_csr(
        self,
        csr_pem,
        *,
        caref,
        digest,
        lifetime_days,
        dns_names,
        ip_addresses,
        description,
    ):
        response = self._request_json(
            "POST",
            CERT_ADD_PATH,
            {
                "cert": {
                    "action": "sign_csr",
                    "caref": caref,
                    "digest": digest,
                    "cert_type": "server_cert",
                    "lifetime": lifetime_days,
                    "key_type": "2048",
                    "csr_payload": csr_pem,
                    "altnames_dns": "\n".join(dns_names),
                    "altnames_ip": "\n".join(ip_addresses),
                    "descr": description,
                }
            },
        )

        if response.get("result") != "saved":
            raise OPNsenseAPIError("OPNsense did not save the signed certificate")

        certificate_uuid = response.get("uuid")
        if not isinstance(certificate_uuid, str):
            raise OPNsenseAPIError("OPNsense response did not contain a valid UUID")

        try:
            parsed_uuid = uuid.UUID(certificate_uuid)
        except (ValueError, AttributeError):
            raise OPNsenseAPIError(
                "OPNsense response did not contain a valid UUID"
            ) from None

        if str(parsed_uuid) != certificate_uuid.casefold():
            raise OPNsenseAPIError("OPNsense response did not contain a valid UUID")

        return str(parsed_uuid)

    def get_certificate(self, certificate_uuid):
        try:
            normalized_uuid = str(uuid.UUID(certificate_uuid))
        except (ValueError, AttributeError):
            raise OPNsenseAPIError("Certificate UUID is invalid") from None

        response = self._request_json(
            "POST",
            CERTIFICATE_PATH.format(uuid=normalized_uuid),
            {},
        )

        certificate_pem = response.get("payload")
        if response.get("status") != "ok" or not isinstance(certificate_pem, str):
            raise OPNsenseAPIError("OPNsense public certificate response is malformed")

        if not certificate_pem.strip():
            raise OPNsenseAPIError("OPNsense public certificate response is malformed")

        return certificate_pem.strip() + "\n"
