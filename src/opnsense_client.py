"""Narrow HTTPS client for the OPNsense Trust certificate API."""

import base64
import json
import math
import os
import re
import unicodedata
import uuid
from ipaddress import ip_address
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from secure_file import SecureFileError, open_secure_file
from tls_policy import create_client_tls_context

CA_LIST_PATH = "/api/trust/cert/ca_list"
CERT_ADD_PATH = "/api/trust/cert/add"
CERTIFICATE_PATH = "/api/trust/cert/generate_file/{uuid}/crt"
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_CERTIFICATE_PEM_BYTES = 64 * 1024
MAX_SECRET_FILE_BYTES = 16 * 1024
MAX_DESCRIPTION_CHARS = 255
MAX_SAN_ENTRIES = 101
_DNS_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_NUMERIC_HOST_COMPONENT_RE = re.compile(r"(?:[0-9]+|0[xX][0-9A-Fa-f]+)\Z")
_UNSAFE_URL_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_UNSAFE_TEXT_CATEGORIES = _UNSAFE_URL_CATEGORIES
_CA_REFERENCE_RE = re.compile(r"[0-9a-f]{13}\Z")


class OPNsenseAPIError(ValueError):
    """A safe-to-display OPNsense API or response error."""


class _DuplicateJSONKeyError(ValueError):
    """A JSON object contains an ambiguous repeated key."""


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKeyError
        result[key] = value
    return result


def _validate_timeout(timeout):
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("OPNsense timeout must be a positive finite number")
    try:
        valid = math.isfinite(timeout) and timeout > 0
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError("OPNsense timeout must be a positive finite number")
    return timeout


def _validate_safe_text(value, label):
    if not isinstance(value, str):
        raise OPNsenseAPIError(f"{label} must be non-empty text")
    if len(value) > MAX_DESCRIPTION_CHARS:
        raise OPNsenseAPIError(f"{label} exceeds the size limit")
    if not value.strip():
        raise OPNsenseAPIError(f"{label} must be non-empty text")
    if any(
        unicodedata.category(character) in _UNSAFE_TEXT_CATEGORIES
        for character in value
    ):
        raise OPNsenseAPIError(f"{label} contains unsafe characters")
    return value


def _validate_sans(dns_names, ip_addresses):
    if not isinstance(dns_names, (list, tuple)) or not isinstance(
        ip_addresses, (list, tuple)
    ):
        raise OPNsenseAPIError("DNS and IP SANs must be lists or tuples")
    if not 1 <= len(dns_names) + len(ip_addresses) <= MAX_SAN_ENTRIES:
        raise OPNsenseAPIError("SAN count must be between 1 and 101")

    seen_dns = set()
    for name in dns_names:
        if not isinstance(name, str) or not name or len(name) > 253:
            raise OPNsenseAPIError("DNS SAN is invalid")
        if re.fullmatch(r"[0-9.]+", name) or any(
            _DNS_LABEL_RE.fullmatch(label) is None for label in name.split(".")
        ):
            raise OPNsenseAPIError("DNS SAN is invalid")
        canonical = name.lower()
        if canonical in seen_dns:
            raise OPNsenseAPIError("DNS SAN is duplicated")
        seen_dns.add(canonical)

    canonical_ips = []
    seen_ips = set()
    for value in ip_addresses:
        if not isinstance(value, str) or not value or len(value) > 64 or "%" in value:
            raise OPNsenseAPIError("IP SAN is invalid")
        try:
            canonical = str(ip_address(value))
        except ValueError:
            raise OPNsenseAPIError("IP SAN is invalid") from None
        if canonical in seen_ips:
            raise OPNsenseAPIError("IP SAN is duplicated")
        seen_ips.add(canonical)
        canonical_ips.append(canonical)

    return tuple(dns_names), tuple(canonical_ips)


class RejectRedirectHandler(HTTPRedirectHandler):
    """Leave redirects unhandled so urllib raises the original HTTP error."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_url(request, *, timeout, ssl_context):
    opener = build_opener(
        ProxyHandler({}),
        RejectRedirectHandler(),
        HTTPSHandler(context=ssl_context),
    )
    return opener.open(request, timeout=timeout)


def validate_base_url(base_url):
    """Validate one explicit HTTPS origin and remove its optional final slash."""

    if not isinstance(base_url, str) or not base_url:
        raise ValueError("opnsense.base_url must be a non-empty HTTPS URL")
    if not base_url.isascii() or any(
        character.isspace() or unicodedata.category(character) in _UNSAFE_URL_CATEGORIES
        for character in base_url
    ):
        raise ValueError("opnsense.base_url contains unsupported characters")

    try:
        parsed = urlsplit(base_url)
        hostname = parsed.hostname
    except ValueError:
        raise ValueError("opnsense.base_url must be a valid HTTPS URL") from None

    if parsed.scheme.casefold() != "https" or not hostname:
        raise ValueError("opnsense.base_url must be a valid HTTPS URL")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("opnsense.base_url must not contain credentials")

    if "?" in base_url or "#" in base_url:
        raise ValueError("opnsense.base_url must not contain a query or fragment")

    if parsed.path not in {"", "/"}:
        raise ValueError("opnsense.base_url must not contain a path")

    authority = parsed.netloc
    bracketed = authority.startswith("[")
    if bracketed:
        closing_bracket = authority.find("]")
        suffix = authority[closing_bracket + 1 :]
        if suffix and not suffix.startswith(":"):
            raise ValueError("opnsense.base_url must be a valid HTTPS URL")
        port_text = suffix[1:] if suffix else None
    else:
        port_text = authority.partition(":")[2] if ":" in authority else None

    if port_text is not None and re.fullmatch(r"[0-9]+", port_text) is None:
        raise ValueError("opnsense.base_url contains an invalid port")

    try:
        port = parsed.port
    except ValueError:
        raise ValueError("opnsense.base_url contains an invalid port") from None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("opnsense.base_url contains an invalid port")

    _validate_url_hostname(hostname, bracketed=bracketed)

    return base_url[:-1] if parsed.path == "/" else base_url


def _validate_url_hostname(hostname, *, bracketed):
    if "%" in hostname:
        raise ValueError("opnsense.base_url contains an invalid hostname")
    try:
        address = ip_address(hostname)
    except ValueError:
        if bracketed or all(
            _NUMERIC_HOST_COMPONENT_RE.fullmatch(label) for label in hostname.split(".")
        ):
            raise ValueError("opnsense.base_url contains an invalid hostname") from None
    else:
        if (address.version == 6) != bracketed:
            raise ValueError("opnsense.base_url contains an invalid hostname")
        return

    if len(hostname) > 253:
        raise ValueError("opnsense.base_url contains an invalid hostname")
    for label in hostname.split("."):
        if _DNS_LABEL_RE.fullmatch(label) is None:
            raise ValueError("opnsense.base_url contains an invalid hostname")


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

    return _validate_credential_content(secret, source_name)


def _validate_credential_content(credential, source_name):
    try:
        encoded_size = len(credential.encode("utf-8"))
    except UnicodeEncodeError:
        raise OPNsenseAPIError(f"{source_name} must contain valid UTF-8") from None
    if encoded_size > MAX_SECRET_FILE_BYTES:
        raise OPNsenseAPIError(f"{source_name} exceeds {MAX_SECRET_FILE_BYTES} bytes")
    if "\x00" in credential:
        raise OPNsenseAPIError(f"{source_name} contains NUL")
    if "\r" in credential or "\n" in credential:
        raise OPNsenseAPIError(f"{source_name} must contain exactly one line")
    if not credential:
        raise OPNsenseAPIError(f"{source_name} is empty")
    return credential


def _load_credential(direct_name, file_name):
    if file_name in os.environ:
        return _read_secret_file(os.environ[file_name], file_name)

    credential = os.environ.get(direct_name)
    if credential is None:
        raise OPNsenseAPIError(f"{direct_name} or {file_name} must be set")
    return _validate_credential_content(credential, direct_name)


class OPNsenseClient:
    """Access only the Trust API routes needed to sign and fetch a certificate."""

    def __init__(self, base_url, *, timeout=30):
        self.base_url = validate_base_url(base_url)
        self.timeout = _validate_timeout(timeout)
        self._authorization = self._load_authorization()
        self._ssl_context = create_client_tls_context()

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
            result = json.loads(
                response_data.decode("utf-8"), object_pairs_hook=_json_object
            )
        except (ValueError, RecursionError):
            raise OPNsenseAPIError("OPNsense API returned malformed JSON") from None

        if not isinstance(result, dict):
            raise OPNsenseAPIError("OPNsense API returned an invalid JSON response")

        return result

    def resolve_ca(self, description):
        description = _validate_safe_text(description, "OPNsense CA description")
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
            raise OPNsenseAPIError("OPNsense CA description was not found")

        if len(matches) != 1:
            raise OPNsenseAPIError("OPNsense CA description is not unique")

        caref = matches[0]
        if _CA_REFERENCE_RE.fullmatch(caref) is None:
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
        if not isinstance(csr_pem, str):
            raise OPNsenseAPIError("CSR PEM must be text")
        if not csr_pem.isascii():
            raise OPNsenseAPIError("CSR PEM must be ASCII")
        if (
            re.fullmatch(
                r"-----BEGIN CERTIFICATE REQUEST-----\r?\n"
                r"[A-Za-z0-9+/=]+(?:\r?\n[A-Za-z0-9+/=]+)*\r?\n"
                r"-----END CERTIFICATE REQUEST-----\r?\n",
                csr_pem,
            )
            is None
        ):
            raise OPNsenseAPIError("CSR PEM is malformed")
        if not isinstance(caref, str) or _CA_REFERENCE_RE.fullmatch(caref) is None:
            raise OPNsenseAPIError("OPNsense CA reference is invalid")
        if not isinstance(digest, str) or digest not in {"sha256", "sha384", "sha512"}:
            raise OPNsenseAPIError("OPNsense digest is unsupported")
        if (
            not isinstance(lifetime_days, int)
            or isinstance(lifetime_days, bool)
            or not 1 <= lifetime_days <= 3650
        ):
            raise OPNsenseAPIError("OPNsense lifetime must be between 1 and 3650 days")
        description = _validate_safe_text(description, "Certificate description")
        dns_names, ip_addresses = _validate_sans(dns_names, ip_addresses)
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

        if not certificate_pem.isascii():
            raise OPNsenseAPIError("OPNsense public certificate response is not ASCII")
        if not certificate_pem.strip():
            raise OPNsenseAPIError("OPNsense public certificate response is malformed")

        certificate_pem = certificate_pem.strip() + "\n"
        if len(certificate_pem) > MAX_CERTIFICATE_PEM_BYTES:
            raise OPNsenseAPIError(
                "OPNsense public certificate payload exceeds the size limit"
            )
        return certificate_pem
