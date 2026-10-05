import ssl
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tls_policy import create_client_tls_context


def test_client_tls_context_has_explicit_floor_and_verification():
    context = create_client_tls_context()

    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.maximum_version == ssl.TLSVersion.MAXIMUM_SUPPORTED
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_client_tls_context_loads_configured_ca_data():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca_data = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")

    context = create_client_tls_context(cadata=ca_data)

    assert context.cert_store_stats()["x509_ca"] == 1
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_client_tls_context_rejects_cafile_authority_without_disclosure():
    with pytest.raises(TypeError, match="cafile") as raised:
        create_client_tls_context(cafile="synthetic-ca-path")

    assert "synthetic-ca-path" not in str(raised.value)

    with pytest.raises(TypeError, match="cafile"):
        create_client_tls_context(cafile="synthetic-ca-path", cadata="synthetic-ca")
