"""Shared TLS client policy for all HTTPS connections."""

import ssl


def create_client_tls_context(*, cafile=None):
    """Create a verified client context with the project's protocol floor."""
    context = ssl.create_default_context(cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise RuntimeError("TLS client verification context is not securely configured")

    return context
