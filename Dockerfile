FROM python:3.14.7-slim-trixie@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2

RUN apt-get update \
    && apt-get install --yes --no-install-recommends --only-upgrade \
        gzip=1.13-1+deb13u1 \
        libpcre2-8-0=10.46-1~deb13u2 \
        libsqlite3-0=3.46.1-7+deb13u2 \
        perl-base=5.40.1-6+deb13u1 \
    && rm -rf /var/lib/apt/lists/*

ARG UNRAID_ICON_REF=main

LABEL org.opencontainers.image.source="https://github.com/lloydsmart/aruba-cert-renewer" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      net.unraid.docker.icon="https://raw.githubusercontent.com/lloydsmart/aruba-cert-renewer/${UNRAID_ICON_REF}/assets/icon.png"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install \
    --no-cache-dir \
    --require-hashes \
    -r requirements.txt \
    && python -m pip uninstall --yes pip

RUN groupadd --gid 10001 aruba-cert-renewer \
    && useradd --uid 10001 \
        --gid 10001 \
        --no-create-home \
        --home-dir /tmp \
        --shell /usr/sbin/nologin \
        aruba-cert-renewer \
    && install -d -o root -g root -m 0555 \
        /config \
        /run/secrets \
        /usr/share/licenses/aruba-cert-renewer

COPY src/ /app/src/
COPY LICENSE /usr/share/licenses/aruba-cert-renewer/LICENSE
RUN chmod -R a-w /app /usr/share/licenses/aruba-cert-renewer

USER 10001:10001

ENTRYPOINT ["python", "/app/src/aruba_cert_renewer.py"]
CMD ["--config", "/config/config.toml", "--renew-due"]
