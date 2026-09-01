FROM python:3.14.7-slim-trixie@sha256:656d12e70054d5fda18a045e2494c96701e9792dd1445f95b3d038df954f57e9

LABEL org.opencontainers.image.source="https://github.com/lloydsmart/aruba-cert-renewer" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      net.unraid.docker.icon="https://raw.githubusercontent.com/lloydsmart/aruba-cert-renewer/main/assets/icon.png"

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
