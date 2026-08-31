#!/usr/bin/env bash

set -euo pipefail

image=${1:-aruba-cert-renewer:test}
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/aruba-cert-renewer-smoke.XXXXXX")

cleanup() {
    rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

docker build --tag "$image" "$repository_root"

docker run --rm \
    --network none \
    "$image" \
    --help >/dev/null

docker run --rm \
    --network none \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    "$image" \
    --help >/dev/null

image_user=$(docker image inspect --format '{{.Config.User}}' "$image")
exposed_ports=$(docker image inspect --format '{{json .Config.ExposedPorts}}' "$image")
entrypoint=$(docker image inspect --format '{{json .Config.Entrypoint}}' "$image")
default_command=$(docker image inspect --format '{{json .Config.Cmd}}' "$image")

[[ "$image_user" == "10001:10001" ]]
[[ "$exposed_ports" == "null" || "$exposed_ports" == "{}" ]]
[[ "$entrypoint" == '["python","/app/src/aruba_cert_renewer.py"]' ]]
[[ "$default_command" == '["--config","/config/config.toml","--renew-due"]' ]]

docker run --rm \
    --network none \
    --read-only \
    --entrypoint /bin/sh \
    "$image" \
    -c 'test -z "$(find /config /run/secrets -mindepth 1 -print -quit)" && test ! -w /app/src/aruba_cert_renewer.py'

docker run --rm \
    --network none \
    --user 0:0 \
    --mount "type=bind,src=$temporary_directory,dst=/staging" \
    --entrypoint /bin/sh \
    "$image" \
    -c 'printf "%s\n" synthetic-api-key >/staging/opnsense_api_key
        printf "%s\n" synthetic-api-secret >/staging/opnsense_api_secret
        chown 0:10001 /staging/opnsense_api_key /staging/opnsense_api_secret
        chmod 0440 /staging/opnsense_api_key /staging/opnsense_api_secret'

[[ "$(stat -c '%u:%g %a' "$temporary_directory/opnsense_api_key")" == "0:10001 440" ]]
[[ "$(stat -c '%u:%g %a' "$temporary_directory/opnsense_api_secret")" == "0:10001 440" ]]

docker run --rm \
    --network none \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --mount "type=bind,src=$temporary_directory/opnsense_api_key,dst=/run/secrets/opnsense_api_key,readonly" \
    --mount "type=bind,src=$temporary_directory/opnsense_api_secret,dst=/run/secrets/opnsense_api_secret,readonly" \
    --env OPNSENSE_API_KEY_FILE=/run/secrets/opnsense_api_key \
    --env OPNSENSE_API_SECRET_FILE=/run/secrets/opnsense_api_secret \
    --entrypoint python \
    "$image" \
    -c 'import sys; sys.path.insert(0, "/app/src"); from opnsense_client import OPNsenseClient; OPNsenseClient("https://opnsense.example.com")'

if env -u ARUBA_CERT_RENEWER_IMAGE \
    docker compose --env-file /dev/null \
        -f "$repository_root/compose.example.yaml" config --quiet >/dev/null 2>&1; then
    printf '%s\n' "Compose example accepted a missing ARUBA_CERT_RENEWER_IMAGE" >&2
    exit 1
fi

ARUBA_CERT_RENEWER_IMAGE="$image" \
    docker compose --env-file /dev/null \
        -f "$repository_root/compose.example.yaml" config --quiet

printf '%s\n' "Container smoke tests passed for $image"
