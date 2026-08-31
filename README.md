# Aruba Certificate Renewer

[![Python lint](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/lint-python.yml/badge.svg)](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/lint-python.yml)
[![Markdown lint](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/lint-markdown.yml/badge.svg)](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/lint-markdown.yml)
[![Actions lint](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/lint-actions.yml/badge.svg)](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/lint-actions.yml)
[![Tests](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/test-python.yml/badge.svg)](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/test-python.yml)
[![Container tests](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/test-container.yml/badge.svg)](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/test-container.yml)
[![CodeQL](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/github-code-scanning/codeql)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

Automates monitoring and staged renewal of HTTPS certificates on
ArubaOS-Switch devices such as the Aruba 2930M.

## Current Status

Implemented:

- SSH connectivity to ArubaOS-Switch using Netmiko
- Mandatory strict SSH host-key verification using a dedicated trust file
- Active Web certificate discovery and expiry reporting
- Explicit CSR generation on one selected switch
- Read-only retrieval of an existing pending CSR
- Cryptographic CSR validation, including legacy WC.16.11 RSA/SHA-1
  proof-of-possession signatures
- Signing an existing CSR with an internal OPNsense CA
- Strict validation and safe output of the issued public certificate
- Install-only activation of an already-issued certificate on a pending Aruba CSR
- Mandatory post-install HTTPS chain, hostname, and exact-certificate verification
- Explicit one-command renewal with collision-safe automatic certificate naming
- Sequential threshold-based renewal across all or one configured switch
- Hardened one-shot container packaging for unattended threshold renewal

The `--sign-csr` stage does **not** install or activate the resulting certificate
on the switch. Generation, retrieval/signing, and installation remain available
as explicit, independently invoked stages for debugging and recovery.
External scheduling and final network deployment remain planned work.

## Architecture

There is one user-facing orchestration command:
`src/aruba_cert_renewer.py`.

- ArubaOS-Switch communication uses SSH through Netmiko. The switch generates
  and retains the certificate private key.
- OPNsense communication uses its HTTPS JSON Trust API through the standard
  Python library. TLS server-certificate verification is always enabled.
- Post-install verification opens a new standard-library TLS connection to the
  configured switch host and verifies that same DNS or IP identity.
- `src/opnsense_client.py` contains only the narrowly scoped OPNsense HTTP/JSON
  interaction.

The OPNsense client is restricted to these routes:

- `GET /api/trust/cert/ca_list`
- `POST /api/trust/cert/add`
- `POST /api/trust/cert/generate_file/<uuid>/crt`

> [!CAUTION]
> `/api/trust/cert/search` must never be used. Current OPNsense versions can
> expose stored private-key material through that endpoint. This project also
> never requests the `prv` or `pkcs12` download types.

## Requirements

- Python 3.12 or later
- cryptography 50.0.1
- Netmiko 4.7.0

Install the development dependencies in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

No additional HTTP runtime dependency is needed.

## Docker

The container is a finite, one-shot job. With no command override, it runs
`--config /config/config.toml --renew-due`, processes configured switches
sequentially, prints the aggregate result, and exits with the application's
normal exit code. It contains no scheduler, daemon, web service, health check,
or inbound port. External scheduling and the final network deployment are
separate concerns.

Build the local image with:

```bash
docker build -t aruba-cert-renewer:local .
```

For a normal deployment, pull the most recently published stable release:

```bash
docker pull ghcr.io/lloydsmart/aruba-cert-renewer:latest
```

Container CI and container publishing are deliberately separate. During normal
development, a relevant pull request or push to `main` builds the container,
runs the full container smoke tests, and discards the local CI image. Nothing is
published to GHCR, and pushes to `main` never update registry tags.

Publishing a GitHub Release with a tag such as `v1.2.3` is the explicit
promotion action; creating a Git tag alone does not publish an image. Release
tags must have the form `vMAJOR.MINOR.PATCH`, optionally followed by a
prerelease suffix such as `-rc.1`; build metadata using `+` is not supported.
The release workflow checks out that exact tag, builds and smoke-tests its
source independently of normal CI, and only then publishes the tested image. A
successful stable release publishes:

```text
ghcr.io/lloydsmart/aruba-cert-renewer:vX.Y.Z
ghcr.io/lloydsmart/aruba-cert-renewer:sha-<commit>
ghcr.io/lloydsmart/aruba-cert-renewer:latest
```

The `vX.Y.Z` tag identifies the human release, the `sha-...` tag identifies its
exact source commit for audit purposes, and `latest` identifies the newest
successfully published stable release. A GitHub prerelease such as
`v1.2.3-rc.1` publishes its version and SHA tags but does not move `latest`.

The release workflow has not by itself demonstrated that a package is already
available. Its first successful publication may create a GHCR package whose
visibility must then be checked and, for the intended deployment, manually set
to public in GitHub. The workflow does not administer package visibility and
does not use a personal access token.

Unraid is intended to consume `latest` once the package is public. Whether
Unraid automatically pulls a changed image and recreates or restarts the
container is a separate operational policy.

The image runs as UID/GID `10001:10001`. A hardened, network-isolated help
check requires no deployment files:

```bash
docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  aruba-cert-renewer:local \
  --help
```

[`compose.example.yaml`](compose.example.yaml) shows the intended generic
mounts and runtime restrictions. Validate its syntax with:

```bash
docker compose -f compose.example.yaml config
```

Do not start the example until local configuration, public CA, and secret files
have been created. The expected paths inside the container are:

- `/config/config.toml`
- `/config/known_hosts`
- `/config/internal-ca.crt.pem`
- `/run/secrets/opnsense_api_key`
- `/run/secrets/opnsense_api_secret`
- `/run/secrets/aruba_example_switch_password`

The real `config.toml`, public CA, and credential files are read-only mounts;
they are not baked into the image. A portable container configuration resolves
the public CA relative to `config.toml` and references the Aruba credential by
its absolute mounted path:

```toml
[ssh]
known_hosts_file = "known_hosts"

[verification]
ca_file = "internal-ca.crt.pem"

[[switches]]
name = "EXAMPLE-SWITCH"
host = "switch.example.com"
username = "cert-renewer"
password_file = "/run/secrets/aruba_example_switch_password"
```

All bind-mounted source files needed at runtime must be readable by container
UID `10001`, including `config.toml`, the dedicated `known_hosts` file, the
public CA certificate, and credential or secret files. Credential files should
also remain inaccessible to unrelated host users. For a typical root-managed
deployment, set each source secret's ownership and mode before starting the
container, for example:

```bash
chown 10001:10001 secrets/opnsense_api_key
chmod 0400 secrets/opnsense_api_key
```

The Compose file is an example, not the final network deployment. A production
network policy should allow only required outbound Aruba SSH (TCP/22), Aruba
HTTPS (TCP/443), OPNsense HTTPS API, and environmental DNS/NTP access. No
inbound connectivity is required.

## Configuration

Copy the example configuration:

```bash
cp config.example.toml config.toml
```

Example:

```toml
[settings]
warning_days = 30

[ssh]
known_hosts_file = "known_hosts"

[csr]
organization = "Example Organization"
organizational_unit = "Infrastructure"
locality = "Example City"
state = "Example State"
country = "GB"
key_type = "rsa"
key_size = 2048

[opnsense]
base_url = "https://tank.example.com:8443"
ca = "internal-ca"
lifetime_days = 397
digest = "sha256"

[verification]
ca_file = "/etc/aruba-cert-renewer/internal-ca.crt.pem"

[[switches]]
name = "EXAMPLE-SWITCH"
host = "switch.example.com"
additional_sans = ["192.0.2.10"]
username = "cert-renewer"
password_file = "/run/secrets/aruba_example_switch_password"
```

`opnsense.ca` is the CA's human-readable description, not its refid. The tool
resolves it through `ca_list` and requires exactly one match.

`ssh.known_hosts_file` is required for every operation. It names the
application's dedicated OpenSSH-format host-key trust file; the user's general
`~/.ssh/known_hosts` is never used as a fallback. Relative paths are resolved
from the directory containing the active `config.toml`, not from the current
working directory, and absolute paths are supported. For a native deployment,
place `known_hosts` alongside `config.toml` or configure an absolute path. The
Compose example mounts the host's `./known_hosts` read-only at
`/config/known_hosts`, so the relative value above resolves correctly from
`/config/config.toml`.

Each switch requires only `name` and `host`. The host may be a DNS hostname,
IPv4 address, or IPv6 address. It is the SSH and live HTTPS connection target,
the certificate Common Name, and the primary SAN; it is included automatically
and does not need to be repeated in `additional_sans`. Optional
`additional_sans` may mix DNS names, IPv4 addresses, and IPv6 addresses.
Duplicate identities are removed without performing DNS resolution. The former
`fqdn` field has been removed and is rejected with a migration error.

The optional `username` and `password_file` fields select credentials for that
switch. Literal `password` values are forbidden in TOML. Relative password-file
paths are resolved relative to `config.toml`; absolute paths such as
`/run/secrets/...` support container secret mounts.

`verification.ca_file` is the public PEM certificate for the CA that issued the
switch HTTPS certificate. It is required by `--install-certificate`, `--renew`,
and `--renew-due`, and is loaded by Python's normal SSL trust machinery.
Relative paths are resolved relative to `config.toml`, not the process working
directory. Do not put a CA private key or real infrastructure certificate in
the repository.

`config.toml` is excluded from Git and should contain the real inventory. It
must never contain OPNsense API credentials.

## SSH Host-Key Enrollment and Rotation

SSH host-key verification is mandatory because SSH credentials and switch
commands must not be exposed to an unauthenticated or impersonated endpoint.
Every connection checks the identity for exactly the configured `switch.host`
against the dedicated `ssh.known_hosts_file`. An unknown key fails closed, and
a changed key fails closed, before authentication or Aruba command execution.
The application never learns, accepts, replaces, or rotates a host key
automatically.

For ArubaOS-S enrollment, collect a candidate key from a trusted administrative
workstation. For a switch configured as `switch.example.com`, an example is:

```bash
ssh-keyscan -T 5 -t rsa switch.example.com > known_hosts.candidate
ssh-keygen -E md5 -lf known_hosts.candidate
```

`ssh-keyscan` does **not** authenticate the key. Successful retrieval is not
evidence that the candidate belongs to the switch. Independently inspect the
switch over an already trusted management path or local console and run:

```text
show crypto host-public-key fingerprint
```

Compare the MD5 fingerprint printed by `ssh-keygen` with the switch's **SSHv2**
host-key fingerprint, labelled `host_ssh2.pub` in the command output. Only after
they match should the candidate entry be copied into the deployment
`known_hosts` file under the exact hostname or IP literal configured as
`switch.host`. Do not substitute a DNS-resolved IP address for a configured
hostname.

A legitimate host-key rotation is deliberately an operator action:

1. Expect monitoring and renewal to fail when the switch presents the changed
   key.
2. Independently verify the new fingerprint through a trusted management path
   or console.
3. Replace only that switch's entry in the deployment `known_hosts` file.
4. Rerun the renewer.

There is no automatic rotation, `accept-new`, trust-on-first-use, or interactive
host-key acceptance mode.

## Credentials

Aruba SSH credentials are resolved independently for every switch. A configured
`switches.username` takes precedence over `ARUBA_SSH_USERNAME`, followed by an
interactive prompt. A configured `switches.password_file` takes precedence over
`ARUBA_SSH_PASSWORD`, followed by a non-echoing interactive prompt. The
environment variables therefore remain convenient global fallbacks:

```text
ARUBA_SSH_USERNAME
ARUBA_SSH_PASSWORD
```

OPNsense API keys and secrets can be supplied directly through environment
variables, which is convenient for interactive or manual use:

```text
OPNSENSE_API_KEY
OPNSENSE_API_SECRET
```

For unattended containers, reference mounted secret files instead:

```text
OPNSENSE_API_KEY_FILE
OPNSENSE_API_SECRET_FILE
```

Each credential is resolved independently. Its `*_FILE` variable takes
precedence over the corresponding direct variable, so the key and secret may
use different source types. A configured file is authoritative: an empty,
invalid, unreadable, or malformed file fails closed and does not fall back to
the direct variable. Each secret file must contain exactly one non-empty UTF-8
line; either no terminator, one final LF, or one final CRLF is accepted.

For example, Docker or another container runtime can mount secrets beneath
`/run/secrets`:

```sh
export OPNSENSE_API_KEY_FILE=/run/secrets/opnsense_api_key
export OPNSENSE_API_SECRET_FILE=/run/secrets/opnsense_api_secret
```

The OPNsense API key and secret are sent using HTTP Basic authentication over
verified HTTPS. Credentials and secret-file contents must never be placed in
`config.toml`, logged, or committed. OPNsense credentials are not accepted in
TOML or as command-line arguments.

## OPNsense Least-Privilege ACL

Install the bundled
[`ACL.xml`](examples/opnsense/ArubaCertRenewer/ACL/ACL.xml) on OPNsense at:

```text
/usr/local/opnsense/mvc/app/models/LloydSmart/ArubaCertRenewer/ACL/ACL.xml
```

After adding or changing the file, rebuild the ACL cache on OPNsense:

```sh
rm -f /var/lib/php/tmp/opnsense_acl_cache.json
```

Then refresh **System -> Access -> Privileges** and assign only
**API: Aruba Certificate Renewer** to the dedicated API user.

Do not grant the automation **System: Certificate Manager** or **All pages**
unless the same user independently needs those privileges for unrelated work.
In particular, **System: Certificate Manager** grants `api/trust/cert/*`, which
includes APIs capable of returning or exporting private keys.

## Usage

Activate the virtual environment, then run the certificate monitor:

```bash
source .venv/bin/activate
python src/aruba_cert_renewer.py
```

Use `--switch NAME` for one switch, `--config FILE` for another configuration
file, and `--debug` for detailed Netmiko connection logging.

### Renew a Certificate Now

Run the complete, explicitly requested renewal for one switch:

```bash
python src/aruba_cert_renewer.py \
  --switch EXAMPLE-SWITCH \
  --renew
```

`--renew` renews immediately. It does not consult `settings.warning_days` to
decide whether renewal is due. Before changing anything, it performs a read-only
preflight that requires exactly one installed Web certificate and no pending Web
CSR. It selects the first unused certificate name for the current UTC date in
the form `webcert-YYYYMMDD-NN`, checking all certificate usages for collisions
and never deleting or overwriting an existing name.

The command then composes the same independently validated generation, signing,
installation, Aruba post-install verification, and mandatory live HTTPS
verification stages described below. It does not persist the intermediate CSR
or certificate to disk. The staged commands remain available for diagnosis and
recovery.

### Renew Certificates at the Warning Threshold

Check every configured switch sequentially and renew only certificates whose
remaining lifetime is less than or equal to `settings.warning_days`:

```bash
python src/aruba_cert_renewer.py --renew-due
```

Add `--switch EXAMPLE-SWITCH` to consider only one switch. Healthy switches do
not contact OPNsense or perform renewal. Per-switch credential, monitoring, or
renewal failures are reported and do not prevent later switches from being
processed; any such error makes the command exit with code 2.

If a pending Web CSR already exists, both renewal modes fail closed without
resuming, replacing, or clearing it. Use the staged commands to inspect and
recover the pending state.

### Generate a CSR

CSR generation is an explicit switch modification. It requires one named switch
and a new, unused certificate name:

```bash
python src/aruba_cert_renewer.py \
  --generate-csr \
  --switch EXAMPLE-SWITCH \
  --certificate-name webcert2027 \
  --csr-output switch.csr.pem
```

The command discovers the active certificate's TA profile, creates a private key
and pending CSR on the switch, retrieves the CSR, and validates its signature,
subject, key type, and key size. Omit `--csr-output` to print the validated CSR.

The switch retains the private key associated with a pending CSR. Do not reboot
the switch while a CSR that you intend to sign and install is pending.

AOS-S WC.16.11.0015 has been observed generating RSA/SHA-1 PKCS#10 CSR
self-signatures. SHA-1 is accepted only to verify this switch proof of possession.
It is rejected for an issued HTTPS certificate.

### Retrieve a Pending CSR

Use the read-only retrieval operation after a CSR already exists:

```bash
python src/aruba_cert_renewer.py \
  --retrieve-csr \
  --switch EXAMPLE-SWITCH \
  --certificate-name webcert2027 \
  --csr-output switch.csr.pem
```

The tool confirms that the named entry is a pending Web CSR and performs the same
validation used after generation. It never enters configuration mode or creates,
replaces, installs, deletes, or saves switch state.

### Sign an Existing Pending CSR

Set the OPNsense environment credentials, then run:

```bash
python src/aruba_cert_renewer.py \
  --switch EXAMPLE-SWITCH \
  --sign-csr \
  --certificate-name webcert2027 \
  --certificate-output switch-2027.crt.pem
```

This operation:

1. Confirms that the named Aruba certificate is an existing pending Web CSR.
2. Retrieves and validates it without generating or replacing anything.
3. Resolves the configured OPNsense CA description.
4. Requests a server certificate with exactly the configured DNS and IP SANs.
5. Retrieves only the public certificate.
6. Validates the key, subject, CN, SANs, Basic Constraints, serverAuth EKU,
   validity period, signature strength, and RSA key size.
7. Exclusively creates `--certificate-output` only after validation succeeds.

The command refuses to overwrite an existing output file. It does not install,
activate, or save the certificate on the Aruba switch.

### Install an Issued Certificate

Install an already-issued public certificate onto its existing pending CSR:

```bash
python src/aruba_cert_renewer.py \
  --switch EXAMPLE-SWITCH \
  --install-certificate \
  --certificate-name webcert2027 \
  --certificate-input switch-2027.crt.pem
```

The install stage reads one bounded ASCII PEM certificate, retrieves and
validates the named pending CSR again, and validates the certificate against
that CSR and the configured switch identity before entering configuration mode.
It then requires the expected Aruba certificate-paste and replacement prompts;
the replacement confirmation is never sent for an unexpected prompt.

Installing a Web certificate replaces the switch's current Web certificate.
The tool confirms that the named entry changed from `CSR` to an installed Web
certificate without changing its TA profile. It does not issue `write memory`,
save, reboot, delete, clear, or CSR-generation commands during installation.

Live HTTPS verification is mandatory. The tool opens a new connection to the
configured `host` on TCP/443 and uses that same DNS name or IP address as
`server_hostname`; `additional_sans` never change the endpoint. Python's normal
CA and identity verification must succeed, and the live peer certificate's DER
bytes must exactly match the supplied certificate. Transient connection,
handshake, and old-certificate results are retried for a bounded window of about
30 seconds.

If an error occurs after installation is attempted, the certificate may already
be active. In particular, a failed live HTTPS check returns exit code `2` and
requires manual investigation. The tool does not automatically restore, delete,
regenerate, reboot, or otherwise roll back certificate state.

### Staged Renewal Workflow

For debugging, recovery, or separately managed artifacts, the staged workflow
remains available:

1. Generate a pending CSR with `--generate-csr`.
2. Retrieve it with `--retrieve-csr`, or retrieve and sign it with `--sign-csr`.
3. Install the issued file with `--install-certificate`.
4. Let the install operation verify the live HTTPS service before treating the
   renewal as successful.

## Exit Codes

| Code | Meaning                                                              |
| ---: | -------------------------------------------------------------------- |
|  `0` | The operation succeeded; `--renew-due` switches are healthy/renewed  |
|  `1` | Read-only monitoring found an expired or renewal-due certificate     |
|  `2` | The requested operation failed or a switch could not be checked      |

## Safety

Monitoring and pending-CSR retrieval are read-only. CSR generation creates
pending switch state. Signing creates a public certificate object in OPNsense
but never retrieves a private key; the corresponding Aruba private key remains
on the switch. Installation explicitly replaces the current Web certificate but
does not save, clear, delete, reboot, or regenerate certificate state. Success is
reported only after mandatory verified HTTPS presents the exact installed
certificate.

## License

This project is licensed under the GNU General Public License v3.0. See
[LICENSE](LICENSE).
