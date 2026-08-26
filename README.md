# Aruba Certificate Renewer

[![Python lint](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/lint-python.yml/badge.svg)](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/lint-python.yml)
[![Markdown lint](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/lint-markdown.yml/badge.svg)](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/lint-markdown.yml)
[![Actions lint](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/lint-actions.yml/badge.svg)](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/lint-actions.yml)
[![Tests](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/test-python.yml/badge.svg)](https://github.com/lloydsmart/aruba-cert-renewer/actions/workflows/test-python.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

Automates monitoring and staged renewal of HTTPS certificates on
ArubaOS-Switch devices such as the Aruba 2930M.

## Current Status

Implemented:

- SSH connectivity to ArubaOS-Switch using Netmiko
- Active Web certificate discovery and expiry reporting
- Explicit CSR generation on one selected switch
- Read-only retrieval of an existing pending CSR
- Cryptographic CSR validation, including legacy WC.16.11 RSA/SHA-1
  proof-of-possession signatures
- Signing an existing CSR with an internal OPNsense CA
- Strict validation and safe output of the issued public certificate
- Install-only activation of an already-issued certificate on a pending Aruba CSR
- Mandatory post-install HTTPS chain, hostname, and exact-certificate verification

The `--sign-csr` stage does **not** install or activate the resulting certificate
on the switch. Generation, retrieval/signing, and installation remain explicit,
independently invoked stages. Automatic orchestration, configuration saving,
container deployment, and unattended renewal remain planned work.

## Architecture

There is one user-facing orchestration command:
`src/aruba_cert_renewer.py`.

- ArubaOS-Switch communication uses SSH through Netmiko. The switch generates
  and retains the certificate private key.
- OPNsense communication uses its HTTPS JSON Trust API through the standard
  Python library. TLS server-certificate verification is always enabled.
- Post-install verification opens a new standard-library TLS connection to the
  switch management IPv4 address, using the switch FQDN for hostname checking.
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

## Configuration

Copy the example configuration:

```bash
cp config.example.toml config.toml
```

Example:

```toml
[settings]
warning_days = 30

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
host = "192.0.2.10"
fqdn = "switch.example.com"
```

`opnsense.ca` is the CA's human-readable description, not its refid. The tool
resolves it through `ca_list` and requires exactly one match. For signing,
`switches.host` must be the switch management IPv4 address; it and
`switches.fqdn` are explicitly requested as IP and DNS SANs.

`verification.ca_file` is the public PEM certificate for the CA that issued the
switch HTTPS certificate. It is required by `--install-certificate` and is
loaded by Python's normal SSL trust machinery. Relative paths are resolved
relative to `config.toml`, not the process working directory. Do not put a CA
private key or real infrastructure certificate in the repository.

`config.toml` is excluded from Git and should contain the real inventory. It
must never contain OPNsense API credentials.

## Credentials

Aruba SSH credentials can be supplied interactively or through:

```text
ARUBA_SSH_USERNAME
ARUBA_SSH_PASSWORD
```

OPNsense credentials are accepted **only** through:

```text
OPNSENSE_API_KEY
OPNSENSE_API_SECRET
```

The OPNsense API key and secret are sent using HTTP Basic authentication over
verified HTTPS. They are not accepted in TOML or as command-line arguments and
must not be logged or committed.

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
  --switch HOUSE-SWITCH \
  --sign-csr \
  --certificate-name webcert2027 \
  --certificate-output house-switch-2027.crt.pem
```

This operation:

1. Confirms that the named Aruba certificate is an existing pending Web CSR.
2. Retrieves and validates it without generating or replacing anything.
3. Resolves the configured OPNsense CA description.
4. Requests a server certificate with explicit FQDN and management-IP SANs.
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
management IPv4 address on TCP/443 and uses the configured FQDN as
`server_hostname`. Python's normal CA and hostname verification must succeed,
and the live peer certificate's DER bytes must exactly match the supplied
certificate. Transient connection, handshake, and old-certificate results are
retried for a bounded window of about 30 seconds.

If an error occurs after installation is attempted, the certificate may already
be active. In particular, a failed live HTTPS check returns exit code `2` and
requires manual investigation. The tool does not automatically restore, delete,
regenerate, reboot, or otherwise roll back certificate state.

### Staged Renewal Workflow

The current workflow is intentionally explicit:

1. Generate a pending CSR with `--generate-csr`.
2. Retrieve it with `--retrieve-csr`, or retrieve and sign it with `--sign-csr`.
3. Install the issued file with `--install-certificate`.
4. Let the install operation verify the live HTTPS service before treating the
   renewal as successful.

## Exit Codes

| Code | Meaning                                                              |
| ---: | -------------------------------------------------------------------- |
|  `0` | The requested operation succeeded or all certificates are healthy    |
|  `1` | One or more certificates are expired or within the renewal threshold |
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
