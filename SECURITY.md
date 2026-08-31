# Security Policy

## Supported Versions

This project is under active development.

Only the latest version of the `main` branch is actively maintained.

## Reporting a Vulnerability

If you discover a security issue in this project, please report it privately rather than opening a public issue.

Use GitHub's private vulnerability reporting feature where available. If private reporting is unavailable, open an issue
requesting a private contact method without including details of the vulnerability.

Please include:

* A description of the issue.
* The affected component or file.
* Steps to reproduce or demonstrate the issue, where applicable.
* Any potential impact you have identified.
* Suggested mitigations, if known.

Do not include passwords, API credentials, private keys, or other live secrets in a report.

Security reports will be reviewed and addressed as appropriate.

## Container Runtime

Production deployments should retain the container's non-root UID/GID
`10001:10001`, read-only root filesystem, and tmpfs-only writable `/tmp`.
Drop all Linux capabilities and enable `no-new-privileges`. Do not use
privileged mode, host networking, a Docker socket mount, published inbound
ports, or broad host filesystem mounts.

Mount only the required configuration, dedicated SSH `known_hosts`, public CA,
and credential files, each read-only, and ensure they are readable by UID
`10001` as appropriate while credential sources remain inaccessible to
unrelated host users. Restrict network egress to the Aruba SSH and HTTPS
services, the OPNsense HTTPS API, and supporting DNS/NTP required by the
environment. These runtime controls reduce container privileges; they do not
replace the application's credential, SSH host-key, TLS, certificate, or
device-level safety checks.

## Container Publication

Normal container CI has no package-write permission and never publishes an
image. Only the GitHub Release publishing workflow receives `packages: write`,
and it authenticates with the repository-scoped `GITHUB_TOKEN`, not a personal
access token, after the exact release image passes the full smoke tests. The SHA
tag provides an exact source-commit audit reference.

Publication does not add real deployment configuration, CA material, or
secrets to the image, and does not weaken the documented runtime hardening.

## Security-Sensitive Areas

This project is intended to interact with network switches and certificate authority infrastructure. Security issues may
therefore include, but are not limited to:

* Exposure or unsafe handling of SSH or API credentials.
* Exposure or unsafe handling of private keys.
* Insufficient validation of certificate signing requests or signed certificates.
* Certificate validation bypasses.
* Command injection through configuration values or device data.
* Unintended or insufficiently constrained changes to network devices.
* Unsafe interaction with certificate authority APIs.

Particular care should be taken with any code capable of modifying device configuration or requesting, installing, or
renewing certificates.

## Sensitive Information

The repository must not contain passwords, access tokens, API keys, SSH private keys, certificate authority private keys,
or other authentication secrets.

Real deployment configuration, including device inventories and infrastructure details, should be kept outside the
repository where appropriate. The committed `config.example.toml` must contain only example data.

Public certificates and certificate signing requests are not normally secret, but their corresponding private keys must
never be committed or exported unnecessarily.

If sensitive information is committed accidentally, it should be treated as compromised and rotated or revoked as
appropriate, even if it is subsequently removed from the repository.

## OPNsense API Privileges and Key Handling

Use a dedicated OPNsense API account for this automation. Install the bundled least-privilege ACL and grant the account
only **API: Aruba Certificate Renewer**. Do not grant **System: Certificate Manager** or **All pages** to the automation
account. **System: Certificate Manager** grants `api/trust/cert/*`, including endpoints capable of returning or exporting
private keys.

The bundled ACL is least-privilege at the URI level: it prevents access to certificate search, get, private-key, and
PKCS#12 export endpoints. OPNsense ACLs cannot restrict the JSON `action` field once `/api/trust/cert/add` is granted,
however, so a compromised API credential retains broader certificate-creation and signing capability than this
application uses. The application itself sends only `action=sign_csr`, but the dedicated API credential remains
sensitive and should be restricted by source network when deployed. If stronger server-side action, CA, or SAN policy is
needed, a future dedicated OPNsense controller could enforce those constraints.

The automation is limited to CA description lookup, CSR signing, and public-certificate retrieval. In particular:

* Never call `/api/trust/cert/search`.
* Never request private-key or PKCS#12 downloads from OPNsense.
* Never log OPNsense API keys, secrets, Basic Authorization headers, full CSRs, or full certificates.
* Supply OPNsense credentials through `OPNSENSE_API_KEY` and `OPNSENSE_API_SECRET`, or reference mounted secret files
  through `OPNSENSE_API_KEY_FILE` and `OPNSENSE_API_SECRET_FILE`; do not put credentials in TOML or CLI arguments.
* Keep TLS certificate and hostname verification enabled for every OPNsense request.

Aruba certificate private keys are generated and stored on the switch. They must not be exported to or retrieved from
OPNsense. A pending CSR represents the valuable association with its switch-held private key and must not be cleared,
replaced, regenerated, or deleted by the signing workflow.

## Aruba SSH Host-Key Trust

All Aruba SSH connections require strict host-key verification against the
dedicated OpenSSH-format file configured by `ssh.known_hosts_file`. The
application does not use the operator's normal `~/.ssh/known_hosts`, perform DNS
resolution to replace the configured `switch.host` with an IP address, or offer
any setting that disables verification. Unknown and changed host keys fail
closed before authentication or command execution.

The application never uses trust-on-first-use, `AutoAddPolicy`, `accept-new`,
interactive acceptance, automatic replacement, or application-driven
`ssh-keyscan`. Operators may collect a candidate key separately with
`ssh-keyscan`, but that command does not authenticate its output. Before adding
the entry, independently compare its fingerprint with
`show crypto host-public-key fingerprint` on the ArubaOS-S switch over an
already trusted management path or console. Compare it specifically with the
switch's **SSHv2** host-key fingerprint labelled `host_ssh2.pub`.

Legitimate rotation requires the operator to verify the new fingerprint,
replace the relevant deployment `known_hosts` entry, and rerun the renewer.
Monitoring and renewal remain failed while the presented key differs from the
trusted entry. Native relative paths resolve beside the active `config.toml`;
the container example mounts `./known_hosts` read-only at
`/config/known_hosts`, beside `/config/config.toml`.

## Aruba Installation and Live Verification

Certificate installation accepts only one bounded ASCII PEM certificate that has
been validated against the currently pending Aruba CSR. The installer must never
confirm an unexpected interactive prompt or issue save, reboot, delete, clear,
or CSR-generation commands.

After installation, a new TLS connection to the switch must verify all three of
these properties before the operation succeeds:

* The served certificate chains to the configured CA.
* Normal hostname or IP verification succeeds for the configured switch host.
* The served certificate is byte-for-byte the expected certificate in DER form.

The configured CA file contains public certificate material only. It must be
loaded by Python's normal SSL trust machinery. TLS hostname checking and
certificate verification must never be disabled, including during bounded
post-install retries.

An installation or verification error after the Aruba installation command may
mean that the new certificate is already active. The tool must report that state
clearly and must not attempt automatic rollback or other recovery changes.
