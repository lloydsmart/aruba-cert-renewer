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
* Keep `OPNSENSE_API_KEY` and `OPNSENSE_API_SECRET` in the environment; do not put them in TOML or CLI arguments.
* Keep TLS certificate and hostname verification enabled for every OPNsense request.

Aruba certificate private keys are generated and stored on the switch. They must not be exported to or retrieved from
OPNsense. A pending CSR represents the valuable association with its switch-held private key and must not be cleared,
replaced, regenerated, or deleted by the signing workflow.
