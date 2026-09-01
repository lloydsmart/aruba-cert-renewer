# AGENTS.md

## Purpose

This repository contains security-sensitive automation for monitoring and renewing
HTTPS certificates on ArubaOS-Switch devices using an internal OPNsense CA.

Changes must preserve the project's fail-closed behaviour, least-privilege
design, and separation between CSR generation, signing, installation, and live
verification.

Read `README.md` and `SECURITY.md` before changing certificate, credential,
network, SSH, TLS, OPNsense, or container behaviour.

## Repository layout

* `src/aruba_cert_renewer.py` contains the CLI, configuration handling, Aruba
  interaction, certificate validation, renewal orchestration, and live HTTPS
  verification.
* `src/opnsense_client.py` is the deliberately narrow OPNsense HTTPS API client.
* `tests/test_aruba_cert_renewer.py` tests the main application behaviour.
* `tests/test_opnsense_client.py` tests the OPNsense client.
* `tests/container-smoke.sh` validates the built container and hardened runtime.
* `.github/workflows/` contains CI and release workflows.
* `config.example.toml` and `compose.example.yaml` must contain example data only.

Keep changes focused. Do not perform unrelated refactoring while implementing a
specific fix or feature.

## Security invariants

Security properties documented in `SECURITY.md` are requirements, not
suggestions.

### Secrets and private keys

Never:

* Commit, print, log, persist, or expose passwords, API credentials, tokens, or
  private keys.
* Add real infrastructure credentials or inventory to examples, fixtures, or
  tests.
* Put OPNsense API credentials in TOML configuration or CLI arguments.
* Put literal Aruba passwords in TOML configuration.
* Retrieve or export Aruba certificate private keys.
* Retrieve private keys or PKCS#12 objects from OPNsense.

Aruba certificate private keys must remain on the switch.

Use synthetic credentials and infrastructure names in tests.

### OPNsense

The OPNsense client is intentionally limited to the minimum API surface required
by the application.

Permitted Trust API operations are:

* `GET /api/trust/cert/ca_list`
* `POST /api/trust/cert/add` using `action=sign_csr`
* `POST /api/trust/cert/generate_file/<uuid>/crt`

Do not:

* Use `/api/trust/cert/search`.
* Add private-key or PKCS#12 download operations.
* Disable TLS certificate or hostname verification.
* Follow redirects to another API endpoint or origin.
* Log Basic Authorization headers, API credentials, full CSRs, or full
  certificates.
* Broaden the OPNsense API surface without an explicit security review.

Credential files are authoritative when configured. Invalid, empty, malformed,
or unreadable secret files must fail closed rather than falling back to another
credential source.

### Aruba certificate state

Treat a pending Aruba CSR as valuable state because it is associated with a
private key held only by the switch.

Do not automatically:

* Clear or replace a pending CSR.
* Regenerate a pending CSR during signing or installation.
* Delete certificate state.
* Roll back an installation.
* Reboot a switch.
* Save configuration using `write memory` or an equivalent command.

Installation must only confirm the exact interactive prompts expected by the
application. Unexpected prompts must fail closed.

If an error occurs after installation has been attempted, report the ambiguous
state and require investigation rather than attempting recovery changes.

### Certificate validation

Do not weaken certificate or CSR validation to make unexpected input pass.

Preserve validation of the relevant:

* CSR proof of possession.
* Subject and Common Name.
* DNS and IP SANs.
* Public key type and size.
* Basic Constraints.
* Extended Key Usage.
* Validity period.
* Certificate signature strength.
* Relationship between the issued certificate and pending CSR.

Legacy RSA/SHA-1 may be accepted only where already documented for verifying the
proof-of-possession signature of ArubaOS-Switch WC.16.11 CSRs. Do not extend
that exception to issued HTTPS certificates.

### Live HTTPS verification

Certificate installation succeeds only after a new TLS connection verifies:

1. The certificate chains to the configured CA.
2. Normal hostname or IP identity verification succeeds for the configured
   switch host.
3. The served certificate exactly matches the expected certificate in DER form.

Do not disable hostname checking, certificate verification, or exact-certificate
matching, including during retries.

## Input handling

Preserve bounded reads and strict parsing for certificates, API responses,
secret files, configuration values, and device output.

Do not remove or materially increase safety bounds without a specific reason and
corresponding tests.

Prefer explicit rejection of malformed or ambiguous input over permissive
normalisation.

Do not overwrite existing CSR or certificate output files.

## Dependencies

The application targets Python 3.12 or later.

The full pytest suite runs in CI on Python 3.12 and Python 3.14. Python 3.14
represents the production application runtime family, while dependency lock
generation remains intentionally fixed to Python 3.12.

Runtime dependencies are deliberately small. Do not add a dependency when the
Python standard library or an existing dependency provides an adequate and
secure implementation.

Dependency additions or major upgrades require consideration of their security
and container impact.

## Tests

Install development dependencies with:

```bash
python -m pip install --require-hashes -r requirements.txt
python -m pip install --require-hashes -r requirements-dev.txt
```

For Python changes, run:

```bash
ruff check .
ruff format --check .
pytest
```

Add or update tests for behaviour changes.

Security-sensitive changes should normally test both:

* The intended successful behaviour.
* The relevant rejection or fail-closed behaviour.

Use `scripts/scan-secrets.sh`, `scripts/scan-dependencies.sh`, and
`scripts/scan-container.sh` for repository security scans. Scanner versions are
intentionally pinned. Fix findings where practical or require explicit review;
do not add broad suppressions, ignored vulnerability classes, or allow-failure
behaviour. Do not change GitHub security settings without an explicit request.

Tests must not require real Aruba switches, a real OPNsense instance, live
credentials, or access to private infrastructure unless explicitly requested.

Do not run modifying operations against real network devices as part of routine
validation.

## Container validation

The production image intentionally:

* Runs as UID/GID `10001:10001`.
* Has no exposed inbound ports.
* Runs as a finite one-shot process.
* Supports a read-only root filesystem.
* Requires no privileged mode or Linux capabilities.
* Keeps application files non-writable.
* Receives configuration and secrets through read-only mounts.

Do not weaken these properties without explicit justification.

For changes affecting `src/`, `Dockerfile`, runtime dependencies, Compose
configuration, or container behaviour, run:

```bash
tests/container-smoke.sh
```

The smoke test also validates:

```bash
docker compose -f compose.example.yaml config --quiet
```

## Documentation and CI

Update `README.md` when a change affects user-visible behaviour, configuration,
deployment, credentials, commands, or operational expectations.

Update `SECURITY.md` when a change affects the threat model, privileges,
credential handling, TLS behaviour, certificate state, or security guarantees.

Markdown must comply with `.markdownlint-cli2.jsonc`, including its 120-character
line-length rule.

GitHub Actions workflows must continue to pass `actionlint`.

Do not weaken CI checks or release safeguards merely to make a change pass.

## Git and change discipline

Maintainers should use a feature or topic branch rather than committing directly
to `main`. The repository provides `.githooks/pre-commit` and
`scripts/setup-git-hooks.sh`; the setup script enables the repository-local
protected-branch commit guard. Agents must not configure Git automatically.

Unless explicitly requested:

* Do not commit changes.
* Do not push branches.
* Do not create or update pull requests.
* Do not create releases or publish containers.
* Do not modify repository or package settings.

Before finishing, inspect the diff for accidental secrets, unrelated changes,
generated files, and formatting damage.

Prefer the smallest change that correctly solves the requested problem.
