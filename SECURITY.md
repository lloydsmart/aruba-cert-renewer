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

## Local Security-Sensitive File Integrity

The application validates `config.toml`, the dedicated SSH `known_hosts` file,
the public verification CA file, Aruba password files, and OPNsense `*_FILE`
credentials through a shared fail-closed opener. The final path component must
not be a symbolic link, the opened descriptor must identify a regular file,
and the owner UID must be either root or the process effective UID. Files that
are group-writable or world-writable are rejected. Owner-write and additional
read bits are allowed when ownership and actual read access are appropriate.

For native execution, owner `the invoking account` and mode `0600` are the
recommended settings for configuration and secrets. Read-only modes such as
`0400` and group-readable modes such as `0440` or `0640` are accepted for
configuration and public trust inputs when the owner remains root or the
effective UID and no group/other write bit is present. Mode `0440` alone does
not establish trust when an unrelated UID owns the file.

The container runs as UID/GID `10001:10001`. Credential files should use one
of these concrete patterns:

* owner `10001:10001`, mode `0400`; or
* preferably owner `root:10001`, mode `0440` where host management permits it.

The same trusted-owner/no-group-or-other-write policy applies to mounted
configuration and trust files. All mounts should remain read-only. Mount
read-only status complements the application's metadata validation and does
not replace it.

Where supported, the opener uses `O_NOFOLLOW` and validates metadata from the
opened descriptor with `fstat`. Its portable fallback rejects a pre-open
symlink and compares pre-open, post-open, and descriptor identities before
reading. Parent-directory symlinks remain supported; only the configured final
component is rejected. The SSL and SSH libraries subsequently reopen CA and
`known_hosts` files by pathname, so the application revalidates immediately
before each handoff but cannot eliminate that final library-level pathname
race. Deployment directories must therefore be protected from unrelated
writers.

## Container Publication

Normal container CI has no package-write permission and never publishes an
image. Only the GitHub Release publishing workflow receives `packages: write`,
and it authenticates with the repository-scoped `GITHUB_TOKEN`, not a personal
access token, after the exact release image passes the full smoke tests. The SHA
tag provides an exact source-commit audit reference. The release workflow also
has only the additional `attestations: write` and `id-token: write` permissions
needed to create attestations; it does not receive `contents: write` or
artifact-metadata write access.

Publication does not add real deployment configuration, CA material, or
secrets to the image, and does not weaken the documented runtime hardening.

## Container Build Supply Chain

Container build inputs are immutable and reconstructable from each source
commit. The Python base image uses a readable exact patch-level tag together
with an immutable multi-platform OCI index digest. Runtime, development, and
lock-generation dependencies are completely version-locked with SHA-256
package hashes. Every committed lock is installed with pip hash verification.

Human-maintained dependency inputs are separate from generated locks. The
runtime input contains direct application dependencies, the development input
contains only development tools and is compiled against the runtime lock, and
the tools input pins both pip and pip-tools. The lock-compilation script requires
Python 3.12 and those exact tool versions, suppresses environment-derived index
configuration in generated output, preserves resolved versions normally, and
supports an explicit full refresh. CI regenerates all locks with the pinned
tools and fails if they change. Weekly Dependabot updates cover pip, Docker, and
GitHub Actions inputs.

Each release generates an SPDX JSON SBOM from the exact local image that already
passed the container smoke tests. The workflow retains the SBOM as a
release-specific workflow artifact, tags and publishes that same local image,
resolves and validates its registry OCI manifest digest, and publishes both build
provenance and SBOM attestations for the digest to GitHub and GHCR. It does not
perform a second image build or automatically upload the SBOM as a GitHub
Release asset. Attestation failure after publication fails visibly and does not
trigger destructive rollback.

To reconstruct and audit the immutable inputs associated with a source commit
or release tag, check out that exact revision, inspect the digest-pinned `FROM`
line and the three dependency inputs, install `requirements-tools.txt` in a
clean Python 3.12 environment with `--require-hashes`, run
`./scripts/compile-requirements.sh`, and require no lockfile diff. Then run
`tests/container-smoke.sh` to build and verify the image from those inputs. For
a published release, compare the source-SHA tag and published OCI digest with
the workflow's SPDX artifact and provenance/SBOM attestations.

These controls make build inputs immutable, reproducible, and auditable. They
do not claim that independent Docker builds on different architectures,
engines, filesystem implementations, or timestamps produce a byte-for-byte
identical final image digest.

## Repository and Release Protection

Repository rulesets protect the integrity and provenance of the default branch
and published release references. They prevent direct or destructive changes
to `main`, require signed commits and CodeQL results for protected history, and
make existing release tags immutable.

External Actions referenced by GitHub Actions workflows use immutable
references. Repository-backed Actions are pinned to full 40-character commit
SHAs, with the intended release or version retained in a same-line comment.
Docker-based Actions are pinned to immutable `sha256` image digests. Dependabot
maintains supported repository-backed GitHub Action SHA pins; Docker-based
`docker://` Action digests currently require manual maintenance. Release
workflows must contain no mutable executable Action references.

The active `Protect main` branch ruleset has no bypass actors and targets
`~DEFAULT_BRANCH`, currently `main`. It applies these rules:

* `deletion`: deletion of `main` is prohibited.
* `non_fast_forward`: force pushes and other non-fast-forward updates are
  prohibited.
* `required_signatures`: commits introduced into protected history must have
  verified signatures.
* `pull_request`: changes require a pull request. The allowed merge methods are
  merge, squash, and rebase. The required approving review count is zero;
  code-owner review, last-push approval, stale-review dismissal, and review
  thread resolution are not required.
* `code_scanning`: CodeQL security alerts at Medium or higher block the merge;
  non-security alerts do not.

GitHub may report
`require_extra_approval_for_unattributed_changes: true` as managed/default
behaviour. It has no practical effect while the required approving review
count is zero and is not a repository policy requirement.

The active `Protect release tags` tag ruleset has no bypass actors and targets
`refs/tags/v*`. Its `update` rule prevents an existing matching tag from being
moved to another commit, and its `deletion` rule prevents deletion. It has no
creation restriction: new tags such as `v1.2.3` can be created, but once
created, matching `v*` tags cannot be moved or deleted.

The existing Python tests, Python lint, Actions lint, Markdown lint, and
container tests intentionally retain their workflow `paths:` filters. Relevant
CI runs on pull requests according to those filters; these jobs are not
universal required merge gates or required status checks in the ruleset.
CodeQL merge protection is enforced separately by the native `code_scanning`
rule described above.

There is no standing administrator or other bypass. An exceptional recovery
that requires bypassing protection is a deliberate break-glass action:

1. Explicitly edit or temporarily disable the relevant ruleset.
2. Perform only the minimum necessary recovery.
3. Document the reason and actions taken.
4. Restore the ruleset immediately afterward.

### Reconstructing and Verifying the Rulesets

After a repository migration or accidental removal, an authorized maintainer
can recreate the rulesets with the GitHub CLI. Confirm the target repository
before issuing either POST request:

```bash
REPO="lloydsmart/aruba-cert-renewer"
```

Create `Protect main`:

```bash
gh api --method POST \
  -H "X-GitHub-Api-Version: 2026-03-10" \
  "repos/$REPO/rulesets" \
  --input - <<'JSON'
{
  "name": "Protect main",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": {
    "ref_name": {
      "include": [
        "~DEFAULT_BRANCH"
      ],
      "exclude": []
    }
  },
  "rules": [
    {
      "type": "deletion"
    },
    {
      "type": "non_fast_forward"
    },
    {
      "type": "required_signatures"
    },
    {
      "type": "pull_request",
      "parameters": {
        "allowed_merge_methods": [
          "merge",
          "squash",
          "rebase"
        ],
        "dismiss_stale_reviews_on_push": false,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_approving_review_count": 0,
        "required_review_thread_resolution": false
      }
    },
    {
      "type": "code_scanning",
      "parameters": {
        "code_scanning_tools": [
          {
            "tool": "CodeQL",
            "alerts_threshold": "none",
            "security_alerts_threshold": "medium_or_higher"
          }
        ]
      }
    }
  ]
}
JSON
```

Create `Protect release tags`:

```bash
gh api --method POST \
  -H "X-GitHub-Api-Version: 2026-03-10" \
  "repos/$REPO/rulesets" \
  --input - <<'JSON'
{
  "name": "Protect release tags",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": {
    "ref_name": {
      "include": [
        "refs/tags/v*"
      ],
      "exclude": []
    }
  },
  "rules": [
    {
      "type": "update",
      "parameters": {
        "update_allows_fetch_and_merge": false
      }
    },
    {
      "type": "deletion"
    }
  ]
}
JSON
```

List the recreated rulesets and inspect their IDs and configuration:

```bash
gh api \
  -H "X-GitHub-Api-Version: 2026-03-10" \
  "repos/$REPO/rulesets"
```

Verify the effective rules applying to `main`:

```bash
gh api \
  -H "X-GitHub-Api-Version: 2026-03-10" \
  "repos/$REPO/rules/branches/main"
```

The effective result for `main` must include `deletion`,
`non_fast_forward`, `required_signatures`, `pull_request`, and
`code_scanning`.

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
been validated against the currently pending Aruba CSR. Before any installation
command is sent, the certificate must also pass cryptographic server-certificate
path and configured-host identity verification against a trust store containing
every public CA certificate in the securely opened `verification.ca_file`
bundle. The installer must never confirm an unexpected interactive prompt or
issue save, reboot, delete, clear, or CSR-generation commands.

After installation, a new TLS connection to the switch must verify all three of
these properties before the operation succeeds:

* The served certificate chains to the configured CA.
* Normal hostname or IP verification succeeds for the configured switch host.
* The served certificate is byte-for-byte the expected certificate in DER form.

The configured CA file contains public certificate material only. It must be
loaded securely for pre-install path verification and by Python's normal SSL
trust machinery for live verification. TLS hostname checking and certificate
verification must never be disabled, including during bounded post-install
retries. The live check remains mandatory because it verifies what the switch
actually serves, including exact certificate equality; pre-install path
verification does not replace it.

An installation or verification error after the Aruba installation command may
mean that the new certificate is already active. The tool must report that state
clearly and must not attempt automatic rollback or other recovery changes.
