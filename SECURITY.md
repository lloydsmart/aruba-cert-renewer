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
image. The release workflow defaults to `contents: read`. Its verification job
inherits only that read permission and receives no package, attestation, or
OIDC write privileges. Before building, six reusable workflows must explicitly
confirm success for lint, the full Python 3.12/3.14 suite, lock freshness,
dependency audit, full-history secrets, Hadolint and Compose. All checkouts use
the exact event commit; missing, skipped, cancelled or failed checks block.

A separate read-only authorization job validates GitHub's signed annotated tag
metadata, main ancestry and the exact event commit. It verifies the raw tag's
object ID, signed name and direct source commit with GnuPG in an isolated
public-only keyring. The approved primary fingerprint is
`02EBB31CC0032A86C2C0401A1534542E61DC82D3`, including its certified signing
subkeys. Tagger names or short key IDs cannot authorize publication. Invalid,
expired, revoked, ambiguous or other-key signatures fail closed. The reviewed
public key is in `.security/release-signing-key.asc`; automatic key retrieval
and key import are disabled during verification.

The builder must use the authorized event commit. It builds one candidate and
smoke-tests, scans, and generates an SPDX JSON SBOM from that exact image.

Only the publication job receives `packages: write`, `attestations: write`, and
`id-token: write`, alongside `contents: read`. It does not receive
`contents: write`, `actions: write`, `artifact-metadata: write`,
`security-events: write`, or other write permissions. It authenticates with
the repository-scoped `GITHUB_TOKEN`, not a personal access token, only after
the verified candidate has been imported and checked.

The unprivileged job exports the tested image with `docker save` and creates a
canonical, bounded manifest for an exact three-file handoff. The manifest binds
the archive size and SHA-256, independently parsed config digest, optional OCI
manifest and archive-index digests, reconstructed Syft-native manifest digest,
SBOM size and SHA-256, and the repository, workflow, run, attempt, release, tag
object, source and prerelease identities. The upload action's numeric artifact
ID and digest select the exact current-run artifact without a name fallback.
The privileged job does not check out, rebuild, or execute repository source.
Fixed inline workflow code rejects non-canonical or ambiguous JSON, unsafe
inventory, identity substitution and an unrelated SPDX subject.

Pinned Syft scans the exported archive with only a display-name setting and no
source-version override. The display name is not an image identity. Both
validators independently parse one Docker image, hash its config and layers,
verify layer diff IDs, and reconstruct the native Syft manifest digest from the
ordered descriptors. The SPDX container's native version, checksum and OCI purl
must match that value. User-overridable scanner metadata is not an identity
authority. OCI-layout archives must contain exactly one index descriptor that
selects one supported image manifest; nested indexes and multiple descriptors
are rejected. Classic single-image Docker archives are supported without
claiming an unavailable archive manifest or index digest. The publisher then
loads the archive and verifies source, license and immutable-icon labels before
registry authentication. This binding assumes the pinned scanner honestly
reports the inventory it observed; it does not prove an intentionally dishonest
scanner produced an accurate package list.

Both archive validators preflight the complete tar stream before Python's tar
parser sees it. They bound expanded archive bytes, ordinary members, extension
headers, POSIX and Solaris PAX records and bytes, metadata files, layer count,
trailing padding, and total uncompressed layer bytes. Oversized numeric PAX
fields and GNU sparse metadata are rejected before integer conversion or sparse
processing. JSON integers and gzip filename/comment fields are also bounded
before conversion or unbounded byte-at-a-time scanning. Gzip inputs must contain
one member; concatenated members are rejected. These limits prevent compressed
or metadata-driven candidate inputs from causing unbounded allocation,
accumulation, or decompression in either trust domain. Outer XZ compression is
rejected because its stream metadata can request decoder memory before an
expanded-byte ceiling takes effect.

The publisher also requires the independent authorization job's source, tag and
tag-object ID and the complete qualification receipt. It rechecks GitHub's
current ref and immutable signed object against those identities before
downloading or loading the candidate. These checks use fixed workflow commands,
not repository scripts or candidate executables; no publisher checkout is added.
The authorization runner, reviewed workflow source and GitHub job-output
integrity remain trusted. The builder cannot supply its own authorization.

Publisher jobs are serialized package-wide in addition to the per-tag workflow
queue. Before a mutation, the publisher strictly inspects both version and
source aliases. It either publishes the version once and copies its exact OCI
digest to the source alias, copies an existing valid digest only to a missing
alias, or preserves two aliases already at the same tested digest. Existing
alias disagreement, config-digest mismatch, index responses and ambiguous
absence fail closed. Absence requires a reference-specific `not found` or
`manifest unknown` result; credential-helper, authentication, authorization,
transport, throttling, server, malformed, mixed and unexplained HTTP errors do
not authorize mutation.
Successful partial state is retained for investigation or a later full rerun;
there is no delete, repoint or destructive rollback. Failures report whether no
mutation was attempted, a remote outcome is uncertain, or version/source alias
publication or reuse was confirmed. An eligible `latest` copy is the final
registry mutation and occurs only after both immutable aliases and both
attestation uploads succeed.

The published-release trigger and existing prerelease suffix and `latest` rules
are retained. Older tagged commits retain their historical workflows; these
controls cannot retroactively secure old release paths. Public revocation/key
updates require a reviewed PR. The [release procedure](docs/releasing.md)
documents the supported signing identity and these limits. The queues serialize
only participating jobs; they are not an atomic registry conditional write and
cannot exclude uncontrolled external GHCR writers. Tag-creation authority,
consumer verification and immutable finalization remain separate controls.

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
passed the container smoke tests and Trivy scan. The unprivileged verification
job retains the SBOM as a release-specific workflow artifact and transfers it
with the exported candidate across the publication boundary. The privileged
job independently validates and imports that candidate without rebuilding it,
then establishes or recovers the version and source aliases at one exact OCI
manifest digest. It uploads both build-provenance and SBOM attestations for that
digest to GitHub and GHCR, using the transferred SBOM rather than generating
another one. These are attestation uploads, not consumer verification. It does
not automatically upload the SBOM as a GitHub Release asset. Attestation failure
after immutable publication fails visibly, prevents `latest`, and does not
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

## Automated Security Scanning

The repository uses three pinned scanners in addition to GitHub CodeQL default
setup, which remains the static source-code security scan:

* Gitleaks scans all reachable Git history with the merge-aware options `--cc`,
  `--full-history`, `--all`, and `--diff-filter=tuxdb`. Before Gitleaks runs,
  the wrapper requires a reachable commit and independently runs the equivalent
  host `git log -p -U0` operation. This prevents an underlying Git failure from
  being mistaken for a clean Gitleaks result.
* pip-audit scans all four fully resolved, hash-locked dependency sets: runtime,
  development/test, lock-generation, and security-scanner tooling. It disables
  pip-based resolution and fails if a committed requirement lacks a hash.
* Trivy scans the tested image and its exact digest-pinned upstream using the
  same downloaded database snapshots and Linux platform. It reports inherited,
  introduced, and removed HIGH/CRITICAL findings. Introduced findings block
  even without a fix. Inherited findings with an available fix block unless an
  exact, explicitly reviewed, unexpired exception applies. Scans run offline
  against exported archives without access to the Docker socket.

Unfixed inherited vulnerabilities remain visible for impact review. A newly
available fix makes an inherited finding block automatically. The
[common image policy](docs/container-image-policy.md) defines matching,
fail-closed inputs, and explicit review with a maximum 90-day exception lifetime.
The initial `.security/container-exceptions.json` registry is empty. Existing
pip-audit risk acceptance does not grant a container exception.

Secret and dependency scans run for every pull request and push to `main`, as
well as weekly. Container CI smoke-tests one image and then scans that same
image, with a weekly run to detect newly disclosed vulnerabilities. Release
candidates are scanned after smoke testing in the unprivileged verification
job, before artifact handoff, registry login, or publication. Scanner
executables are immutable and version-pinned, while their vulnerability
databases and resulting findings intentionally evolve.

The only current scanner exception is the exact pip-audit advisory
`PYSEC-2026-2858` for `paramiko 4.0.0` in the runtime lock. Its aliases are
`CVE-2026-44405` and `GHSA-r374-rxx8-8654`; its current severity is Low, with a
CVSS score of 3.4. The issue concerns Paramiko allowing RSA/SHA-1 signing and
verification. This is a genuine finding, not a false positive, and the
repository does not claim that it is currently mitigated.

Paramiko 5 removes the affected SHA-1 behaviour, but Netmiko 4.7.0 currently
requires Paramiko `>=3.5.0,<5.0` because Paramiko 5 caused significant upstream
compatibility breakage. Forcing an unsupported major version solely to make the
scanner green is not acceptable. `PYSEC-2026-2858` is therefore an explicit,
temporary accepted risk. Issue #10 owns review of the actual SSH algorithms
required for supported ArubaOS-Switch devices and is the appropriate place to
determine whether SHA-1 SSH support can be disabled safely; this policy does not
claim that Aruba compatibility currently requires SHA-1. Remove the exception
as soon as a supported dependency or protocol-policy remediation is available.

Any future exception must identify the exact finding, include a reviewable
rationale, and remain as narrow as the scanner permits; scanner failure must
not be bypassed globally.

The release workflow generates SPDX JSON from the tested release candidate,
retains it as a standalone workflow artifact, and transfers the same SBOM to
the publication job. Build-provenance and SBOM attestations remain bound to the
published OCI digest. Security scanning neither adds a second SBOM system nor
rebuilds the release image.

### Reconstructing GitHub-Native Security Settings

The settings in this checklist are repository-level GitHub state rather than
controls implemented in tracked files. The Dependabot version-update
configuration is the exception: it is reconstructed from the tracked
`.github/dependabot.yml` file. After a repository migration or recreation,
verify:

* Private vulnerability reporting: enabled.
* Dependency graph: enabled.
* Automatic dependency submission: enabled.
* Dependabot alerts: enabled.
* Dependabot malware alerts: enabled.
* Dependabot security updates: enabled.
* Grouped security updates: enabled.
* Dependabot version updates: configured through `.github/dependabot.yml`.
* CodeQL analysis: default setup enabled.
* Copilot Autofix for CodeQL: enabled.
* AI findings (Preview): disabled intentionally. This feature is not part of
  the repository's required security control set. It previously caused a
  failing `ghas-code-scanning-agentic` pull-request check when GitHub attempted
  to use an unsupported model.
* Secret Protection / secret scanning: enabled.
* Push protection: enabled.

These native features complement rather than replace the existing controls.
Gitleaks remains the full reachable-history secret scan, pip-audit remains the
committed dependency-lock audit, Trivy remains the tested-container-image
scanner, and CodeQL remains the native SAST and code-scanning control.
Dependabot version updates remain defined in `.github/dependabot.yml`.
The separately documented repository rulesets continue to protect `main` and
release tags.

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

## Transport Algorithms and Terminal Output

Every client TLS context uses a shared policy requiring TLS 1.2 or newer for
OPNsense API requests and Aruba live HTTPS verification. TLS 1.3 remains
available. CA certificate verification and normal DNS hostname or IP identity
verification are mandatory, and the live Aruba check also requires exact DER
equality with the expected certificate.

Supported ArubaOS-S WC.16.11 devices provide AES-CTR, HMAC-SHA2, ECDH-SHA2 or
SHA-256 key exchange, and RSA-SHA2 host-key signatures. The SSH client therefore
explicitly disables CBC and 3DES ciphers, MD5 and SHA-1 MACs, SHA-1 key
exchange, and the SHA-1 `ssh-rsa` signature algorithm. An RSA host key remains
supported through RSA-SHA2. The application does not re-enable DSA or implement
the Aruba-specific X.509 SSH algorithms advertised by some switches.

Legacy ArubaOS-S WC.16.11 firmware may generate an RSA/SHA-1 PKCS#10 CSR
self-signature. SHA-1 is accepted only in the narrowly scoped CSR
proof-of-possession verification path. Issued HTTPS certificates must use
SHA-256 or stronger, and SSH SHA-1 algorithms are independently prohibited.
This exception should be removed when supported switches no longer require it.

Operator-facing dynamic text visibly escapes all C0 and C1 control characters
before reaching stdout or stderr. Debug log messages receive the same treatment
after formatting, so endpoint-controlled ANSI sequences and embedded line breaks
cannot alter terminal state or forge log lines. Validated PEM CSR output that is
deliberately written to stdout is not passed through this display transformation.

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

This includes failure to leave configuration mode after certificate confirmation.
A cleanup failure must not hide an earlier installation failure or replace an
interruption with a misleading success result.

## Common PR Gate

The [common CI gate](docs/ci-gate-policy.md) checks explicit success from every
mandatory workflow and its internal jobs, including full-history secret and
dependency scans. It fails on cancellation, unexpected skips, malformed results,
or absent evidence. Only documented changes can skip container validation;
workflow and policy changes run the full graph. The gate has read-only
permissions and no publication privileges. Repository settings must separately
require its stable check name; this workflow change does not modify protection.
Human review remains necessary because PR code can also change its own gate.
