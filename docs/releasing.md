# Releasing

Publishing a GitHub Release remains the explicit image-promotion action. Creating
a tag alone does not publish an image. Use a reviewed commit already merged to
`main` and containing the current release controls; required main CI and CodeQL
rules continue to apply.

## Create and verify the signed tag

Release tags must be annotated and signed using Lloyd Smart's existing GPG key.
Its approved primary fingerprint is
`02EBB31CC0032A86C2C0401A1534542E61DC82D3`. Confirm that fingerprint locally, then
create the selected new tag at the reviewed commit. Never move an existing tag.

```bash
RELEASE_TAG='<new-release-tag>'
RELEASE_COMMIT='<reviewed-main-commit>'
git -c user.name='Lloyd Smart' \
  -c user.email='lloydsmart@users.noreply.github.com' \
  tag -u 02EBB31CC0032A86C2C0401A1534542E61DC82D3 \
  "$RELEASE_TAG" "$RELEASE_COMMIT" -m "$RELEASE_TAG"
git tag -v "$RELEASE_TAG"
git push origin "$RELEASE_TAG"
```

Publish the GitHub Release for that exact tag only after the operator authorizes
the release. This procedure does not authorize an agent to publish. The existing
`vMAJOR.MINOR.PATCH` syntax and alphanumeric prerelease suffixes are preserved,
including `-rc.1` and `-beta.1`. Build metadata using `+` is rejected. Either a
suffix or GitHub's prerelease flag suppresses updating `latest`; an ordinary
stable release publishes version and source-SHA aliases, then may update
`latest` after both attestation uploads succeed. This workflow does not compare
semantic versions or claim that the highest version wins.

## Qualification and authorization

### Promote a qualified release candidate

Stable releases reuse an already published and live-tested RC image. Create the
stable signed tag at exactly the same source commit as that RC, and include
these two lines in the signed annotation (using the actual RC and OCI digest):

```text
Promotion-Source: v0.4.0-rc.3
Promotion-Digest: sha256:<64-lowercase-hex-digest>
```

The RC must be a published prerelease of the same version. The authorization
job verifies both signed tags using the approved key and requires identical
source commits. Stable tags without this signed instruction fail closed.
Prerelease tags cannot carry promotion instructions.

Before pulling or running the selected image, the verifier independently checks
both its provenance and SPDX attestations against this repository, the release
workflow, the exact source commit and the selected RC tag. It then smoke-tests
and scans that exact image without rebuilding it. All source qualification checks
run again. The publisher requires the existing source alias to equal the signed
digest, copies that manifest to the stable version, uploads fresh attestations,
and updates `latest` last. Missing or conflicting state fails without replacing
an immutable alias. Live-test evidence remains an operator responsibility;
signing the stable annotation records the operator's promotion decision.

### Archive representation

Docker exports may contain an OCI manifest with uncompressed layers, whose
manifest digest differs from the compressed registry representation. Before
SBOM generation, the builder validates the export's bounded inventory, config,
layer descriptors, blob hashes and ordered uncompressed layer hashes. It then
normalizes that export to a classic single-image Docker archive while preserving
the exact config and layer content. The normalized archive is independently
revalidated and is the only input to Syft and the publisher. The publisher's
existing archive, config and registry rootfs checks remain mandatory. An export
manifest digest is never substituted for the registry manifest digest.

Every release invokes the existing reusable Actions lint, Markdown lint, Ruff,
full Python 3.12/3.14/3.15 suite, lock freshness, dependency audit, full-history secret
scan, Hadolint and Compose checks. Their checkouts explicitly use the immutable
event commit. No documentation filter or earlier green commit can replace these
checks. Every workflow must succeed and emit its internal `passed=true` receipt.
Missing, failed, cancelled or skipped checks stop the release.

A separate read-only authorization job then requires GitHub-valid signed
annotated tag metadata, a direct commit target equal to the event SHA, and main
ancestry. It verifies the exact raw tag object using the reviewed public key in
`.security/release-signing-key.asc`, in a fresh temporary GnuPG home. The full
cryptographically verified primary fingerprint must match the approved value.
A valid certified signing subkey is accepted; tagger identity, issuer text and
short key IDs do not grant authority. Unknown owner trust in a fresh keyring is
normal. Invalid, expired, revoked, ambiguous or unapproved signatures fail,
as do signatures outside SHA-256/SHA-384/SHA-512. Automatic retrieval and import
of keys from signatures are disabled. The public key and fingerprint policy
must be updated through review for rotation or new public revocation information.
Private signing material must never enter the repository or Actions.

Only after qualification and authorization does the read-only builder build a
prerelease image (or verify and reuse the promoted image), smoke-test it, scan
it and generate its SBOM. The existing immutable
source icon reference is preserved. The independent container-lint workflow
does not build a second candidate. The builder creates a bounded, canonical
candidate manifest for an exact three-file handoff: the image archive, SPDX JSON
SBOM and manifest. It binds the repository, workflow, run, attempt, release,
signed tag object, source, prerelease decision, archive hash, config digest,
optional OCI manifest and archive-index digests, Syft-native manifest digest and
SBOM subject. The image is exported before pinned Syft scans that archive. A
display-only source name is configured, but no source-version override is
supplied or trusted. The validators independently reconstruct
Syft's native manifest identity and require the SPDX version, checksum and OCI
purl to match it. The upload's numeric artifact ID and artifact digest identify
the exact current-run artifact; the publisher has no name-based fallback.

Only unambiguous single-image archives are supported. A classic Docker archive
must describe exactly one image. An OCI-layout archive must have exactly one
index descriptor selecting one supported image manifest; multiple descriptors,
nested indexes and unsupported layer representations fail closed. The archive
byte hash, config digest, OCI manifest digest, archive-index JSON digest and
Syft-native manifest digest are separate identities and must not be substituted
for one another. Docker `.Id` is not treated as the config digest.

The fresh publisher requires both successful qualification and the independent
authorization job's source, tag and tag-object identities. It compares these
with the event and builder metadata, then rechecks the current GitHub ref and
immutable verified object. It checks out no repository source and executes no
repository script or candidate container. Fixed inline publisher code validates
the exact inventory, bounded sizes, canonical JSON, independent identities,
archive and SBOM hashes, SPDX subject relationships and loaded image identity
labels before GHCR authentication. Loading and inspecting the image does not
run or execute it. Registry postchecks read one raw image manifest, verify its
byte digest and config digest, and reject an index. Where the archive contained
an OCI manifest, its digest must be the registry digest.

Publication serializes participating publisher jobs package-wide and inspects
both version and source aliases before changing either. If neither exists, it
pushes the tested image once under the version alias and copies that exact OCI
manifest digest to the source alias. If one exists with the tested config digest,
it copies only its exact digest to the missing alias. If both already identify
the same tested digest, it preserves them without a fresh push. Different
digests, a different config digest, or an ambiguous registry response fail closed
without repointing an existing immutable alias. A partial success is preserved
for a later full workflow rerun; there is no destructive rollback.

Only an exact reference-specific `not found` or `manifest unknown` diagnostic is
treated as an absent alias. Credential-helper, authentication, authorization,
transport, throttling, server, malformed, contradictory and unexplained HTTP
errors fail before mutation. If a write command fails, its remote result is
reported as uncertain. Later failures distinguish confirmed publication by this
run from reuse of a pre-existing alias and identify the remaining incomplete
verification, attestation or `latest` stages.

After both immutable aliases pass their postcheck, the workflow uploads build
provenance and SBOM attestations for that selected digest. These are attestation
uploads, not proof that a consumer has verified them. Only an eligible stable
release then copies that exact digest to `latest` and postchecks it. Thus failure
of either attestation upload prevents the `latest` mutation.

## Limits and follow-up

The authorization runner, reviewed workflow code, GitHub event/job-output and
artifact services, GnuPG, and the image publisher remain trusted.
Qualification does not prove a compromised test or build runner was honest.
Historical tagged commits run their historical workflows, so new controls
cannot retroactively constrain those paths. Tag-creation authorization and
immutable release finalization remain separate work.

Workflow and publisher concurrency keep up to 100 pending items queued rather
than cancelling them; additional items are cancelled when a queue is full. The
package-wide publisher group covers different tags that might share a source
alias or update `latest`. These locks coordinate only participating GitHub
Actions jobs: they are not an atomic registry conditional write and cannot
prevent an uncontrolled external GHCR writer from racing the inspection and
mutation sequence.

Reusing the original candidate requires the same run and attempt artifact. A
downstream-only retry cannot substitute an earlier attempt's handoff. A full
rerun rebuilds the candidate and may reuse existing registry state only through
the checks above. If that rebuild differs at the same source SHA, its existing
source alias conflicts; selecting a new version does not cure that conflict and
the workflow will not repoint it.

This bounded increment does not complete F06, immutable release finalization,
or a standalone consumer verifier. Live prerelease testing and actual
publication require separate operator authorization. Syft's root package binds
the configured image name and the independently reconstructed native manifest
identity. The producer and scanner remain trusted: these checks reject accidental
or substituted scan input but do not prove that an intentionally dishonest
scanner reported an accurate package inventory.
