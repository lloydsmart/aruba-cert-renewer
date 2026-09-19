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

Every release invokes the existing reusable Actions lint, Markdown lint, Ruff,
full Python 3.12/3.14 suite, lock freshness, dependency audit, full-history secret
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

Only after qualification and authorization does the read-only builder build
and smoke-test one image, scan it and generate its SBOM. The existing immutable
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

Workflow and publisher concurrency both keep pending runs queued rather than
cancelling them. The package-wide publisher group covers different tags that
might share a source alias or update `latest`. These locks coordinate only
participating GitHub Actions jobs: they are not an atomic registry conditional
write and cannot prevent an uncontrolled external GHCR writer from racing the
inspection and mutation sequence.

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
