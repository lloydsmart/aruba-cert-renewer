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
stable release retains its existing version, source-SHA and `latest` tags.

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
does not build a second candidate.

The fresh publisher requires both successful qualification and the independent
authorization job's source, tag and tag-object identities. It compares these
with the event and builder metadata, then rechecks the current GitHub ref and
immutable verified object. It checks out no repository source and executes no
repository script or candidate container. Existing artifact digest, archive
checksum, image-ID and release-tag checks still precede GHCR authentication;
the published digest must resolve to the tested image. Provenance and SBOM
attestations retain their existing publication behavior.

## Limits and follow-up

The authorization runner, reviewed workflow code, GitHub event/job-output and
artifact integrity, GnuPG, and the existing image publisher remain trusted.
Qualification does not prove a compromised test or build runner was honest.
Historical tagged commits run their historical workflows, so new controls
cannot retroactively constrain those paths. Tag-creation authorization and
broader immutable publication/finalization remain separate work.

This change preserves the existing publication trigger, artifact protocol and
version/source/channel update behavior. It does not implement no-overwrite
registry promotion, the common candidate manifest, or finalization changes.
Those controls remain F06 follow-up work. Live prerelease testing and actual
publication require separate operator authorization.
