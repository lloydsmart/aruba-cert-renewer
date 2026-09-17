# Common container image policy

UniFi and Aruba use the same scanner wrapper, comparator, tests, and exception
schema. Each repository keeps its own reviewed exception registry. No runtime
application code or dependency lock is shared by this policy.

## Enforcement

The wrapper compares the tested image with its exact digest-pinned upstream on
the same Linux platform. It exports both images, downloads one set of Trivy OS
and Java database snapshots, then scans both archives offline with those same
snapshots. Scanner and comparator containers have no Docker socket. Scanning
and comparison run without network access; database downloads require network.

| Finding | Gate result |
| --- | --- |
| Introduced HIGH/CRITICAL, with or without a fix | Block |
| Inherited HIGH/CRITICAL with a fixed version | Block unless exactly excepted |
| Inherited HIGH/CRITICAL without a fixed version | Report for impact review |
| Removed upstream finding | Report |
| Missing, malformed, conflicting, or unreadable inputs | Fail closed |

An exception can never waive an introduced finding. No automatic exceptions,
blanket inherited exemptions, vulnerability-class exclusions, or Trivy ignore
files are used. A passing gate is not an assertion that an image has no
vulnerabilities or that an inherited finding is harmless. A newly available fix
turns a previously unfixed inherited finding into a blocker.

Identity includes result class/type, target, vulnerability ID, package name,
package ID/path, and installed version. OS targets use the distribution family
and version because Trivy's displayed OS target includes the image name. Java
and other language targets retain their exact paths. Shared identities must
agree on severity and fixed-version metadata or comparison fails closed.
An existing Debian OS finding can remain inherited through a package upgrade
when the same CVE, package, distribution, path, severity, and fix metadata occur
exactly once in each image. Both IDs must be canonical `package@version` values,
and Debian's `dpkg --compare-versions` must confirm a strictly newer version.
The report shows both versions. New CVEs, downgrades, changed metadata, ambiguous
multiple versions, and other package ecosystems retain exact matching. Missing
or failing `dpkg` fails closed. The pinned comparison container supplies `dpkg`;
standalone comparison of these upgrades needs `/usr/bin/dpkg` too. See
[Debian version ordering](https://www.debian.org/doc/debian-policy/ch-controlfields.html#version).

This corrects inheritance classification; it grants no risk exception. Fixable
upgraded findings still block. Exceptions continue to match the derivative's
full installed version and package ID, so an old-version approval cannot carry
forward automatically. Unfixed inherited findings remain visible for review.

The CLI exits 0 for a passing policy, 1 for blocked findings, and 2 for invalid
comparison inputs. Scanner/download failures also stop the wrapper. Running the
comparator directly without an exception file grants no exceptions.

## Explicit review and expiry

`.security/container-exceptions.json` starts with an empty list:

```json
{
  "schema_version": 1,
  "exceptions": []
}
```

Only a maintainer's explicit risk decision may add or renew an exception through
a manually reviewed PR. A scanner result, an existing finding inventory, or a
request to make CI green is not risk acceptance. Review must consider exposure,
reachability, vendor support, available fixes, operational impact, and why the
fix cannot yet be used. Do not invent a mitigation where none is established.

Every entry requires these exact fields; unknown or missing fields fail closed:

| Field | Required content |
| --- | --- |
| `identifier` | Unique `EX-` identifier with uppercase letters, digits, and hyphens |
| `upstream_image` | Exact repository reference and SHA-256 digest used by the scan |
| `platform` | Exact Linux OS/architecture, including variant when present |
| `finding` | Exact identity, severity, and fixed-version string described below |
| `owner` | Person responsible for remediation and expiry review |
| `reviewed_by` | Maintainer who explicitly approved the risk |
| `reviewed_on` | Actual approval date, `YYYY-MM-DD`, no future dates |
| `expires_on` | Expiry date, `YYYY-MM-DD`, at most 90 days after review |
| `tracking_url` | HTTPS link to the remediation/review record, without credentials |
| `exposure` | Evidence about where and how the component is exposed |
| `reason` | Why accepting this exact finding temporarily is justified |
| `mitigation` | Verified mitigation, or an explicit statement that none is established |

`finding` has exactly `identity`, `severity` (`HIGH` or `CRITICAL`), and
`fixed_version` (the complete nonempty Trivy string). `identity` has exactly
`result_class`, `result_type`, `target`, `vulnerability_id`, `package_name`,
`package_id`, `package_path`, and `installed_version`. Copy these values from
the normalized scan finding; only absent package ID/path may be empty strings.
Every field is matched literally, with no wildcard expansion or CVE aliasing.
Changing the upstream, platform, package, version, location, severity, or fix
metadata requires a new review for the new scope.

Expiry is exclusive: an exception expires at 00:00 UTC on `expires_on`. The
runtime UTC clock is authoritative; the CLI has no date override. Any malformed,
duplicate, expired, or future-dated entry fails the whole registry closed,
even if it is not relevant to this image. Remove stale entries or explicitly
review a renewal. Valid entries for other exact image scopes do not apply.

The registry is bounded to 1 MiB and 256 entries, and each text field to 2048
characters without control characters or surrounding whitespace. Review fields
provide an audit record; software cannot establish that a named person really
approved it. Signed changes and human PR review must establish that approval.
The scanner never writes this registry. An empty, valid registry grants nothing;
a missing registry is an error.

## Local use

Build and test the derivative first. Pull the exact upstream used by that build,
then pass both references:

```bash
./scripts/scan-container.sh "$TESTED_IMAGE" "$EXACT_UPSTREAM_IMAGE"
```

CI and release verification resolve the pinned upstream before scanning. The
workflow remains blocked when the policy rejects a finding; publication must
not proceed past a failed verification step. Existing non-container dependency
exceptions are separate and do not grant container-image exceptions.
