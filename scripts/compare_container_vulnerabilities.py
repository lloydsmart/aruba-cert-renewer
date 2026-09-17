#!/usr/bin/env python3
"""Compare HIGH/CRITICAL findings from two Trivy container reports."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, fields, replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

TRIVY_SCHEMA_VERSION = 2
MAX_REPORT_BYTES = 128 * 1024 * 1024
MAX_EXCEPTION_BYTES = 1024 * 1024
MAX_EXCEPTION_DAYS = 90
PINNED_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}")
PLATFORM = re.compile(r"linux/[a-z0-9]+(?:/[a-z0-9]+)?")
BLOCKING_SEVERITIES = frozenset({"HIGH", "CRITICAL"})
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1}


class InvalidReportError(ValueError):
    """Raised when a Trivy report cannot be compared safely."""


@dataclass(frozen=True, order=True)
class FindingIdentity:
    """A component identity stable across derivative and upstream artifacts."""

    result_class: str
    result_type: str
    target: str
    vulnerability_id: str
    package_name: str
    package_id: str
    package_path: str
    installed_version: str


@dataclass(frozen=True)
class Finding:
    identity: FindingIdentity
    severity: str
    fixed_version: str


@dataclass(frozen=True)
class Comparison:
    introduced: tuple[Finding, ...]
    inherited: tuple[Finding, ...]
    removed: tuple[Finding, ...]
    accepted: tuple[ImageException, ...] = ()

    @property
    def unexcepted_fixable(self) -> tuple[Finding, ...]:
        accepted = {exception.finding for exception in self.accepted}
        return tuple(
            finding
            for finding in self.inherited
            if finding.fixed_version and finding not in accepted
        )

    @property
    def blocked(self) -> bool:
        return bool(self.introduced or self.unexcepted_fixable)


@dataclass(frozen=True)
class ImageException:
    identifier: str
    upstream_image: str
    platform: str
    finding: Finding
    owner: str
    reviewed_by: str
    reviewed_on: date
    expires_on: date
    tracking_url: str
    exposure: str
    reason: str
    mitigation: str


def _exact_fields(value: Any, expected: set[str], description: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise InvalidReportError(f"{description} has missing or unexpected fields")
    return value


def _review_text(value: Any, description: str, *, empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or value != value.strip()
        or (not empty and not value)
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise InvalidReportError(f"{description} must be bounded plain text")
    return value


def _review_date(value: Any, description: str) -> date:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value
    ):
        raise InvalidReportError(f"{description} must be a YYYY-MM-DD date")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise InvalidReportError(f"{description} is not a calendar date") from None


def _scan_context(upstream_image: str, platform: str) -> None:
    if not PINNED_IMAGE.fullmatch(upstream_image):
        raise InvalidReportError(
            "exception context requires a digest-pinned upstream image"
        )
    if not PLATFORM.fullmatch(platform):
        raise InvalidReportError("exception context requires an exact Linux platform")


def load_exceptions(
    path: Path, *, today: date | None = None
) -> tuple[ImageException, ...]:
    today = today if today is not None else datetime.now(UTC).date()
    policy = load_report(path, "exception", maximum=MAX_EXCEPTION_BYTES)
    _exact_fields(policy, {"schema_version", "exceptions"}, "exception registry")
    if type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
        raise InvalidReportError("unsupported exception registry schema")
    entries = policy["exceptions"]
    if not isinstance(entries, list) or len(entries) > 256:
        raise InvalidReportError("exception registry must contain at most 256 entries")
    result = []
    identifiers = set()
    scopes = set()
    record_fields = {field.name for field in fields(ImageException)}
    identity_fields = {field.name for field in fields(FindingIdentity)}
    for raw in entries:
        entry = _exact_fields(raw, record_fields, "exception")
        text = {
            key: _review_text(entry[key], f"exception {key}")
            for key in record_fields - {"finding", "reviewed_on", "expires_on"}
        }
        if not re.fullmatch(r"EX-[A-Z0-9][A-Z0-9-]{0,63}", text["identifier"]):
            raise InvalidReportError(
                "exception identifier must start with EX- and be unique"
            )
        _scan_context(text["upstream_image"], text["platform"])
        try:
            link = urlsplit(text["tracking_url"])
            valid_link = (
                link.scheme == "https"
                and bool(link.hostname)
                and not link.username
                and not link.password
            )
        except ValueError:
            valid_link = False
        if not valid_link:
            raise InvalidReportError(
                "exception tracking_url must be an HTTPS remediation link"
            )
        finding_data = _exact_fields(
            entry["finding"],
            {"identity", "severity", "fixed_version"},
            "exception finding",
        )
        raw_identity = _exact_fields(
            finding_data["identity"], identity_fields, "exception finding identity"
        )
        identity = FindingIdentity(
            **{
                key: _review_text(
                    value,
                    f"exception finding {key}",
                    empty=key in {"package_id", "package_path"},
                )
                for key, value in raw_identity.items()
            }
        )
        severity = _review_text(finding_data["severity"], "exception severity")
        if severity not in BLOCKING_SEVERITIES:
            raise InvalidReportError("exceptions apply only to HIGH/CRITICAL findings")
        finding = Finding(
            identity,
            severity,
            _review_text(finding_data["fixed_version"], "exception fixed_version"),
        )
        reviewed_on = _review_date(entry["reviewed_on"], "reviewed_on")
        expires_on = _review_date(entry["expires_on"], "expires_on")
        if reviewed_on > today or expires_on <= today:
            raise InvalidReportError("exception review is in the future or has expired")
        if not 0 < (expires_on - reviewed_on).days <= MAX_EXCEPTION_DAYS:
            raise InvalidReportError("exception lifetime must be between 1 and 90 days")
        scope = (text["upstream_image"], text["platform"], finding.identity)
        if text["identifier"] in identifiers or scope in scopes:
            raise InvalidReportError("duplicate exception identifier or finding scope")
        identifiers.add(text["identifier"])
        scopes.add(scope)
        result.append(
            ImageException(
                **text, finding=finding, reviewed_on=reviewed_on, expires_on=expires_on
            )
        )
    return tuple(sorted(result, key=lambda entry: entry.identifier))


def apply_exceptions(
    comparison: Comparison,
    exceptions: tuple[ImageException, ...],
    upstream_image: str,
    platform: str,
) -> Comparison:
    _scan_context(upstream_image, platform)
    # Introduced findings are never eligible, even if someone lists them.
    eligible = set(comparison.inherited)
    return replace(
        comparison,
        accepted=tuple(
            entry
            for entry in exceptions
            if entry.upstream_image == upstream_image
            and entry.platform == platform
            and entry.finding in eligible
            and entry.finding.fixed_version
        ),
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidReportError("JSON contains a duplicate object key")
        result[key] = value
    return result


def load_report(
    path: Path, role: str, *, maximum: int = MAX_REPORT_BYTES
) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise InvalidReportError(f"{role} report is not readable") from error

    if size == 0:
        raise InvalidReportError(f"{role} report is empty")
    if size > maximum:
        raise InvalidReportError(f"{role} report exceeds the size limit")

    try:
        with path.open(encoding="utf-8") as report_file:
            report = json.load(report_file, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InvalidReportError(f"{role} report is not valid UTF-8 JSON") from error

    if not isinstance(report, dict):
        raise InvalidReportError(f"{role} report must be a JSON object")
    return report


def _required_text(value: Any, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidReportError(f"{description} must be non-empty text")
    return value


def _optional_text(container: dict[str, Any], key: str, description: str) -> str:
    if key not in container:
        return ""
    value = container[key]
    if not isinstance(value, str):
        raise InvalidReportError(f"{description} must be text when present")
    return value


def _os_target(report: dict[str, Any]) -> str:
    # Trivy's OS-result Target contains the scanned image name. Metadata.OS is
    # the stable component context shared by exact upstream and derivative scans.
    metadata = report.get("Metadata")
    if not isinstance(metadata, dict):
        raise InvalidReportError("OS findings require object Metadata")
    operating_system = metadata.get("OS")
    if not isinstance(operating_system, dict):
        raise InvalidReportError("OS findings require object Metadata.OS")
    family = _required_text(operating_system.get("Family"), "Metadata.OS.Family")
    name = _required_text(operating_system.get("Name"), "Metadata.OS.Name")
    return f"os:{family}/{name}"


def normalize_findings(
    report: dict[str, Any], role: str
) -> dict[FindingIdentity, Finding]:
    if not isinstance(report, dict):
        raise InvalidReportError(f"{role} report must be a JSON object")
    schema_version = report.get("SchemaVersion")
    if isinstance(schema_version, bool) or schema_version != TRIVY_SCHEMA_VERSION:
        raise InvalidReportError(
            f"{role} report does not use Trivy schema version {TRIVY_SCHEMA_VERSION}"
        )
    if report.get("ArtifactType") != "container_image":
        raise InvalidReportError(f"{role} report is not a container-image report")

    if "Results" not in report:
        raise InvalidReportError(f"{role} report is missing Results")
    results = report["Results"]
    if not isinstance(results, list):
        raise InvalidReportError(f"{role} report Results must be an array")
    if not results:
        raise InvalidReportError(f"{role} report Results must not be empty")

    normalized: dict[FindingIdentity, Finding] = {}
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            raise InvalidReportError(f"{role} result {result_index} must be an object")

        target = _required_text(result.get("Target"), "result Target")
        result_class = _required_text(result.get("Class"), "result Class")
        result_type = _required_text(result.get("Type"), "result Type")
        stable_target = _os_target(report) if result_class == "os-pkgs" else target

        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise InvalidReportError(
                f"{role} result {result_index} Vulnerabilities must be an array"
            )
        if not vulnerabilities:
            continue

        for finding_index, vulnerability in enumerate(vulnerabilities):
            if not isinstance(vulnerability, dict):
                raise InvalidReportError(
                    f"{role} result {result_index} finding {finding_index} "
                    "must be an object"
                )

            severity = _required_text(vulnerability.get("Severity"), "finding Severity")
            if severity not in BLOCKING_SEVERITIES:
                raise InvalidReportError(
                    f"{role} report contains a finding outside the requested "
                    "HIGH/CRITICAL severity scope"
                )

            identity = FindingIdentity(
                # Trivy's Fingerprint includes ArtifactID, and Layer identifies
                # image construction rather than the vulnerable component.
                result_class=result_class,
                result_type=result_type,
                target=stable_target,
                vulnerability_id=_required_text(
                    vulnerability.get("VulnerabilityID"), "finding VulnerabilityID"
                ),
                package_name=_required_text(
                    vulnerability.get("PkgName"), "finding PkgName"
                ),
                package_id=_optional_text(vulnerability, "PkgID", "finding PkgID"),
                package_path=_optional_text(
                    vulnerability, "PkgPath", "finding PkgPath"
                ),
                installed_version=_required_text(
                    vulnerability.get("InstalledVersion"),
                    "finding InstalledVersion",
                ),
            )
            finding = Finding(
                identity=identity,
                severity=severity,
                fixed_version=_optional_text(
                    vulnerability, "FixedVersion", "finding FixedVersion"
                ),
            )
            previous = normalized.get(identity)
            if previous is not None and previous != finding:
                raise InvalidReportError(
                    f"{role} report contains conflicting duplicate findings"
                )
            normalized[identity] = finding

    return normalized


def _finding_sort_key(finding: Finding) -> tuple[Any, ...]:
    identity = finding.identity
    return (
        SEVERITY_ORDER[finding.severity],
        identity.vulnerability_id,
        identity.package_name,
        identity.installed_version,
        identity.result_class,
        identity.result_type,
        identity.target,
        identity.package_id,
        identity.package_path,
    )


def compare_reports(
    derivative_report: dict[str, Any], upstream_report: dict[str, Any]
) -> Comparison:
    derivative = normalize_findings(derivative_report, "derivative")
    upstream = normalize_findings(upstream_report, "upstream")
    derivative_keys = set(derivative)
    upstream_keys = set(upstream)

    if any(derivative[key] != upstream[key] for key in derivative_keys & upstream_keys):
        raise InvalidReportError("shared finding metadata differs between scan reports")

    return Comparison(
        introduced=tuple(
            sorted(
                (derivative[key] for key in derivative_keys - upstream_keys),
                key=_finding_sort_key,
            )
        ),
        inherited=tuple(
            sorted(
                (derivative[key] for key in derivative_keys & upstream_keys),
                key=_finding_sort_key,
            )
        ),
        removed=tuple(
            sorted(
                (upstream[key] for key in upstream_keys - derivative_keys),
                key=_finding_sort_key,
            )
        ),
    )


def _quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _format_finding(finding: Finding) -> str:
    identity = finding.identity
    fixed_version = (
        _quoted(finding.fixed_version) if finding.fixed_version else "<none>"
    )
    fields = [
        finding.severity,
        f"vulnerability={_quoted(identity.vulnerability_id)}",
        f"package={_quoted(identity.package_name)}",
        f"installed={_quoted(identity.installed_version)}",
        f"fixed={fixed_version}",
        f"class={_quoted(identity.result_class)}",
        f"type={_quoted(identity.result_type)}",
        f"target={_quoted(identity.target)}",
    ]
    if identity.package_id:
        fields.append(f"package_id={_quoted(identity.package_id)}")
    if identity.package_path:
        fields.append(f"package_path={_quoted(identity.package_path)}")
    return "  " + " | ".join(fields)


def render_comparison(comparison: Comparison) -> str:
    lines: list[str] = []
    categories = (
        ("Introduced derivative-only HIGH/CRITICAL findings", comparison.introduced),
        (
            "Inherited HIGH/CRITICAL findings requiring impact review",
            comparison.inherited,
        ),
        (
            "Unexcepted fixable inherited HIGH/CRITICAL findings",
            comparison.unexcepted_fixable,
        ),
        ("Removed upstream-only HIGH/CRITICAL findings", comparison.removed),
    )
    for heading, findings in categories:
        lines.append(f"{heading}: {len(findings)}")
        lines.extend(_format_finding(finding) for finding in findings)

    lines.append(
        f"Reviewed inherited finding exceptions applied: {len(comparison.accepted)}"
    )
    for entry in comparison.accepted:
        lines.append(_format_finding(entry.finding))
        lines.append(
            f"  exception={_quoted(entry.identifier)} | owner={_quoted(entry.owner)}"
            f" | reviewed_by={_quoted(entry.reviewed_by)} | expires_on={entry.expires_on}"
            f" | tracking={_quoted(entry.tracking_url)}"
        )

    if comparison.blocked:
        lines.append(
            "BLOCKED: introduced or unexcepted fixable inherited HIGH/CRITICAL findings were found."
        )
    else:
        lines.append(
            "PASS: no introduced or unexcepted fixable inherited HIGH/CRITICAL findings were found."
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare derivative and exact-upstream Trivy JSON reports."
    )
    parser.add_argument("derivative_report", type=Path)
    parser.add_argument("upstream_report", type=Path)
    parser.add_argument("--exceptions", type=Path)
    parser.add_argument("--upstream-image", default="")
    parser.add_argument("--platform", default="")
    arguments = parser.parse_args(argv)

    try:
        derivative_report = load_report(arguments.derivative_report, "derivative")
        upstream_report = load_report(arguments.upstream_report, "upstream")
        comparison = compare_reports(derivative_report, upstream_report)
        if arguments.exceptions is not None:
            exceptions = load_exceptions(arguments.exceptions)
            comparison = apply_exceptions(
                comparison, exceptions, arguments.upstream_image, arguments.platform
            )
    except InvalidReportError as error:
        print(f"Comparison failed closed: {error}", file=sys.stderr)
        return 2

    print(render_comparison(comparison))
    return 1 if comparison.blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
