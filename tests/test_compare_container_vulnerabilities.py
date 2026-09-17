import copy
import importlib
import json
import sys
from dataclasses import asdict
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
comparator = importlib.import_module("compare_container_vulnerabilities")


def vulnerability(
    vulnerability_id: str,
    *,
    severity: str = "HIGH",
    package: str = "example-package",
    installed: str = "1.0",
    fixed: str | None = "1.1",
    package_id: str = "example-package@1.0",
    package_path: str | None = None,
) -> dict[str, str]:
    finding = {
        "VulnerabilityID": vulnerability_id,
        "PkgID": package_id,
        "PkgName": package,
        "InstalledVersion": installed,
        "Severity": severity,
    }
    if fixed is not None:
        finding["FixedVersion"] = fixed
    if package_path is not None:
        finding["PkgPath"] = package_path
    return finding


def result(
    *findings: dict[str, str],
    target: str = "image (debian 12)",
    result_class: str = "os-pkgs",
    result_type: str = "debian",
) -> dict[str, object]:
    scan_result: dict[str, object] = {
        "Target": target,
        "Class": result_class,
        "Type": result_type,
    }
    if findings:
        scan_result["Vulnerabilities"] = list(findings)
    return scan_result


def report(*results: dict[str, object]) -> dict[str, object]:
    if not results:
        results = (result(),)
    return {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "Metadata": {"OS": {"Family": "debian", "Name": "12"}},
        "Results": list(results),
    }


def compare(
    derivative: dict[str, object], upstream: dict[str, object]
) -> comparator.Comparison:
    return comparator.compare_reports(derivative, upstream)


def test_introduced_high_finding_blocks() -> None:
    comparison = compare(report(result(vulnerability("CVE-HIGH"))), report())

    assert comparison.blocked
    assert [finding.identity.vulnerability_id for finding in comparison.introduced] == [
        "CVE-HIGH"
    ]


def test_introduced_critical_finding_blocks() -> None:
    comparison = compare(
        report(result(vulnerability("CVE-CRITICAL", severity="CRITICAL"))), report()
    )

    assert comparison.blocked
    assert comparison.introduced[0].severity == "CRITICAL"


@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL"])
def test_introduced_unfixed_finding_blocks(severity: str) -> None:
    comparison = compare(
        report(result(vulnerability("CVE-UNFIXED", severity=severity, fixed=None))),
        report(),
    )

    assert comparison.blocked
    assert comparison.introduced[0].fixed_version == ""
    assert "fixed=<none>" in comparator.render_comparison(comparison)


def test_unfixed_inherited_finding_is_reported_and_passes() -> None:
    finding = vulnerability("CVE-INHERITED", fixed=None)
    comparison = compare(
        report(result(finding, target="derivative:reviewed (debian 12)")),
        report(result(finding, target="upstream@sha256:digest (debian 12)")),
    )

    assert not comparison.blocked
    assert len(comparison.inherited) == 1
    assert not comparison.introduced
    output = comparator.render_comparison(comparison)
    assert "Inherited HIGH/CRITICAL findings requiring impact review: 1" in output
    assert "PASS:" in output


def test_upstream_only_finding_is_removed_and_passes() -> None:
    comparison = compare(report(), report(result(vulnerability("CVE-REMOVED"))))

    assert not comparison.blocked
    assert len(comparison.removed) == 1
    assert not comparison.introduced


def test_duplicate_records_are_deduplicated() -> None:
    finding = vulnerability("CVE-DUPLICATE")
    comparison = compare(report(result(finding, finding)), report())

    assert len(comparison.introduced) == 1
    output = comparator.render_comparison(comparison)
    assert output.count('vulnerability="CVE-DUPLICATE"') == 1


def test_distinct_package_and_target_contexts_are_not_conflated() -> None:
    inherited = vulnerability("CVE-SHARED", package="alpha", package_id="alpha@1.0")
    other_package = vulnerability("CVE-SHARED", package="beta", package_id="beta@1.0")
    other_target = vulnerability("CVE-SHARED", package="alpha", package_id="alpha@1.0")
    upstream = report(
        result(
            inherited,
            target="usr/lib/python/site-packages",
            result_class="lang-pkgs",
            result_type="python-pkg",
        )
    )
    derivative = report(
        result(
            inherited,
            other_package,
            target="usr/lib/python/site-packages",
            result_class="lang-pkgs",
            result_type="python-pkg",
        ),
        result(
            other_target,
            target="opt/application/site-packages",
            result_class="lang-pkgs",
            result_type="python-pkg",
        ),
    )

    comparison = compare(derivative, upstream)

    assert len(comparison.inherited) == 1
    assert len(comparison.introduced) == 2
    assert {
        (finding.identity.package_name, finding.identity.target)
        for finding in comparison.introduced
    } == {
        ("beta", "usr/lib/python/site-packages"),
        ("alpha", "opt/application/site-packages"),
    }


def test_distinct_package_ids_in_one_target_are_not_conflated() -> None:
    first = vulnerability("CVE-SHARED", package_id="module-a:example-package@1.0")
    second = vulnerability("CVE-SHARED", package_id="module-b:example-package@1.0")
    context = {
        "target": "application.jar",
        "result_class": "lang-pkgs",
        "result_type": "jar",
    }

    comparison = compare(
        report(result(first, second, **context)), report(result(first, **context))
    )

    assert len(comparison.inherited) == 1
    assert len(comparison.introduced) == 1
    assert (
        comparison.introduced[0].identity.package_id == "module-b:example-package@1.0"
    )


@pytest.mark.parametrize(
    "malformed",
    [
        [],
        {},
        {"SchemaVersion": True, "ArtifactType": "container_image"},
        {"SchemaVersion": 1, "ArtifactType": "container_image"},
        {"SchemaVersion": 2, "ArtifactType": "filesystem"},
        {"SchemaVersion": 2, "ArtifactType": "container_image"},
        {"SchemaVersion": 2, "ArtifactType": "container_image", "Results": None},
        {"SchemaVersion": 2, "ArtifactType": "container_image", "Results": []},
        {"SchemaVersion": 2, "ArtifactType": "container_image", "Results": {}},
    ],
)
def test_malformed_top_level_json_fails_closed(malformed: object) -> None:
    with pytest.raises(comparator.InvalidReportError):
        comparator.normalize_findings(malformed, "derivative")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "malformed_result",
    [
        "not-an-object",
        {},
        {"Class": "os-pkgs", "Type": "debian"},
        {"Target": "image (debian 12)", "Type": "debian"},
        {"Target": "image (debian 12)", "Class": "os-pkgs"},
        result() | {"Vulnerabilities": {}},
        {
            "Target": "image (debian 12)",
            "Class": "os-pkgs",
            "Type": "debian",
            "Vulnerabilities": ["not-an-object"],
        },
        result({"PkgName": "missing-required-fields"}),
        result(vulnerability("CVE-WRONG-SCOPE", severity="MEDIUM")),
        result(vulnerability("CVE-NULL", fixed=None) | {"FixedVersion": None}),
    ],
)
def test_malformed_result_or_finding_fails_closed(malformed_result: object) -> None:
    malformed_report = report()
    malformed_report["Results"] = [malformed_result]

    with pytest.raises(comparator.InvalidReportError):
        comparator.normalize_findings(malformed_report, "derivative")


@pytest.mark.parametrize(
    "empty_report",
    [
        report(),
        report(result() | {"Vulnerabilities": []}),
        report(
            result(
                target="requirements.txt",
                result_class="lang-pkgs",
                result_type="python-pkg",
            )
        ),
    ],
)
def test_empty_valid_scan_passes(empty_report: dict[str, object]) -> None:
    comparison = compare(empty_report, report())

    assert not comparison.blocked
    assert not comparison.introduced
    assert not comparison.inherited
    assert not comparison.removed


def test_mixed_inherited_and_introduced_findings_blocks_for_introduced() -> None:
    inherited = vulnerability("CVE-INHERITED")
    introduced = vulnerability("CVE-INTRODUCED", severity="CRITICAL", fixed=None)
    comparison = compare(
        report(result(inherited, introduced)), report(result(inherited))
    )

    assert comparison.blocked
    assert len(comparison.inherited) == 1
    assert len(comparison.introduced) == 1
    assert comparison.introduced[0].identity.vulnerability_id == "CVE-INTRODUCED"


def test_output_order_is_deterministic() -> None:
    critical = vulnerability("CVE-Z", severity="CRITICAL")
    high_a = vulnerability("CVE-A")
    high_b = vulnerability("CVE-B")

    forward = compare(report(result(critical, high_b, high_a)), report())
    reverse = compare(report(result(high_a, high_b, critical)), report())

    assert comparator.render_comparison(forward) == comparator.render_comparison(
        reverse
    )
    assert [finding.identity.vulnerability_id for finding in forward.introduced] == [
        "CVE-Z",
        "CVE-A",
        "CVE-B",
    ]


def test_conflicting_duplicate_metadata_fails_closed() -> None:
    high = vulnerability("CVE-CONFLICT", severity="HIGH")
    critical = vulnerability("CVE-CONFLICT", severity="CRITICAL")

    with pytest.raises(
        comparator.InvalidReportError, match="conflicting duplicate findings"
    ):
        comparator.normalize_findings(report(result(high, critical)), "derivative")


def test_cli_returns_policy_and_invalid_report_exit_codes(tmp_path, capsys) -> None:
    derivative_path = tmp_path / "derivative.json"
    upstream_path = tmp_path / "upstream.json"
    derivative_path.write_text(
        json.dumps(report(result(vulnerability("CVE-CLI")))), encoding="utf-8"
    )
    upstream_path.write_text(json.dumps(report()), encoding="utf-8")

    assert comparator.main([str(derivative_path), str(upstream_path)]) == 1
    assert "BLOCKED:" in capsys.readouterr().out

    derivative_path.write_text("", encoding="utf-8")
    assert comparator.main([str(derivative_path), str(upstream_path)]) == 2
    captured = capsys.readouterr()
    assert "failed closed" in captured.err
    assert not captured.out


def test_duplicate_json_keys_fail_closed(tmp_path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text(
        '{"SchemaVersion":2,"SchemaVersion":2,"ArtifactType":"container_image"}',
        encoding="utf-8",
    )

    with pytest.raises(comparator.InvalidReportError, match="duplicate object key"):
        comparator.load_report(path, "derivative")


PINNED = "example.invalid/vendor@sha256:" + "a" * 64
PLATFORM = "linux/amd64"
TODAY = date(2026, 9, 17)


def exception_entry():
    finding = next(
        iter(
            comparator.normalize_findings(
                report(result(vulnerability("CVE-EXAMPLE"))), "test"
            ).values()
        )
    )
    return {
        "identifier": "EX-TEST-001",
        "upstream_image": PINNED,
        "platform": PLATFORM,
        "finding": asdict(finding),
        "owner": "Synthetic maintainer",
        "reviewed_by": "Synthetic reviewer",
        "reviewed_on": "2026-09-01",
        "expires_on": "2026-10-01",
        "tracking_url": "https://example.invalid/issues/1",
        "exposure": "Synthetic isolated fixture only",
        "reason": "Testing exact exception matching",
        "mitigation": "Synthetic mitigation for policy tests",
    }


def load_policy(tmp_path, entries, *, today=TODAY):
    path = tmp_path / "exceptions.json"
    path.write_text(json.dumps({"schema_version": 1, "exceptions": entries}))
    return comparator.load_exceptions(path, today=today)


def matching_comparison():
    fixture = report(result(vulnerability("CVE-EXAMPLE")))
    return compare(fixture, fixture)


@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL"])
@pytest.mark.parametrize("fixed", [None, "", "1.1"])
def test_inherited_fix_availability_controls_gate(severity, fixed):
    fixture = report(
        result(vulnerability("CVE-EXAMPLE", severity=severity, fixed=fixed))
    )
    comparison = compare(fixture, fixture)
    assert comparison.blocked == bool(fixed)
    assert len(comparison.unexcepted_fixable) == int(bool(fixed))


def test_exact_reviewed_exception_allows_only_inherited_finding(tmp_path):
    entries = load_policy(tmp_path, [exception_entry()])
    accepted = comparator.apply_exceptions(
        matching_comparison(), entries, PINNED, PLATFORM
    )
    assert not accepted.blocked
    assert len(accepted.accepted) == 1
    output = comparator.render_comparison(accepted)
    assert "Reviewed inherited finding exceptions applied: 1" in output
    assert "EX-TEST-001" in output and "2026-10-01" in output
    assert "Synthetic maintainer" in output and "Synthetic reviewer" in output
    assert "PASS:" in output


def test_exception_never_allows_introduced_finding(tmp_path):
    entries = load_policy(tmp_path, [exception_entry()])
    comparison = compare(report(result(vulnerability("CVE-EXAMPLE"))), report())
    actual = comparator.apply_exceptions(comparison, entries, PINNED, PLATFORM)
    assert actual.blocked
    assert not actual.accepted


@pytest.mark.parametrize(
    "context",
    [
        ("example.invalid/vendor@sha256:" + "b" * 64, PLATFORM),
        ("other.invalid/vendor@sha256:" + "a" * 64, PLATFORM),
        (PINNED, "linux/arm64"),
    ],
)
def test_exception_does_not_cross_image_or_platform(tmp_path, context):
    entries = load_policy(tmp_path, [exception_entry()])
    actual = comparator.apply_exceptions(matching_comparison(), entries, *context)
    assert actual.blocked and not actual.accepted


@pytest.mark.parametrize(
    "field,value",
    [
        ("result_class", "lang-pkgs"),
        ("result_type", "ubuntu"),
        ("target", "os:debian/13"),
        ("vulnerability_id", "CVE-DIFFERENT"),
        ("package_name", "other-package"),
        ("package_id", "other-package@1.0"),
        ("package_path", "other/location"),
        ("installed_version", "2.0"),
    ],
)
def test_exception_requires_every_finding_identity_field(tmp_path, field, value):
    entry = exception_entry()
    entry["finding"]["identity"][field] = value
    entries = load_policy(tmp_path, [entry])
    actual = comparator.apply_exceptions(
        matching_comparison(), entries, PINNED, PLATFORM
    )
    assert actual.blocked and not actual.accepted


@pytest.mark.parametrize(
    "field,value", [("severity", "CRITICAL"), ("fixed_version", "1.2")]
)
def test_changed_severity_or_fix_requires_review(tmp_path, field, value):
    entry = exception_entry()
    entry["finding"][field] = value
    entries = load_policy(tmp_path, [entry])
    actual = comparator.apply_exceptions(
        matching_comparison(), entries, PINNED, PLATFORM
    )
    assert actual.blocked and not actual.accepted


@pytest.mark.parametrize(
    "field,value", [("Severity", "CRITICAL"), ("FixedVersion", "")]
)
def test_conflicting_shared_scan_metadata_fails_closed(field, value):
    original = vulnerability("CVE-EXAMPLE")
    changed = original | {field: value}
    with pytest.raises(comparator.InvalidReportError, match="metadata differs"):
        compare(report(result(changed)), report(result(original)))


@pytest.mark.parametrize(
    "field,value",
    [
        ("reviewed_on", "2026-09-18"),
        ("reviewed_on", "2026-01-01"),
        ("reviewed_on", "20260901"),
        ("expires_on", "2026-09-17"),
        ("expires_on", "2026-09-16"),
        ("expires_on", "2026-08-31"),
        ("expires_on", "2026-13-01"),
        ("expires_on", "2026-12-01"),
        ("expires_on", "2026-10-01T00:00:00Z"),
        ("expires_on", None),
    ],
)
def test_invalid_or_expired_review_dates_fail_closed(tmp_path, field, value):
    entry = exception_entry()
    entry[field] = value
    with pytest.raises(comparator.InvalidReportError):
        load_policy(tmp_path, [entry])


def test_expiry_is_exclusive_and_not_silently_ignored_for_other_images(tmp_path):
    entry = exception_entry()
    assert load_policy(tmp_path, [entry], today=date(2026, 9, 30))
    with pytest.raises(comparator.InvalidReportError, match="expired"):
        load_policy(tmp_path, [entry], today=date(2026, 10, 1))


@pytest.mark.parametrize("field", list(exception_entry()))
def test_missing_exception_fields_fail_closed(tmp_path, field):
    entry = exception_entry()
    del entry[field]
    with pytest.raises(comparator.InvalidReportError):
        load_policy(tmp_path, [entry])


@pytest.mark.parametrize(
    "field,value",
    [
        ("identifier", "*"),
        ("upstream_image", "example.invalid/vendor:latest"),
        ("upstream_image", "*@sha256:" + "a" * 64),
        ("platform", "linux/*"),
        ("owner", ""),
        ("owner", " "),
        ("reviewed_by", ""),
        ("exposure", ""),
        ("reason", "line1\nline2"),
        ("mitigation", "x" * 2049),
        ("tracking_url", "http://example.invalid/issues/1"),
        ("tracking_url", "https://user:password@example.invalid/issues/1"),
    ],
)
def test_unbounded_or_incomplete_exception_scope_fails_closed(tmp_path, field, value):
    entry = exception_entry()
    entry[field] = value
    with pytest.raises(comparator.InvalidReportError):
        load_policy(tmp_path, [entry])


@pytest.mark.parametrize(
    "mutation",
    [
        lambda entry: entry.update(unrecognized=True),
        lambda entry: entry["finding"].update(severity="MEDIUM"),
        lambda entry: entry["finding"].update(fixed_version=""),
        lambda entry: entry["finding"]["identity"].pop("package_path"),
        lambda entry: entry["finding"].update(allow_introduced=True),
    ],
)
def test_exception_schema_fails_closed(tmp_path, mutation):
    entry = exception_entry()
    mutation(entry)
    with pytest.raises(comparator.InvalidReportError):
        load_policy(tmp_path, [entry])


def test_duplicate_scope_or_identifier_fails_closed(tmp_path):
    first = exception_entry()
    for second in (
        copy.deepcopy(first),
        first | {"identifier": "EX-TEST-002"},
        first | {"platform": "linux/arm64"},
    ):
        with pytest.raises(comparator.InvalidReportError, match="duplicate exception"):
            load_policy(tmp_path, [first, second])


@pytest.mark.parametrize(
    "policy",
    [
        [],
        {},
        {"schema_version": True, "exceptions": []},
        {"schema_version": 1.0, "exceptions": []},
        {"schema_version": 2, "exceptions": []},
        {"schema_version": 1, "exceptions": None},
        {"schema_version": 1, "exceptions": [], "allow_inherited": True},
        {"schema_version": 1, "exceptions": [exception_entry()] * 257},
    ],
)
def test_invalid_registry_fails_closed(tmp_path, policy):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    with pytest.raises(comparator.InvalidReportError):
        comparator.load_exceptions(path, today=TODAY)


def test_missing_oversize_duplicate_key_or_invalid_json_registry_fails_closed(tmp_path):
    path = tmp_path / "policy.json"
    with pytest.raises(comparator.InvalidReportError):
        comparator.load_exceptions(path)
    for value in (
        "x" * (comparator.MAX_EXCEPTION_BYTES + 1),
        "{bad",
        '{"schema_version":1,"schema_version":1,"exceptions":[]}',
    ):
        path.write_text(value)
        with pytest.raises(comparator.InvalidReportError):
            comparator.load_exceptions(path)


def test_cli_empty_registry_enforces_fixable_inherited_and_requires_context(
    tmp_path, capsys
):
    derivative = tmp_path / "derivative.json"
    upstream = tmp_path / "upstream.json"
    policy = tmp_path / "policy.json"
    fixture = report(result(vulnerability("CVE-EXAMPLE")))
    derivative.write_text(json.dumps(fixture))
    upstream.write_text(json.dumps(fixture))
    policy.write_text('{"schema_version":1,"exceptions":[]}')
    args = [str(derivative), str(upstream), "--exceptions", str(policy)]
    assert comparator.main(args) == 2
    assert "failed closed" in capsys.readouterr().err
    assert (
        comparator.main(args + ["--upstream-image", PINNED, "--platform", PLATFORM])
        == 1
    )
    output = capsys.readouterr().out
    assert "Unexcepted fixable inherited HIGH/CRITICAL findings: 1" in output
    assert "BLOCKED:" in output


def debian_finding(version, *, fixed=None, vulnerability_id="CVE-EXISTING"):
    return vulnerability(
        vulnerability_id,
        installed=version,
        fixed=fixed,
        package_id=f"example-package@{version}",
    )


def test_existing_unfixed_debian_finding_survives_security_upgrade():
    old = debian_finding("5.40.1-6")
    new = debian_finding("5.40.1-6+deb13u1")
    comparison = compare(report(result(new)), report(result(old)))
    assert not comparison.blocked
    assert not comparison.introduced and not comparison.removed
    assert len(comparison.inherited) == len(comparison.package_upgrades) == 1
    assert comparison.inherited[0].identity.installed_version == "5.40.1-6+deb13u1"
    output = comparator.render_comparison(comparison)
    assert 'previous_upstream_version="5.40.1-6"' in output
    assert 'installed="5.40.1-6+deb13u1"' in output
    assert "Reviewed inherited finding exceptions applied: 0" in output


@pytest.mark.parametrize(
    "new,old,increased",
    [
        ("1.10-1", "1.9-1", True),
        ("1.9-1", "1.10-1", False),
        ("1:1.0-1", "9.0-1", True),
        ("9.0-1", "1:1.0-1", False),
        ("1.0-1", "1.0~rc1-1", True),
        ("1.0~rc1-1", "1.0-1", False),
        ("1.0-0", "1.0", False),
        ("1.0", "1.0", False),
    ],
)
def test_debian_version_order_is_not_lexical_or_semver(new, old, increased):
    assert comparator._debian_version_increased(new, old) is increased


@pytest.mark.parametrize("fixed", [None, "5.40.1-8"])
def test_debian_downgrade_remains_introduced(fixed):
    comparison = compare(
        report(result(debian_finding("5.40.1-6", fixed=fixed))),
        report(result(debian_finding("5.40.1-6+deb13u1", fixed=fixed))),
    )
    assert comparison.blocked and len(comparison.introduced) == 1
    assert not comparison.package_upgrades


def test_debian_upgrade_with_new_cve_still_blocks():
    old = debian_finding("1.0-1")
    new = debian_finding("1.0-2")
    introduced = debian_finding("1.0-2", vulnerability_id="CVE-NEW")
    comparison = compare(report(result(new, introduced)), report(result(old)))
    assert comparison.blocked and len(comparison.package_upgrades) == 1
    assert [row.identity.vulnerability_id for row in comparison.introduced] == [
        "CVE-NEW"
    ]


def test_fixable_upgrade_needs_exception_for_exact_new_version(tmp_path):
    old = debian_finding("1.0", fixed="1.2", vulnerability_id="CVE-EXAMPLE")
    new = debian_finding("1.1", fixed="1.2", vulnerability_id="CVE-EXAMPLE")
    comparison = compare(report(result(new)), report(result(old)))
    assert comparison.blocked and len(comparison.unexcepted_fixable) == 1
    entry = exception_entry()
    entry["finding"]["fixed_version"] = "1.2"
    old_exception = load_policy(tmp_path, [entry])
    actual = comparator.apply_exceptions(comparison, old_exception, PINNED, PLATFORM)
    assert actual.blocked and not actual.accepted
    entry["finding"]["identity"].update(
        installed_version="1.1", package_id="example-package@1.1"
    )
    exact_exception = load_policy(tmp_path, [entry])
    actual = comparator.apply_exceptions(comparison, exact_exception, PINNED, PLATFORM)
    assert not actual.blocked and len(actual.accepted) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"VulnerabilityID": "CVE-NEW"},
        {"PkgName": "other", "PkgID": "other@1.1"},
        {"PkgID": "module:example-package@1.1"},
        {"PkgID": ""},
        {"PkgPath": "different/location"},
        {"Severity": "CRITICAL"},
        {"FixedVersion": "1.2"},
    ],
)
def test_debian_upgrade_does_not_cross_identity_or_advisory_fields(change):
    old = debian_finding("1.0")
    new = debian_finding("1.1") | change
    comparison = compare(report(result(new)), report(result(old)))
    assert comparison.blocked and len(comparison.introduced) == 1
    assert not comparison.package_upgrades


@pytest.mark.parametrize(
    "context",
    [
        {"result_class": "lang-pkgs", "result_type": "python-pkg"},
        {"result_class": "lang-pkgs", "result_type": "jar"},
        {"result_type": "ubuntu"},
        {"result_type": "alpine"},
    ],
)
def test_other_package_ecosystems_keep_exact_version_matching(context):
    comparison = compare(
        report(result(debian_finding("1.1"), **context)),
        report(result(debian_finding("1.0"), **context)),
    )
    assert comparison.blocked and not comparison.package_upgrades


def test_os_release_change_is_not_package_inheritance():
    old = report(result(debian_finding("1.0")))
    new = report(result(debian_finding("1.1")))
    new["Metadata"]["OS"]["Name"] = "13"
    comparison = compare(new, old)
    assert comparison.blocked and not comparison.package_upgrades


@pytest.mark.parametrize("side", ["derivative", "upstream"])
def test_multiple_versions_are_not_guessed_as_an_upgrade(side):
    old = debian_finding("1.0")
    new = debian_finding("1.1")
    derivative = [new, old] if side == "derivative" else [new]
    upstream = [old, debian_finding("0.9")] if side == "upstream" else [old]
    comparison = compare(report(result(*derivative)), report(result(*upstream)))
    assert comparison.blocked and not comparison.package_upgrades
    assert comparison.introduced[0].identity.installed_version == "1.1"


@pytest.mark.parametrize("version", ["--help", "x", "1\n2", "1" * 257, ""])
def test_untrusted_debian_version_rejected_before_subprocess(monkeypatch, version):
    comparator._debian_version_increased.cache_clear()

    def unexpected(*args, **kwargs):
        pytest.fail("invalid version must not reach dpkg")

    monkeypatch.setattr(comparator.subprocess, "run", unexpected)
    with pytest.raises(comparator.InvalidReportError, match="invalid Debian"):
        comparator._debian_version_increased(version, "1.0")


@pytest.mark.parametrize("failure", ["missing", "timeout", "exit", "warning"])
def test_debian_comparison_failure_is_not_an_exemption(monkeypatch, failure):
    comparator._debian_version_increased.cache_clear()

    def failing_run(arguments, **kwargs):
        assert arguments == ["/usr/bin/dpkg", "--compare-versions", "1.1", "gt", "1.0"]
        assert kwargs["timeout"] == 5
        assert "shell" not in kwargs
        if failure == "missing":
            raise FileNotFoundError()
        if failure == "timeout":
            raise comparator.subprocess.TimeoutExpired(arguments, 5)
        return comparator.subprocess.CompletedProcess(
            arguments, 2 if failure == "exit" else 0, stderr=b"warning"
        )

    monkeypatch.setattr(comparator.subprocess, "run", failing_run)
    with pytest.raises(comparator.InvalidReportError):
        compare(
            report(result(debian_finding("1.1"))),
            report(result(debian_finding("1.0"))),
        )
    comparator._debian_version_increased.cache_clear()
