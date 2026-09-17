"""Exercise CI decisions and their checked-in workflow wiring without GitHub."""

import copy
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ci_policy", ROOT / "scripts/ci_policy.py"
)
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)
WORKFLOWS = ROOT / ".github/workflows"
BAD_RESULTS = ("failure", "cancelled", "skipped", "", "neutral", "timed_out")


def successful_needs(containers="true"):
    jobs = {
        name: {"result": "success", "outputs": {"passed": "true"}}
        for name in (*policy.REQUIRED_JOBS, "deployment")
    }
    jobs["changes"]["outputs"] = {"containers": containers}
    if containers == "false":
        jobs["deployment"] = {"result": "skipped", "outputs": {}}
    return jobs


@pytest.mark.parametrize("containers", ["true", "false"])
def test_gate_accepts_exact_success_or_documented_skip(containers):
    policy.validate_gate(json.dumps(successful_needs(containers)))


@pytest.mark.parametrize("name", (*policy.REQUIRED_JOBS, "deployment"))
@pytest.mark.parametrize("result", BAD_RESULTS)
def test_every_required_job_must_succeed(name, result):
    needs = successful_needs()
    needs[name]["result"] = result
    with pytest.raises(policy.PolicyError):
        policy.validate_gate(json.dumps(needs))


@pytest.mark.parametrize("name", (*policy.REQUIRED_JOBS[1:], "deployment"))
@pytest.mark.parametrize("receipt", [None, "", "false", "True", True, 1])
def test_green_parent_needs_explicit_internal_success(name, receipt):
    needs = successful_needs()
    needs[name]["outputs"] = {} if receipt is None else {"passed": receipt}
    with pytest.raises(policy.PolicyError):
        policy.validate_gate(json.dumps(needs))


@pytest.mark.parametrize("value", [None, "", "TRUE", True, False, 0, [], {}])
def test_relevance_must_be_an_explicit_boolean_string(value):
    needs = successful_needs()
    needs["changes"]["outputs"] = {} if value is None else {"containers": value}
    with pytest.raises(policy.PolicyError):
        policy.validate_gate(json.dumps(needs))


@pytest.mark.parametrize("result", ["success", "failure", "cancelled", "", "neutral"])
def test_documentation_only_does_not_hide_unexpected_deployment_result(result):
    needs = successful_needs("false")
    needs["deployment"]["result"] = result
    with pytest.raises(policy.PolicyError):
        policy.validate_gate(json.dumps(needs))


def test_skipped_container_job_cannot_report_old_success():
    needs = successful_needs("false")
    needs["deployment"]["outputs"] = {"passed": "true"}
    with pytest.raises(policy.PolicyError):
        policy.validate_gate(json.dumps(needs))


@pytest.mark.parametrize("name", (*policy.REQUIRED_JOBS, "deployment"))
def test_missing_jobs_are_not_success(name):
    needs = successful_needs()
    del needs[name]
    with pytest.raises(policy.PolicyError):
        policy.validate_gate(json.dumps(needs))


def test_new_job_cannot_be_silently_ignored():
    needs = successful_needs()
    needs["new_check"] = {"result": "failure", "outputs": {}}
    with pytest.raises(policy.PolicyError):
        policy.validate_gate(json.dumps(needs))


@pytest.mark.parametrize(
    "record",
    [None, "success", {}, {"result": "success"}, {"result": "success", "outputs": []}],
)
def test_malformed_job_records_fail(record):
    needs = successful_needs()
    needs["actions"] = record
    with pytest.raises(policy.PolicyError):
        policy.validate_gate(json.dumps(needs))


@pytest.mark.parametrize("raw", ["", "{", "[]", "null", "true", '{"a":1,"a":2}'])
def test_invalid_json_cannot_prove_success(raw):
    with pytest.raises(policy.PolicyError):
        policy.validate_gate(raw)


def test_duplicate_success_value_is_not_accepted():
    raw = json.dumps(successful_needs()).replace(
        '"result": "success"', '"result": "failure", "result": "success"', 1
    )
    with pytest.raises(policy.PolicyError):
        policy.validate_gate(raw)


@pytest.mark.parametrize("status", [b"A", b"M"])
@pytest.mark.parametrize(
    "path",
    [
        b"README.md",
        b"CONTRIBUTING.md",
        b"CHANGELOG.md",
        b"docs/guide.md",
        b"docs/sub/a guide.md",
    ],
)
def test_only_explicit_documentation_additions_and_edits_skip_containers(status, path):
    assert not policy.containers_required(status + b"\0" + path + b"\0")


@pytest.mark.parametrize(
    "path",
    [
        b".github/workflows/pull-request-ci.yml",
        b".github/workflows/release.yml",
        b".github/ci.json",
        b".security/container-exceptions.json",
        b"SECURITY.md",
        b"AGENTS.md",
        b"docs/baseline.json",
        b"unknown.md",
        b"src/app.py",
        b"scripts/ci_policy.py",
        b"tests/test_ci_policy.py",
        b"requirements.txt",
        b"Dockerfile",
        b"deployment/unifi/Dockerfile",
        b"LICENSE",
        b"new-input",
    ],
)
def test_workflow_baseline_runtime_and_unknown_inputs_require_containers(path):
    assert policy.containers_required(b"M\0" + path + b"\0")


@pytest.mark.parametrize("status", [b"D", b"T", b"U", b"X", b"B"])
def test_deleted_or_type_changed_documentation_requires_containers(status):
    assert policy.containers_required(status + b"\0docs/guide.md\0")


def test_rename_reported_as_delete_and_add_requires_containers():
    assert policy.containers_required(b"D\0docs/old.md\0A\0docs/new.md\0")


def test_mixed_doc_and_code_changes_require_containers():
    assert policy.containers_required(b"M\0README.md\0M\0src/app.py\0")


def test_empty_diff_runs_full_validation():
    assert policy.containers_required(b"")


@pytest.mark.parametrize(
    "raw",
    [
        b"M\0README.md",
        b"M\0",
        b"M\0\0",
        b"R100\0old\0new\0",
        b"?\0file\0",
        b"M\0/README.md\0",
        b"M\0docs/../app.md\0",
        b"M\0docs//app.md\0",
        b"M\0docs/./app.md\0",
        b"M\0docs/evil\n.md\0",
        b"M\0docs/\xff.md\0",
    ],
)
def test_malformed_path_input_fails_closed(raw):
    with pytest.raises(policy.PolicyError):
        policy.containers_required(raw)


def test_inputs_are_bounded(monkeypatch):
    monkeypatch.setattr(policy, "MAX_INPUT", 10)
    with pytest.raises(policy.PolicyError):
        policy.containers_required(b"M\0README.md\0")
    with pytest.raises(policy.PolicyError):
        policy.validate_gate(json.dumps(successful_needs()))


def workflow_jobs(text):
    return set(re.findall(r"^  ([a-z_]+):$", text.split("\njobs:\n", 1)[1], re.M))


def test_aggregate_workflow_covers_every_job_and_preserves_required_name():
    text = (WORKFLOWS / "pull-request-ci.yml").read_text()
    assert workflow_jobs(text) == {*policy.REQUIRED_JOBS, "deployment", "gate"}
    needs = re.search(r"    needs: \[([^\]]+)\]", text).group(1)
    assert set(needs.split(", ")) == {*policy.REQUIRED_JOBS, "deployment"}
    assert "    name: Required CI gate\n" in text
    assert "    if: always()\n" in text
    assert "          CI_NEEDS: ${{ toJSON(needs) }}" in text
    assert "        run: python scripts/ci_policy.py gate" in text
    assert "  pull_request:\n    branches:\n      - main\n" in text
    assert "pull_request_target" not in text and "    paths:" not in text
    assert "permissions:\n  contents: read\n" in text
    assert "continue-on-error" not in text
    assert "    timeout-minutes: 5" in text
    # The only relevance condition guards containers; cheap checks always run.
    assert re.findall(r"^    if: (.+)$", text, re.M) == [
        "needs.changes.outputs.containers == 'true'",
        "always()",
    ]
    assert "      force-validation: true" in text
    assert "--no-ext-diff --no-textconv --no-renames --name-status -z" in text
    assert '"$PR_BASE...$PR_HEAD"' in text
    assert 'python scripts/ci_policy.py changes "$RUNNER_TEMP/ci-changes"' in text


def workflow_receipt(filename):
    text = (WORKFLOWS / filename).read_text()
    call = text.split("  workflow_call:", 1)[1].split("\n\n", 1)[0]
    assert "value: ${{ jobs.ci_result.outputs.passed }}" in call
    expression = re.search(r"PASSED: \$\{\{(.*?)\}\}", text, re.S).group(1)
    terms = []
    for term in expression.split("&&"):
        match = re.fullmatch(
            r"needs\.([a-z_]+)\.(result|outputs\.passed) == '(success|true)'",
            term.strip(),
        )
        assert match, f"Unsupported receipt expression in {filename}: {term}"
        terms.append(match.groups())
    return text, terms


@pytest.mark.parametrize(
    "filename",
    [
        "lint-actions.yml",
        "lint-markdown.yml",
        "lint-python.yml",
        "test-python.yml",
        "security.yml",
        "deployment.yml",
    ],
)
def test_reusable_receipts_cover_every_internal_job_and_reject_bad_results(filename):
    text, terms = workflow_receipt(filename)
    jobs = workflow_jobs(text) - {"ci_result"}
    assert {job for job, field, _ in terms if field == "result"} == jobs
    assert "continue-on-error" not in text
    result_job = text.split("  ci_result:\n", 1)[1]
    declared = re.search(r"needs: \[([^\]]+)\]", result_job).group(1)
    assert set(declared.split(", ")) == jobs
    if filename == "deployment.yml" and "  validate:\n" in text:
        assert "    if: always() && inputs.force-validation\n" in result_job
    else:
        assert "    if: always()\n" in result_job
    assert "      passed: ${{ steps.check.outputs.passed }}" in result_job
    assert "          test \"$PASSED\" = 'true'" in result_job
    results = {(job, field): expected for job, field, expected in terms}
    assert all(results[job, field] == expected for job, field, expected in terms)
    for job in jobs:
        for result in BAD_RESULTS:
            changed = copy.copy(results)
            changed[job, "result"] = result
            assert not all(changed[j, field] == value for j, field, value in terms)
    # Nested reusable workflows also need their internal-success output.
    for job in jobs:
        block = re.search(
            rf"^  {job}:\n(.*?)(?=^  [a-z_]+:|\Z)", text, re.M | re.S
        ).group(1)
        if "    uses: ./.github/workflows/" in block:
            assert (job, "outputs.passed", "true") in terms
            called = re.search(r"uses: ./\.github/workflows/(.+)", block).group(1)
            child, child_terms = workflow_receipt(called)
            assert {
                j for j, field, _ in child_terms if field == "result"
            } == workflow_jobs(child) - {"ci_result"}


def test_python_matrix_and_security_jobs_remain_required():
    text, terms = workflow_receipt("test-python.yml")
    assert "          - '3.12'" in text and "          - '3.14'" in text
    assert "      fail-fast: false" in text
    assert {job for job, _, _ in terms} == {"test", "locks"}
    _, terms = workflow_receipt("security.yml")
    assert {job for job, _, _ in terms} == {"secrets", "dependencies"}


def test_unifi_called_validation_cannot_skip_on_old_path_filter():
    text = (WORKFLOWS / "deployment.yml").read_text()
    if "  validate:\n" in text:
        assert "FORCE_VALIDATION: ${{ inputs.force-validation }}" in text
        assert (
            "if [[ " + chr(34) + "$FORCE_VALIDATION" + chr(34) + " == 'true' ||" in text
        )
        assert "relevant=true" in text


def test_cli_reports_success_and_blocks_missing_results(tmp_path):
    command = [sys.executable, str(ROOT / "scripts/ci_policy.py")]
    paths = tmp_path / "changes"
    paths.write_bytes(b"M\0README.md\0")
    result = subprocess.run(
        command + ["changes", str(paths)], capture_output=True, text=True
    )
    assert result.returncode == 0 and result.stdout == "containers=false\n"
    environment = {**os.environ, "CI_NEEDS": json.dumps(successful_needs())}
    result = subprocess.run(
        command + ["gate"], env=environment, capture_output=True, text=True
    )
    assert result.returncode == 0
    environment.pop("CI_NEEDS")
    result = subprocess.run(
        command + ["gate"], env=environment, capture_output=True, text=True
    )
    assert result.returncode == 1
    result = subprocess.run(
        command + ["changes", str(tmp_path / "missing")], capture_output=True
    )
    assert result.returncode == 1
