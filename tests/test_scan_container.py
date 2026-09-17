"""Exercise the scanner boundary without a daemon, registry, or network."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = "example.invalid/base@sha256:" + "a" * 64
pytestmark = pytest.mark.skipif(os.name != "posix", reason="Bash wrapper needs POSIX")

FAKE_DOCKER = r"""
import json
import os
import subprocess
import sys
from pathlib import Path

args = sys.argv[1:]
with open(os.environ["DOCKER_CALLS"], "a") as output:
    output.write(json.dumps(args) + "\n")
mode = os.environ.get("SCAN_TEST_MODE", "clean")
if args[:2] == ["image", "inspect"]:
    if mode == "missing-image":
        sys.exit(1)
    if "--format" in args:
        print("linux/arm64" if mode == "platform" and "@" in args[-1] else "linux/amd64")
    sys.exit(0)
if args[0] == "save":
    Path(args[args.index("--output") + 1]).write_bytes(b"synthetic archive")
    sys.exit(0)
if args[0] != "run":
    sys.exit(99)
mounts = {}
for i, arg in enumerate(args):
    if arg == "--mount":
        parts = dict(item.split("=", 1) for item in args[i + 1].split(",") if "=" in item)
        mounts[parts["dst"]] = parts["src"]
if any(arg.startswith("--download-") for arg in args):
    sys.exit(7 if mode == "download-failure" else 0)
if "--input" in args:
    if mode == "scan-failure":
        sys.exit(8)
    if mode == "missing-report":
        sys.exit(0)
    target = Path(mounts["/output"]) / Path(args[args.index("--output") + 1]).name
    result = {"Target": "image", "Class": "os-pkgs", "Type": "debian"}
    if mode == "introduced" and target.name == "derivative.json":
        result["Vulnerabilities"] = [{"VulnerabilityID": "CVE-EXAMPLE", "PkgName": "example",
                                     "InstalledVersion": "1", "Severity": "HIGH"}]
    target.write_text(json.dumps({"SchemaVersion": 2, "ArtifactType": "container_image",
                                 "Metadata": {"OS": {"Family": "debian", "Name": "13"}},
                                 "Results": [result]}))
    sys.exit(0)
if "python" in args:
    command = [mounts.get(arg, arg) for arg in args[args.index("python") + 1:]]
    sys.exit(subprocess.run([sys.executable, *command], check=False).returncode)
sys.exit(99)
"""


@pytest.fixture
def scanner(tmp_path):
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / ".security").mkdir()
    for name in ("scan-container.sh", "compare_container_vulnerabilities.py"):
        shutil.copyfile(ROOT / "scripts" / name, repo / "scripts" / name)
    registry = repo / ".security/container-exceptions.json"
    registry.write_text('{"schema_version":1,"exceptions":[]}')
    bin_path = tmp_path / "bin"
    bin_path.mkdir()
    docker = bin_path / "docker"
    docker.write_text(f"#!{sys.executable}\n" + FAKE_DOCKER)
    docker.chmod(0o700)
    calls = tmp_path / "calls.jsonl"

    def run(*arguments, mode="clean"):
        calls.write_text("")
        environment = os.environ | {
            "PATH": str(bin_path) + os.pathsep + os.environ["PATH"],
            "DOCKER_CALLS": str(calls),
            "SCAN_TEST_MODE": mode,
            "TMPDIR": str(tmp_path),
        }
        completed = subprocess.run(
            ["bash", str(repo / "scripts/scan-container.sh"), *arguments],
            capture_output=True,
            text=True,
            env=environment,
            timeout=30,
            check=False,
        )
        return completed, [json.loads(line) for line in calls.read_text().splitlines()]

    return run, registry


@pytest.mark.parametrize("arguments", [(), ("derived",), ("derived", "base:latest")])
def test_invalid_arguments_stop_before_docker(scanner, arguments):
    run, _ = scanner
    completed, calls = run(*arguments)
    assert completed.returncode == 2
    assert not calls


def test_missing_registry_stops_before_docker(scanner):
    run, registry = scanner
    registry.unlink()
    completed, calls = run("derived", UPSTREAM)
    assert completed.returncode == 2
    assert not calls


@pytest.mark.parametrize("mode", ["missing-image", "platform"])
def test_image_or_platform_mismatch_stops_before_export(scanner, mode):
    run, _ = scanner
    completed, calls = run("derived", UPSTREAM, mode=mode)
    assert completed.returncode != 0
    assert all(call[:2] == ["image", "inspect"] for call in calls)


@pytest.mark.parametrize(
    "mode,expected",
    [("download-failure", 7), ("scan-failure", 8), ("missing-report", 2)],
)
def test_scan_pipeline_fails_closed(scanner, mode, expected):
    run, _ = scanner
    completed, calls = run("derived", UPSTREAM, mode=mode)
    assert completed.returncode == expected
    if mode != "missing-report":
        assert not any("python" in call for call in calls)


@pytest.mark.parametrize("mode,expected", [("clean", 0), ("introduced", 1)])
def test_wrapper_enforces_real_comparator_and_isolated_shared_scans(
    scanner, mode, expected
):
    run, _ = scanner
    completed, calls = run("derived", UPSTREAM, mode=mode)
    assert completed.returncode == expected, completed.stderr
    assert ("PASS:" if expected == 0 else "BLOCKED:") in completed.stdout
    downloads = [call for call in calls if any("--download-" in arg for arg in call)]
    scans = [call for call in calls if "--input" in call]
    comparisons = [call for call in calls if "python" in call]
    assert len(downloads) == 2 and len(scans) == 2 and len(comparisons) == 1
    cache_mounts = set()
    for call in downloads + scans:
        cache_mounts.update(arg for arg in call if "dst=/cache" in arg)
    assert len(cache_mounts) == 1
    for call in scans + comparisons:
        assert call[call.index("--network") + 1] == "none"
        assert "--read-only" in call and "--cap-drop" in call
        assert not any("docker.sock" in arg for arg in call)
    for call in scans:
        assert {"--offline-scan", "--skip-db-update", "--skip-java-db-update"} <= set(
            call
        )
    comparison = comparisons[0]
    assert comparison[comparison.index("--upstream-image") + 1] == UPSTREAM
    assert comparison[comparison.index("--platform") + 1] == "linux/amd64"
    assert any("dst=/exceptions.json,readonly" in arg for arg in comparison)


def test_invalid_registry_is_not_treated_as_empty(scanner):
    run, registry = scanner
    registry.write_text('{"schema_version":1,"exceptions":null}')
    completed, _ = run("derived", UPSTREAM)
    assert completed.returncode == 2
    assert "failed closed" in completed.stderr
