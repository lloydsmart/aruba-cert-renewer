"""Exercise lock-generation tool pin and installed-version validation."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_lock_tools", ROOT / "scripts/check_lock_tools.py"
)
lock_tools = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lock_tools)


def test_tool_versions_follow_changed_pins(tmp_path, monkeypatch):
    pins = tmp_path / "requirements-tools.in"
    pins.write_bytes(
        b"# Lock-generation tools\r\n\r\n"
        b" pip-tools == 99.8.7rc1  # candidate\r\n"
        b"pip==42.1\r\n"
    )
    installed = {"pip": "42.1", "pip-tools": "99.8.7rc1"}
    monkeypatch.setattr(lock_tools.metadata, "version", installed.__getitem__)

    lock_tools.check_tool_versions(pins)


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        ("pip==42.1\n", "missing the pip-tools pin"),
        ("pip-tools==99.8.7\n", "missing the pip pin"),
        ("pip==42.1\npip==42.1\npip-tools==99.8.7\n", "duplicate pip pin"),
        (
            "pip==42.1\npip-tools==99.8.7\npip-tools==99.8.8\n",
            "duplicate pip-tools pin",
        ),
        ("pip==42.1\npip-tools\n", "line 2 must be an exact"),
        ("pip==42.1\npip-tools>=99.8.7\n", "line 2 must be an exact"),
        ("pip==42.1\npip-tools===99.8.7\n", "line 2 must be an exact"),
        ("pip==42.1\npip-tools==99.8.*\n", "line 2 must be an exact"),
        ("pip==42.1\npip-tools==99..7\n", "line 2 must be an exact"),
        ("pip==42.1\npip-tools==99.8.7,!=99.8.8\n", "line 2 must be an exact"),
        (
            "pip==42.1\npip-tools==99.8.7; python_version=='3.15'\n",
            "line 2 must be an exact",
        ),
        ("pip==42.1\npip_tools==99.8.7\n", "line 2 must be an exact"),
        ("pip==42.1 # comment \\" + "\npip-tools==99.8.7\n", "line 1 must be an exact"),
    ],
)
def test_invalid_pins_are_rejected_before_checking_installed_versions(
    tmp_path, monkeypatch, contents, message
):
    pins = tmp_path / "requirements-tools.in"
    pins.write_text(contents, encoding="utf-8")

    def unexpected_lookup(name):
        pytest.fail(f"Looked up {name} before validating every pin")

    monkeypatch.setattr(lock_tools.metadata, "version", unexpected_lookup)
    with pytest.raises(ValueError, match=message):
        lock_tools.check_tool_versions(pins)


@pytest.mark.parametrize("name", lock_tools.TOOLS)
@pytest.mark.parametrize("found", ["1.0", None])
def test_mismatched_or_missing_installed_version_is_rejected(
    tmp_path, monkeypatch, name, found
):
    pins = tmp_path / "requirements-tools.in"
    expected = {"pip": "42.1", "pip-tools": "99.8.7"}
    pins.write_text(
        "".join(f"{tool}=={version}\n" for tool, version in expected.items()),
        encoding="utf-8",
    )

    def installed_version(tool):
        if tool != name:
            return expected[tool]
        if found is None:
            raise lock_tools.metadata.PackageNotFoundError(tool)
        return found

    monkeypatch.setattr(lock_tools.metadata, "version", installed_version)
    detail = "is not installed" if found is None else "found '1.0'"
    with pytest.raises(ValueError, match=rf"requires {name} .*{detail}"):
        lock_tools.check_tool_versions(pins)
