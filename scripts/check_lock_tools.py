"""Check the installed lock-generation tools against requirements-tools.in."""

import re
from importlib import metadata
from pathlib import Path

TOOLS = ("pip", "pip-tools")
NUMBER = r"(?:0|[1-9][0-9]*)"
# Match canonical PEP 440 versions so the installed metadata can be compared
# verbatim. In particular, no wildcard, marker, or range can match.
VERSION = re.compile(
    rf"(?:[1-9][0-9]*!)?{NUMBER}(?:\.{NUMBER})*"
    rf"(?:(?:a|b|rc){NUMBER})?(?:\.post{NUMBER})?(?:\.dev{NUMBER})?"
    rf"(?:\+[a-z0-9]+(?:\.[a-z0-9]+)*)?"
)
PIN = re.compile(r"(pip|pip-tools)[ \t]*==[ \t]*([^ \t]+)")


def read_pins(path: Path) -> dict[str, str]:
    pins = {}
    with path.open(encoding="utf-8") as source:
        for line_number, raw_line in enumerate(source, 1):
            line = raw_line.strip(" \t\n")
            if not line or line.startswith("#"):
                continue
            # pip joins continued lines before stripping inline comments.
            pin = re.split(r"[ \t]+#", line, maxsplit=1)[0]
            match = None if line.endswith("\\") else PIN.fullmatch(pin)
            if match is None or VERSION.fullmatch(match[2]) is None:
                raise ValueError(
                    f"requirements-tools.in line {line_number} must be an exact "
                    "pip or pip-tools pin (name==version)."
                )
            name, version = match.groups()
            if name in pins:
                raise ValueError(f"requirements-tools.in has a duplicate {name} pin.")
            pins[name] = version

    for name in TOOLS:
        if name not in pins:
            raise ValueError(f"requirements-tools.in is missing the {name} pin.")
    return pins


def check_tool_versions(path: Path) -> None:
    pins = read_pins(path)
    for name in TOOLS:
        expected = pins[name]
        try:
            installed = metadata.version(name)
        except metadata.PackageNotFoundError:
            raise ValueError(
                f"Lock generation requires {name} {expected}, but it is not installed."
            ) from None
        if installed != expected:
            raise ValueError(
                f"Lock generation requires {name} {expected}, found {installed!a}."
            )


if __name__ == "__main__":
    try:
        check_tool_versions(Path("requirements-tools.in"))
    except (OSError, UnicodeError):
        raise SystemExit("Cannot read requirements-tools.in as UTF-8.") from None
    except ValueError as error:
        raise SystemExit(str(error)) from None
