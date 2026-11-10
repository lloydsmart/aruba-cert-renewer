#!/usr/bin/env python3
"""Read a promotion instruction from an already authenticated annotated tag."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def promotion(tag: str, signed_tag: bytes) -> tuple[str, str]:
    if len(signed_tag) > 64 * 1024:
        raise ValueError("signed tag exceeds the promotion metadata bound")
    text = signed_tag.decode("utf-8")
    message = text.split("\n\n", 1)[1].split("-----BEGIN PGP SIGNATURE-----", 1)[0]
    fields = [line for line in message.splitlines() if line.startswith("Promotion-")]
    stable = re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag)
    if not stable:
        if fields:
            raise ValueError("prereleases must build their own candidate")
        return "", ""
    if len(fields) != 2:
        raise ValueError("stable releases require exactly one signed source and digest")
    values = dict(line.split(": ", 1) for line in fields)
    if set(values) != {"Promotion-Source", "Promotion-Digest"}:
        raise ValueError("invalid promotion metadata")
    source, digest = values["Promotion-Source"], values["Promotion-Digest"]
    if re.fullmatch(re.escape(tag) + r"-rc\.[1-9][0-9]*", source) is None:
        raise ValueError("promotion must use an RC of the same stable version")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise ValueError("promotion digest is invalid")
    return source, digest


if __name__ == "__main__":
    source, digest = promotion(sys.argv[1], Path(sys.argv[2]).read_bytes())
    print(f"promotion_source={source}\npromotion_digest={digest}")
