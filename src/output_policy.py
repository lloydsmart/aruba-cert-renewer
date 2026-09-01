"""Safe rendering policy for operator-facing terminal and log text."""

import logging

_READABLE_CONTROL_ESCAPES = {
    "\0": r"\x00",
    "\b": r"\b",
    "\t": r"\t",
    "\n": r"\n",
    "\v": r"\v",
    "\f": r"\f",
    "\r": r"\r",
}


def sanitize_terminal_text(value):
    """Visibly escape C0/C1 controls while preserving printable Unicode."""
    text = str(value)
    escaped = []

    for character in text:
        codepoint = ord(character)
        if character in _READABLE_CONTROL_ESCAPES:
            escaped.append(_READABLE_CONTROL_ESCAPES[character])
        elif codepoint <= 0x1F or 0x7F <= codepoint <= 0x9F:
            escaped.append(f"\\x{codepoint:02x}")
        else:
            escaped.append(character)

    return "".join(escaped)


class SanitizingFormatter(logging.Formatter):
    """Escape controls after a log record has been completely formatted."""

    def format(self, record):
        return sanitize_terminal_text(super().format(record))
