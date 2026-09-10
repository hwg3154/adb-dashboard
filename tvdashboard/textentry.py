"""Text entry for the "Send to TV" field.

Everything the browser sends is treated as untrusted text: capped, stripped of control
characters and quoted before it reaches the device shell.

See docs/remote-key-press.md, "Type into the focused input field".
"""

from __future__ import annotations

from .config import MAX_TEXT_CHARS


class TextRejected(ValueError):
    """Raised when nothing safe is left to send."""


_DISALLOWED = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f"
_DISALLOWED += "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f"
#: Characters `input text` cannot handle; typing them on a TV keyboard is the app's job.
_BLOCKED_CHARS = frozenset("`|&;<>(){}[]$\\\"'")


def sanitize_text(raw: object, max_chars: int = MAX_TEXT_CHARS) -> str:
    """Return text that is safe to hand to `input text`.

    - reject non-strings, empty-after-strip and oversized payloads
    - drop control characters (keep tab, newline, carriage return)
    - drop characters that break `input text` or the device shell
    """
    if not isinstance(raw, str):
        raise TextRejected("text must be a string")

    cleaned: list[str] = []
    for ch in raw:
        if ch in _DISALLOWED:
            continue
        code = ord(ch)
        if code < 0x20 and ch not in "\t\n\r":
            continue
        if code == 0x7F:
            continue
        if ch in _BLOCKED_CHARS:
            continue
        if code > 0x10FFFF:
            continue
        cleaned.append(ch)

    text = "".join(cleaned).strip("\r\n")
    if not text.strip():
        raise TextRejected("nothing to send")
    if len(text) > max_chars:
        raise TextRejected("text too long")
    return text


def encode_text_arg(text: str) -> str:
    """Encode sanitized text for `adb shell input text`.

    adb joins arguments with a single space, so a space has to travel as `%s`; the quotes keep
    the remaining punctuation out of the device shell.
    """
    body = text.replace("\\", "").replace("%", "%25").replace(" ", "%s")
    return "'" + body.replace("'", "") + "'"
