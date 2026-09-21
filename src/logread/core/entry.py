"""The unit of everything LogRead displays: one parsed log entry."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

from .severity import Severity

__all__ = ["LogEntry", "signature_of"]


@dataclass(slots=True)
class LogEntry:
    """One logical entry, which may span several physical lines.

    ``raw`` keeps the bytes as they appeared so the Raw view is faithful and
    "Copy" hands back something that can be pasted into a bug report.
    """

    raw: str
    message: str
    severity: Severity = Severity.UNKNOWN
    timestamp: datetime | None = None
    source: str | None = None
    pid: int | None = None
    line_no: int = 0
    guessed: bool = False
    extra_lines: list[str] = field(default_factory=list)

    @property
    def is_multiline(self) -> bool:
        return bool(self.extra_lines)

    @property
    def full_raw(self) -> str:
        if not self.extra_lines:
            return self.raw
        return "\n".join([self.raw, *self.extra_lines])

    @property
    def full_message(self) -> str:
        if not self.extra_lines:
            return self.message
        return "\n".join([self.message, *self.extra_lines])

    @property
    def line_count(self) -> int:
        return 1 + len(self.extra_lines)

    def append_continuation(self, line: str) -> None:
        self.extra_lines.append(line)

    def copy_text(self) -> str:
        """What the per-entry copy button puts on the clipboard."""
        return self.full_raw


# Normalising away the parts of a message that change between occurrences lets
# "Top problems" collapse 4000 identical failures into one row with a count.
_VOLATILE = [
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"), "<mac>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<hex>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<hash>"),
    (re.compile(r"(?<=[\s=:\"'])/[\w.\-/@+]{2,}"), "<path>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*"), "<time>"),
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<time>"),
    # Not \b-anchored: durations like "32ms" and sizes like "4KiB" carry the
    # number right up against a letter, and those vary between occurrences too.
    (re.compile(r"\d+(?:\.\d+)?"), "<n>"),
    (re.compile(r"\s+"), " "),
]


def signature_of(message: str) -> str:
    """Collapse an entry to a stable shape so repeats can be counted."""
    text = message.strip()[:400]
    for pattern, replacement in _VOLATILE:
        text = pattern.sub(replacement, text)
    return text.strip().lower()
