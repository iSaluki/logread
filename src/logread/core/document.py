"""One loaded log, ready to display.

Reading, parsing and summarising happen together so the window only has to
hand a `LogDocument` to each of its three views.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import journal
from .analysis import ProblemGroup, Summary, TimeBuckets, bucket_entries, problem_groups, summarise
from .entry import LogEntry
from .parsers import LogParser
from .reader import DEFAULT_MAX_BYTES, ReadOutcome, ReadProblem, read_file

__all__ = ["LogDocument", "load_file", "load_journal"]

BUCKET_COUNT = 56


@dataclass(slots=True)
class LogDocument:
    """Everything the views need about one log."""

    title: str
    subtitle: str = ""
    path: str = ""
    entries: list[LogEntry] = field(default_factory=list)
    problem: ReadProblem = ReadProblem.NONE
    detail: str = ""
    hint: str = ""
    truncated: bool = False
    used_privilege: bool = False
    can_elevate: bool = False
    format_name: str = ""
    encoding: str = ""
    total_bytes: int = 0
    loaded_at: datetime = field(default_factory=datetime.now)
    summary: Summary = field(default_factory=Summary)
    buckets: TimeBuckets = field(default_factory=TimeBuckets)
    groups: list[ProblemGroup] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.problem is ReadProblem.NONE and bool(self.entries)

    @property
    def is_empty(self) -> bool:
        return self.problem is ReadProblem.NONE and not self.entries

    def analyse(self, *, include_debug: bool = False) -> None:
        self.summary = summarise(self.entries)
        self.buckets = bucket_entries(self.entries, BUCKET_COUNT)
        self.groups = problem_groups(self.entries, include_debug=include_debug)

    def raw_text(self) -> str:
        return "\n".join(entry.full_raw for entry in self.entries)


def _year_hint(path: str) -> int | None:
    try:
        return datetime.fromtimestamp(os.stat(path).st_mtime).year
    except OSError:
        return None


def load_file(
    path: str,
    *,
    title: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_lines: int = 400_000,
    allow_privilege: bool = False,
    include_debug: bool = False,
) -> LogDocument:
    """Read, parse and summarise one log file."""
    outcome: ReadOutcome = read_file(
        path, max_bytes=max_bytes, max_lines=max_lines, allow_privilege=allow_privilege
    )
    document = LogDocument(
        title=title or Path(path).name,
        subtitle=path,
        path=path,
        problem=outcome.problem,
        detail=outcome.detail,
        truncated=outcome.truncated,
        used_privilege=outcome.used_privilege,
        can_elevate=outcome.can_elevate,
        encoding=outcome.encoding,
        total_bytes=outcome.total_bytes,
    )
    if outcome.problem is ReadProblem.PERMISSION:
        document.hint = (
            "LogRead can open this with administrator access. "
            "You will be asked to authenticate."
        )
    if not outcome.ok and not outcome.lines:
        return document

    parser = LogParser(year_hint=_year_hint(path))
    document.entries = list(parser.parse(outcome.lines))
    document.format_name = parser.format_name
    if outcome.replaced_characters:
        document.hint = "Some characters in this file are not valid text and were replaced."
    document.analyse(include_debug=include_debug)
    return document


def load_journal(
    query: journal.JournalQuery,
    *,
    title: str,
    subtitle: str = "",
    allow_privilege: bool = False,
    include_debug: bool = False,
) -> LogDocument:
    """Run one journal query and summarise the result."""
    result = journal.read_journal(query, allow_privilege=allow_privilege)
    document = LogDocument(
        title=title,
        subtitle=subtitle or "systemd journal",
        path="",
        problem=result.problem,
        detail=result.detail,
        hint=result.hint,
        truncated=result.truncated,
        used_privilege=result.used_privilege,
        can_elevate=result.problem is ReadProblem.PERMISSION and not query.user_scope,
        format_name="systemd journal",
        encoding="utf-8",
    )
    document.entries = result.entries
    if document.entries:
        document.analyse(include_debug=include_debug)
    return document
