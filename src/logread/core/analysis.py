"""Turning a pile of entries into something you can read at a glance.

Two questions matter when a log is 200,000 lines long: *when* did it go wrong,
and *what* went wrong most. `TimeBuckets` answers the first, `problem_groups`
the second by collapsing repeats of the same message into one row with a count.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .entry import LogEntry, signature_of
from .severity import Severity

__all__ = ["Summary", "TimeBucket", "TimeBuckets", "ProblemGroup", "summarise", "bucket_entries", "problem_groups"]


@dataclass(slots=True)
class Summary:
    """Headline numbers for one log."""

    total: int = 0
    counts: dict[Severity, int] = field(default_factory=dict)
    first: datetime | None = None
    last: datetime | None = None
    guessed: int = 0
    sources: int = 0

    @property
    def errors(self) -> int:
        return sum(count for severity, count in self.counts.items() if severity.is_error)

    @property
    def warnings(self) -> int:
        return self.counts.get(Severity.WARNING, 0)

    @property
    def problems(self) -> int:
        return self.errors + self.warnings

    @property
    def span(self) -> timedelta | None:
        if self.first and self.last:
            return self.last - self.first
        return None

    @property
    def has_timestamps(self) -> bool:
        return self.first is not None

    @property
    def health(self) -> str:
        """A one-word verdict used to colour the overview."""
        if self.errors:
            return "error"
        if self.warnings:
            return "warning"
        return "clear"


def summarise(entries: list[LogEntry]) -> Summary:
    summary = Summary(total=len(entries))
    sources: set[str] = set()
    for entry in entries:
        summary.counts[entry.severity] = summary.counts.get(entry.severity, 0) + 1
        if entry.guessed:
            summary.guessed += 1
        if entry.source:
            sources.add(entry.source)
        moment = entry.timestamp
        if moment is not None:
            if summary.first is None or moment < summary.first:
                summary.first = moment
            if summary.last is None or moment > summary.last:
                summary.last = moment
    summary.sources = len(sources)
    return summary


@dataclass(slots=True)
class TimeBucket:
    """One column of the activity strip."""

    index: int
    start: datetime | None
    end: datetime | None
    first_entry: int = 0
    errors: int = 0
    warnings: int = 0
    other: int = 0

    @property
    def total(self) -> int:
        return self.errors + self.warnings + self.other

    @property
    def problems(self) -> int:
        return self.errors + self.warnings

    def label(self, *, time_based: bool, fmt: str = "%H:%M") -> str:
        if time_based and self.start and self.end:
            if self.end - self.start >= timedelta(days=1):
                return self.start.strftime("%-d %b")
            return f"{self.start.strftime(fmt)}–{self.end.strftime(fmt)}"
        return f"Lines {self.first_entry + 1}+"

    def describe(self, *, time_based: bool) -> str:
        parts = []
        if self.errors:
            parts.append(f"{self.errors} error" + ("s" if self.errors != 1 else ""))
        if self.warnings:
            parts.append(f"{self.warnings} warning" + ("s" if self.warnings != 1 else ""))
        if not parts:
            parts.append(f"{self.total} message" + ("s" if self.total != 1 else ""))
        elif self.other:
            parts.append(f"{self.other} other")
        return f"{self.label(time_based=time_based)} · " + ", ".join(parts)


@dataclass(slots=True)
class TimeBuckets:
    """The activity strip: equal slices of a log, counted by severity."""

    buckets: list[TimeBucket] = field(default_factory=list)
    time_based: bool = False
    peak: int = 0
    peak_problems: int = 0
    span: timedelta | None = None
    unit_label: str = ""

    @property
    def usable(self) -> bool:
        return len(self.buckets) > 1 and self.peak > 0

    @property
    def busiest(self) -> TimeBucket | None:
        candidates = [bucket for bucket in self.buckets if bucket.problems]
        if not candidates:
            return None
        return max(candidates, key=lambda bucket: bucket.problems)


def _describe_span(span: timedelta) -> str:
    seconds = max(span.total_seconds(), 0)
    if seconds < 90:
        return "seconds"
    if seconds < 90 * 60:
        return "minutes"
    if seconds < 48 * 3600:
        return "hours"
    if seconds < 60 * 86400:
        return "days"
    return "months"


def bucket_entries(entries: list[LogEntry], count: int = 48) -> TimeBuckets:
    """Split entries into `count` slices, by time when we have it.

    Logs without timestamps still get a strip — it just measures position in
    the file rather than the clock, which is still the answer to "where in this
    file did it start going wrong".
    """
    result = TimeBuckets()
    if not entries or count < 2:
        return result

    stamped = [entry for entry in entries if entry.timestamp is not None]
    use_time = len(stamped) >= max(4, len(entries) * 0.25)

    if use_time:
        first = min(entry.timestamp for entry in stamped)
        last = max(entry.timestamp for entry in stamped)
        span = last - first
        if span.total_seconds() <= 0:
            use_time = False
        else:
            result.time_based = True
            result.span = span
            result.unit_label = _describe_span(span)
            step = span / count
            result.buckets = [
                TimeBucket(index=index, start=first + step * index, end=first + step * (index + 1))
                for index in range(count)
            ]
            seconds = span.total_seconds()
            for position, entry in enumerate(entries):
                moment = entry.timestamp
                if moment is None:
                    continue
                offset = (moment - first).total_seconds()
                index = min(count - 1, max(0, int(offset / seconds * count)))
                bucket = result.buckets[index]
                if bucket.total == 0:
                    bucket.first_entry = position
                _tally(bucket, entry.severity)

    if not use_time:
        result.time_based = False
        size = max(1, math.ceil(len(entries) / count))
        buckets = [
            TimeBucket(index=index, start=None, end=None, first_entry=index * size)
            for index in range(math.ceil(len(entries) / size))
        ]
        result.buckets = buckets
        for position, entry in enumerate(entries):
            _tally(buckets[min(position // size, len(buckets) - 1)], entry.severity)

    result.peak = max((bucket.total for bucket in result.buckets), default=0)
    result.peak_problems = max((bucket.problems for bucket in result.buckets), default=0)
    return result


def _tally(bucket: TimeBucket, severity: Severity) -> None:
    if severity.is_error:
        bucket.errors += 1
    elif severity is Severity.WARNING:
        bucket.warnings += 1
    else:
        bucket.other += 1


@dataclass(slots=True)
class ProblemGroup:
    """One recurring problem, with every occurrence behind it."""

    signature: str
    severity: Severity
    sample: LogEntry
    count: int = 1
    first: datetime | None = None
    last: datetime | None = None
    positions: list[int] = field(default_factory=list)

    @property
    def is_repeat(self) -> bool:
        return self.count > 1

    def when(self) -> str:
        if self.first is None:
            return ""
        if self.count == 1 or self.last is None or self.first == self.last:
            return self.first.strftime("%-d %b, %H:%M:%S")
        return f"{self.first.strftime('%-d %b, %H:%M')} – {self.last.strftime('%-d %b, %H:%M')}"

    def copy_text(self) -> str:
        """What the row's copy button puts on the clipboard."""
        lines = [self.sample.full_raw]
        if self.count > 1:
            lines.append(f"[repeated {self.count} times]")
        return "\n".join(lines)


def problem_groups(
    entries: list[LogEntry],
    *,
    include_debug: bool = False,
    minimum: Severity = Severity.WARNING,
    limit: int = 2000,
) -> list[ProblemGroup]:
    """Collapse the problem entries into distinct, counted groups."""
    groups: dict[str, ProblemGroup] = {}
    order: list[str] = []
    for position, entry in enumerate(entries):
        too_quiet = entry.severity > minimum
        if too_quiet and not (include_debug and entry.severity is Severity.DEBUG):
            continue
        key = f"{entry.severity.value}\x00{signature_of(entry.message)}"
        group = groups.get(key)
        if group is None:
            if len(groups) >= limit:
                continue
            group = ProblemGroup(
                signature=key,
                severity=entry.severity,
                sample=entry,
                count=0,
                first=entry.timestamp,
                last=entry.timestamp,
            )
            groups[key] = group
            order.append(key)
        group.count += 1
        if len(group.positions) < 500:
            group.positions.append(position)
        if entry.timestamp is not None:
            if group.first is None or entry.timestamp < group.first:
                group.first = entry.timestamp
            if group.last is None or entry.timestamp > group.last:
                group.last = entry.timestamp
    return [groups[key] for key in order]


def rank_groups(groups: list[ProblemGroup], limit: int = 6) -> list[ProblemGroup]:
    """The handful of problems worth putting on the overview."""
    ranked = sorted(
        groups,
        key=lambda group: (group.severity.value, -group.count, -(group.last.timestamp() if group.last else 0)),
    )
    return ranked[:limit]
