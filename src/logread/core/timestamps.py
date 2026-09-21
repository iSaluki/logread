"""Timestamp parsing shared by the log format rules.

Every timestamp LogRead produces is a *naive local* `datetime`, so entries from
an ISO-8601-with-offset file sort correctly against entries from a BSD syslog
file that has no timezone at all.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

__all__ = ["to_local_naive", "parse_iso", "parse_bsd", "parse_apache", "parse_clf"]

_MONTHS = {
    name: index
    for index, name in enumerate(
        ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"],
        start=1,
    )
}

_ISO = re.compile(
    r"""(?x)
    (?P<year>\d{4}) [-/] (?P<month>\d{2}) [-/] (?P<day>\d{2})
    [T\ ]
    (?P<hour>\d{2}) : (?P<minute>\d{2}) (?: : (?P<second>\d{2}) )?
    (?: [.,] (?P<frac>\d{1,9}) )?
    (?P<tz> Z | z | [+-]\d{2}:?\d{2} )?
    """
)

_BSD = re.compile(
    r"(?i)^(?P<month>jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\w*\s+"
    r"(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:[.,](?P<frac>\d{1,6}))?"
)

# [Wed Oct 11 14:32:52.123456 2000]
_APACHE = re.compile(
    r"(?i)^\w{3}\s+(?P<month>jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s+"
    r"(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<frac>\d{1,6}))?\s+(?P<year>\d{4})"
)

# 10/Oct/2000:13:55:36 -0700
_CLF = re.compile(
    r"(?i)^(?P<day>\d{1,2})/(?P<month>jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)/"
    r"(?P<year>\d{4}):(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\s+(?P<tz>[+-]\d{4}))?"
)


def to_local_naive(moment: datetime) -> datetime:
    """Normalise an aware datetime to naive local time; pass naive ones through."""
    if moment.tzinfo is None:
        return moment
    return moment.astimezone().replace(tzinfo=None)


def _microseconds(frac: str | None) -> int:
    if not frac:
        return 0
    return int(frac[:6].ljust(6, "0"))


def _tzinfo(raw: str | None) -> timezone | None:
    if not raw:
        return None
    if raw in ("Z", "z"):
        return timezone.utc
    text = raw.replace(":", "")
    try:
        sign = 1 if text[0] == "+" else -1
        hours = int(text[1:3])
        minutes = int(text[3:5])
    except (IndexError, ValueError):
        return None
    offset = timedelta(hours=hours, minutes=minutes) * sign
    if abs(offset) >= timedelta(hours=24):
        return None
    return timezone(offset)


def _build(
    year: int, month: int, day: int, hour: int, minute: int, second: int,
    micro: int = 0, tz: timezone | None = None,
) -> datetime | None:
    try:
        moment = datetime(year, month, day, hour, minute, second, micro, tzinfo=tz)
    except ValueError:
        return None
    return to_local_naive(moment)


def parse_iso(text: str) -> tuple[datetime, int] | None:
    """Parse an ISO-8601-ish stamp anchored at the start of `text`."""
    match = _ISO.match(text)
    if not match:
        return None
    moment = _build(
        int(match["year"]), int(match["month"]), int(match["day"]),
        int(match["hour"]), int(match["minute"]), int(match["second"] or 0),
        _microseconds(match["frac"]), _tzinfo(match["tz"]),
    )
    return (moment, match.end()) if moment else None


def parse_bsd(text: str, year_hint: int | None = None) -> tuple[datetime, int] | None:
    """Parse a ``Oct 11 22:14:15`` stamp, which carries no year."""
    match = _BSD.match(text)
    if not match:
        return None
    month = _MONTHS[match["month"].lower()]
    year = year_hint or datetime.now().year
    moment = _build(
        year, month, int(match["day"]), int(match["hour"]),
        int(match["minute"]), int(match["second"]), _microseconds(match["frac"]),
    )
    if moment is None:
        return None
    # A stamp comfortably in the future means the file rolled over a new year.
    if moment - datetime.now() > timedelta(days=1):
        rolled = _build(
            year - 1, month, int(match["day"]), int(match["hour"]),
            int(match["minute"]), int(match["second"]), _microseconds(match["frac"]),
        )
        if rolled is not None:
            moment = rolled
    return moment, match.end()


def parse_apache(text: str) -> tuple[datetime, int] | None:
    match = _APACHE.match(text)
    if not match:
        return None
    moment = _build(
        int(match["year"]), _MONTHS[match["month"].lower()], int(match["day"]),
        int(match["hour"]), int(match["minute"]), int(match["second"]),
        _microseconds(match["frac"]),
    )
    return (moment, match.end()) if moment else None


def parse_clf(text: str) -> tuple[datetime, int] | None:
    match = _CLF.match(text)
    if not match:
        return None
    moment = _build(
        int(match["year"]), _MONTHS[match["month"].lower()], int(match["day"]),
        int(match["hour"]), int(match["minute"]), int(match["second"]),
        0, _tzinfo(match["tz"]),
    )
    return (moment, match.end()) if moment else None
