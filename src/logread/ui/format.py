"""Small formatting helpers shared by the views."""

from __future__ import annotations

from datetime import datetime, timedelta

__all__ = ["file_size", "relative_time", "duration", "plural", "clock", "count"]


def file_size(size: int) -> str:
    if size <= 0:
        return "Empty"
    units = ("bytes", "kB", "MB", "GB", "TB")
    value = float(size)
    index = 0
    while value >= 1000 and index < len(units) - 1:
        value /= 1000
        index += 1
    if index == 0:
        return f"{int(value)} bytes"
    return f"{value:.1f} {units[index]}" if value < 10 else f"{value:.0f} {units[index]}"


def count(number: int) -> str:
    return f"{number:,}".replace(",", " ")


def plural(number: int, singular: str, many: str | None = None) -> str:
    word = singular if number == 1 else (many or f"{singular}s")
    return f"{count(number)} {word}"


def clock(moment: datetime | None, *, with_date: bool = False) -> str:
    if moment is None:
        return ""
    if with_date:
        return moment.strftime("%-d %b %Y, %H:%M:%S")
    return moment.strftime("%H:%M:%S")


def relative_time(moment: datetime | float | None) -> str:
    """"3 minutes ago", "Yesterday", "12 Mar" — never a raw epoch."""
    if moment is None:
        return "Unknown"
    if isinstance(moment, (int, float)):
        if moment <= 0:
            return "Unknown"
        try:
            moment = datetime.fromtimestamp(moment)
        except (OverflowError, OSError, ValueError):
            return "Unknown"
    now = datetime.now()
    delta = now - moment
    seconds = delta.total_seconds()
    if seconds < 0:
        return "Just now"
    if seconds < 60:
        return "Just now"
    if seconds < 3600:
        minutes = int(seconds // 60)
        return f"{minutes} minute ago" if minutes == 1 else f"{minutes} minutes ago"
    if seconds < 86400 and moment.date() == now.date():
        hours = int(seconds // 3600)
        return f"{hours} hour ago" if hours == 1 else f"{hours} hours ago"
    if (now.date() - moment.date()).days == 1:
        return f"Yesterday, {moment.strftime('%H:%M')}"
    if (now.date() - moment.date()).days < 7:
        return moment.strftime("%A, %H:%M")
    if moment.year == now.year:
        return moment.strftime("%-d %b")
    return moment.strftime("%-d %b %Y")


def duration(span: timedelta | None) -> str:
    if span is None:
        return "Unknown"
    seconds = int(max(span.total_seconds(), 0))
    if seconds < 60:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{seconds // 60} min"
    if seconds < 86400:
        hours, rest = divmod(seconds, 3600)
        minutes = rest // 60
        return f"{hours} h {minutes} min" if minutes else f"{hours} h"
    days, rest = divmod(seconds, 86400)
    hours = rest // 3600
    return f"{days} d {hours} h" if hours else f"{days} d"
