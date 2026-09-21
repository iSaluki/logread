"""Severity classification for log entries.

Everything LogRead reads is mapped onto the eight syslog priorities so that a
DNF transaction log, an nginx error log and a journald entry can be filtered,
counted and coloured with one vocabulary.
"""

from __future__ import annotations

import re
from enum import IntEnum

__all__ = [
    "Severity",
    "severity_from_token",
    "severity_from_priority",
    "guess_severity",
]


class Severity(IntEnum):
    """Syslog priorities, plus ``UNKNOWN`` for entries we could not classify."""

    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7
    UNKNOWN = 8

    @property
    def label(self) -> str:
        return _LABELS[self]

    @property
    def short_label(self) -> str:
        return _SHORT_LABELS[self]

    @property
    def css_class(self) -> str:
        """Style class used by both the text tags and the widget tree."""
        return _CSS_CLASSES[self]

    @property
    def icon_name(self) -> str:
        return _ICONS[self]

    @property
    def is_problem(self) -> bool:
        """Errors and warnings — the entries the Highlights view keeps."""
        return self <= Severity.WARNING

    @property
    def is_error(self) -> bool:
        return self <= Severity.ERROR

    @property
    def bucket(self) -> str:
        """Coarse grouping used by charts and summaries."""
        if self <= Severity.ERROR:
            return "error"
        if self == Severity.WARNING:
            return "warning"
        if self == Severity.DEBUG:
            return "debug"
        return "info"


_LABELS = {
    Severity.EMERGENCY: "Emergency",
    Severity.ALERT: "Alert",
    Severity.CRITICAL: "Critical",
    Severity.ERROR: "Error",
    Severity.WARNING: "Warning",
    Severity.NOTICE: "Notice",
    Severity.INFO: "Info",
    Severity.DEBUG: "Debug",
    Severity.UNKNOWN: "Message",
}

_SHORT_LABELS = {
    Severity.EMERGENCY: "EMERG",
    Severity.ALERT: "ALERT",
    Severity.CRITICAL: "CRIT",
    Severity.ERROR: "ERROR",
    Severity.WARNING: "WARN",
    Severity.NOTICE: "NOTICE",
    Severity.INFO: "INFO",
    Severity.DEBUG: "DEBUG",
    Severity.UNKNOWN: "",
}

_CSS_CLASSES = {
    Severity.EMERGENCY: "sev-critical",
    Severity.ALERT: "sev-critical",
    Severity.CRITICAL: "sev-critical",
    Severity.ERROR: "sev-error",
    Severity.WARNING: "sev-warning",
    Severity.NOTICE: "sev-notice",
    Severity.INFO: "sev-info",
    Severity.DEBUG: "sev-debug",
    Severity.UNKNOWN: "sev-unknown",
}

_ICONS = {
    Severity.EMERGENCY: "dialog-error-symbolic",
    Severity.ALERT: "dialog-error-symbolic",
    Severity.CRITICAL: "dialog-error-symbolic",
    Severity.ERROR: "dialog-error-symbolic",
    Severity.WARNING: "dialog-warning-symbolic",
    Severity.NOTICE: "dialog-information-symbolic",
    Severity.INFO: "dialog-information-symbolic",
    Severity.DEBUG: "bug-symbolic",
    Severity.UNKNOWN: "text-x-generic-symbolic",
}


# Level tokens as they appear across ecosystems: syslog, Python logging, Java
# util.logging, log4j, Go (zap/logrus/klog), systemd, Android, Xorg, PHP, Ruby.
_TOKENS: dict[str, Severity] = {
    "emerg": Severity.EMERGENCY,
    "emergency": Severity.EMERGENCY,
    "panic": Severity.EMERGENCY,
    "alert": Severity.ALERT,
    "crit": Severity.CRITICAL,
    "critical": Severity.CRITICAL,
    "fatal": Severity.CRITICAL,
    "severe": Severity.CRITICAL,
    "err": Severity.ERROR,
    "error": Severity.ERROR,
    "errors": Severity.ERROR,
    "eror": Severity.ERROR,
    "ee": Severity.ERROR,
    "e": Severity.ERROR,
    "failure": Severity.ERROR,
    "failed": Severity.ERROR,
    "warn": Severity.WARNING,
    "warning": Severity.WARNING,
    "warnings": Severity.WARNING,
    "wrn": Severity.WARNING,
    "ww": Severity.WARNING,
    "w": Severity.WARNING,
    "notice": Severity.NOTICE,
    "note": Severity.NOTICE,
    "n": Severity.NOTICE,
    "info": Severity.INFO,
    "information": Severity.INFO,
    "informational": Severity.INFO,
    "inf": Severity.INFO,
    "ii": Severity.INFO,
    "i": Severity.INFO,
    "log": Severity.INFO,
    "msg": Severity.INFO,
    "status": Severity.INFO,
    "config": Severity.INFO,
    "cfg": Severity.INFO,
    "debug": Severity.DEBUG,
    "dbg": Severity.DEBUG,
    "dd": Severity.DEBUG,
    "d": Severity.DEBUG,
    "trace": Severity.DEBUG,
    "trce": Severity.DEBUG,
    "verbose": Severity.DEBUG,
    "vrb": Severity.DEBUG,
    "fine": Severity.DEBUG,
    "finer": Severity.DEBUG,
    "finest": Severity.DEBUG,
    "v": Severity.DEBUG,
}

# Single letters are ambiguous enough that we only honour them when a parser
# explicitly says the token came from a level field.
_AMBIGUOUS = {"e", "w", "i", "d", "n", "v", "log", "msg", "status", "config", "cfg"}


def severity_from_token(token: str | None, *, allow_ambiguous: bool = False) -> Severity:
    """Map a textual level such as ``WARN`` or ``(EE)`` onto a `Severity`."""
    if not token:
        return Severity.UNKNOWN
    key = token.strip().strip("[](){}<>:*-_ \t").lower()
    if not key:
        return Severity.UNKNOWN
    if key in _AMBIGUOUS and not allow_ambiguous:
        return Severity.UNKNOWN
    return _TOKENS.get(key, Severity.UNKNOWN)


def severity_from_priority(value: object) -> Severity:
    """Map a numeric syslog priority (or a string holding one) onto a `Severity`."""
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return Severity.UNKNOWN
    if number < 0:
        return Severity.UNKNOWN
    # Values above 7 are full PRI values: facility * 8 + severity.
    number &= 0x07 if number > 7 else 0xFF
    if 0 <= number <= 7:
        return Severity(number)
    return Severity.UNKNOWN


# Heuristics for logs with no level field at all. Kept deliberately narrow: a
# false "error" in a 200k line file is worse than a missed one, because the
# Highlights view is only trustworthy if it is quiet.
_ERROR_PHRASES = re.compile(
    r"""(?xi)
    \b(
        fatal \s error
      | segmentation \s fault
      | segfault
      | kernel \s panic
      | core \s dumped
      | out \s of \s memory
      | no \s space \s left
      | permission \s denied
      | access \s denied
      | connection \s (?: refused | reset )
      | authentication \s failure
      | unable \s to \s \w+
      | fail (?: ed | ure | ures | ing | s )?
      | cannot \s (?: open | read | write | start | connect | load | create | allocate | find )
      | couldn't \s \w+
      | traceback \s \(most \s recent \s call \s last\)
      | unhandled \s exception
      | uncaught \s exception
      | assertion \s failed
      | i/o \s error
      | read-only \s file \s system
      | aborted
      | crashed
      | core \s dump
      | stack \s trace
    )(?!\w)
    """
)

_WARNING_PHRASES = re.compile(
    r"""(?xi)
    \b(
        deprecated
      | deprecation
      | timed \s out
      | timeout \s (?: reached | exceeded )
      | retrying
      | will \s retry
      | falling \s back
      | not \s found,? \s skipping
      | ignoring \s invalid
      | no \s such \s file \s or \s directory
      | could \s not \s find
      | permission \s warning
    )(?!\w)
    """
)

# "0 errors", "error: none", "errors=0" and friends must not trip the heuristic.
_NEGATED = re.compile(
    r"(?i)\b(?:0|no|none|zero)\s+(?:errors?|warnings?|failures?|failed)\b"
    r"|\b(?:without|never)\s+(?:error|failure|failing)s?\b"
    r"|\bfail(?:ure)?s?\s*[:=]\s*(?:0|none|null|false)\b"
    r"|\berrors?\s*[:=]\s*(?:0|none|null|false)\b"
    r"|\bwarnings?\s*[:=]\s*(?:0|none|null|false)\b"
)

_BARE_LEVEL = re.compile(
    r"(?i)(?:^|[\s\[\(<|])(error|warning|warn|critical|fatal|panic)(?:[\s\]\)>:|,!]|$)"
)


def guess_severity(message: str) -> tuple[Severity, bool]:
    """Best-effort severity for an entry with no explicit level.

    Returns the severity together with a flag marking it as a guess, so the UI
    can tell the user the classification came from the message text.
    """
    if not message:
        return Severity.UNKNOWN, False
    sample = message[:600]
    if _NEGATED.search(sample):
        return Severity.UNKNOWN, False
    if _ERROR_PHRASES.search(sample):
        return Severity.ERROR, True
    if _WARNING_PHRASES.search(sample):
        return Severity.WARNING, True
    match = _BARE_LEVEL.search(sample)
    if match:
        word = match.group(1).lower()
        if word in ("critical", "fatal", "panic"):
            return Severity.CRITICAL, True
        if word == "error":
            return Severity.ERROR, True
        return Severity.WARNING, True
    return Severity.UNKNOWN, False
