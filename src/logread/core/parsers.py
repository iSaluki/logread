"""Log format rules.

LogRead does not ask the user what format a file is in. It tries an ordered set
of rules against every line, most specific first, and remembers which rule wins
so the rest of the file is parsed with that one tried first. Anything nothing
matches still becomes an entry — a log reader that drops lines it does not
understand is worse than useless.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from .entry import LogEntry
from .severity import Severity, guess_severity, severity_from_priority, severity_from_token
from .timestamps import parse_apache, parse_bsd, parse_clf, parse_iso

__all__ = ["LogParser", "FORMAT_NAMES", "parse_lines"]


@dataclass(slots=True)
class _Fields:
    message: str
    severity: Severity = Severity.UNKNOWN
    timestamp: datetime | None = None
    source: str | None = None
    pid: int | None = None
    guessed: bool = False


Rule = Callable[[str, int | None], "_Fields | None"]


# --------------------------------------------------------------------------
# Individual format rules. Each returns None when the line is not its shape.
# --------------------------------------------------------------------------

_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$"
)


def _rule_rfc5424(line: str, year_hint: int | None) -> _Fields | None:
    match = _RFC5424.match(line)
    if not match:
        return None
    stamp = parse_iso(match["ts"])
    rest = match["rest"]
    # Strip structured data elements so the message reads cleanly.
    while rest.startswith("["):
        depth, index = 0, 0
        for index, char in enumerate(rest):
            if char == "[":
                depth += 1
            elif char == "]" and rest[index - 1] != "\\":
                depth -= 1
                if depth == 0:
                    break
        if depth != 0:
            break
        rest = rest[index + 1 :].lstrip()
    if rest.startswith("-") and (len(rest) == 1 or rest[1].isspace()):
        rest = rest[1:].lstrip()
    pid = match["pid"]
    app = match["app"]
    return _Fields(
        message=rest,
        severity=severity_from_priority(match["pri"]),
        timestamp=stamp[0] if stamp else None,
        source=None if app == "-" else app,
        pid=int(pid) if pid.isdigit() else None,
    )


_SYSLOG_TAIL = re.compile(
    r"^(?P<host>[\w.\-:]+)\s+(?P<tag>[^\s:\[]{1,64})(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)


def _syslog_body(rest: str, stamp: datetime | None) -> _Fields | None:
    match = _SYSLOG_TAIL.match(rest)
    if not match:
        return None
    message = match["msg"]
    severity, guessed = guess_severity(message)
    return _Fields(
        message=message,
        severity=severity,
        timestamp=stamp,
        source=match["tag"],
        pid=int(match["pid"]) if match["pid"] else None,
        guessed=guessed,
    )


def _rule_syslog_bsd(line: str, year_hint: int | None) -> _Fields | None:
    stamp = parse_bsd(line, year_hint)
    if not stamp:
        return None
    return _syslog_body(line[stamp[1] :].lstrip(), stamp[0])


def _rule_syslog_iso(line: str, year_hint: int | None) -> _Fields | None:
    stamp = parse_iso(line)
    if not stamp:
        return None
    return _syslog_body(line[stamp[1] :].lstrip(), stamp[0])


# 2024/01/01 12:00:00 [error] 1234#0: *5 message
_NGINX_ERROR = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\]\s+"
    r"(?P<pid>\d+)#(?P<tid>\d+):\s*(?P<msg>.*)$"
)


def _rule_nginx_error(line: str, year_hint: int | None) -> _Fields | None:
    match = _NGINX_ERROR.match(line)
    if not match:
        return None
    stamp = parse_iso(match["ts"])
    return _Fields(
        message=match["msg"],
        severity=severity_from_token(match["level"], allow_ambiguous=True),
        timestamp=stamp[0] if stamp else None,
        source="nginx",
        pid=int(match["pid"]),
    )


# [Wed Oct 11 14:32:52.123456 2000] [core:error] [pid 123:tid 456] [client 1.2.3.4] message
_APACHE_ERROR = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+\[(?:(?P<module>[\w.\-]+):)?(?P<level>\w+)\]"
    r"(?:\s+\[pid\s+(?P<pid>\d+)(?::tid\s+\d+)?\])?\s*(?P<msg>.*)$"
)


def _rule_apache_error(line: str, year_hint: int | None) -> _Fields | None:
    match = _APACHE_ERROR.match(line)
    if not match:
        return None
    stamp = parse_apache(match["ts"])
    if stamp is None:
        iso = parse_iso(match["ts"])
        stamp = iso if iso else None
    severity = severity_from_token(match["level"], allow_ambiguous=True)
    if severity is Severity.UNKNOWN:
        return None
    return _Fields(
        message=match["msg"],
        severity=severity,
        timestamp=stamp[0] if stamp else None,
        source=match["module"] or "httpd",
        pid=int(match["pid"]) if match["pid"] else None,
    )


# 1.2.3.4 - user [10/Oct/2000:13:55:36 -0700] "GET /x HTTP/1.0" 500 2326 ...
_ACCESS = re.compile(
    r"^(?P<host>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?P<rest>.*)$'
)


def _rule_access_log(line: str, year_hint: int | None) -> _Fields | None:
    match = _ACCESS.match(line)
    if not match:
        return None
    stamp = parse_clf(match["ts"])
    status = int(match["status"])
    if status >= 500:
        severity = Severity.ERROR
    elif status >= 400:
        severity = Severity.WARNING
    else:
        severity = Severity.INFO
    message = f'{match["request"]} → {status}'
    if match["size"] not in ("-", "0"):
        message += f' ({match["size"]} bytes)'
    message += f' from {match["host"]}'
    return _Fields(
        message=message,
        severity=severity,
        timestamp=stamp[0] if stamp else None,
        source="access",
    )


# [    12.345] (EE) message   — Xorg and friends
_XORG = re.compile(r"^\[\s*(?P<up>\d+\.\d+)\]\s*\((?P<level>[A-Za-z*+-]{1,2})\)\s*(?P<msg>.*)$")
_XORG_LEVELS = {
    "EE": Severity.ERROR,
    "WW": Severity.WARNING,
    "II": Severity.INFO,
    "NI": Severity.NOTICE,
    "--": Severity.INFO,
    "**": Severity.INFO,
    "++": Severity.INFO,
    "==": Severity.INFO,
}


def _rule_xorg(line: str, year_hint: int | None) -> _Fields | None:
    match = _XORG.match(line)
    if not match:
        return None
    return _Fields(
        message=match["msg"],
        severity=_XORG_LEVELS.get(match["level"].upper(), Severity.UNKNOWN),
        source="Xorg",
    )


# <3>[ 1234.567890] message  — dmesg with or without a kernel priority
_KERNEL = re.compile(r"^(?:<(?P<pri>\d{1,3})>)?\[\s*(?P<up>\d+\.\d+)\]\s*(?P<msg>.*)$")


def _rule_kernel(line: str, year_hint: int | None) -> _Fields | None:
    match = _KERNEL.match(line)
    if not match:
        return None
    message = match["msg"]
    guessed = False
    if match["pri"]:
        severity = severity_from_priority(match["pri"])
    else:
        severity, guessed = guess_severity(message)
    return _Fields(message=message, severity=severity, source="kernel", guessed=guessed)


_JSON_LEVEL_KEYS = ("level", "severity", "lvl", "levelname", "loglevel", "log_level", "priority", "PRIORITY")
_JSON_MESSAGE_KEYS = ("message", "msg", "MESSAGE", "text", "log", "event", "short_message")
_JSON_TIME_KEYS = ("time", "timestamp", "ts", "@timestamp", "asctime", "datetime", "eventTime")
_JSON_SOURCE_KEYS = ("logger", "name", "component", "unit", "service", "module", "caller", "SYSLOG_IDENTIFIER", "tag")


def _rule_json(line: str, year_hint: int | None) -> _Fields | None:
    stripped = line.lstrip()
    if not stripped.startswith("{") or not stripped.rstrip().endswith("}"):
        return None
    try:
        payload = json.loads(stripped)
    except (ValueError, RecursionError):
        return None
    if not isinstance(payload, dict):
        return None

    severity = Severity.UNKNOWN
    for key in _JSON_LEVEL_KEYS:
        if key in payload:
            value = payload[key]
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                severity = _numeric_level(int(value), payload)
            else:
                severity = severity_from_token(str(value), allow_ambiguous=True)
            if severity is not Severity.UNKNOWN:
                break

    message = ""
    for key in _JSON_MESSAGE_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value:
            message = value
            break
    if not message:
        message = ", ".join(
            f"{key}={value}" for key, value in payload.items() if not isinstance(value, (dict, list))
        )

    timestamp = None
    for key in _JSON_TIME_KEYS:
        value = payload.get(key)
        if isinstance(value, str):
            parsed = parse_iso(value)
            if parsed:
                timestamp = parsed[0]
                break
        elif isinstance(value, (int, float)) and value > 0:
            seconds = float(value)
            # Heuristically shrink milli/micro/nanosecond epochs down to seconds.
            while seconds > 1e11:
                seconds /= 1000.0
            try:
                timestamp = datetime.fromtimestamp(seconds)
            except (OverflowError, OSError, ValueError):
                timestamp = None
            if timestamp:
                break

    source = None
    for key in _JSON_SOURCE_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value:
            source = value
            break

    guessed = False
    if severity is Severity.UNKNOWN:
        severity, guessed = guess_severity(message)
    fields = _Fields(
        message=message, severity=severity, timestamp=timestamp, source=source, guessed=guessed
    )
    pid = payload.get("pid") or payload.get("_PID")
    if isinstance(pid, (int, str)) and str(pid).isdigit():
        fields.pid = int(pid)
    return fields


# Python's logging module and the bunyan/pino family both number their levels in
# tens, but they disagree about what each number means. Pick the scale from the
# other keys the record carries.
_PYTHON_LEVELS = {
    10: Severity.DEBUG, 20: Severity.INFO, 30: Severity.WARNING,
    40: Severity.ERROR, 50: Severity.CRITICAL,
}
_BUNYAN_LEVELS = {
    10: Severity.DEBUG, 20: Severity.DEBUG, 30: Severity.INFO,
    40: Severity.WARNING, 50: Severity.ERROR, 60: Severity.CRITICAL,
}


def _numeric_level(value: int, payload: dict) -> Severity:
    if 0 <= value <= 7 and not _is_tens_scale(value, payload):
        return severity_from_priority(value)
    if _is_tens_scale(value, payload):
        table = _BUNYAN_LEVELS if ("v" in payload or "hostname" in payload) else _PYTHON_LEVELS
        return table.get(value, Severity.UNKNOWN)
    return severity_from_priority(value)


def _is_tens_scale(value: int, payload: dict) -> bool:
    return 10 <= value <= 60 and value % 10 == 0


_LOGFMT_PAIR = re.compile(r'([\w.\-]+)=("(?:[^"\\]|\\.)*"|\S*)')


def _rule_logfmt(line: str, year_hint: int | None) -> _Fields | None:
    if "=" not in line:
        return None
    pairs = _LOGFMT_PAIR.findall(line)
    if len(pairs) < 2:
        return None
    # Guard against prose that happens to contain "a=b".
    consumed = sum(len(key) + len(value) + 1 for key, value in pairs)
    if consumed < len(line.strip()) * 0.6:
        return None
    values = {}
    for key, raw in pairs:
        if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
            try:
                raw = json.loads(raw)
            except ValueError:
                raw = raw[1:-1]
        values[key.lower()] = raw

    severity = Severity.UNKNOWN
    for key in ("level", "lvl", "severity", "loglevel"):
        if key in values:
            severity = severity_from_token(values[key], allow_ambiguous=True)
            if severity is not Severity.UNKNOWN:
                break
    message = ""
    for key in ("msg", "message", "event", "error", "err"):
        if values.get(key):
            message = values[key]
            break
    if not message:
        return None

    timestamp = None
    for key in ("ts", "time", "timestamp", "t"):
        if key in values:
            parsed = parse_iso(values[key])
            if parsed:
                timestamp = parsed[0]
                break
    source = values.get("logger") or values.get("component") or values.get("caller")
    guessed = False
    if severity is Severity.UNKNOWN:
        severity, guessed = guess_severity(message)
    extras = " ".join(
        f"{key}={value}"
        for key, value in values.items()
        if key not in ("msg", "message", "level", "lvl", "severity", "loglevel", "ts", "time", "timestamp", "t")
    )
    if extras:
        message = f"{message}  ({extras})"
    return _Fields(
        message=message, severity=severity, timestamp=timestamp, source=source, guessed=guessed
    )


# [2024-01-01T12:00:00+0000] [ALPM] upgraded foo  — pacman
_PACMAN = re.compile(r"^\[(?P<ts>[^\]]+)\]\s+\[(?P<sub>[A-Z\-]+)\]\s*(?P<msg>.*)$")


def _rule_pacman(line: str, year_hint: int | None) -> _Fields | None:
    match = _PACMAN.match(line)
    if not match:
        return None
    stamp = parse_iso(match["ts"])
    if stamp is None:
        return None
    message = match["msg"]
    severity, guessed = guess_severity(message)
    if severity is Severity.UNKNOWN:
        severity, guessed = Severity.INFO, False
    return _Fields(
        message=message, severity=severity, timestamp=stamp[0],
        source=match["sub"].lower(), guessed=guessed,
    )


# 2024-01-01T12:00:00+0000 INFO message            — dnf
# 2024-01-01 12:00:00,123 - logger - LEVEL - msg   — python logging
# 2024-01-01 12:00:00.123 LEVEL [thread] logger - msg
_TS_LEVEL = re.compile(
    r"""(?x)
    ^
    (?:
        (?P<sep1>\s*[-:|\u2013]?\s*)
        (?:\[(?P<blevel>[A-Za-z]{1,8})\]|\((?P<plevel>[A-Za-z]{1,8})\)|(?P<level>[A-Za-z]{1,8})\b)
    )
    (?P<rest>.*)$
    """
)
_PY_LOGGER = re.compile(r"^\s*[-:|]\s*(?P<logger>[\w.\-]{1,64})\s*[-:|]\s*(?P<rest>.*)$")


def _rule_timestamp_level(line: str, year_hint: int | None) -> _Fields | None:
    stamp = parse_iso(line)
    if not stamp:
        return None
    moment, offset = stamp
    rest = line[offset:]
    if not rest[:1].isspace() and rest[:1] not in ("", "-", ":", "|", "["):
        return None

    source = None
    severity = Severity.UNKNOWN
    logger_match = _PY_LOGGER.match(rest)
    if logger_match and severity_from_token(logger_match["logger"]) is Severity.UNKNOWN:
        source = logger_match["logger"]
        rest = " " + logger_match["rest"]

    level_match = _TS_LEVEL.match(rest)
    if level_match:
        token = level_match["blevel"] or level_match["plevel"] or level_match["level"]
        candidate = severity_from_token(token)
        if candidate is not Severity.UNKNOWN:
            severity = candidate
            rest = level_match["rest"]

    message = rest.strip().lstrip("-:|").strip() if severity is not Severity.UNKNOWN else rest.strip()
    guessed = False
    if severity is Severity.UNKNOWN:
        severity, guessed = guess_severity(message)
        if severity is Severity.UNKNOWN:
            return None
    return _Fields(
        message=message, severity=severity, timestamp=moment, source=source, guessed=guessed
    )


# [ERROR] message / ERROR: message / E: message / <3>message
_LEADING_LEVEL = re.compile(
    r"^\s*(?:\[(?P<b>[A-Za-z]{1,8})\]|\((?P<p>[A-Za-z]{1,8})\)|(?P<w>[A-Za-z]{1,8})\s*:)\s*(?P<msg>.*)$"
)


def _rule_leading_level(line: str, year_hint: int | None) -> _Fields | None:
    match = _LEADING_LEVEL.match(line)
    if not match:
        return None
    token = match["b"] or match["p"] or match["w"]
    bracketed = bool(match["b"] or match["p"])
    severity = severity_from_token(token, allow_ambiguous=bracketed)
    if severity is Severity.UNKNOWN:
        return None
    return _Fields(message=match["msg"], severity=severity)


def _rule_fallback(line: str, year_hint: int | None) -> _Fields | None:
    """Never fails: keeps the line, finds a timestamp if one is there."""
    rest = line
    timestamp = None
    for parse in (parse_iso, lambda text: parse_bsd(text, year_hint)):
        stamp = parse(line)
        if stamp:
            timestamp, rest = stamp[0], line[stamp[1] :].lstrip()
            break
    severity, guessed = guess_severity(rest)
    return _Fields(message=rest, severity=severity, timestamp=timestamp, guessed=guessed)


_RULES: list[tuple[str, Rule]] = [
    ("RFC 5424 syslog", _rule_rfc5424),
    ("nginx error log", _rule_nginx_error),
    ("Apache error log", _rule_apache_error),
    ("Web access log", _rule_access_log),
    ("Xorg log", _rule_xorg),
    ("JSON lines", _rule_json),
    ("pacman log", _rule_pacman),
    ("syslog", _rule_syslog_bsd),
    ("syslog (ISO time)", _rule_syslog_iso),
    ("Timestamped log", _rule_timestamp_level),
    ("logfmt", _rule_logfmt),
    ("Kernel ring buffer", _rule_kernel),
    ("Level-prefixed log", _rule_leading_level),
]

FORMAT_NAMES = [name for name, _ in _RULES] + ["Plain text"]

# Lines that belong to the entry above them: stack traces, indented detail,
# continuation markers. Folding them in keeps a traceback attached to its error.
_CONTINUATION = re.compile(
    r"""(?x)
    ^(?:
        \s{2,}
      | \t
      | \s*(?: at\ [\w.$<>]+ | Caused\ by: | \.\.\. \ \d+\ more | \#\d+\ )
      | \s*File\ "
      | \s*\^+\s*$
      | \s*\|\s
      | \s*>\s
      | Traceback\ \(most\ recent\ call\ last\):
      | During\ handling\ of\ the\ above\ exception
      | The\ above\ exception\ was\ the\ direct\ cause
      | Stack\ trace:
      | goroutine\ \d+\ \[
    )
    """
)

# The final line of a Python traceback is flush left, so it only counts as a
# continuation when we are already inside one.
_TRACEBACK_TAIL = re.compile(
    r"^(?:[A-Za-z_][\w.]*\.)*[A-Za-z_]\w*(?:Error|Exception|Warning|Exit|Interrupt|Fault|Abort)"
    r"\s*(?::|$)"
)


class LogParser:
    """Parses a stream of physical lines into `LogEntry` objects."""

    def __init__(self, year_hint: int | None = None, fold_continuations: bool = True) -> None:
        self.year_hint = year_hint
        self.fold_continuations = fold_continuations
        self._hits: dict[str, int] = {}
        self._preferred: tuple[str, Rule] | None = None
        self.format_name = "Plain text"

    # -- internal -------------------------------------------------------
    def _match(self, line: str) -> tuple[str, _Fields] | None:
        if self._preferred is not None:
            name, rule = self._preferred
            try:
                fields = rule(line, self.year_hint)
            except Exception:  # a malformed line must never kill the read
                fields = None
            if fields is not None:
                return name, fields
        for name, rule in _RULES:
            if self._preferred is not None and name == self._preferred[0]:
                continue
            try:
                fields = rule(line, self.year_hint)
            except Exception:
                continue
            if fields is not None:
                return name, fields
        return None

    def _record(self, name: str) -> None:
        self._hits[name] = self._hits.get(name, 0) + 1
        total = sum(self._hits.values())
        if total in (24, 64, 256, 1024) or (total > 1024 and total % 4096 == 0):
            best = max(self._hits.items(), key=lambda item: item[1])
            if best[1] >= total * 0.5:
                self.format_name = best[0]
                for entry in _RULES:
                    if entry[0] == best[0]:
                        self._preferred = entry
                        break

    def _folds(self, previous: LogEntry, line: str) -> bool:
        """Does `line` belong to the entry above it rather than start a new one?"""
        if _CONTINUATION.match(line):
            return True
        # ``ConnectionResetError: ...`` closes a traceback we are already in.
        return bool(previous.extra_lines and _TRACEBACK_TAIL.match(line))

    # -- public ---------------------------------------------------------
    def parse(self, lines: Iterable[str]) -> Iterator[LogEntry]:
        previous: LogEntry | None = None
        for index, raw in enumerate(lines, start=1):
            line = raw.rstrip("\n\r")
            if not line.strip():
                if previous is not None and previous.extra_lines:
                    previous.append_continuation(line)
                continue

            matched = self._match(line)
            if matched is None:
                if self.fold_continuations and previous is not None and self._folds(previous, line):
                    previous.append_continuation(line)
                    continue
                fields = _rule_fallback(line, self.year_hint)
                name = "Plain text"
            else:
                name, fields = matched
                if (
                    self.fold_continuations
                    and previous is not None
                    and fields.timestamp is None
                    and name in ("Plain text", "Kernel ring buffer", "Level-prefixed log")
                    and self._folds(previous, line)
                ):
                    previous.append_continuation(line)
                    continue
                self._record(name)

            if previous is not None:
                yield previous
            previous = LogEntry(
                raw=line,
                message=fields.message or line,
                severity=fields.severity,
                timestamp=fields.timestamp,
                source=fields.source,
                pid=fields.pid,
                line_no=index,
                guessed=fields.guessed,
            )
        if previous is not None:
            yield previous
        if self.format_name == "Plain text" and self._hits:
            best = max(self._hits.items(), key=lambda item: item[1])
            total = sum(self._hits.values())
            if best[1] >= total * 0.5:
                self.format_name = best[0]


def parse_lines(lines: Iterable[str], year_hint: int | None = None) -> list[LogEntry]:
    """Convenience wrapper used by tests and one-shot callers."""
    parser = LogParser(year_hint=year_hint)
    return list(parser.parse(lines))
