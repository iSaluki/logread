"""systemd-journald as a log source.

On Fedora Workstation almost nothing writes plain files any more — the journal
is the log. LogRead talks to it through ``journalctl -o json``, which gives
exact priorities and timestamps instead of guessing them from text.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime

from . import privileged
from .entry import LogEntry
from .reader import ReadOutcome, ReadProblem
from .severity import Severity, severity_from_priority

__all__ = [
    "JournalQuery",
    "JournalResult",
    "is_available",
    "list_units",
    "list_boots",
    "read_journal",
    "probe_access",
]

_JSON_FIELDS = (
    "MESSAGE",
    "PRIORITY",
    "SYSLOG_IDENTIFIER",
    "_PID",
    "_COMM",
    "_SYSTEMD_UNIT",
    "_SYSTEMD_USER_UNIT",
    "_HOSTNAME",
    "CODE_FILE",
    "CODE_LINE",
)

_NO_ACCESS_HINTS = (
    "no journal files were found",
    "operation not permitted",
    "permission denied",
    "failed to open files",
)


@dataclass(slots=True)
class JournalQuery:
    """A slice of the journal to show."""

    unit: str | None = None
    identifier: str | None = None
    user_scope: bool = False
    boot: str | None = None          # "0" for this boot, "-1" for the previous one
    kernel_only: bool = False
    max_entries: int = 50_000
    since: str | None = None
    min_priority: int | None = None  # 0-7; journalctl -p

    def cache_key(self) -> tuple:
        return (
            self.unit, self.identifier, self.user_scope, self.boot,
            self.kernel_only, self.max_entries, self.since, self.min_priority,
        )


@dataclass(slots=True)
class JournalResult:
    entries: list[LogEntry] = field(default_factory=list)
    problem: ReadProblem = ReadProblem.NONE
    detail: str = ""
    truncated: bool = False
    used_privilege: bool = False
    hint: str = ""

    @property
    def ok(self) -> bool:
        return self.problem is ReadProblem.NONE


def _journalctl() -> str | None:
    return shutil.which("journalctl")


def is_available() -> bool:
    return _journalctl() is not None


def _run(argv: list[str], *, timeout: int = 45) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        capture_output=True,
        timeout=timeout,
        check=False,
        stdin=subprocess.DEVNULL,
        env={**os.environ, "LC_ALL": "C.UTF-8", "SYSTEMD_COLORS": "0"},
    )


def _denied(stderr: bytes, stdout: bytes) -> bool:
    text = stderr.decode("utf-8", "replace").lower()
    if any(hint in text for hint in _NO_ACCESS_HINTS):
        return True
    return not stdout.strip() and "no entries" not in text


@dataclass(slots=True)
class JournalAccess:
    """What this account can see in the journal, and how to widen it."""

    system: bool = False
    user: bool = False
    hint: str = ""


def probe_access() -> JournalAccess:
    """Check up front whether the system journal is readable without a prompt."""
    access = JournalAccess()
    if not is_available():
        access.hint = "systemd's journalctl is not installed on this system."
        return access
    try:
        system = _run([_journalctl(), "--no-pager", "-n", "1", "-o", "cat"], timeout=15)
        access.system = system.returncode == 0 and not _denied(system.stderr, system.stdout)
        user = _run([_journalctl(), "--user", "--no-pager", "-n", "1", "-o", "cat"], timeout=15)
        access.user = user.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return access
    if not access.system:
        access.hint = (
            "Add your account to the systemd-journal group to read system logs "
            "without being asked each time."
        )
    return access


def list_units(*, user_scope: bool = False, timeout: int = 30) -> list[str]:
    """Unit names that actually have entries in the journal."""
    journalctl = _journalctl()
    if journalctl is None:
        return []
    field_name = "_SYSTEMD_USER_UNIT" if user_scope else "_SYSTEMD_UNIT"
    argv = [journalctl, "--no-pager", "-F", field_name]
    if user_scope:
        argv.insert(1, "--user")
    try:
        completed = _run(argv, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if completed.returncode != 0:
        return _list_units_via_systemctl(user_scope=user_scope)
    names = {
        line.strip()
        for line in completed.stdout.decode("utf-8", "replace").splitlines()
        if line.strip() and not line.startswith("-")
    }
    if not names:
        return _list_units_via_systemctl(user_scope=user_scope)
    return sorted(names)


def _list_units_via_systemctl(*, user_scope: bool = False) -> list[str]:
    systemctl = shutil.which("systemctl")
    if systemctl is None:
        return []
    argv = [systemctl, "list-units", "--all", "--no-legend", "--plain", "--no-pager", "--type=service"]
    if user_scope:
        argv.insert(1, "--user")
    try:
        completed = _run(argv, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return []
    names = []
    for line in completed.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if parts and parts[0].endswith(".service"):
            names.append(parts[0])
    return sorted(set(names))


def list_boots(timeout: int = 20) -> list[tuple[str, str]]:
    """``(offset, label)`` for each boot the journal still remembers."""
    journalctl = _journalctl()
    if journalctl is None:
        return []
    try:
        completed = _run([journalctl, "--no-pager", "--list-boots", "-o", "json"], timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return []
    boots: list[tuple[str, str]] = []
    text = completed.stdout.decode("utf-8", "replace").strip()
    if text.startswith("["):
        try:
            for record in json.loads(text):
                index = str(record.get("index", ""))
                stamp = record.get("first_entry")
                label = _boot_label(index, stamp)
                boots.append((index, label))
        except ValueError:
            pass
    if not boots:
        try:
            completed = _run([journalctl, "--no-pager", "--list-boots"], timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            return []
        for line in completed.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split()
            if parts and (parts[0].lstrip("-").isdigit()):
                boots.append((parts[0], _boot_label(parts[0], None)))
    boots.sort(key=lambda item: int(item[0]), reverse=True)
    return boots[:12]


def _boot_label(index: str, first_entry: object) -> str:
    when = ""
    if isinstance(first_entry, (int, float)) and first_entry > 0:
        try:
            when = datetime.fromtimestamp(first_entry / 1_000_000).strftime("%-d %b %Y, %H:%M")
        except (OverflowError, OSError, ValueError):
            when = ""
    if index == "0":
        return f"Current boot · started {when}" if when else "Current boot"
    if index == "-1":
        return f"Previous boot · {when}" if when else "Previous boot"
    return f"{index} boots ago · {when}" if when else f"{index} boots ago"


def _build_argv(query: JournalQuery, journalctl: str) -> list[str]:
    argv = [journalctl, "--no-pager", "-o", "json"]
    argv += ["--output-fields", ",".join(_JSON_FIELDS)]
    if query.user_scope:
        argv.append("--user")
    if query.unit:
        argv += ["--user-unit" if query.user_scope else "-u", query.unit]
    if query.identifier:
        argv += ["-t", query.identifier]
    if query.kernel_only:
        argv.append("-k")
    if query.boot is not None:
        argv += ["-b", query.boot]
    if query.since:
        argv += ["--since", query.since]
    if query.min_priority is not None:
        argv += ["-p", str(query.min_priority)]
    argv += ["-n", str(max(1, query.max_entries))]
    return argv


def _message_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        # journald hands back byte arrays for messages that are not valid UTF-8.
        try:
            return bytes(int(item) & 0xFF for item in value).decode("utf-8", "replace")
        except (TypeError, ValueError):
            return " ".join(str(item) for item in value)
    if value is None:
        return ""
    return str(value)


def _entry_from_record(record: dict, index: int) -> LogEntry:
    message = _message_text(record.get("MESSAGE"))
    severity = severity_from_priority(record.get("PRIORITY"))
    timestamp = None
    raw_time = record.get("__REALTIME_TIMESTAMP")
    if raw_time:
        try:
            timestamp = datetime.fromtimestamp(int(raw_time) / 1_000_000)
        except (OverflowError, OSError, ValueError, TypeError):
            timestamp = None

    source = (
        _text(record.get("SYSLOG_IDENTIFIER"))
        or _text(record.get("_COMM"))
        or _text(record.get("_SYSTEMD_UNIT"))
        or _text(record.get("_SYSTEMD_USER_UNIT"))
    )
    pid_raw = _text(record.get("_PID"))
    pid = int(pid_raw) if pid_raw.isdigit() else None

    stamp = timestamp.strftime("%b %d %H:%M:%S") if timestamp else ""
    prefix = f"{stamp} {source}" if source else stamp
    if pid:
        prefix += f"[{pid}]"
    raw = f"{prefix}: {message}" if prefix else message

    first, _, rest = message.partition("\n")
    entry = LogEntry(
        raw=raw if not rest else f"{prefix}: {first}" if prefix else first,
        message=first,
        severity=severity if severity is not Severity.UNKNOWN else Severity.INFO,
        timestamp=timestamp,
        source=source or None,
        pid=pid,
        line_no=index,
    )
    if rest:
        entry.extra_lines.extend(rest.split("\n"))
    return entry


def _text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return _message_text(value)
    return ""


def read_journal(query: JournalQuery, *, allow_privilege: bool = False) -> JournalResult:
    """Run one journalctl query and turn its records into entries."""
    journalctl = _journalctl()
    if journalctl is None:
        return JournalResult(
            problem=ReadProblem.UNREADABLE,
            detail="systemd's journalctl is not installed on this system.",
        )

    argv = _build_argv(query, journalctl)
    used_privilege = False
    try:
        if allow_privilege and not query.user_scope:
            payload = privileged.run_journalctl(argv[1:], timeout=90)
            used_privilege = True
            stderr = b""
            returncode = 0
        else:
            completed = _run(argv, timeout=90)
            payload, stderr, returncode = completed.stdout, completed.stderr, completed.returncode
    except privileged.PrivilegeError as error:
        return JournalResult(problem=ReadProblem.PERMISSION, detail=str(error))
    except subprocess.TimeoutExpired:
        return JournalResult(
            problem=ReadProblem.UNREADABLE,
            detail="The journal took too long to answer. Try narrowing the range.",
        )
    except OSError as error:
        return JournalResult(problem=ReadProblem.UNREADABLE, detail=str(error))

    if returncode != 0 and not payload.strip():
        if _denied(stderr, payload):
            return JournalResult(
                problem=ReadProblem.PERMISSION,
                detail="Your account cannot read the system journal.",
                hint=(
                    "Run “sudo usermod -aG systemd-journal $USER” and log back in to "
                    "read system logs without a prompt."
                ),
            )
        detail = stderr.decode("utf-8", "replace").strip().splitlines()
        return JournalResult(
            problem=ReadProblem.UNREADABLE,
            detail=detail[-1] if detail else "The journal could not be read.",
        )

    entries: list[LogEntry] = []
    for index, line in enumerate(payload.decode("utf-8", "replace").splitlines(), start=1):
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            entries.append(_entry_from_record(record, index))

    if not entries:
        if not used_privilege and _denied(stderr, payload):
            return JournalResult(
                problem=ReadProblem.PERMISSION,
                detail="Your account cannot read the system journal.",
                hint=(
                    "Run “sudo usermod -aG systemd-journal $USER” and log back in to "
                    "read system logs without a prompt."
                ),
            )
        return JournalResult(
            problem=ReadProblem.EMPTY,
            detail="The journal has no entries for this selection.",
            used_privilege=used_privilege,
        )

    return JournalResult(
        entries=entries,
        truncated=len(entries) >= query.max_entries,
        used_privilege=used_privilege,
    )


def outcome_from_result(result: JournalResult, label: str) -> ReadOutcome:
    """Adapt a journal result to the same shape file reads produce."""
    return ReadOutcome(
        path=label,
        lines=[entry.raw for entry in result.entries],
        problem=result.problem,
        detail=result.detail,
        truncated=result.truncated,
        used_privilege=result.used_privilege,
    )
