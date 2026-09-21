"""Finding logs without being told where they are.

The scan walks a set of roots that covers Fedora, Debian/Ubuntu, Arch,
openSUSE and the per-application directories used by Flatpak and Snap, groups
what it finds into applications and services, and folds in whatever systemd's
journal knows about. Directories it is not allowed to enter are remembered
rather than skipped silently, so the window can offer to unlock them.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import journal, privileged
from .catalog import Category, Description, describe_key, desktop_entries, group_key, prettify
from .reader import ReadProblem, probe_file

__all__ = ["LogFile", "LogSource", "DiscoveryResult", "ScanOptions", "scan", "SYSTEM_ROOTS"]

# (path, max depth). Depths are tight on purpose: /var/log on a busy server can
# hold tens of thousands of files, and a log reader that hangs is a broken one.
SYSTEM_ROOTS: tuple[tuple[str, int], ...] = (
    ("/var/log", 4),
    ("/run/log", 3),
    ("/usr/local/var/log", 3),
    ("/var/lib/systemd/coredump", 1),
)

_USER_ROOTS: tuple[tuple[str, int], ...] = (
    (".local/state", 4),
    (".local/share/xorg", 2),
    (".cache", 3),
    (".config", 3),
    (".var/app", 5),
    ("snap", 5),
    (".logs", 3),
)

# Never descend into these: binary journals, package caches, source trees and
# the multi-gigabyte browser caches that dominate ~/.cache.
_PRUNE_NAMES = {
    "journal", "sysstat", "lost+found", ".git", ".svn", "node_modules",
    "__pycache__", "site-packages", "dist-packages", "cache2", "Cache",
    "Code Cache", "GPUCache", "ShaderCache", "Service Worker", "IndexedDB",
    "CacheStorage", "thumbnails", "mesa_shader_cache", "mesa_shader_cache_db",
    "fontconfig", "gstreamer-1.0", "tracker3", "pip", "go-build", "typescript",
    "chromium", "google-chrome", "BraveSoftware", "Microsoft", "spotify",
}

_ACCEPT_SUFFIXES = (".log", ".err", ".out", ".trace", ".journal-text")
_COMPRESSED = (".gz", ".bz2", ".xz", ".lzma", ".zst", ".zstd")

# Files with no extension that are still logs.
_ACCEPT_NAMES = {
    "messages", "syslog", "secure", "maillog", "cron", "spooler", "debug",
    "dmesg", "dmesg.old", "wtmp", "btmp", "lastlog", "faillog", "tallylog",
    "xsession-errors", "boot", "auth", "kern", "daemon", "user", "mail",
    "history", "current", "errors", "output", "console",
}

_SKIP_NAMES = {"README", "LICENSE", "COPYING", ".gitignore", "lock", "LOCK"}

# name.1 / name.log.3 / name.20240101 — a rotated sibling.
_ROTATED = re.compile(r"\.(?:\d{1,8}|\d{4}-?\d{2}-?\d{2})(?:\.(?:gz|bz2|xz|lzma|zst|zstd))?$")

_MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024
_DEFAULT_FILE_BUDGET = 40_000


@dataclass(slots=True)
class LogFile:
    """One readable (or lockable) file belonging to a source."""

    path: str
    name: str
    size: int = 0
    mtime: float = 0.0
    readable: bool = True
    problem: ReadProblem = ReadProblem.NONE
    compressed: bool = False
    archived: bool = False

    @property
    def needs_privilege(self) -> bool:
        return self.problem is ReadProblem.PERMISSION

    @property
    def can_unlock(self) -> bool:
        return self.needs_privilege and privileged.is_elevation_root(self.path)


@dataclass(slots=True)
class LogSource:
    """An application or service, as shown at the top level of the sidebar."""

    key: str
    name: str
    summary: str = ""
    icon: str = "text-x-generic-symbolic"
    category: str = Category.OTHER
    kind: str = "files"  # files | journal | journal-unit
    files: list[LogFile] = field(default_factory=list)
    journal_queries: list[tuple[str, journal.JournalQuery]] = field(default_factory=list)
    locked_count: int = 0
    last_activity: float = 0.0

    @property
    def item_count(self) -> int:
        return len(self.files) + len(self.journal_queries)

    @property
    def is_journal(self) -> bool:
        return self.kind != "files"

    @property
    def fully_locked(self) -> bool:
        return bool(self.files) and self.locked_count == len(self.files)

    def subtitle(self) -> str:
        if self.summary:
            return self.summary
        count = self.item_count
        return "1 log" if count == 1 else f"{count} logs"


@dataclass(slots=True)
class DiscoveryResult:
    sources: list[LogSource] = field(default_factory=list)
    denied_directories: list[str] = field(default_factory=list)
    locked_files: int = 0
    scanned_directories: int = 0
    file_count: int = 0
    duration: float = 0.0
    journal_hint: str = ""
    journal_locked: bool = False
    truncated: bool = False
    notes: list[str] = field(default_factory=list)

    def by_category(self) -> list[tuple[str, list[LogSource]]]:
        grouped: dict[str, list[LogSource]] = {}
        for source in self.sources:
            grouped.setdefault(source.category, []).append(source)
        ordered: list[tuple[str, list[LogSource]]] = []
        for category in Category.ORDER:
            items = grouped.pop(category, None)
            if items:
                ordered.append((category, items))
        for category in sorted(grouped):
            ordered.append((category, grouped[category]))
        return ordered

    @property
    def has_locked_content(self) -> bool:
        return bool(self.denied_directories) or self.locked_files > 0 or self.journal_locked


@dataclass(slots=True)
class ScanOptions:
    include_journal: bool = True
    include_user_logs: bool = True
    include_system_logs: bool = True
    include_archived: bool = True
    include_empty: bool = False
    extra_roots: list[str] = field(default_factory=list)
    file_budget: int = _DEFAULT_FILE_BUDGET
    time_budget: float = 25.0
    elevated_listing: bool = False


def _is_candidate(name: str, parent_is_log_dir: bool) -> bool:
    if name in _SKIP_NAMES or name.startswith(".#") or name.endswith("~"):
        return False
    lower = name.lower()
    if lower.endswith(".journal") or lower.endswith(".journal~"):
        return False
    if lower in _ACCEPT_NAMES:
        return True
    stem = lower
    for suffix in _COMPRESSED:
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    stem = _ROTATED.sub("", stem)
    if stem.endswith(_ACCEPT_SUFFIXES):
        return True
    if stem in _ACCEPT_NAMES:
        return True
    if "log" in stem and not stem.endswith((".conf", ".cfg", ".ini", ".json", ".yaml", ".yml", ".py", ".sh")):
        return True
    return parent_is_log_dir and "." not in stem


def _log_dir(name: str) -> bool:
    return name.lower() in ("log", "logs", "log-files", "logfiles")


@dataclass(slots=True)
class _Found:
    path: str
    size: int
    mtime: float
    root: str


def _walk(
    root: str,
    max_depth: int,
    budget: list[int],
    deadline: float,
    denied: list[str],
    stats: dict[str, int],
) -> list[_Found]:
    """Depth-limited scan that records, rather than raises, what it cannot open."""
    found: list[_Found] = []
    stack: list[tuple[str, int, bool]] = [(root, 0, False)]
    while stack:
        if budget[0] <= 0 or time.monotonic() > deadline:
            break
        directory, depth, in_log_dir = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                stats["dirs"] = stats.get("dirs", 0) + 1
                for item in iterator:
                    if budget[0] <= 0:
                        break
                    name = item.name
                    try:
                        if item.is_dir(follow_symlinks=False):
                            if depth + 1 > max_depth or name in _PRUNE_NAMES:
                                continue
                            hidden = name.startswith(".") and depth > 0 and not in_log_dir
                            if hidden and name not in (".local", ".config", ".cache", ".var"):
                                continue
                            stack.append((item.path, depth + 1, in_log_dir or _log_dir(name)))
                            continue
                        if not item.is_file(follow_symlinks=False):
                            continue
                        if not _is_candidate(name, in_log_dir or _log_dir(Path(directory).name)):
                            continue
                        info = item.stat(follow_symlinks=False)
                        if info.st_size > _MAX_FILE_BYTES:
                            continue
                        budget[0] -= 1
                        found.append(_Found(item.path, info.st_size, info.st_mtime, root))
                    except (PermissionError, OSError):
                        continue
        except PermissionError:
            denied.append(directory)
        except (NotADirectoryError, FileNotFoundError):
            continue
        except OSError:
            continue
    return found


def _owner_for(path: str, root: str) -> tuple[str, str]:
    """Return ``(group key, category)`` for a discovered file."""
    home = str(Path.home())
    relative = os.path.relpath(path, root)
    parts = Path(relative).parts

    if "/.var/app/" in path:
        try:
            index = path.index("/.var/app/") + len("/.var/app/")
            app_id = path[index:].split("/", 1)[0]
            if app_id:
                return app_id, Category.FLATPAK
        except ValueError:
            pass
    if path.startswith(os.path.join(home, "snap") + os.sep):
        snap_name = path[len(os.path.join(home, "snap")) + 1 :].split("/", 1)[0]
        if snap_name:
            return snap_name, Category.APPLICATIONS

    user_root = path.startswith(home)
    category = Category.APPLICATIONS if user_root else Category.SYSTEM

    # A directory below the root almost always names the owning program.
    for part in parts[:-1]:
        if _log_dir(part) or part in (".", ""):
            continue
        return part.lower(), (Category.APPLICATIONS if user_root else Category.SERVICES)

    return group_key(parts[-1]), category


def _describe(key: str, fallback_category: str) -> Description:
    known = describe_key(key)
    if known:
        return known
    entries = desktop_entries()
    candidate = entries.get(key) or entries.get(key.replace("-", "")) or entries.get(key.split(".")[-1])
    if candidate:
        return Description(
            name=candidate.name,
            summary=candidate.summary,
            icon=candidate.icon,
            category=candidate.category if candidate.category != Category.APPLICATIONS else fallback_category,
        )
    return Description(name=prettify(key), category=fallback_category)


def _build_file(found: _Found, *, quick: bool) -> LogFile:
    name = Path(found.path).name
    lower = name.lower()
    compressed = lower.endswith(_COMPRESSED)
    archived = bool(_ROTATED.search(lower)) or compressed
    readable = os.access(found.path, os.R_OK)
    problem = ReadProblem.NONE
    if not readable:
        problem = ReadProblem.PERMISSION
    elif not quick:
        problem = probe_file(found.path).problem
    return LogFile(
        path=found.path,
        name=name,
        size=found.size,
        mtime=found.mtime,
        readable=readable,
        problem=problem,
        compressed=compressed,
        archived=archived,
    )


def _sort_files(files: list[LogFile]) -> list[LogFile]:
    return sorted(files, key=lambda item: (item.archived, -item.mtime, item.name))


def _add_journal_sources(result: DiscoveryResult, options: ScanOptions) -> None:
    if not options.include_journal or not journal.is_available():
        return
    access = journal.probe_access()
    result.journal_hint = access.hint
    result.journal_locked = not access.system

    boots = journal.list_boots()
    queries: list[tuple[str, journal.JournalQuery]] = [
        ("All messages", journal.JournalQuery()),
        ("Errors and warnings", journal.JournalQuery(min_priority=4)),
        ("Kernel", journal.JournalQuery(kernel_only=True)),
    ]
    for index, label in boots[:6]:
        queries.append((label, journal.JournalQuery(boot=index)))

    result.sources.append(
        LogSource(
            key="journal:system",
            name="System Journal",
            summary="Everything systemd recorded on this machine",
            icon="computer-symbolic",
            category=Category.SYSTEM,
            kind="journal",
            journal_queries=queries,
            locked_count=0 if access.system else len(queries),
            last_activity=time.time(),
        )
    )

    if access.user:
        result.sources.append(
            LogSource(
                key="journal:user",
                name="My Session",
                summary="Logs from programs running as you",
                icon="system-users-symbolic",
                category=Category.SYSTEM,
                kind="journal",
                journal_queries=[
                    ("All messages", journal.JournalQuery(user_scope=True)),
                    ("Errors and warnings", journal.JournalQuery(user_scope=True, min_priority=4)),
                ],
                last_activity=time.time(),
            )
        )

    for user_scope in (False, True):
        if user_scope and not access.user:
            continue
        if not user_scope and not access.system:
            continue
        for unit in journal.list_units(user_scope=user_scope):
            if not unit or unit == "-":
                continue
            stem = unit.rsplit(".", 1)[0]
            description = _describe(stem.lower(), Category.SERVICES)
            result.sources.append(
                LogSource(
                    key=f"journal:{'user' if user_scope else 'system'}:{unit}",
                    name=description.name if description.name != prettify(stem) else prettify(stem),
                    summary=description.summary or unit,
                    icon=description.icon,
                    category=Category.APPLICATIONS if user_scope else Category.SERVICES,
                    kind="journal-unit",
                    journal_queries=[
                        ("All messages", journal.JournalQuery(unit=unit, user_scope=user_scope)),
                        (
                            "Errors and warnings",
                            journal.JournalQuery(unit=unit, user_scope=user_scope, min_priority=4),
                        ),
                        ("This boot", journal.JournalQuery(unit=unit, user_scope=user_scope, boot="0")),
                    ],
                    last_activity=time.time(),
                )
            )


def _roots(options: ScanOptions) -> list[tuple[str, int]]:
    roots: list[tuple[str, int]] = []
    if options.include_system_logs:
        roots.extend(SYSTEM_ROOTS)
    if options.include_user_logs:
        home = Path.home()
        state_home = os.environ.get("XDG_STATE_HOME")
        if state_home:
            roots.append((state_home, 4))
        for relative, depth in _USER_ROOTS:
            roots.append((str(home / relative), depth))
        for name in (".xsession-errors", ".wayland-errors"):
            candidate = home / name
            if candidate.exists():
                roots.append((str(candidate), 0))
    roots.extend((path, 4) for path in options.extra_roots)

    seen: set[str] = set()
    unique: list[tuple[str, int]] = []
    for path, depth in roots:
        resolved = os.path.normpath(path)
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append((resolved, depth))
    return unique


def scan(options: ScanOptions | None = None, *, quick_probe: bool = True) -> DiscoveryResult:
    """Discover every log this account can see, grouped by application."""
    options = options or ScanOptions()
    started = time.monotonic()
    result = DiscoveryResult()
    budget = [options.file_budget]
    deadline = started + options.time_budget
    stats: dict[str, int] = {}
    found: list[_Found] = []

    for root, depth in _roots(options):
        if not os.path.exists(root):
            continue
        if os.path.isfile(root):
            try:
                info = os.stat(root)
            except OSError:
                continue
            found.append(_Found(root, info.st_size, info.st_mtime, str(Path(root).parent)))
            continue
        found.extend(_walk(root, depth, budget, deadline, result.denied_directories, stats))

    if options.elevated_listing:
        found.extend(_elevated_listing(result, options))

    if budget[0] <= 0 or time.monotonic() > deadline:
        result.truncated = True

    seen_paths: set[str] = set()
    buckets: dict[tuple[str, str], list[LogFile]] = {}
    for item in found:
        if item.path in seen_paths:
            continue
        seen_paths.add(item.path)
        log_file = _build_file(item, quick=quick_probe)
        if log_file.problem is ReadProblem.BINARY and log_file.name.lower() not in _ACCEPT_NAMES:
            continue
        if not options.include_archived and log_file.archived:
            continue
        if not options.include_empty and log_file.size == 0 and log_file.readable:
            continue
        key, category = _owner_for(item.path, item.root)
        buckets.setdefault((key, category), []).append(log_file)

    for (key, category), files in buckets.items():
        description = _describe(key, category)
        # A hand-written catalog entry knows better than the directory layout
        # that APT belongs under System even though it lives in /var/log/apt.
        resolved_category = description.category if describe_key(key) else category
        if category == Category.FLATPAK:
            resolved_category = Category.FLATPAK
        files = _sort_files(files)
        locked = sum(1 for item in files if item.needs_privilege)
        result.sources.append(
            LogSource(
                key=f"files:{category}:{key}",
                name=description.name,
                summary=description.summary,
                icon=description.icon,
                category=resolved_category,
                kind="files",
                files=files,
                locked_count=locked,
                last_activity=max((item.mtime for item in files), default=0.0),
            )
        )
        result.locked_files += locked
        result.file_count += len(files)

    _add_journal_sources(result, options)

    result.sources.sort(key=lambda source: (-source.last_activity, source.name.lower()))
    result.scanned_directories = stats.get("dirs", 0)
    result.duration = time.monotonic() - started
    if result.truncated:
        result.notes.append(
            "The scan stopped early because there were a great many files. "
            "Narrow the locations in Preferences to see the rest."
        )
    return result


def _elevated_listing(result: DiscoveryResult, options: ScanOptions) -> list[_Found]:
    """Re-list the directories we were refused, with administrator access."""
    roots = [path for path in privileged.ELEVATION_ROOTS if os.path.isdir(path)]
    if not roots:
        return []
    try:
        listing = privileged.scan_tree(roots, max_depth=5)
    except privileged.PrivilegeError as error:
        if not error.cancelled:
            result.notes.append(str(error))
        return []
    found: list[_Found] = []
    for path, size, mtime in listing:
        name = Path(path).name
        parent = Path(path).parent.name
        if not _is_candidate(name, _log_dir(parent)):
            continue
        if size > _MAX_FILE_BYTES:
            continue
        root = next((candidate for candidate in roots if path.startswith(candidate + os.sep)), roots[0])
        found.append(_Found(path, size, mtime, root))
    result.denied_directories.clear()
    return found
