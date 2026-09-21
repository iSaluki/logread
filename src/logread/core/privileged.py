"""Reading things the user cannot read as themselves.

Most of ``/var/log`` is mode 0600 root on a stock Fedora Workstation, so a log
reader that gives up on ``PermissionError`` shows the user almost nothing. When
the user asks for it, LogRead re-runs one of a small set of fixed system
binaries under ``pkexec``; in a GNOME session polkit shows its own
authentication dialog, and the answer is cached for a few minutes.

Nothing here ever builds a shell command line, and every target path is
resolved and checked against an allow-list before it is handed to ``pkexec``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

__all__ = [
    "PrivilegeError",
    "ELEVATION_ROOTS",
    "is_available",
    "unavailable_reason",
    "read_bytes",
    "scan_tree",
    "run_journalctl",
]

# The only places LogRead will ever ask for administrator access.
ELEVATION_ROOTS: tuple[str, ...] = (
    "/var/log",
    "/var/lib",
    "/var/crash",
    "/var/spool",
    "/run/log",
    "/run/systemd",
    "/opt",
    "/srv",
    "/usr/local/var/log",
)

# Resolved once; pkexec refuses relative program names anyway.
_BINARIES = ("cat", "tail", "find", "journalctl", "stat")

_DEFAULT_TIMEOUT = 60


class PrivilegeError(Exception):
    """Raised when an elevated read could not be completed."""

    def __init__(self, message: str, *, cancelled: bool = False) -> None:
        super().__init__(message)
        self.cancelled = cancelled


def _which(name: str) -> str | None:
    if name not in _BINARIES:
        return None
    return shutil.which(name)


def is_available() -> bool:
    """True when we can plausibly show a graphical authentication prompt."""
    return unavailable_reason() is None


def unavailable_reason() -> str | None:
    """Explain, in the user's terms, why elevation is not on offer."""
    if os.geteuid() == 0:
        return None
    if shutil.which("pkexec") is None:
        return "Administrator access needs the polkit tools, which are not installed."
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return "Administrator access needs a graphical session."
    return None


def is_elevation_root(path: str | os.PathLike[str]) -> bool:
    """True when `path` lies under a directory LogRead may unlock."""
    try:
        resolved = Path(path).resolve()
    except (OSError, RuntimeError):
        return False
    for root in ELEVATION_ROOTS:
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        return True
    return False


def _check_target(path: str | os.PathLike[str]) -> str:
    text = os.fspath(path)
    if "\0" in text:
        raise PrivilegeError("That path is not valid.")
    if not os.path.isabs(text):
        raise PrivilegeError("Only absolute paths can be opened with administrator access.")
    resolved = str(Path(text).resolve())
    if not is_elevation_root(resolved):
        raise PrivilegeError(
            "LogRead only requests administrator access for system log directories."
        )
    return resolved


def _run(argv: list[str], *, timeout: int = _DEFAULT_TIMEOUT) -> bytes:
    if os.geteuid() != 0:
        reason = unavailable_reason()
        if reason:
            raise PrivilegeError(reason)
        argv = ["pkexec", *argv]
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
            env={**os.environ, "LC_ALL": "C.UTF-8"},
        )
    except FileNotFoundError as error:
        raise PrivilegeError("The required system tool is not installed.") from error
    except subprocess.TimeoutExpired as error:
        raise PrivilegeError("The request timed out.") from error

    if completed.returncode == 126:
        raise PrivilegeError("Authentication was dismissed.", cancelled=True)
    if completed.returncode == 127:
        raise PrivilegeError("Authentication failed.", cancelled=True)
    if completed.returncode != 0 and not completed.stdout:
        detail = completed.stderr.decode("utf-8", "replace").strip().splitlines()
        message = detail[-1] if detail else "The command did not complete."
        raise PrivilegeError(message)
    return completed.stdout


def read_bytes(path: str | os.PathLike[str], max_bytes: int | None = None) -> bytes:
    """Read a file with administrator access, optionally only its last bytes."""
    target = _check_target(path)
    if max_bytes and max_bytes > 0:
        tail = _which("tail")
        if tail:
            return _run([tail, "-c", str(max_bytes), "--", target])
    cat = _which("cat")
    if cat is None:
        raise PrivilegeError("The required system tool is not installed.")
    return _run([cat, "--", target])


def scan_tree(roots: list[str], *, max_depth: int = 6, timeout: int = 90) -> list[tuple[str, int, float]]:
    """List files under `roots` with administrator access.

    Returns ``(path, size, mtime)`` triples. Directories the user can already
    read are included too; the caller de-duplicates.
    """
    targets = [_check_target(root) for root in roots if os.path.isdir(root)]
    if not targets:
        return []
    find = _which("find")
    if find is None:
        raise PrivilegeError("The required system tool is not installed.")
    argv = [
        find, *targets,
        "-maxdepth", str(max_depth),
        "-type", "f",
        "-size", "-2G",
        "-printf", "%s\t%T@\t%p\n",
    ]
    output = _run(argv, timeout=timeout)
    results: list[tuple[str, int, float]] = []
    for line in output.decode("utf-8", "replace").splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        try:
            results.append((parts[2], int(parts[0]), float(parts[1])))
        except ValueError:
            continue
    return results


def run_journalctl(args: list[str], *, timeout: int = 60) -> bytes:
    """Run journalctl with administrator access, with a fixed-shape argument list."""
    journalctl = _which("journalctl")
    if journalctl is None:
        raise PrivilegeError("systemd's journalctl is not installed.")
    for argument in args:
        if "\0" in argument:
            raise PrivilegeError("That request is not valid.")
    return _run([journalctl, *args], timeout=timeout)
