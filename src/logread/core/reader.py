"""Getting text out of a log file, whatever shape it is in.

Handles rotated archives (``.gz``, ``.bz2``, ``.xz``, ``.zst`` when the system
has a decompressor), files that are not text at all (``wtmp``, ``lastlog``,
journal files), unknown encodings, files larger than memory, and files the user
is not allowed to read.

Every failure is a value, never an exception that escapes: the UI turns a
`ReadOutcome` into a status page the user can act on.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
import shutil
import subprocess
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from . import privileged

__all__ = ["ReadProblem", "FileProbe", "ReadOutcome", "probe_file", "read_file", "DEFAULT_MAX_BYTES"]

DEFAULT_MAX_BYTES = 12 * 1024 * 1024
_SNIFF_BYTES = 8192

_COMPRESSED_SUFFIXES = {".gz", ".bz2", ".xz", ".lzma", ".zst", ".zstd", ".z"}

# Files whose contents are structured binary rather than text. Listing them by
# name is more reliable than sniffing, because some start with printable bytes.
_BINARY_NAMES = {
    "wtmp", "btmp", "utmp", "lastlog", "faillog", "tallylog", "wtmpdb",
    "dmesg.old", "pacman.db", "journal",
}
_BINARY_SUFFIXES = {".journal", ".journal~", ".db", ".sqlite", ".sqlite3", ".pcap", ".gcda"}

_MAGIC = {
    b"\x1f\x8b": "gzip",
    b"BZh": "bzip2",
    b"\xfd7zXZ": "xz",
    b"\x28\xb5\x2f\xfd": "zstd",
    b"\x5d\x00\x00": "lzma",
    b"LPKSHHRH": "journal",
    b"SQLite f": "sqlite",
}


class ReadProblem(Enum):
    """Why a file could not be shown as it is."""

    NONE = "none"
    PERMISSION = "permission"
    MISSING = "missing"
    BINARY = "binary"
    EMPTY = "empty"
    UNREADABLE = "unreadable"
    NO_DECOMPRESSOR = "no-decompressor"

    @property
    def title(self) -> str:
        return {
            ReadProblem.NONE: "",
            ReadProblem.PERMISSION: "Administrator access needed",
            ReadProblem.MISSING: "File is gone",
            ReadProblem.BINARY: "Not a text log",
            ReadProblem.EMPTY: "Nothing logged yet",
            ReadProblem.UNREADABLE: "Could not read this file",
            ReadProblem.NO_DECOMPRESSOR: "Compressed with an unsupported format",
        }[self]

    @property
    def icon_name(self) -> str:
        return {
            ReadProblem.NONE: "text-x-generic-symbolic",
            ReadProblem.PERMISSION: "channel-secure-symbolic",
            ReadProblem.MISSING: "edit-find-symbolic",
            ReadProblem.BINARY: "application-x-executable-symbolic",
            ReadProblem.EMPTY: "text-x-generic-symbolic",
            ReadProblem.UNREADABLE: "dialog-warning-symbolic",
            ReadProblem.NO_DECOMPRESSOR: "package-x-generic-symbolic",
        }[self]


@dataclass(slots=True)
class FileProbe:
    """What we can learn about a file without reading all of it."""

    path: str
    exists: bool = False
    size: int = 0
    mtime: float = 0.0
    readable: bool = False
    compression: str | None = None
    looks_binary: bool = False
    problem: ReadProblem = ReadProblem.NONE

    @property
    def can_elevate(self) -> bool:
        return self.problem is ReadProblem.PERMISSION and privileged.is_elevation_root(self.path)


@dataclass(slots=True)
class ReadOutcome:
    """The result of asking for a file's text."""

    path: str
    lines: list[str] = field(default_factory=list)
    problem: ReadProblem = ReadProblem.NONE
    detail: str = ""
    encoding: str = "utf-8"
    truncated: bool = False
    bytes_considered: int = 0
    total_bytes: int = 0
    used_privilege: bool = False
    replaced_characters: bool = False

    @property
    def ok(self) -> bool:
        return self.problem is ReadProblem.NONE

    @property
    def can_elevate(self) -> bool:
        return self.problem is ReadProblem.PERMISSION and privileged.is_elevation_root(self.path)


# ---------------------------------------------------------------------------
# Probing
# ---------------------------------------------------------------------------

def _compression_from_name(path: str) -> str | None:
    suffix = Path(path).suffix.lower()
    return {
        ".gz": "gzip", ".z": "gzip",
        ".bz2": "bzip2",
        ".xz": "xz", ".lzma": "lzma",
        ".zst": "zstd", ".zstd": "zstd",
    }.get(suffix)


def _magic_of(head: bytes) -> str | None:
    for magic, name in _MAGIC.items():
        if head.startswith(magic):
            return name
    return None


def _looks_binary(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    printable = sum(
        1 for byte in sample if byte in (9, 10, 13) or 32 <= byte < 127 or byte >= 128
    )
    return printable / len(sample) < 0.85


def _name_suggests_binary(path: str) -> bool:
    name = Path(path).name
    if name in _BINARY_NAMES:
        return True
    stem = name.split(".")[0]
    if stem in _BINARY_NAMES and not name.endswith((".log", ".txt")):
        return True
    return any(name.endswith(suffix) for suffix in _BINARY_SUFFIXES)


def probe_file(path: str | os.PathLike[str]) -> FileProbe:
    """Cheaply classify a file: readable? text? compressed? how big?"""
    text_path = os.fspath(path)
    result = FileProbe(path=text_path)
    try:
        stat = os.stat(text_path)
    except PermissionError:
        result.problem = ReadProblem.PERMISSION
        return result
    except FileNotFoundError:
        result.problem = ReadProblem.MISSING
        return result
    except OSError:
        result.problem = ReadProblem.UNREADABLE
        return result

    result.exists = True
    result.size = stat.st_size
    result.mtime = stat.st_mtime
    result.compression = _compression_from_name(text_path)

    if _name_suggests_binary(text_path):
        result.looks_binary = True
        result.problem = ReadProblem.BINARY
        result.readable = os.access(text_path, os.R_OK)
        return result

    try:
        with open(text_path, "rb") as handle:
            head = handle.read(_SNIFF_BYTES)
    except PermissionError:
        result.problem = ReadProblem.PERMISSION
        return result
    except OSError:
        result.problem = ReadProblem.UNREADABLE
        return result

    result.readable = True
    magic = _magic_of(head)
    if magic in ("gzip", "bzip2", "xz", "zstd", "lzma"):
        result.compression = magic
    elif magic in ("journal", "sqlite") or result.compression is None and _looks_binary(head):
        result.looks_binary = True
        result.problem = ReadProblem.BINARY
        return result

    if stat.st_size == 0:
        result.problem = ReadProblem.EMPTY
    return result


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

def _decode(data: bytes) -> tuple[str, str, bool]:
    """Decode bytes to text, reporting the encoding and whether we lost anything."""
    for encoding in ("utf-8", "utf-8-sig"):
        try:
            return data.decode(encoding), encoding, False
        except UnicodeDecodeError:
            continue
    for encoding in ("cp1252", "latin-1"):
        try:
            return data.decode(encoding), encoding, False
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace"), "utf-8 (with replacements)", True


def _split_lines(text: str) -> list[str]:
    return text.splitlines()


# ---------------------------------------------------------------------------
# Decompression
# ---------------------------------------------------------------------------

def _open_decompressed(path: str, compression: str):
    if compression == "gzip":
        return gzip.open(path, "rb")
    if compression == "bzip2":
        return bz2.open(path, "rb")
    if compression in ("xz", "lzma"):
        return lzma.open(path, "rb")
    raise LookupError(compression)


def _decompress_bytes(data: bytes, compression: str) -> bytes:
    if compression == "gzip":
        return gzip.decompress(data)
    if compression == "bzip2":
        return bz2.decompress(data)
    if compression in ("xz", "lzma"):
        return lzma.decompress(data)
    if compression == "zstd":
        return _zstd_decompress(data)
    raise LookupError(compression)


def _zstd_decompress(data: bytes) -> bytes:
    try:  # Python 3.14 ships a zstd module; before that, shell out.
        import compression.zstd as zstd_module  # type: ignore[import-not-found]

        return zstd_module.decompress(data)
    except Exception:
        pass
    tool = shutil.which("zstd") or shutil.which("unzstd")
    if tool is None:
        raise LookupError("zstd")
    completed = subprocess.run(
        [tool, "-dc"], input=data, capture_output=True, check=False, timeout=120
    )
    if completed.returncode != 0 and not completed.stdout:
        raise LookupError("zstd")
    return completed.stdout


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

def _tail_plain(path: str, max_bytes: int, size: int) -> tuple[bytes, bool]:
    """Read at most `max_bytes` from the end, starting at a line boundary."""
    if size <= max_bytes:
        with open(path, "rb") as handle:
            return handle.read(), False
    with open(path, "rb") as handle:
        handle.seek(size - max_bytes)
        data = handle.read()
    newline = data.find(b"\n")
    if newline != -1:
        data = data[newline + 1 :]
    return data, True


def _tail_stream(stream, max_lines: int) -> tuple[list[bytes], bool]:
    """Keep only the last `max_lines` of a stream we cannot seek in."""
    window: deque[bytes] = deque(maxlen=max_lines)
    seen = 0
    for line in stream:
        window.append(line.rstrip(b"\n\r"))
        seen += 1
    return list(window), seen > max_lines


def read_file(
    path: str | os.PathLike[str],
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_lines: int = 400_000,
    allow_privilege: bool = False,
    probe: FileProbe | None = None,
) -> ReadOutcome:
    """Read a log file into lines, tailing it if it is large.

    ``allow_privilege`` is only ever set when the user has explicitly asked to
    unlock the file — it triggers a polkit authentication prompt.
    """
    text_path = os.fspath(path)
    info = probe or probe_file(text_path)
    outcome = ReadOutcome(path=text_path, total_bytes=info.size)

    if info.problem is ReadProblem.MISSING:
        outcome.problem = ReadProblem.MISSING
        outcome.detail = "The file no longer exists. It may have been rotated away."
        return outcome
    if info.problem is ReadProblem.BINARY:
        outcome.problem = ReadProblem.BINARY
        outcome.detail = (
            "This file stores records in a binary format rather than lines of text."
        )
        return outcome
    if info.problem is ReadProblem.PERMISSION and not allow_privilege:
        outcome.problem = ReadProblem.PERMISSION
        outcome.detail = "This log belongs to the system and is not readable by your account."
        return outcome
    if info.problem is ReadProblem.EMPTY and info.size == 0:
        outcome.problem = ReadProblem.EMPTY
        outcome.detail = "The file is empty."
        return outcome

    data: bytes | None = None
    compression = info.compression

    if info.problem is ReadProblem.PERMISSION and allow_privilege:
        try:
            raw = privileged.read_bytes(text_path, None if compression else max_bytes)
        except privileged.PrivilegeError as error:
            outcome.problem = ReadProblem.PERMISSION
            outcome.detail = str(error)
            return outcome
        outcome.used_privilege = True
        outcome.truncated = bool(not compression and info.size > max_bytes)
        data = raw
    else:
        try:
            if compression:
                data = None  # streamed below
            else:
                data, outcome.truncated = _tail_plain(text_path, max_bytes, info.size)
        except PermissionError:
            outcome.problem = ReadProblem.PERMISSION
            outcome.detail = "This log belongs to the system and is not readable by your account."
            return outcome
        except FileNotFoundError:
            outcome.problem = ReadProblem.MISSING
            outcome.detail = "The file no longer exists. It may have been rotated away."
            return outcome
        except OSError as error:
            outcome.problem = ReadProblem.UNREADABLE
            outcome.detail = error.strerror or str(error)
            return outcome

    if compression:
        try:
            if data is not None:
                payload = _decompress_bytes(data, compression)
                text, outcome.encoding, outcome.replaced_characters = _decode(payload)
                lines = _split_lines(text)
                if len(lines) > max_lines:
                    lines = lines[-max_lines:]
                    outcome.truncated = True
                outcome.lines = lines
            elif compression == "zstd":
                with open(text_path, "rb") as handle:
                    payload = _zstd_decompress(handle.read())
                text, outcome.encoding, outcome.replaced_characters = _decode(payload)
                lines = _split_lines(text)
                if len(lines) > max_lines:
                    lines = lines[-max_lines:]
                    outcome.truncated = True
                outcome.lines = lines
            else:
                with _open_decompressed(text_path, compression) as stream:
                    raw_lines, clipped = _tail_stream(stream, max_lines)
                outcome.truncated = outcome.truncated or clipped
                joined = b"\n".join(raw_lines)
                text, outcome.encoding, outcome.replaced_characters = _decode(joined)
                outcome.lines = _split_lines(text)
        except LookupError:
            outcome.problem = ReadProblem.NO_DECOMPRESSOR
            outcome.detail = (
                f"Reading {compression}-compressed logs needs a decompressor that is not installed."
            )
            return outcome
        except PermissionError:
            outcome.problem = ReadProblem.PERMISSION
            outcome.detail = "This log belongs to the system and is not readable by your account."
            return outcome
        except (OSError, EOFError, ValueError) as error:
            outcome.problem = ReadProblem.UNREADABLE
            outcome.detail = f"The archive appears to be damaged ({error})."
            return outcome
    else:
        assert data is not None
        text, outcome.encoding, outcome.replaced_characters = _decode(data)
        lines = _split_lines(text)
        if len(lines) > max_lines:
            lines = lines[-max_lines:]
            outcome.truncated = True
        outcome.lines = lines

    outcome.bytes_considered = len(data) if data is not None else info.size
    if not outcome.lines:
        outcome.problem = ReadProblem.EMPTY
        outcome.detail = "There is nothing in this log yet."
    return outcome
