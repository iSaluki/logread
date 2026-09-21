"""User preferences, kept in a plain JSON file under XDG config.

LogRead deliberately avoids a compiled GSettings schema so that running it
straight out of a checked-out tree behaves exactly like running it installed.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

__all__ = ["Settings", "load_settings", "APP_ID", "APP_NAME"]

APP_ID = "io.github.isaluki.LogRead"
APP_NAME = "LogRead"

_LOCK = threading.Lock()


def _config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "logread"


@dataclass
class Settings:
    """Everything the Preferences dialog can change."""

    scan_system_logs: bool = True
    scan_user_logs: bool = True
    include_archived: bool = True
    include_empty: bool = False
    include_debug_in_highlights: bool = False
    use_journal: bool = True
    max_read_megabytes: int = 12
    max_entries: int = 200_000
    extra_locations: list[str] = field(default_factory=list)
    wrap_lines: bool = True
    monospace_size: int = 0  # 0 = follow the system monospace font
    remember_window: bool = True
    window_width: int = 1180
    window_height: int = 760
    window_maximized: bool = False
    sidebar_width: int = 320

    # -- persistence ----------------------------------------------------
    @property
    def path(self) -> Path:
        return _config_dir() / "settings.json"

    def save(self) -> None:
        payload = asdict(self)
        with _LOCK:
            try:
                directory = _config_dir()
                directory.mkdir(parents=True, exist_ok=True)
                temporary = directory / "settings.json.tmp"
                temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                temporary.replace(directory / "settings.json")
            except OSError:
                # Preferences are a convenience; failing to store them must not
                # take the window down.
                pass

    @property
    def max_read_bytes(self) -> int:
        return max(1, self.max_read_megabytes) * 1024 * 1024


def load_settings() -> Settings:
    settings = Settings()
    try:
        raw = (_config_dir() / "settings.json").read_text(encoding="utf-8")
        stored = json.loads(raw)
    except (OSError, ValueError):
        return settings
    if not isinstance(stored, dict):
        return settings
    known = {item.name: item for item in fields(Settings)}
    for key, value in stored.items():
        target = known.get(key)
        if target is None:
            continue
        if target.name == "extra_locations":
            if isinstance(value, list):
                settings.extra_locations = [str(item) for item in value if isinstance(item, str)]
            continue
        if isinstance(value, bool) and target.type in ("bool", bool) or isinstance(value, int) and not isinstance(value, bool) or isinstance(value, str):
            setattr(settings, key, value)
    return settings
