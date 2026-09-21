"""Icon names that actually render on the machine LogRead is running on.

``Gtk.IconTheme.has_icon()`` is not trustworthy: it answers from the theme's
index, which on minimal installs and in containers lists icons whose files are
not really there. A row of "image missing" placeholders makes an application
look broken, so every icon goes through `resolve`, which looks the icon up for
real and walks a chain of alternatives until something renders.
"""

from __future__ import annotations

from gi.repository import Gdk, Gtk

__all__ = ["resolve", "FALLBACK", "APP_FALLBACK"]

FALLBACK = "text-x-generic-symbolic"
APP_FALLBACK = "application-x-executable-symbolic"

_MISSING = "image-missing"

# Preferred name first, then progressively more common stand-ins. The last
# entry of every chain is part of the small set that even a cut-down Adwaita
# install still ships.
_CHAINS: dict[str, tuple[str, ...]] = {
    "computer-symbolic": ("user-desktop-symbolic", "drive-harddisk-symbolic"),
    "system-users-symbolic": ("user-home-symbolic", "emoji-people-symbolic"),
    "user-home-symbolic": ("system-users-symbolic", "folder-symbolic"),
    "system-software-install-symbolic": (
        "software-update-available-symbolic", "package-x-generic-symbolic", "insert-object-symbolic",
    ),
    "software-update-available-symbolic": (
        "system-software-install-symbolic", "package-x-generic-symbolic", "insert-object-symbolic",
    ),
    "package-x-generic-symbolic": ("insert-object-symbolic", "folder-symbolic"),
    "channel-secure-symbolic": ("changes-prevent-symbolic", "dialog-password-symbolic"),
    "security-high-symbolic": ("changes-prevent-symbolic", "emblem-important-symbolic"),
    "security-medium-symbolic": ("changes-prevent-symbolic", "emblem-important-symbolic"),
    "dialog-password-symbolic": ("changes-prevent-symbolic", "emblem-important-symbolic"),
    "alarm-symbolic": ("document-open-recent-symbolic", "media-playback-start-symbolic"),
    "video-display-symbolic": ("display-brightness-symbolic", "user-desktop-symbolic"),
    "audio-card-symbolic": ("audio-volume-high-symbolic",),
    "audio-speakers-symbolic": ("audio-volume-high-symbolic",),
    "application-x-firmware-symbolic": ("drive-harddisk-symbolic", APP_FALLBACK),
    "drive-multidisk-symbolic": ("drive-harddisk-symbolic",),
    "mail-unread-symbolic": ("mail-send-symbolic", "folder-documents-symbolic"),
    "network-wired-symbolic": ("network-workgroup-symbolic", "network-server-symbolic"),
    "network-wireless-symbolic": ("network-workgroup-symbolic", "network-server-symbolic"),
    "network-vpn-symbolic": ("network-server-symbolic", "network-workgroup-symbolic"),
    "bluetooth-symbolic": ("network-wireless-symbolic", "network-workgroup-symbolic"),
    "folder-remote-symbolic": ("network-workgroup-symbolic", "folder-symbolic"),
    "preferences-system-symbolic": ("emblem-system-symbolic", "system-run-symbolic"),
    "preferences-desktop-symbolic": ("user-desktop-symbolic", "emblem-system-symbolic"),
    "preferences-other-symbolic": ("emblem-system-symbolic", "system-run-symbolic"),
    "system-run-symbolic": ("emblem-system-symbolic", APP_FALLBACK),
    "bug-symbolic": ("dialog-warning-symbolic",),
    "go-jump-symbolic": ("go-next-symbolic", "pan-end-symbolic"),
    "emblem-ok-symbolic": ("object-select-symbolic", "face-smile-symbolic"),
    "weather-few-clouds-symbolic": ("network-workgroup-symbolic", "folder-symbolic"),
    "edit-find-symbolic": ("system-search-symbolic",),
    "view-reveal-symbolic": ("view-grid-symbolic", "view-list-symbolic"),
    "text-x-generic-symbolic": ("document-open-symbolic", APP_FALLBACK),
}

_cache: dict[tuple[str, str], str] = {}
_watched: set[int] = set()


def _theme() -> Gtk.IconTheme | None:
    display = Gdk.Display.get_default()
    if display is None:
        return None
    theme = Gtk.IconTheme.get_for_display(display)
    # Themes can change while the window is open; drop what we worked out.
    if theme is not None and id(theme) not in _watched:
        _watched.add(id(theme))
        theme.connect("changed", lambda *_a: _cache.clear())
    return theme


def _renders(theme: Gtk.IconTheme, name: str) -> bool:
    """True when the theme can really draw `name`, not just index it."""
    try:
        paintable = theme.lookup_icon(name, None, 16, 1, Gtk.TextDirection.LTR, 0)
    except Exception:
        return False
    if paintable is None:
        return False
    resolved = paintable.get_icon_name()
    if not resolved or resolved == _MISSING:
        return False
    # Falling back to a full-colour icon inside a symbolic context looks worse
    # than a neutral stand-in, so treat that as a miss too.
    return not (name.endswith("-symbolic") and not resolved.endswith("-symbolic"))


def resolve(name: str | None, fallback: str = FALLBACK) -> str:
    """Return `name` if it renders here, otherwise the closest thing that does."""
    if not name:
        return fallback
    if fallback == FALLBACK and not name.endswith("-symbolic"):
        # A desktop entry's icon name; a generic app glyph reads better than a
        # document one when the theme does not have the real icon.
        fallback = APP_FALLBACK
    key = (name, fallback)
    cached = _cache.get(key)
    if cached is not None:
        return cached

    theme = _theme()
    if theme is None:
        return name

    candidates: list[str] = [name]
    candidates.extend(_CHAINS.get(name, ()))
    if not name.endswith("-symbolic"):
        # Application icons from desktop entries are usually not symbolic.
        candidates.append(f"{name}-symbolic")
    candidates.append(fallback)
    candidates.extend(_CHAINS.get(fallback, ()))
    candidates.append(APP_FALLBACK)
    candidates.append(FALLBACK)

    chosen = name
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if _renders(theme, candidate):
            chosen = candidate
            break

    _cache[key] = chosen
    return chosen
