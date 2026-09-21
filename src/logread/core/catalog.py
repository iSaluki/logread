"""Turning log paths into names a person recognises.

``/var/log/dnf.librepo.log`` means nothing to most people; "Software Updates"
does. This module holds the hand-written table for the logs that ship with the
major distributions, and falls back to desktop-entry metadata and then to a
tidied-up filename.
"""

from __future__ import annotations

import configparser
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

__all__ = ["Category", "Description", "describe_key", "describe_file", "desktop_entries", "prettify"]


class Category:
    """Top-level grouping in the sidebar, in display order."""

    SYSTEM = "System"
    SERVICES = "Services"
    APPLICATIONS = "Applications"
    FLATPAK = "Flatpak apps"
    OTHER = "Other logs"

    ORDER = (SYSTEM, SERVICES, APPLICATIONS, FLATPAK, OTHER)


@dataclass(frozen=True, slots=True)
class Description:
    name: str
    summary: str = ""
    icon: str = "text-x-generic-symbolic"
    category: str = Category.OTHER


def _d(name: str, summary: str, icon: str, category: str) -> Description:
    return Description(name=name, summary=summary, icon=icon, category=category)


# Keyed by directory name or by the leading component of a filename.
KNOWN: dict[str, Description] = {
    # --- Cross-distribution system logs ----------------------------------
    "messages": _d("System Messages", "General system activity", "computer-symbolic", Category.SYSTEM),
    "syslog": _d("System Messages", "General system activity", "computer-symbolic", Category.SYSTEM),
    "secure": _d("Authentication", "Logins, sudo and access control", "channel-secure-symbolic", Category.SYSTEM),
    "auth": _d("Authentication", "Logins, sudo and access control", "channel-secure-symbolic", Category.SYSTEM),
    "kern": _d("Kernel", "Hardware and driver messages", "application-x-firmware-symbolic", Category.SYSTEM),
    "dmesg": _d("Kernel Ring Buffer", "Messages from the last boot", "application-x-firmware-symbolic", Category.SYSTEM),
    "boot": _d("Boot", "What happened while starting up", "system-run-symbolic", Category.SYSTEM),
    "daemon": _d("Background Services", "Messages from system daemons", "system-run-symbolic", Category.SYSTEM),
    "user": _d("User Processes", "Messages from user-space programs", "system-users-symbolic", Category.SYSTEM),
    "debug": _d("Debug Messages", "Verbose diagnostics", "bug-symbolic", Category.SYSTEM),
    "audit": _d("Audit", "SELinux and kernel audit records", "security-high-symbolic", Category.SYSTEM),
    "cron": _d("Scheduled Tasks", "cron and anacron activity", "alarm-symbolic", Category.SYSTEM),
    "maillog": _d("Mail", "Local mail delivery", "mail-unread-symbolic", Category.SERVICES),
    "mail": _d("Mail", "Local mail delivery", "mail-unread-symbolic", Category.SERVICES),
    "firewalld": _d("Firewall", "firewalld decisions", "security-medium-symbolic", Category.SYSTEM),
    "ufw": _d("Firewall", "ufw decisions", "security-medium-symbolic", Category.SYSTEM),
    "wtmp": _d("Login Records", "Binary account of logins", "system-users-symbolic", Category.SYSTEM),
    "btmp": _d("Failed Logins", "Binary account of failed logins", "dialog-password-symbolic", Category.SYSTEM),
    "lastlog": _d("Last Logins", "Binary account of last logins", "system-users-symbolic", Category.SYSTEM),
    "faillog": _d("Login Failures", "Binary account of login failures", "dialog-password-symbolic", Category.SYSTEM),
    "xorg": _d("X.Org Display Server", "Graphics and input devices", "video-display-symbolic", Category.SYSTEM),
    "gpu-manager": _d("Graphics Setup", "GPU driver selection", "video-display-symbolic", Category.SYSTEM),
    "alternatives": _d("Alternatives", "Default program selections", "preferences-other-symbolic", Category.SYSTEM),
    "wpa_supplicant": _d("Wi-Fi", "Wireless association and authentication", "network-wireless-symbolic", Category.SYSTEM),
    "cloud-init": _d("Cloud Init", "First-boot cloud configuration", "weather-few-clouds-symbolic", Category.SYSTEM),
    "xsession-errors": _d("Desktop Session", "Errors from the graphical session", "preferences-desktop-symbolic", Category.SYSTEM),

    # --- Package management ---------------------------------------------
    "dnf": _d("Software Updates (DNF)", "Package installs, updates and removals", "system-software-install-symbolic", Category.SYSTEM),
    "hawkey": _d("Software Updates (DNF)", "Dependency resolution", "system-software-install-symbolic", Category.SYSTEM),
    "yum": _d("Software Updates (YUM)", "Package installs and updates", "system-software-install-symbolic", Category.SYSTEM),
    "dpkg": _d("Package Database (dpkg)", "Low-level package operations", "system-software-install-symbolic", Category.SYSTEM),
    "apt": _d("Software Updates (APT)", "Package installs, updates and removals", "system-software-install-symbolic", Category.SYSTEM),
    "unattended-upgrades": _d("Automatic Updates", "Unattended package upgrades", "software-update-available-symbolic", Category.SYSTEM),
    "pacman": _d("Software Updates (pacman)", "Package installs, updates and removals", "system-software-install-symbolic", Category.SYSTEM),
    "zypp": _d("Software Updates (zypper)", "Package installs and repository changes", "system-software-install-symbolic", Category.SYSTEM),
    "zypper": _d("Software Updates (zypper)", "Package manager activity", "system-software-install-symbolic", Category.SYSTEM),
    "rpmpkgs": _d("Installed Packages", "Nightly package inventory", "package-x-generic-symbolic", Category.SYSTEM),
    "packagekit": _d("Software Installer", "GNOME Software back end", "system-software-install-symbolic", Category.SYSTEM),
    "flatpak": _d("Flatpak", "Flatpak installs and updates", "package-x-generic-symbolic", Category.SYSTEM),
    "snapd": _d("Snap", "Snap installs and updates", "package-x-generic-symbolic", Category.SYSTEM),

    # --- Installers and recovery ----------------------------------------
    "anaconda": _d("Fedora Installer", "Records from installing this system", "drive-harddisk-symbolic", Category.SYSTEM),
    "installer": _d("Installer", "Records from installing this system", "drive-harddisk-symbolic", Category.SYSTEM),
    "apport": _d("Crash Reports", "Ubuntu crash handling", "dialog-error-symbolic", Category.SYSTEM),
    "abrt": _d("Crash Reports", "Automatic bug reporting", "dialog-error-symbolic", Category.SYSTEM),
    "yast2": _d("YaST", "openSUSE system configuration", "preferences-system-symbolic", Category.SYSTEM),

    # --- Services ---------------------------------------------------------
    "nginx": _d("nginx", "Web server requests and errors", "network-server-symbolic", Category.SERVICES),
    "httpd": _d("Apache HTTP Server", "Web server requests and errors", "network-server-symbolic", Category.SERVICES),
    "apache2": _d("Apache HTTP Server", "Web server requests and errors", "network-server-symbolic", Category.SERVICES),
    "mysql": _d("MySQL", "Database server", "drive-multidisk-symbolic", Category.SERVICES),
    "mariadb": _d("MariaDB", "Database server", "drive-multidisk-symbolic", Category.SERVICES),
    "postgresql": _d("PostgreSQL", "Database server", "drive-multidisk-symbolic", Category.SERVICES),
    "mongodb": _d("MongoDB", "Database server", "drive-multidisk-symbolic", Category.SERVICES),
    "redis": _d("Redis", "In-memory data store", "drive-multidisk-symbolic", Category.SERVICES),
    "cups": _d("Printing", "Print jobs and printer errors", "printer-symbolic", Category.SERVICES),
    "samba": _d("Samba", "Windows file sharing", "folder-remote-symbolic", Category.SERVICES),
    "sssd": _d("Directory Services", "Domain and identity lookups", "system-users-symbolic", Category.SERVICES),
    "libvirt": _d("Virtual Machines", "libvirt guests and networking", "computer-symbolic", Category.SERVICES),
    "docker": _d("Docker", "Container engine", "package-x-generic-symbolic", Category.SERVICES),
    "containers": _d("Containers", "Container runtime output", "package-x-generic-symbolic", Category.SERVICES),
    "chrony": _d("Time Synchronisation", "Clock accuracy", "alarm-symbolic", Category.SERVICES),
    "ntpstats": _d("Time Synchronisation", "Clock accuracy", "alarm-symbolic", Category.SERVICES),
    "squid": _d("Squid", "Caching web proxy", "network-server-symbolic", Category.SERVICES),
    "exim4": _d("Exim", "Mail transfer agent", "mail-unread-symbolic", Category.SERVICES),
    "fail2ban": _d("Fail2ban", "Blocked intrusion attempts", "security-high-symbolic", Category.SERVICES),
    "clamav": _d("ClamAV", "Virus scanning", "security-high-symbolic", Category.SERVICES),
    "openvpn": _d("OpenVPN", "VPN connections", "network-vpn-symbolic", Category.SERVICES),
    "tor": _d("Tor", "Anonymity network", "network-vpn-symbolic", Category.SERVICES),
    "gdm": _d("Login Screen", "GNOME display manager", "preferences-desktop-symbolic", Category.SERVICES),
    "sddm": _d("Login Screen", "Simple desktop display manager", "preferences-desktop-symbolic", Category.SERVICES),
    "lightdm": _d("Login Screen", "LightDM display manager", "preferences-desktop-symbolic", Category.SERVICES),
    "speech-dispatcher": _d("Speech Synthesis", "Screen reader voices", "audio-speakers-symbolic", Category.SERVICES),
    "pulse": _d("Audio", "PulseAudio sound server", "audio-card-symbolic", Category.SERVICES),
    "pipewire": _d("Audio and Video", "PipeWire media server", "audio-card-symbolic", Category.SERVICES),
    "bluetooth": _d("Bluetooth", "Pairing and connections", "bluetooth-symbolic", Category.SERVICES),
    "networkmanager": _d("Network", "Connections and Wi-Fi", "network-wired-symbolic", Category.SERVICES),
    "vmware": _d("VMware", "Virtual machine tools", "computer-symbolic", Category.SERVICES),
    "landscape": _d("Landscape", "Ubuntu systems management", "network-server-symbolic", Category.SERVICES),
}

# Rotation and compression noise stripped when grouping files together.
_ROTATION = re.compile(
    r"(?:[.\-_](?:\d{1,8}|\d{4}-\d{2}-\d{2}|old|bak|prev|previous))*"
    r"(?:\.(?:gz|bz2|xz|lzma|zst|zstd|z))?$",
    re.IGNORECASE,
)

_WORD_SPLIT = re.compile(r"[._\-\s]+")

_ACRONYMS = {
    "api", "cpu", "cups", "dns", "dhcp", "gpu", "gtk", "http", "https", "id",
    "io", "ip", "json", "led", "nfs", "npm", "os", "pam", "pci", "php", "smb", "ssh",
    "ssl", "tls", "tty", "ui", "url", "usb", "vpn", "xml", "yaml",
}

# Names that neither title case nor upper case get right.
_SPELLINGS = {
    "dbus": "D-Bus",
    "networkmanager": "NetworkManager",
    "modemmanager": "ModemManager",
    "pipewire": "PipeWire",
    "pulseaudio": "PulseAudio",
    "wireplumber": "WirePlumber",
    "polkit": "polkit",
    "systemd": "systemd",
    "journald": "journald",
    "udev": "udev",
    "udisks2": "UDisks",
    "upower": "UPower",
    "xorg": "X.Org",
    "gnome": "GNOME",
    "kde": "KDE",
    "sddm": "SDDM",
    "gdm": "GDM",
    "iwd": "iwd",
    "nginx": "nginx",
    "firewalld": "firewalld",
    "containerd": "containerd",
    "dockerd": "dockerd",
    "postgresql": "PostgreSQL",
    "mariadb": "MariaDB",
    "mysqld": "MySQL",
    "openvpn": "OpenVPN",
    "sshd": "OpenSSH",
    "chronyd": "chrony",
    "rsyslog": "rsyslog",
    "abrt": "ABRT",
    "sssd": "SSSD",
    "selinux": "SELinux",
    "libvirtd": "libvirt",
    "flatpak": "Flatpak",
    "snapd": "snapd",
    "packagekit": "PackageKit",
    "dnf": "DNF",
    "rpm": "RPM",
    "apt": "APT",
    "dpkg": "dpkg",
    "pacman": "pacman",
    "zypper": "zypper",
}


def strip_rotation(name: str) -> str:
    """``syslog.2.gz`` → ``syslog``; ``dnf.rpm.log`` is left alone."""
    stripped = _ROTATION.sub("", name)
    return stripped or name


def group_key(name: str) -> str:
    """The token used to gather rotated siblings under one application."""
    base = strip_rotation(name)
    for suffix in (".log", ".err", ".out", ".txt", ".trace"):
        if base.lower().endswith(suffix):
            base = base[: -len(suffix)]
            break
    head = base.split(".", 1)[0]
    return (head or base).lower()


def prettify(token: str) -> str:
    """Make a bare identifier presentable: ``network-manager`` → ``Network Manager``."""
    collapsed = token.lower()
    if collapsed in _SPELLINGS:
        return _SPELLINGS[collapsed]
    words = [word for word in _WORD_SPLIT.split(token) if word]
    if not words:
        return token
    out = []
    for word in words:
        lower = word.lower()
        if lower in _SPELLINGS:
            out.append(_SPELLINGS[lower])
        elif lower in _ACRONYMS:
            out.append(lower.upper())
        elif word.isupper() and len(word) > 1:
            out.append(word)
        else:
            out.append(word[:1].upper() + word[1:])
    return " ".join(out)


def describe_key(token: str) -> Description | None:
    """Look up a known log family by its group key."""
    return KNOWN.get(token.lower())


def describe_file(path: str) -> Description:
    """Best available description for a single log path."""
    parts = Path(path).parts
    parent = Path(path).parent.name.lower()
    known = KNOWN.get(parent)
    if known:
        return known
    key = group_key(Path(path).name)
    known = KNOWN.get(key)
    if known:
        return known
    for part in reversed(parts[:-1]):
        known = KNOWN.get(part.lower())
        if known:
            return known
    return Description(name=prettify(key), category=Category.OTHER)


# ---------------------------------------------------------------------------
# Desktop entries — nicer names and real app icons
# ---------------------------------------------------------------------------

_DESKTOP_DIRS = (
    "/usr/share/applications",
    "/usr/local/share/applications",
    "/var/lib/flatpak/exports/share/applications",
    "/var/lib/snapd/desktop/applications",
)


def _user_desktop_dirs() -> list[str]:
    home = Path.home()
    data_home = os.environ.get("XDG_DATA_HOME") or str(home / ".local/share")
    return [
        os.path.join(data_home, "applications"),
        os.path.join(data_home, "flatpak/exports/share/applications"),
    ]


@lru_cache(maxsize=1)
def desktop_entries() -> dict[str, Description]:
    """Index installed applications by a few keys we can match logs against."""
    index: dict[str, Description] = {}
    for directory in [*_DESKTOP_DIRS, *_user_desktop_dirs()]:
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for filename in names:
            if not filename.endswith(".desktop"):
                continue
            entry = _read_desktop(os.path.join(directory, filename))
            if entry is None:
                continue
            description, keys = entry
            for key in keys:
                index.setdefault(key, description)
    return index


def _read_desktop(path: str) -> tuple[Description, list[str]] | None:
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    parser.optionxform = str  # keys in desktop files are case sensitive
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            parser.read_file(handle)
    except (OSError, configparser.Error):
        return None
    if not parser.has_section("Desktop Entry"):
        return None
    section = parser["Desktop Entry"]
    if section.get("NoDisplay", "false").strip().lower() == "true":
        return None
    if section.get("Type", "Application").strip() != "Application":
        return None
    name = (section.get("Name") or "").strip()
    if not name:
        return None
    icon = (section.get("Icon") or "application-x-executable-symbolic").strip()
    comment = (section.get("Comment") or section.get("GenericName") or "").strip()

    app_id = Path(path).stem
    keys = {app_id.lower(), app_id.rsplit(".", 1)[-1].lower()}
    executable = (section.get("TryExec") or section.get("Exec") or "").strip()
    if executable:
        first = executable.split()[0] if executable.split() else ""
        if first:
            keys.add(Path(first).name.lower())
    keys.add(re.sub(r"[^a-z0-9]+", "", name.lower()))
    keys.discard("")
    category = Category.FLATPAK if "flatpak" in path else Category.APPLICATIONS
    return Description(name=name, summary=comment, icon=icon, category=category), sorted(keys)
