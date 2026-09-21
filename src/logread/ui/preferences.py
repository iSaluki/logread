"""Preferences: where LogRead looks, and how much of a log it reads."""

from __future__ import annotations

from collections.abc import Callable

from gi.repository import Adw, Gtk

from ..config import Settings
from .dialogs import new_preferences_container, present_preferences_window
from .icons import resolve as resolve_icon

__all__ = ["show_preferences"]


def show_preferences(
    parent: Gtk.Window, settings: Settings, on_scan_change: Callable[[], None]
) -> None:
    container, is_dialog = new_preferences_container(parent)
    container.set_title("Preferences")

    page = Adw.PreferencesPage(title="General", icon_name=resolve_icon("preferences-system-symbolic"))

    locations = Adw.PreferencesGroup(
        title="Where to look",
        description="Changing these starts a new scan.",
    )

    def toggle(title: str, subtitle: str, attribute: str, rescan: bool) -> Adw.SwitchRow:
        row = Adw.SwitchRow(title=title, subtitle=subtitle)
        row.set_active(getattr(settings, attribute))

        def changed(switch_row, _param) -> None:
            setattr(settings, attribute, switch_row.get_active())
            settings.save()
            if rescan:
                on_scan_change()

        row.connect("notify::active", changed)
        return row

    locations.add(
        toggle(
            "System logs",
            "/var/log and the other places services write to",
            "scan_system_logs",
            True,
        )
    )
    locations.add(
        toggle(
            "My logs",
            "Application logs under your home folder, including Flatpak apps",
            "scan_user_logs",
            True,
        )
    )
    locations.add(
        toggle(
            "systemd journal",
            "Read logs from journald as well as from files",
            "use_journal",
            True,
        )
    )
    locations.add(
        toggle(
            "Rotated copies",
            "Include older, often compressed, archives of each log",
            "include_archived",
            True,
        )
    )
    locations.add(
        toggle("Empty logs", "Show logs that have nothing in them yet", "include_empty", True)
    )
    page.add(locations)

    extra = Adw.PreferencesGroup(
        title="Extra locations",
        description="Folders LogRead should scan in addition to the usual ones.",
    )
    extra_rows: list[Adw.ActionRow] = []

    def refresh_extra() -> None:
        for row in extra_rows:
            extra.remove(row)
        extra_rows.clear()
        for path in settings.extra_locations:
            row = Adw.ActionRow(title=path)
            row.add_prefix(Gtk.Image.new_from_icon_name(resolve_icon("folder-symbolic")))
            remove = Gtk.Button(icon_name=resolve_icon("user-trash-symbolic"))
            remove.add_css_class("flat")
            remove.set_valign(Gtk.Align.CENTER)
            remove.set_tooltip_text("Stop scanning this folder")
            remove.connect("clicked", lambda _b, target=path: drop(target))
            row.add_suffix(remove)
            extra.add(row)
            extra_rows.append(row)

    def drop(path: str) -> None:
        settings.extra_locations = [item for item in settings.extra_locations if item != path]
        settings.save()
        refresh_extra()
        on_scan_change()

    add_row = Adw.ActionRow(title="Add a folder", subtitle="Choose another place to scan for logs")
    add_row.set_activatable(True)
    add_row.add_prefix(Gtk.Image.new_from_icon_name(resolve_icon("list-add-symbolic")))

    def pick(_row) -> None:
        chooser = Gtk.FileDialog(title="Choose a folder to scan")

        def chosen(dialog, result) -> None:
            try:
                folder = dialog.select_folder_finish(result)
            except Exception:
                return
            if folder is None:
                return
            path = folder.get_path()
            if path and path not in settings.extra_locations:
                settings.extra_locations.append(path)
                settings.save()
                refresh_extra()
                on_scan_change()

        chooser.select_folder(parent, None, chosen)

    add_row.connect("activated", pick)
    extra.add(add_row)
    refresh_extra()
    page.add(extra)

    reading = Adw.PreferencesGroup(
        title="Reading",
        description="Limits that keep very large logs from slowing the window down.",
    )

    size_row = Adw.SpinRow.new_with_range(1, 512, 1)
    size_row.set_title("Read at most")
    size_row.set_subtitle("Megabytes from the end of each log")
    size_row.set_value(settings.max_read_megabytes)

    def size_changed(row, _param) -> None:
        settings.max_read_megabytes = int(row.get_value())
        settings.save()

    size_row.connect("notify::value", size_changed)
    reading.add(size_row)

    entries_row = Adw.SpinRow.new_with_range(1000, 2_000_000, 1000)
    entries_row.set_title("Keep at most")
    entries_row.set_subtitle("Entries held in memory for one log")
    entries_row.set_value(settings.max_entries)

    def entries_changed(row, _param) -> None:
        settings.max_entries = int(row.get_value())
        settings.save()

    entries_row.connect("notify::value", entries_changed)
    reading.add(entries_row)

    debug_row = Adw.SwitchRow(
        title="Include debug messages in Highlights",
        subtitle="Off by default, because debug output drowns out real problems",
    )
    debug_row.set_active(settings.include_debug_in_highlights)

    def debug_changed(row, _param) -> None:
        settings.include_debug_in_highlights = row.get_active()
        settings.save()

    debug_row.connect("notify::active", debug_changed)
    reading.add(debug_row)
    page.add(reading)

    container.add(page)
    present_preferences_window(container, is_dialog, parent)
