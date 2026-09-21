"""Dialog helpers that work across the libadwaita versions in the wild.

`Adw.AlertDialog` arrived in 1.5 and `Adw.PreferencesDialog` in 1.5 as well;
Fedora 39 and Debian 12 still ship 1.4. LogRead targets 1.4 and uses the newer
widgets when they are there.
"""

from __future__ import annotations

from collections.abc import Callable

from gi.repository import Adw, Gtk

__all__ = ["confirm", "present_preferences_window", "HAS_ALERT_DIALOG"]

HAS_ALERT_DIALOG = hasattr(Adw, "AlertDialog")
HAS_PREFERENCES_DIALOG = hasattr(Adw, "PreferencesDialog")


def confirm(
    parent: Gtk.Window,
    *,
    heading: str,
    body: str,
    confirm_label: str,
    on_confirm: Callable[[], None],
    destructive: bool = False,
) -> None:
    """Ask a yes/no question and run `on_confirm` only on yes."""
    if HAS_ALERT_DIALOG:
        dialog = Adw.AlertDialog(heading=heading, body=body)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("confirm", confirm_label)
        dialog.set_response_appearance(
            "confirm",
            Adw.ResponseAppearance.DESTRUCTIVE if destructive else Adw.ResponseAppearance.SUGGESTED,
        )
        dialog.set_default_response("confirm")
        dialog.set_close_response("cancel")

        def responded(_dialog, response: str) -> None:
            if response == "confirm":
                on_confirm()

        dialog.connect("response", responded)
        dialog.present(parent)
        return

    dialog = Adw.MessageDialog(transient_for=parent, heading=heading, body=body)
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("confirm", confirm_label)
    dialog.set_response_appearance(
        "confirm",
        Adw.ResponseAppearance.DESTRUCTIVE if destructive else Adw.ResponseAppearance.SUGGESTED,
    )
    dialog.set_default_response("confirm")
    dialog.set_close_response("cancel")
    dialog.connect(
        "response", lambda _d, response: on_confirm() if response == "confirm" else None
    )
    dialog.present()


def new_preferences_container(parent: Gtk.Window):
    """An `Adw.PreferencesDialog` where available, otherwise a window."""
    if HAS_PREFERENCES_DIALOG:
        return Adw.PreferencesDialog(), True
    window = Adw.PreferencesWindow(transient_for=parent, modal=True)
    return window, False


def present_preferences_window(container, is_dialog: bool, parent: Gtk.Window) -> None:
    if is_dialog:
        container.present(parent)
    else:
        container.present()
