"""Application entry point."""

from __future__ import annotations

import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from .config import APP_ID, APP_NAME, load_settings  # noqa: E402
from .ui.window import LogReadWindow  # noqa: E402

__all__ = ["LogReadApplication", "main"]

VERSION = "1.0.0"

_STYLE_RESOURCE = "style.css"


class LogReadApplication(Adw.Application):
    """Holds the window, the stylesheet, and the application-wide actions."""

    def __init__(self) -> None:
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.HANDLES_COMMAND_LINE)
        self._settings = load_settings()
        self._window: LogReadWindow | None = None
        GLib.set_application_name(APP_NAME)
        GLib.set_prgname(APP_ID)

        self.add_main_option(
            "version", ord("v"), GLib.OptionFlags.NONE, GLib.OptionArg.NONE,
            "Show the version and exit", None,
        )

    # -- lifecycle ------------------------------------------------------
    def do_startup(self) -> None:
        Adw.Application.do_startup(self)
        self._load_styles()
        self._install_actions()

    def do_activate(self) -> None:
        if self._window is None:
            self._window = LogReadWindow(self, self._settings)
            self._window.start_scan()
        self._window.present()

    def do_command_line(self, command_line: Gio.ApplicationCommandLine) -> int:
        options = command_line.get_options_dict()
        if options.contains("version"):
            command_line.print_literal(f"{APP_NAME} {VERSION}\n")
            return 0
        self.activate()
        return 0

    # -- setup ----------------------------------------------------------
    def _load_styles(self) -> None:
        display = Gdk.Display.get_default()
        if display is None:
            return
        provider = Gtk.CssProvider()
        css = _read_stylesheet()
        if not css:
            return
        provider.load_from_data(css.encode("utf-8"))
        Gtk.StyleContext.add_provider_for_display(
            display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

    def _install_actions(self) -> None:
        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", lambda *_a: self.quit())
        self.add_action(quit_action)
        self.set_accels_for_action("app.quit", ["<Control>q"])

        about_action = Gio.SimpleAction.new("about", None)
        about_action.connect("activate", lambda *_a: self._show_about())
        self.add_action(about_action)

    def _show_about(self) -> None:
        parent = self.get_active_window()
        if hasattr(Adw, "AboutDialog"):
            about = Adw.AboutDialog(
                application_name=APP_NAME,
                application_icon=APP_ID,
                version=VERSION,
                developer_name="The LogRead contributors",
                comments=(
                    "Read the logs on this computer without knowing where they live "
                    "or what format they are in."
                ),
                website="https://github.com/iSaluki/logread",
                issue_url="https://github.com/iSaluki/logread/issues",
                license_type=Gtk.License.GPL_3_0,
            )
            about.present(parent)
            return
        about = Adw.AboutWindow(
            transient_for=parent,
            application_name=APP_NAME,
            application_icon=APP_ID,
            version=VERSION,
            developer_name="The LogRead contributors",
            comments=(
                "Read the logs on this computer without knowing where they live "
                "or what format they are in."
            ),
            website="https://github.com/iSaluki/logread",
            issue_url="https://github.com/iSaluki/logread/issues",
            license_type=Gtk.License.GPL_3_0,
        )
        about.present()


def _read_stylesheet() -> str:
    """Load the stylesheet from the installed package."""
    try:
        from importlib.resources import files

        return (files("logread.ui") / _STYLE_RESOURCE).read_text(encoding="utf-8")
    except (OSError, ModuleNotFoundError, TypeError):
        from pathlib import Path

        candidate = Path(__file__).parent / "ui" / _STYLE_RESOURCE
        try:
            return candidate.read_text(encoding="utf-8")
        except OSError:
            return ""


def main(argv: list[str] | None = None) -> int:
    return LogReadApplication().run(argv if argv is not None else sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())
