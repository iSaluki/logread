"""The LogRead window.

Sidebar on the left (applications, then their logs), the chosen log on the
right. Scanning and reading both happen on worker threads; results come back
through `GLib.idle_add` so the window never freezes on a slow disk or a
journal query that takes a while.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from gi.repository import Adw, Gio, GLib, Gtk

from ..config import APP_NAME, Settings
from ..core import privileged
from ..core.discovery import DiscoveryResult, LogFile, LogSource, ScanOptions, scan
from ..core.document import LogDocument, load_file, load_journal
from ..core.journal import JournalQuery
from ..core.reader import ReadProblem
from .dialogs import confirm
from .logpage import LogPage
from .preferences import show_preferences
from .sidebar import Sidebar

__all__ = ["LogReadWindow"]


class LogReadWindow(Adw.ApplicationWindow):
    """Main window: discovery on the left, one log on the right."""

    __gtype_name__ = "LogReadWindow"

    def __init__(self, application: Adw.Application, settings: Settings) -> None:
        super().__init__(application=application, title=APP_NAME)
        self._settings = settings
        self._document: LogDocument | None = None
        self._current_request: dict[str, Any] | None = None
        self._load_token = 0
        self._scan_token = 0
        self._watch_source: int | None = None
        self._watching = False

        # AdwBreakpoint needs a stated minimum before it will apply a setter.
        self.set_size_request(360, 320)
        self.set_default_size(settings.window_width, settings.window_height)
        if settings.window_maximized:
            self.maximize()

        self._toasts = Adw.ToastOverlay()
        self._split = Adw.NavigationSplitView()
        self._split.set_min_sidebar_width(280)
        self._split.set_max_sidebar_width(420)
        self._split.set_sidebar_width_fraction(0.32)

        self._sidebar = Sidebar()
        self._sidebar.connect("file-chosen", self._on_file_chosen)
        self._sidebar.connect("journal-chosen", self._on_journal_chosen)
        self._sidebar.connect("rescan-requested", lambda _s: self.start_scan())
        self._sidebar.connect("unlock-requested", lambda _s: self._request_unlock_scan())
        self._split.set_sidebar(self._sidebar)

        self._log_page = LogPage(self._build_menu())
        self._log_page.connect("unlock-requested", lambda _p: self._request_unlock_read())
        self._log_page.connect("reload-requested", lambda _p: self.reload())
        self._log_page.connect("copied", self._on_copied)

        content = Adw.NavigationPage(title="Log", child=self._log_page)
        self._split.set_content(content)

        self._toasts.set_child(self._split)
        self.set_content(self._toasts)

        self._install_actions()
        self._add_breakpoint()
        self.connect("close-request", self._on_close)

    # -- chrome ---------------------------------------------------------
    def _add_breakpoint(self) -> None:
        condition = Adw.BreakpointCondition.parse("max-width: 720sp")
        breakpoint_ = Adw.Breakpoint.new(condition)
        breakpoint_.add_setter(self._split, "collapsed", True)
        breakpoint_.connect("apply", lambda *_a: self._log_page.set_narrow(True))
        breakpoint_.connect("unapply", lambda *_a: self._log_page.set_narrow(False))
        self.add_breakpoint(breakpoint_)

    def _build_menu(self) -> Gio.Menu:
        view_section = Gio.Menu()
        view_section.append("Overview", "win.view::overview")
        view_section.append("Highlights", "win.view::highlights")
        view_section.append("Full log", "win.view::raw")

        log_section = Gio.Menu()
        log_section.append("Read again", "win.reload")
        log_section.append("Watch for new messages", "win.watch")
        log_section.append("Wrap long lines", "win.wrap")

        copy_section = Gio.Menu()
        copy_section.append("Copy all highlights", "win.copy-highlights")
        copy_section.append("Save a copy…", "win.save-copy")

        application_section = Gio.Menu()
        application_section.append("Preferences", "win.preferences")
        application_section.append("Keyboard Shortcuts", "win.shortcuts")
        application_section.append(f"About {APP_NAME}", "app.about")

        menu = Gio.Menu()
        menu.append_section(None, view_section)
        menu.append_section(None, log_section)
        menu.append_section(None, copy_section)
        menu.append_section(None, application_section)
        return menu

    def _install_actions(self) -> None:
        def add(name: str, callback: Callable[..., None], accels: list[str] | None = None) -> None:
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", lambda *_a: callback())
            self.add_action(action)
            if accels:
                application = self.get_application()
                if application is not None:
                    application.set_accels_for_action(f"win.{name}", accels)

        add("reload", self.reload, ["<Control>r", "F5"])
        add("search", self._log_page.start_search, ["<Control>f"])
        add("find-source", self._sidebar.focus_search, ["<Control>k"])
        add("copy-highlights", self._log_page.copy_all_highlights, ["<Control><Shift>c"])
        add("copy", self._log_page.copy_visible, ["<Control>c"])
        add("save-copy", self._save_copy, ["<Control>s"])
        add("rescan", self.start_scan, ["<Control><Shift>r"])
        add("preferences", self._show_preferences, ["<Control>comma"])
        add("shortcuts", self._show_shortcuts, ["<Control>question"])
        add("unlock", self._request_unlock_read, ["<Control>u"])

        view_action = Gio.SimpleAction.new_stateful(
            "view", GLib.VariantType.new("s"), GLib.Variant.new_string("overview")
        )
        view_action.connect("activate", self._on_view_action)
        self.add_action(view_action)
        application = self.get_application()
        if application is not None:
            application.set_accels_for_action("win.view::overview", ["<Control>1"])
            application.set_accels_for_action("win.view::highlights", ["<Control>2"])
            application.set_accels_for_action("win.view::raw", ["<Control>3"])

        wrap_action = Gio.SimpleAction.new_stateful(
            "wrap", None, GLib.Variant.new_boolean(self._settings.wrap_lines)
        )
        wrap_action.connect("activate", self._on_wrap_action)
        self.add_action(wrap_action)
        self._log_page.set_wrap(self._settings.wrap_lines)

        watch_action = Gio.SimpleAction.new_stateful(
            "watch", None, GLib.Variant.new_boolean(False)
        )
        watch_action.connect("activate", self._on_watch_action)
        self.add_action(watch_action)
        self._watch_action = watch_action

    # -- scanning -------------------------------------------------------
    def start_scan(self, *, elevated: bool = False) -> None:
        self._scan_token += 1
        token = self._scan_token
        self._sidebar.show_scanning()
        options = ScanOptions(
            include_journal=self._settings.use_journal,
            include_user_logs=self._settings.scan_user_logs,
            include_system_logs=self._settings.scan_system_logs,
            include_archived=self._settings.include_archived,
            include_empty=self._settings.include_empty,
            extra_roots=list(self._settings.extra_locations),
            elevated_listing=elevated,
        )

        def work() -> None:
            try:
                result = scan(options)
            except Exception as error:  # a broken mount must not kill the window
                result = DiscoveryResult(notes=[f"The scan stopped early: {error}"])
            GLib.idle_add(self._scan_done, token, result, priority=GLib.PRIORITY_DEFAULT_IDLE)

        threading.Thread(target=work, daemon=True, name="logread-scan").start()

    def _scan_done(self, token: int, result: DiscoveryResult) -> bool:
        if token != self._scan_token:
            return GLib.SOURCE_REMOVE
        self._sidebar.set_result(result)
        if result.notes:
            self._toast(result.notes[0])
        return GLib.SOURCE_REMOVE

    def _request_unlock_scan(self) -> None:
        reason = privileged.unavailable_reason()
        if reason:
            self._toast(reason)
            return
        confirm(
            self,
            heading="Unlock system logs?",
            body=(
                "LogRead will ask for your administrator password so it can list and "
                "read the log folders your account cannot open. It only reads — nothing "
                "is written or changed."
            ),
            confirm_label="Unlock",
            on_confirm=lambda: self.start_scan(elevated=True),
        )

    # -- loading a log ---------------------------------------------------
    def _on_file_chosen(self, _sidebar: Sidebar, log_file: LogFile, source: LogSource) -> None:
        self._current_request = {
            "kind": "file",
            "file": log_file,
            "source": source,
            "title": log_file.name,
            "subtitle": log_file.path,
        }
        self._load(allow_privilege=False)

    def _on_journal_chosen(
        self, _sidebar: Sidebar, query: JournalQuery, source: LogSource, label: str
    ) -> None:
        self._current_request = {
            "kind": "journal",
            "query": query,
            "source": source,
            "title": f"{source.name} · {label}",
            "subtitle": "systemd journal",
        }
        self._load(allow_privilege=False)

    def _load(self, *, allow_privilege: bool) -> None:
        request = self._current_request
        if request is None:
            return
        self._load_token += 1
        token = self._load_token
        self._log_page.show_loading(request["title"], request["subtitle"])
        if self._split.get_collapsed():
            self._split.set_show_content(True)

        settings = self._settings
        include_debug = settings.include_debug_in_highlights

        def work() -> None:
            try:
                if request["kind"] == "file":
                    document = load_file(
                        request["file"].path,
                        title=request["title"],
                        max_bytes=settings.max_read_bytes,
                        max_lines=settings.max_entries,
                        allow_privilege=allow_privilege,
                        include_debug=include_debug,
                    )
                else:
                    document = load_journal(
                        request["query"],
                        title=request["title"],
                        subtitle=request["subtitle"],
                        allow_privilege=allow_privilege,
                        include_debug=include_debug,
                    )
            except Exception as error:
                document = LogDocument(
                    title=request["title"],
                    subtitle=request["subtitle"],
                    problem=ReadProblem.UNREADABLE,
                    detail=f"LogRead could not read this log: {error}",
                )
            GLib.idle_add(self._load_done, token, document, priority=GLib.PRIORITY_DEFAULT_IDLE)

        threading.Thread(target=work, daemon=True, name="logread-read").start()

    def _load_done(self, token: int, document: LogDocument) -> bool:
        if token != self._load_token:
            return GLib.SOURCE_REMOVE
        self._document = document
        self._log_page.set_document(
            document, include_debug=self._settings.include_debug_in_highlights
        )
        if document.used_privilege:
            self._toast("Read with administrator access")
        return GLib.SOURCE_REMOVE

    def reload(self) -> None:
        if self._current_request is None:
            self.start_scan()
            return
        self._load(allow_privilege=bool(self._document and self._document.used_privilege))

    def _request_unlock_read(self) -> None:
        if self._current_request is None:
            return
        reason = privileged.unavailable_reason()
        if reason:
            self._toast(reason)
            return
        target = self._current_request["subtitle"]
        confirm(
            self,
            heading="Read this log as administrator?",
            body=(
                f"LogRead will ask for your administrator password so it can read "
                f"{target}. It only reads the file — nothing is written or changed."
            ),
            confirm_label="Read it",
            on_confirm=lambda: self._load(allow_privilege=True),
        )

    # -- actions ---------------------------------------------------------
    def _on_view_action(self, action: Gio.SimpleAction, parameter: GLib.Variant) -> None:
        name = parameter.get_string()
        action.set_state(parameter)
        self._log_page.show_view(name)

    def _on_wrap_action(self, action: Gio.SimpleAction, _parameter) -> None:
        state = not action.get_state().get_boolean()
        action.set_state(GLib.Variant.new_boolean(state))
        self._settings.wrap_lines = state
        self._settings.save()
        self._log_page.set_wrap(state)

    def _on_watch_action(self, action: Gio.SimpleAction, _parameter) -> None:
        state = not action.get_state().get_boolean()
        action.set_state(GLib.Variant.new_boolean(state))
        self._set_watching(state)

    def _set_watching(self, watching: bool) -> None:
        self._watching = watching
        if self._watch_source is not None:
            GLib.source_remove(self._watch_source)
            self._watch_source = None
        if watching:
            self._watch_source = GLib.timeout_add_seconds(5, self._watch_tick)
            self._toast("Watching for new messages")

    def _watch_tick(self) -> bool:
        if not self._watching or self._current_request is None:
            self._watch_source = None
            return GLib.SOURCE_REMOVE
        self.reload()
        return GLib.SOURCE_CONTINUE

    def _save_copy(self) -> None:
        document = self._document
        if document is None or not document.entries:
            self._toast("There is nothing to save yet")
            return
        dialog = Gtk.FileDialog(title="Save a copy of this log")
        dialog.set_initial_name(_safe_filename(document.title))

        def finished(file_dialog: Gtk.FileDialog, result) -> None:
            try:
                target = file_dialog.save_finish(result)
            except GLib.Error:
                return
            except Exception:
                return
            if target is None:
                return
            path = target.get_path()
            if not path:
                return
            try:
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(document.raw_text())
            except OSError as error:
                self._toast(f"Could not save the copy: {error.strerror or error}")
                return
            self._toast("Copy saved")

        dialog.save(self, None, finished)

    def _show_preferences(self) -> None:
        show_preferences(self, self._settings, self.start_scan)

    def _show_shortcuts(self) -> None:
        window = _shortcuts_window()
        window.set_transient_for(self)
        window.present()

    # -- misc ------------------------------------------------------------
    def _on_copied(self, _page, message: str) -> None:
        self._toast(message)

    def _toast(self, message: str) -> None:
        self._toasts.add_toast(Adw.Toast.new(message))

    def _on_close(self, *_args) -> bool:
        if self._settings.remember_window:
            width, height = self.get_default_size()
            self._settings.window_width = width
            self._settings.window_height = height
            self._settings.window_maximized = self.is_maximized()
            self._settings.save()
        return False


def _safe_filename(title: str) -> str:
    cleaned = "".join(char if char.isalnum() or char in "-_. " else "-" for char in title)
    cleaned = cleaned.strip().strip("-") or "log"
    return f"{cleaned}.log"


def _shortcuts_window() -> Gtk.ShortcutsWindow:
    window = Gtk.ShortcutsWindow(modal=True)
    section = Gtk.ShortcutsSection(section_name="shortcuts", max_height=10)

    def group(title: str, items: list[tuple[str, str]]) -> Gtk.ShortcutsGroup:
        shortcuts_group = Gtk.ShortcutsGroup(title=title)
        for accelerator, description in items:
            shortcuts_group.add_shortcut(
                Gtk.ShortcutsShortcut(accelerator=accelerator, title=description)
            )
        return shortcuts_group

    section.add_group(
        group(
            "Reading",
            [
                ("<Control>1", "Overview"),
                ("<Control>2", "Highlights"),
                ("<Control>3", "Full log"),
                ("<Control>f", "Search this log"),
                ("<Control>g", "Next match"),
                ("<Control><Shift>g", "Previous match"),
            ],
        )
    )
    section.add_group(
        group(
            "Logs",
            [
                ("<Control>k", "Find an application"),
                ("<Control>r", "Read this log again"),
                ("<Control><Shift>r", "Look for logs again"),
                ("<Control>u", "Read with administrator access"),
            ],
        )
    )
    section.add_group(
        group(
            "Clipboard",
            [
                ("<Control>c", "Copy the selection"),
                ("<Control><Shift>c", "Copy all highlights"),
                ("<Control>s", "Save a copy"),
            ],
        )
    )
    section.add_group(
        group("Window", [("<Control>comma", "Preferences"), ("<Control>q", "Quit")])
    )
    window.add_section(section)
    return window
