"""The content side of the window: one log, three ways to read it.

Overview answers "is anything wrong and when", Highlights lists the problems
themselves, and Raw shows the file verbatim. Every failure — no permission, a
binary file, an empty log — lands on a status page that says what to do next.
"""

from __future__ import annotations

from gi.repository import Adw, Gdk, GLib, GObject, Gtk

from ..core.document import LogDocument
from ..core.reader import ReadProblem
from .format import count as format_count
from .format import plural
from .icons import resolve as resolve_icon
from .overview import OverviewPage
from .problems import ProblemList
from .rawview import RawView

__all__ = ["LogPage"]


class LogPage(Adw.Bin):
    """Shows one `LogDocument`, or the reason there is not one."""

    __gtype_name__ = "LogReadLogPage"

    __gsignals__ = {
        "unlock-requested": (GObject.SignalFlags.RUN_FIRST, None, ()),
        "reload-requested": (GObject.SignalFlags.RUN_FIRST, None, ()),
        "copied": (GObject.SignalFlags.RUN_FIRST, None, (str,)),
    }

    def __init__(self, menu_model) -> None:
        super().__init__()
        self._document: LogDocument | None = None
        self._include_debug = False

        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)

        self._views = Adw.ViewStack()
        self._overview = OverviewPage()
        self._problems = ProblemList()
        self._raw = RawView()

        self._views.add_named(self._overview, "overview")
        self._views.add_named(self._build_highlights(), "highlights")
        self._views.add_named(self._raw, "raw")
        self._views.connect("notify::visible-child-name", self._on_view_changed)

        self._overview.connect("entry-activated", self._on_entry_activated)
        self._overview.connect("show-highlights", lambda _w: self.show_view("highlights"))
        self._overview.connect("copied", self._relay_copied)
        self._problems.connect("entry-activated", self._on_entry_activated)
        self._problems.connect("copied", self._relay_copied)
        self._raw.connect("copied", self._relay_copied)
        self._raw.connect("matches-changed", self._on_matches)

        self._stack.add_named(self._build_placeholder(), "placeholder")
        self._stack.add_named(self._build_loading(), "loading")
        self._stack.add_named(self._build_status(), "status")
        self._stack.add_named(self._views, "content")
        self._stack.set_visible_child_name("placeholder")

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(self._build_header(menu_model))
        toolbar.add_top_bar(self._build_search_bar())
        self._banner = Adw.Banner()
        self._banner.set_revealed(False)
        toolbar.add_top_bar(self._banner)
        toolbar.set_content(self._stack)

        self._toolbar = toolbar
        self.set_child(toolbar)

    # -- chrome ---------------------------------------------------------
    def _build_header(self, menu_model) -> Adw.HeaderBar:
        header = Adw.HeaderBar()

        # A segmented control rather than an AdwViewSwitcher: the switcher
        # would take the title area, and knowing which file you are reading
        # matters more than a slightly larger set of tabs.
        self._toggles = _ViewToggles()
        self._toggles.connect("view-selected", self._on_toggle_selected)
        self._toggles.set_visible(False)
        header.pack_start(self._toggles)

        self._title = Adw.WindowTitle(title="LogRead", subtitle="")
        header.set_title_widget(self._title)

        self._unlock_button = Gtk.Button()
        self._unlock_button.set_child(
            Adw.ButtonContent(icon_name=resolve_icon("channel-secure-symbolic"), label="Unlock")
        )
        self._unlock_button.add_css_class("suggested-action")
        self._unlock_button.set_tooltip_text("Read this log with administrator access")
        self._unlock_button.set_visible(False)
        self._unlock_button.connect("clicked", lambda _b: self.emit("unlock-requested"))
        header.pack_start(self._unlock_button)

        self._search_button = Gtk.ToggleButton(icon_name=resolve_icon("system-search-symbolic"))
        self._search_button.set_tooltip_text("Search this log (Ctrl+F)")
        self._search_button.set_visible(False)
        header.pack_end(self._build_menu_button(menu_model))
        header.pack_end(self._search_button)

        self._reload_button = Gtk.Button(icon_name=resolve_icon("view-refresh-symbolic"))
        self._reload_button.set_tooltip_text("Read this log again (Ctrl+R)")
        self._reload_button.set_visible(False)
        self._reload_button.connect("clicked", lambda _b: self.emit("reload-requested"))
        header.pack_end(self._reload_button)
        return header

    def _build_menu_button(self, menu_model) -> Gtk.MenuButton:
        button = Gtk.MenuButton()
        button.set_icon_name(resolve_icon("open-menu-symbolic"))
        button.set_menu_model(menu_model)
        button.set_tooltip_text("Main menu")
        self._menu_button = button
        return button

    def _build_search_bar(self) -> Gtk.SearchBar:
        self._search_entry = Gtk.SearchEntry()
        self._search_entry.set_placeholder_text("Search this log")
        self._search_entry.set_hexpand(True)
        self._search_entry.connect("search-changed", self._on_search_changed)
        self._search_entry.connect("activate", lambda _e: self._raw.next_match())
        self._search_entry.connect("next-match", lambda _e: self._raw.next_match())
        self._search_entry.connect("previous-match", lambda _e: self._raw.previous_match())

        self._match_label = Gtk.Label(label="")
        self._match_label.add_css_class("dim-label")
        self._match_label.add_css_class("tabular")

        previous = Gtk.Button(icon_name=resolve_icon("go-up-symbolic"))
        previous.add_css_class("flat")
        previous.set_tooltip_text("Previous match (Shift+Ctrl+G)")
        previous.connect("clicked", lambda _b: self._raw.previous_match())
        following = Gtk.Button(icon_name=resolve_icon("go-down-symbolic"))
        following.add_css_class("flat")
        following.set_tooltip_text("Next match (Ctrl+G)")
        following.connect("clicked", lambda _b: self._raw.next_match())

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        row.set_margin_start(6)
        row.set_margin_end(6)
        row.append(self._search_entry)
        row.append(self._match_label)
        navigation = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        navigation.add_css_class("linked")
        navigation.append(previous)
        navigation.append(following)
        row.append(navigation)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=560)
        clamp.set_child(row)

        bar = Gtk.SearchBar()
        bar.set_child(clamp)
        bar.set_key_capture_widget(self)
        bar.connect_entry(self._search_entry)
        self._search_button.bind_property(
            "active", bar, "search-mode-enabled", GObject.BindingFlags.BIDIRECTIONAL
        )
        self._search_bar = bar
        return bar

    def _build_highlights(self) -> Gtk.Widget:
        """The Highlights list, under a strip that counts and copies it."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        strip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        strip.set_margin_top(10)
        strip.set_margin_bottom(6)
        strip.set_margin_start(14)
        strip.set_margin_end(14)

        self._highlights_summary = Gtk.Label(xalign=0.0)
        self._highlights_summary.add_css_class("dim-label")
        self._highlights_summary.set_hexpand(True)
        self._highlights_summary.set_wrap(True)
        strip.append(self._highlights_summary)

        copy_all = Gtk.Button()
        copy_all.set_child(
            Adw.ButtonContent(icon_name=resolve_icon("edit-copy-symbolic"), label="Copy all")
        )
        copy_all.add_css_class("flat")
        copy_all.set_tooltip_text("Copy every highlight (Shift+Ctrl+C)")
        copy_all.connect("clicked", lambda _b: self.copy_all_highlights())
        strip.append(copy_all)

        box.append(strip)
        box.append(self._problems)

        self._highlights_empty = Adw.StatusPage(
            icon_name=resolve_icon("emblem-ok-symbolic"),
            title="Nothing to flag",
            description="No errors or warnings turned up in this log.",
        )
        self._highlights_stack = Gtk.Stack()
        self._highlights_stack.add_named(box, "list")
        self._highlights_stack.add_named(self._highlights_empty, "empty")
        return self._highlights_stack

    def _build_placeholder(self) -> Gtk.Widget:
        page = Adw.StatusPage(
            icon_name=resolve_icon("text-x-generic-symbolic"),
            title="Choose a log",
            description=(
                "Pick an application or service on the left, then choose one of its logs. "
                "LogRead reads it, works out what the format is, and points at the errors."
            ),
        )
        return page

    def _build_loading(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        box.set_valign(Gtk.Align.CENTER)
        box.set_halign(Gtk.Align.CENTER)
        spinner = Gtk.Spinner()
        spinner.set_size_request(32, 32)
        spinner.start()
        box.append(spinner)
        self._loading_label = Gtk.Label(label="Reading the log…")
        self._loading_label.add_css_class("dim-label")
        box.append(self._loading_label)
        return box

    def _build_status(self) -> Gtk.Widget:
        self._status_page = Adw.StatusPage()
        self._status_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self._status_actions.set_halign(Gtk.Align.CENTER)

        self._status_unlock = Gtk.Button(label="Unlock with administrator access")
        self._status_unlock.add_css_class("suggested-action")
        self._status_unlock.add_css_class("pill")
        self._status_unlock.connect("clicked", lambda _b: self.emit("unlock-requested"))
        self._status_actions.append(self._status_unlock)

        self._status_retry = Gtk.Button(label="Try again")
        self._status_retry.add_css_class("pill")
        self._status_retry.connect("clicked", lambda _b: self.emit("reload-requested"))
        self._status_actions.append(self._status_retry)

        self._status_page.set_child(self._status_actions)
        return self._status_page

    # -- state ----------------------------------------------------------
    def show_placeholder(self) -> None:
        self._document = None
        self._stack.set_visible_child_name("placeholder")
        self._title.set_title("LogRead")
        self._title.set_subtitle("")
        self._toggles.set_visible(False)
        self._banner.set_revealed(False)
        for button in (self._search_button, self._reload_button, self._unlock_button):
            button.set_visible(False)

    def show_loading(self, title: str, subtitle: str = "") -> None:
        self._title.set_title(title)
        self._title.set_subtitle(subtitle)
        self._toggles.set_visible(False)
        self._loading_label.set_text("Reading the log…")
        self._stack.set_visible_child_name("loading")
        self._banner.set_revealed(False)
        for button in (self._search_button, self._reload_button, self._unlock_button):
            button.set_visible(False)

    def set_document(self, document: LogDocument, *, include_debug: bool = False) -> None:
        self._document = document
        self._include_debug = include_debug
        self._title.set_title(document.title)
        self._title.set_subtitle(document.subtitle)
        self._reload_button.set_visible(True)

        if document.problem is not ReadProblem.NONE and not document.entries:
            self._show_problem(document)
            return

        self._unlock_button.set_visible(False)
        self._search_button.set_visible(True)
        self._toggles.set_visible(True)

        self._overview.set_document(document)
        self._problems.set_groups(document.groups)
        self._update_highlights_strip(document)
        self._raw.set_document(document)
        self._update_highlight_badge(document)
        self._update_banner(document)

        self._stack.set_visible_child_name("content")
        if not document.groups and self._views.get_visible_child_name() == "highlights":
            self._views.set_visible_child_name("overview")

    def _show_problem(self, document: LogDocument) -> None:
        problem = document.problem
        self._status_page.set_icon_name(resolve_icon(problem.icon_name))
        self._status_page.set_title(problem.title or "Could not read this log")
        description = document.detail
        if document.hint:
            description = f"{description}\n\n{document.hint}" if description else document.hint
        self._status_page.set_description(description)

        can_unlock = document.can_elevate
        self._status_unlock.set_visible(can_unlock)
        self._unlock_button.set_visible(can_unlock)
        self._status_retry.set_visible(problem is not ReadProblem.BINARY)
        self._search_button.set_visible(False)
        self._toggles.set_visible(False)
        self._banner.set_revealed(False)
        self._stack.set_visible_child_name("status")

    def _update_highlight_badge(self, document: LogDocument) -> None:
        summary = document.summary
        self._toggles.set_problem_count(summary.problems, has_errors=bool(summary.errors))

    def _update_highlights_strip(self, document: LogDocument) -> None:
        summary = document.summary
        groups = document.groups
        if not groups:
            self._highlights_stack.set_visible_child_name("empty")
            return
        self._highlights_stack.set_visible_child_name("list")
        occurrences = sum(group.count for group in groups)
        parts = []
        if summary.errors:
            parts.append(plural(summary.errors, "error"))
        if summary.warnings:
            parts.append(plural(summary.warnings, "warning"))
        text = " and ".join(parts) if parts else plural(occurrences, "entry", "entries")
        if occurrences != len(groups):
            text += f", grouped into {plural(len(groups), 'distinct message')}"
        self._highlights_summary.set_text(text)

    def _update_banner(self, document: LogDocument) -> None:
        messages: list[str] = []
        if document.truncated:
            messages.append("This log is large, so only its most recent part was read.")
        if document.hint and document.problem is ReadProblem.NONE:
            messages.append(document.hint)
        if document.used_privilege:
            messages.append("Read with administrator access.")
        if messages:
            self._banner.set_title(" ".join(messages))
            self._banner.set_revealed(True)
        else:
            self._banner.set_revealed(False)

    # -- interaction ----------------------------------------------------
    def show_view(self, name: str) -> None:
        if self._stack.get_visible_child_name() == "content":
            self._views.set_visible_child_name(name)

    def set_narrow(self, narrow: bool) -> None:
        """Drop the toggle labels when the window is too tight for them."""
        self._toggles.set_narrow(narrow)

    def _on_toggle_selected(self, _toggles, name: str) -> None:
        self.show_view(name)

    def _on_view_changed(self, *_args) -> None:
        name = self._views.get_visible_child_name()
        if name:
            self._toggles.select(name)

    @property
    def current_view(self) -> str:
        return self._views.get_visible_child_name() or "overview"

    def start_search(self) -> None:
        if not self._search_button.get_visible():
            return
        self.show_view("raw")
        self._search_button.set_active(True)
        self._search_entry.grab_focus()

    def set_wrap(self, wrap: bool) -> None:
        self._raw.set_wrap(wrap)

    def copy_all_highlights(self) -> None:
        if self._document is None or not self._document.groups:
            self.emit("copied", "There are no highlights to copy")
            return
        lines: list[str] = []
        for group in self._document.groups:
            lines.append(group.copy_text())
        display = Gdk.Display.get_default()
        if display is not None:
            display.get_clipboard().set("\n".join(lines))
        self.emit("copied", f"Copied {plural(len(self._document.groups), 'highlight')}")

    def copy_visible(self) -> None:
        if self.current_view == "raw":
            self._raw.copy_selection_or_all()
        else:
            self.copy_all_highlights()

    def _on_entry_activated(self, _widget, position: int) -> None:
        self.show_view("raw")
        GLib.idle_add(self._scroll_later, position, priority=GLib.PRIORITY_LOW)

    def _scroll_later(self, position: int) -> bool:
        self._raw.scroll_to_entry(position)
        return GLib.SOURCE_REMOVE

    def _on_search_changed(self, entry: Gtk.SearchEntry) -> None:
        self._raw.search(entry.get_text())

    def _on_matches(self, _view: RawView, current: int, total: int) -> None:
        if not self._search_entry.get_text():
            self._match_label.set_text("")
        elif total == 0:
            self._match_label.set_text("No matches")
        else:
            self._match_label.set_text(f"{current} of {format_count(total)}")

    def _relay_copied(self, _widget, message: str) -> None:
        self.emit("copied", message)


class _ViewToggles(Gtk.Box):
    """Segmented control for Overview / Highlights / Full log."""

    __gtype_name__ = "LogReadViewToggles"

    __gsignals__ = {
        "view-selected": (GObject.SignalFlags.RUN_FIRST, None, (str,)),
    }

    _VIEWS = (
        ("overview", "Overview", "view-reveal-symbolic", "Summary of this log (Ctrl+1)"),
        ("highlights", "Highlights", "dialog-warning-symbolic", "Errors and warnings only (Ctrl+2)"),
        ("raw", "Full log", "view-list-symbolic", "Every line, as written (Ctrl+3)"),
    )

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self.add_css_class("linked")
        self._buttons: dict[str, Gtk.ToggleButton] = {}
        self._labels: dict[str, Gtk.Label] = {}
        self._updating = False

        group: Gtk.ToggleButton | None = None
        for name, label, icon, tooltip in self._VIEWS:
            button = Gtk.ToggleButton()
            content = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            content.append(Gtk.Image.new_from_icon_name(resolve_icon(icon)))
            text = Gtk.Label(label=label)
            content.append(text)
            if name == "highlights":
                self._badge = Gtk.Label()
                self._badge.add_css_class("count-badge")
                self._badge.set_visible(False)
                content.append(self._badge)
            button.set_child(content)
            button.set_tooltip_text(tooltip)
            if group is None:
                group = button
            else:
                button.set_group(group)
            button.connect("toggled", self._on_toggled, name)
            self.append(button)
            self._buttons[name] = button
            self._labels[name] = text
        self._buttons["overview"].set_active(True)

    def select(self, name: str) -> None:
        button = self._buttons.get(name)
        if button is None or button.get_active():
            return
        self._updating = True
        button.set_active(True)
        self._updating = False

    def set_problem_count(self, count: int, *, has_errors: bool) -> None:
        if count <= 0:
            self._badge.set_visible(False)
            return
        self._badge.set_text(format_count(count) if count < 10_000 else "9999+")
        self._badge.remove_css_class("is-error")
        self._badge.remove_css_class("is-warning")
        self._badge.add_css_class("is-error" if has_errors else "is-warning")
        self._badge.set_visible(True)

    def set_narrow(self, narrow: bool) -> None:
        for label in self._labels.values():
            label.set_visible(not narrow)

    def _on_toggled(self, button: Gtk.ToggleButton, name: str) -> None:
        if self._updating or not button.get_active():
            return
        self.emit("view-selected", name)
