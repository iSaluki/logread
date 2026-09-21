"""The sidebar: applications first, then their logs.

Nobody should need to know that the printer's logs live in /var/log/cups. The
top level lists applications and services by name; choosing one pushes a second
page listing its logs, newest first, with rotated archives clearly marked.
"""

from __future__ import annotations

from gi.repository import Adw, GLib, GObject, Gtk

from ..core.discovery import DiscoveryResult, LogFile, LogSource
from ..core.journal import JournalQuery
from .format import count as format_count
from .format import file_size, plural, relative_time
from .icons import APP_FALLBACK
from .icons import resolve as resolve_icon

__all__ = ["Sidebar"]


class Sidebar(Adw.NavigationPage):
    """Two-level navigation over discovered sources."""

    __gtype_name__ = "LogReadSidebar"

    __gsignals__ = {
        "file-chosen": (GObject.SignalFlags.RUN_FIRST, None, (object, object)),
        "journal-chosen": (GObject.SignalFlags.RUN_FIRST, None, (object, object, str)),
        "rescan-requested": (GObject.SignalFlags.RUN_FIRST, None, ()),
        "unlock-requested": (GObject.SignalFlags.RUN_FIRST, None, ()),
    }

    def __init__(self) -> None:
        super().__init__(title="Logs")
        self._result: DiscoveryResult | None = None
        self._filter_text = ""

        self._navigation = Adw.NavigationView()
        self._sources_page = _SourcesPage(self)
        self._navigation.add(self._sources_page)
        self.set_child(self._navigation)

    # -- public ---------------------------------------------------------
    def show_scanning(self) -> None:
        self._sources_page.show_scanning()
        self._navigation.pop_to_page(self._sources_page)

    def set_result(self, result: DiscoveryResult) -> None:
        self._result = result
        self._navigation.pop_to_page(self._sources_page)
        self._sources_page.set_result(result)

    def open_source(self, source: LogSource) -> None:
        page = _FilesPage(self, source)
        self._navigation.push(page)

    def focus_search(self) -> None:
        self._navigation.pop_to_page(self._sources_page)
        self._sources_page.focus_search()

    @property
    def result(self) -> DiscoveryResult | None:
        return self._result


class _SourcesPage(Adw.NavigationPage):
    """Top level: every application and service that has logs."""

    def __init__(self, sidebar: Sidebar) -> None:
        super().__init__(title="Logs", tag="sources")
        self._sidebar = sidebar
        self._rows: list[tuple[str, Adw.ActionRow, Adw.PreferencesGroup]] = []

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.set_show_title(True)

        self._search_button = Gtk.ToggleButton(icon_name=resolve_icon("system-search-symbolic"))
        self._search_button.set_tooltip_text("Find an application (Ctrl+K)")
        header.pack_end(self._search_button)

        rescan = Gtk.Button(icon_name=resolve_icon("view-refresh-symbolic"))
        rescan.set_tooltip_text("Look for logs again")
        rescan.connect("clicked", lambda _b: sidebar.emit("rescan-requested"))
        header.pack_start(rescan)
        toolbar.add_top_bar(header)

        self._search_bar = self._build_search_bar()
        toolbar.add_top_bar(self._search_bar)

        self._banner = Adw.Banner(button_label="Unlock")
        self._banner.set_revealed(False)
        self._banner.connect("button-clicked", lambda _b: sidebar.emit("unlock-requested"))
        toolbar.add_top_bar(self._banner)

        self._stack = Gtk.Stack()
        self._stack.add_named(self._build_scanning(), "scanning")
        self._stack.add_named(self._build_empty(), "empty")
        self._stack.add_named(self._build_no_matches(), "no-matches")

        self._content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        self._content.set_margin_top(12)
        self._content.set_margin_bottom(18)
        self._content.set_margin_start(12)
        self._content.set_margin_end(12)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_child(self._content)
        scroller.set_vexpand(True)
        self._stack.add_named(scroller, "list")

        self._footer = Gtk.Label()
        self._footer.add_css_class("dim-label")
        self._footer.add_css_class("caption")
        self._footer.set_margin_top(6)
        self._footer.set_margin_bottom(8)
        self._footer.set_wrap(True)

        toolbar.set_content(self._stack)
        toolbar.add_bottom_bar(self._footer)
        self.set_child(toolbar)
        self._stack.set_visible_child_name("scanning")

    def _build_search_bar(self) -> Gtk.SearchBar:
        entry = Gtk.SearchEntry()
        entry.set_placeholder_text("Find an application or service")
        entry.set_hexpand(True)
        entry.connect("search-changed", self._on_search)
        entry.set_margin_start(6)
        entry.set_margin_end(6)
        self._search_entry = entry

        bar = Gtk.SearchBar()
        bar.set_child(entry)
        bar.connect_entry(entry)
        bar.set_key_capture_widget(self)
        self._search_button.bind_property(
            "active", bar, "search-mode-enabled", GObject.BindingFlags.BIDIRECTIONAL
        )
        return bar

    def _build_scanning(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_valign(Gtk.Align.CENTER)
        box.set_halign(Gtk.Align.CENTER)
        spinner = Gtk.Spinner()
        spinner.set_size_request(28, 28)
        spinner.start()
        box.append(spinner)
        label = Gtk.Label(label="Looking for logs…")
        label.add_css_class("dim-label")
        box.append(label)
        return box

    def _build_empty(self) -> Gtk.Widget:
        return Adw.StatusPage(
            icon_name=resolve_icon("edit-find-symbolic"),
            title="No logs found",
            description=(
                "LogRead looked in the usual places and came up empty. "
                "Add a location in Preferences, or try unlocking the system log "
                "directories."
            ),
        )

    def _build_no_matches(self) -> Gtk.Widget:
        self._no_matches_page = Adw.StatusPage(
            icon_name=resolve_icon("system-search-symbolic"),
            title="No matches",
            description="Nothing here matches that search.",
        )
        return self._no_matches_page

    # -- population -----------------------------------------------------
    def show_scanning(self) -> None:
        self._stack.set_visible_child_name("scanning")
        self._footer.set_text("")
        self._banner.set_revealed(False)

    def focus_search(self) -> None:
        self._search_button.set_active(True)
        self._search_entry.grab_focus()

    def set_result(self, result: DiscoveryResult) -> None:
        child = self._content.get_first_child()
        while child is not None:
            following = child.get_next_sibling()
            self._content.remove(child)
            child = following
        self._rows.clear()

        for category, sources in result.by_category():
            group = Adw.PreferencesGroup(title=category)
            listed = 0
            for source in sources:
                row = self._make_row(source)
                group.add(row)
                self._rows.append((_haystack(source), row, group))
                listed += 1
            if listed:
                self._content.append(group)

        if not result.sources:
            self._stack.set_visible_child_name("empty")
        else:
            self._stack.set_visible_child_name("list")

        self._update_footer(result)
        self._update_banner(result)
        self._apply_filter()

    def _make_row(self, source: LogSource) -> Adw.ActionRow:
        row = Adw.ActionRow(title=_escape(source.name))
        row.set_subtitle(_escape(_subtitle_for(source)))
        row.set_title_lines(1)
        row.set_subtitle_lines(1)
        row.set_activatable(True)
        icon = Gtk.Image.new_from_icon_name(resolve_icon(source.icon, APP_FALLBACK))
        row.add_prefix(icon)

        if source.locked_count:
            lock = Gtk.Image.new_from_icon_name(resolve_icon("channel-secure-symbolic"))
            lock.set_tooltip_text(
                f"{plural(source.locked_count, 'log')} here need administrator access"
            )
            row.add_suffix(lock)
            row.add_css_class("locked-row")

        count_label = Gtk.Label(label=format_count(source.item_count))
        count_label.add_css_class("count-badge")
        count_label.set_valign(Gtk.Align.CENTER)
        row.add_suffix(count_label)
        row.add_suffix(Gtk.Image.new_from_icon_name(resolve_icon("go-next-symbolic")))
        row.connect("activated", lambda _r, item=source: self._sidebar.open_source(item))
        return row

    def _update_footer(self, result: DiscoveryResult) -> None:
        parts = [plural(len(result.sources), "source")]
        if result.file_count:
            parts.append(plural(result.file_count, "file"))
        parts.append(
            "scanned instantly" if result.duration < 0.1 else f"scanned in {result.duration:.1f} s"
        )
        text = " · ".join(parts)
        if result.notes:
            text += "\n" + " ".join(result.notes)
        self._footer.set_text(text)

    def _update_banner(self, result: DiscoveryResult) -> None:
        if not result.has_locked_content:
            self._banner.set_revealed(False)
            return
        bits: list[str] = []
        if result.locked_files:
            bits.append(plural(result.locked_files, "log"))
        if result.denied_directories:
            bits.append(plural(len(result.denied_directories), "folder"))
        if result.journal_locked:
            bits.append("the system journal")
        listed = _join(bits)
        verb = "needs" if len(bits) == 1 and not bits[0][0].isdigit() else "need"
        if len(bits) == 1 and bits[0].split()[0] == "1":
            verb = "needs"
        self._banner.set_title(f"{listed} {verb} administrator access.")
        self._banner.set_revealed(True)

    # -- filtering ------------------------------------------------------
    def _on_search(self, entry: Gtk.SearchEntry) -> None:
        self._filter_text = entry.get_text().strip().lower()
        self._apply_filter()

    def _apply_filter(self) -> None:
        text = getattr(self, "_filter_text", "")
        if not self._rows:
            return
        visible_groups: dict[Adw.PreferencesGroup, int] = {}
        for haystack, row, group in self._rows:
            matches = text in haystack if text else True
            row.set_visible(matches)
            visible_groups[group] = visible_groups.get(group, 0) + (1 if matches else 0)
        for group, shown in visible_groups.items():
            group.set_visible(bool(shown))
        if text and not any(visible_groups.values()):
            self._no_matches_page.set_description(f"Nothing matches “{text}”.")
            self._stack.set_visible_child_name("no-matches")
        elif self._stack.get_visible_child_name() in ("no-matches", "list"):
            self._stack.set_visible_child_name("list")


class _FilesPage(Adw.NavigationPage):
    """Second level: the individual logs belonging to one source."""

    def __init__(self, sidebar: Sidebar, source: LogSource) -> None:
        super().__init__(title=_escape(source.name))
        self._sidebar = sidebar
        self._source = source

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        toolbar.add_top_bar(header)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        content.set_margin_top(12)
        content.set_margin_bottom(18)
        content.set_margin_start(12)
        content.set_margin_end(12)

        if source.summary:
            caption = Gtk.Label(label=_escape(source.summary), xalign=0.0)
            caption.add_css_class("dim-label")
            caption.set_wrap(True)
            caption.set_margin_start(4)
            content.append(caption)

        if source.journal_queries:
            group = Adw.PreferencesGroup(title="Journal")
            for label, query in source.journal_queries:
                group.add(self._journal_row(label, query, source))
            content.append(group)

        current = [item for item in source.files if not item.archived]
        archived = [item for item in source.files if item.archived]
        if current:
            group = Adw.PreferencesGroup(title="Current")
            for item in current:
                group.add(self._file_row(item))
            content.append(group)
        if archived:
            group = Adw.PreferencesGroup(
                title="Earlier",
                description="Rotated copies kept by the system, oldest last.",
            )
            for item in archived:
                group.add(self._file_row(item))
            content.append(group)

        if not source.files and not source.journal_queries:
            content.append(
                Adw.StatusPage(
                    icon_name=resolve_icon("text-x-generic-symbolic"),
                    title="No logs here",
                    description="This application has not written anything yet.",
                )
            )

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_child(content)
        scroller.set_vexpand(True)
        toolbar.set_content(scroller)
        self.set_child(toolbar)

    def _file_row(self, item: LogFile) -> Adw.ActionRow:
        row = Adw.ActionRow(title=_escape(item.name))
        details = [file_size(item.size), relative_time(item.mtime)]
        if item.compressed:
            details.append("compressed")
        if item.needs_privilege:
            details.append("needs administrator access")
        row.set_subtitle(_escape(" · ".join(details)))
        row.set_title_lines(1)
        row.set_subtitle_lines(1)
        row.set_activatable(True)

        icon_name = "channel-secure-symbolic" if item.needs_privilege else (
            "package-x-generic-symbolic" if item.compressed else "text-x-generic-symbolic"
        )
        row.add_prefix(Gtk.Image.new_from_icon_name(resolve_icon(icon_name)))
        if item.needs_privilege:
            row.add_css_class("locked-row")
        row.add_suffix(Gtk.Image.new_from_icon_name(resolve_icon("go-next-symbolic")))
        row.connect(
            "activated",
            lambda _r, chosen=item: self._sidebar.emit("file-chosen", chosen, self._source),
        )
        return row

    def _journal_row(self, label: str, query: JournalQuery, source: LogSource) -> Adw.ActionRow:
        row = Adw.ActionRow(title=_escape(label))
        subtitle = "systemd journal"
        if query.min_priority is not None:
            subtitle = "Only entries at warning level or above"
        elif query.kernel_only:
            subtitle = "Messages from the kernel"
        elif query.boot is not None:
            subtitle = "One boot at a time"
        row.set_subtitle(subtitle)
        row.set_activatable(True)
        row.add_prefix(Gtk.Image.new_from_icon_name(resolve_icon("computer-symbolic")))
        if source.locked_count:
            row.add_suffix(Gtk.Image.new_from_icon_name(resolve_icon("channel-secure-symbolic")))
        row.add_suffix(Gtk.Image.new_from_icon_name(resolve_icon("go-next-symbolic")))
        row.connect(
            "activated",
            lambda _r: self._sidebar.emit("journal-chosen", query, self._source, label),
        )
        return row


def _subtitle_for(source: LogSource) -> str:
    bits: list[str] = []
    if source.summary:
        bits.append(source.summary)
    elif source.is_journal:
        bits.append("systemd journal")
    if source.files:
        newest = max((item.mtime for item in source.files), default=0.0)
        if newest:
            bits.append(f"updated {relative_time(newest).lower()}")
    return " · ".join(bits)


def _haystack(source: LogSource) -> str:
    parts = [source.name, source.summary, source.key, source.category]
    parts.extend(item.name for item in source.files)
    parts.extend(item.path for item in source.files)
    return " ".join(part for part in parts if part).lower()


def _escape(text: str) -> str:
    """Rows use Pango markup, so anything from the filesystem must be escaped."""
    return GLib.markup_escape_text(text or "")


def _join(items: list[str]) -> str:
    if not items:
        return ""
    if len(items) == 1:
        return items[0][0].upper() + items[0][1:]
    joined = ", ".join(items[:-1]) + f" and {items[-1]}"
    return joined[0].upper() + joined[1:]
