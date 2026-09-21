"""The Raw view: the log as it is, coloured but not rewritten.

Text goes in through a `Gtk.TextView` rather than a list so it can be selected
and copied the way people expect from a terminal. Large logs are filled in
chunks on the main loop's idle handler so the window stays responsive while a
quarter of a million lines land.
"""

from __future__ import annotations

from gi.repository import Gdk, GLib, GObject, Gtk, Pango

from ..core.document import LogDocument
from ..core.entry import LogEntry
from ..core.severity import Severity

__all__ = ["RawView"]

_CHUNK = 4000


class RawView(Gtk.Box):
    """A monospace view of every entry, with severity colouring and search."""

    __gtype_name__ = "LogReadRawView"

    __gsignals__ = {
        "copied": (GObject.SignalFlags.RUN_FIRST, None, (str,)),
        "loading-changed": (GObject.SignalFlags.RUN_FIRST, None, (bool,)),
        "matches-changed": (GObject.SignalFlags.RUN_FIRST, None, (int, int)),
    }

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self._entries: list[LogEntry] = []
        self._line_for_entry: list[int] = []
        self._fill_source: int | None = None
        self._matches: list[tuple[int, int]] = []
        self._match_index = -1
        self._search_text = ""
        self._position = 0

        self._buffer = Gtk.TextBuffer()
        self._make_tags()

        self._view = Gtk.TextView(buffer=self._buffer)
        self._view.set_editable(False)
        self._view.set_cursor_visible(False)
        self._view.set_monospace(True)
        self._view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self._view.set_left_margin(14)
        self._view.set_right_margin(14)
        self._view.set_top_margin(10)
        self._view.set_bottom_margin(24)
        self._view.add_css_class("log-text")
        self._view.set_vexpand(True)

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroller.set_child(self._view)
        scroller.set_vexpand(True)
        self._scroller = scroller
        self.append(scroller)

    # -- tags -----------------------------------------------------------
    def _make_tags(self) -> None:
        table = self._buffer.get_tag_table()
        for name in ("sev-critical", "sev-error", "sev-warning", "sev-notice", "sev-debug",
                     "match", "current-match"):
            if table.lookup(name) is None:
                table.add(Gtk.TextTag(name=name))
        critical = table.lookup("sev-critical")
        if critical is not None:
            critical.set_property("weight", Pango.Weight.BOLD)
        self._refresh_tag_colours()

    def _refresh_tag_colours(self) -> None:
        """Resolve tag colours from the widget's own style so themes apply."""
        table = self._buffer.get_tag_table()
        palette = _palette(self)
        for name, key in (
            ("sev-critical", "error"),
            ("sev-error", "error"),
            ("sev-warning", "warning"),
            ("sev-notice", "accent"),
            ("sev-debug", "dim"),
        ):
            tag = table.lookup(name)
            if tag is not None:
                tag.set_property("foreground-rgba", palette[key])
        for name in ("match", "current-match"):
            tag = table.lookup(name)
            if tag is not None:
                tag.set_property("background-rgba", palette[name])

    # -- population -----------------------------------------------------
    def set_document(self, document: LogDocument | None) -> None:
        self._cancel_fill()
        self._buffer.set_text("")
        self._entries = list(document.entries) if document else []
        self._line_for_entry = []
        self._matches.clear()
        self._match_index = -1
        if not self._entries:
            self.emit("loading-changed", False)
            return
        self._refresh_tag_colours()
        self.emit("loading-changed", True)
        self._position = 0
        self._fill_source = GLib.idle_add(self._fill_chunk, priority=GLib.PRIORITY_DEFAULT_IDLE)

    def _cancel_fill(self) -> None:
        if self._fill_source is not None:
            GLib.source_remove(self._fill_source)
            self._fill_source = None

    def _fill_chunk(self) -> bool:
        start = self._position
        end = min(start + _CHUNK, len(self._entries))
        buffer = self._buffer
        for index in range(start, end):
            entry = self._entries[index]
            iterator = buffer.get_end_iter()
            self._line_for_entry.append(buffer.get_line_count() - 1)
            offset = iterator.get_offset()
            text = entry.full_raw + "\n"
            buffer.insert(iterator, text)
            tag_name = _tag_for(entry.severity)
            if tag_name:
                begin = buffer.get_iter_at_offset(offset)
                stop = buffer.get_iter_at_offset(offset + len(text) - 1)
                buffer.apply_tag_by_name(tag_name, begin, stop)
        self._position = end
        if end >= len(self._entries):
            self._fill_source = None
            self.emit("loading-changed", False)
            if self._search_text:
                self.search(self._search_text)
            return GLib.SOURCE_REMOVE
        return GLib.SOURCE_CONTINUE

    @property
    def is_filling(self) -> bool:
        return self._fill_source is not None

    # -- navigation -----------------------------------------------------
    def scroll_to_entry(self, index: int) -> None:
        if not self._entries:
            return
        index = max(0, min(index, len(self._entries) - 1))
        if index >= len(self._line_for_entry):
            # The buffer is still filling; land on what is there so far.
            index = len(self._line_for_entry) - 1
            if index < 0:
                return
        line = self._line_for_entry[index]
        iterator = self._buffer.get_iter_at_line(line)
        if isinstance(iterator, tuple):  # PyGObject returns (ok, iter)
            iterator = iterator[1]
        self._buffer.place_cursor(iterator)
        mark = self._buffer.create_mark(None, iterator, True)
        self._view.scroll_to_mark(mark, 0.12, True, 0.0, 0.25)
        self._buffer.delete_mark(mark)

    def set_wrap(self, wrap: bool) -> None:
        self._view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR if wrap else Gtk.WrapMode.NONE)
        self._scroller.set_policy(
            Gtk.PolicyType.NEVER if wrap else Gtk.PolicyType.AUTOMATIC,
            Gtk.PolicyType.AUTOMATIC,
        )

    def set_font_size(self, points: int) -> None:
        if points <= 0:
            self._view.remove_css_class("custom-font")
            return
        self._view.add_css_class("custom-font")

    # -- search ---------------------------------------------------------
    def search(self, text: str) -> None:
        self._search_text = text
        buffer = self._buffer
        start, end = buffer.get_bounds()
        buffer.remove_tag_by_name("match", start, end)
        buffer.remove_tag_by_name("current-match", start, end)
        self._matches.clear()
        self._match_index = -1
        if not text:
            self.emit("matches-changed", 0, 0)
            return

        haystack = buffer.get_text(start, end, False).lower()
        needle = text.lower()
        position = haystack.find(needle)
        limit = 20_000
        while position != -1 and len(self._matches) < limit:
            self._matches.append((position, position + len(needle)))
            position = haystack.find(needle, position + max(1, len(needle)))

        for begin, stop in self._matches:
            buffer.apply_tag_by_name(
                "match", buffer.get_iter_at_offset(begin), buffer.get_iter_at_offset(stop)
            )
        self.emit("matches-changed", 0 if not self._matches else 1, len(self._matches))
        if self._matches:
            self._focus_match(0)

    def next_match(self) -> None:
        if self._matches:
            self._focus_match((self._match_index + 1) % len(self._matches))

    def previous_match(self) -> None:
        if self._matches:
            self._focus_match((self._match_index - 1) % len(self._matches))

    def _focus_match(self, index: int) -> None:
        buffer = self._buffer
        if self._match_index >= 0 and self._match_index < len(self._matches):
            previous = self._matches[self._match_index]
            buffer.remove_tag_by_name(
                "current-match",
                buffer.get_iter_at_offset(previous[0]),
                buffer.get_iter_at_offset(previous[1]),
            )
        self._match_index = index
        begin, stop = self._matches[index]
        start_iter = buffer.get_iter_at_offset(begin)
        end_iter = buffer.get_iter_at_offset(stop)
        buffer.apply_tag_by_name("current-match", start_iter, end_iter)
        buffer.place_cursor(start_iter)
        mark = buffer.create_mark(None, start_iter, True)
        self._view.scroll_to_mark(mark, 0.2, True, 0.0, 0.3)
        buffer.delete_mark(mark)
        self.emit("matches-changed", index + 1, len(self._matches))

    # -- clipboard ------------------------------------------------------
    def copy_selection_or_all(self) -> None:
        buffer = self._buffer
        bounds = buffer.get_selection_bounds()
        if bounds:
            text = buffer.get_text(bounds[0], bounds[1], False)
            label = "Selection copied"
        else:
            start, end = buffer.get_bounds()
            text = buffer.get_text(start, end, False)
            label = "Whole log copied"
        display = Gdk.Display.get_default()
        if display is not None:
            display.get_clipboard().set(text)
        self.emit("copied", label)

    @property
    def text_view(self) -> Gtk.TextView:
        return self._view


def _tag_for(severity: Severity) -> str | None:
    if severity.is_error:
        return "sev-critical" if severity <= Severity.CRITICAL else "sev-error"
    if severity is Severity.WARNING:
        return "sev-warning"
    if severity is Severity.NOTICE:
        return "sev-notice"
    if severity is Severity.DEBUG:
        return "sev-debug"
    return None


def _palette(widget: Gtk.Widget) -> dict[str, Gdk.RGBA]:
    """Severity colours that track the current light/dark theme.

    GTK's text tags need concrete colours, so the GNOME palette values are
    picked per theme rather than read back out of CSS.
    """
    from gi.repository import Adw

    dark = Adw.StyleManager.get_default().get_dark()
    if dark:
        values = {
            "error": "#ff7b63",
            "warning": "#f8e45c",
            "accent": "#78aeed",
            "dim": "#9a9996",
            "match": "#62a0ea55",
            "current-match": "#f5c21199",
        }
    else:
        values = {
            "error": "#c01c28",
            "warning": "#a45500",
            "accent": "#1c71d8",
            "dim": "#77767b",
            "match": "#62a0ea55",
            "current-match": "#f5c211aa",
        }
    palette: dict[str, Gdk.RGBA] = {}
    for key, value in values.items():
        rgba = Gdk.RGBA()
        rgba.parse(value)
        palette[key] = rgba
    return palette
