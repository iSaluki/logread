"""The Highlights view: every error and warning as its own card.

Repeats of the same message are collapsed into one card with an occurrence
count, so a log that failed the same way 4,000 times reads as one problem
rather than 4,000 lines. Each card carries its own copy button — the quickest
path from "something broke" to a paste in a bug report.
"""

from __future__ import annotations

from collections.abc import Callable

from gi.repository import Gdk, Gio, GLib, GObject, Gtk

from ..core.analysis import ProblemGroup
from .format import count as format_count
from .icons import resolve as resolve_icon

__all__ = ["ProblemList", "ProblemItem", "build_card"]

_MAX_DETAIL_LINES = 40


class ProblemItem(GObject.Object):
    """List-model wrapper so `Gtk.ListView` can recycle problem cards."""

    __gtype_name__ = "LogReadProblemItem"

    def __init__(self, group: ProblemGroup) -> None:
        super().__init__()
        self.group = group


class ProblemList(Gtk.Box):
    """A virtualised list of problem cards."""

    __gtype_name__ = "LogReadProblemList"

    __gsignals__ = {
        "entry-activated": (GObject.SignalFlags.RUN_FIRST, None, (int,)),
        "copied": (GObject.SignalFlags.RUN_FIRST, None, (str,)),
    }

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self._list_store = Gio.ListStore.new(ProblemItem)
        selection = Gtk.NoSelection(model=self._list_store)

        factory = Gtk.SignalListItemFactory()
        factory.connect("setup", self._on_setup)
        factory.connect("bind", self._on_bind)

        self._view = Gtk.ListView(model=selection, factory=factory)
        self._view.add_css_class("problem-list")
        self._view.set_single_click_activate(False)
        self._view.set_vexpand(True)

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_child(self._view)
        scroller.set_vexpand(True)
        self.append(scroller)
        self._scroller = scroller

    # -- population -----------------------------------------------------
    def set_groups(self, groups: list[ProblemGroup]) -> None:
        items = [ProblemItem(group) for group in groups]
        self._list_store.splice(0, self._list_store.get_n_items(), items)
        GLib.idle_add(self._scroll_to_top, priority=GLib.PRIORITY_LOW)

    def _scroll_to_top(self) -> bool:
        adjustment = self._scroller.get_vadjustment()
        if adjustment is not None:
            adjustment.set_value(adjustment.get_lower())
        return GLib.SOURCE_REMOVE

    @property
    def is_empty(self) -> bool:
        return self._list_store.get_n_items() == 0

    # -- factory --------------------------------------------------------
    def _on_setup(self, _factory: Gtk.SignalListItemFactory, item: Gtk.ListItem) -> None:
        clamp_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        clamp_box.set_margin_start(12)
        clamp_box.set_margin_end(12)
        card = _ProblemCard()
        clamp_box.append(card)
        item.set_child(clamp_box)

    def _on_bind(self, _factory: Gtk.SignalListItemFactory, item: Gtk.ListItem) -> None:
        container = item.get_child()
        card = container.get_first_child()
        entry = item.get_item()
        if isinstance(card, _ProblemCard) and isinstance(entry, ProblemItem):
            card.bind(entry.group, on_copy=self._copy, on_open=self._open)

    # -- actions --------------------------------------------------------
    def _copy(self, group: ProblemGroup) -> None:
        display = Gdk.Display.get_default()
        if display is not None:
            display.get_clipboard().set(group.copy_text())
        self.emit("copied", "Entry copied")

    def _open(self, group: ProblemGroup) -> None:
        if group.positions:
            self.emit("entry-activated", group.positions[0])


class _ProblemCard(Gtk.Box):
    """One problem, with its severity, message, when it happened, and a copy button."""

    __gtype_name__ = "LogReadProblemCard"

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add_css_class("problem-card")
        self._group: ProblemGroup | None = None
        self._on_copy: Callable[[ProblemGroup], None] | None = None
        self._on_open: Callable[[ProblemGroup], None] | None = None

        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)

        self._pill = Gtk.Label()
        self._pill.add_css_class("severity-pill")
        self._pill.set_valign(Gtk.Align.START)
        self._pill.set_margin_top(2)
        top.append(self._pill)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        body.set_hexpand(True)

        self._message = Gtk.Label(xalign=0.0)
        self._message.add_css_class("problem-message")
        self._message.set_wrap(True)
        self._message.set_wrap_mode(2)  # Pango.WrapMode.WORD_CHAR
        self._message.set_selectable(True)
        self._message.set_max_width_chars(80)
        body.append(self._message)

        meta_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._meta = Gtk.Label(xalign=0.0)
        self._meta.add_css_class("problem-meta")
        self._meta.set_ellipsize(3)  # Pango.EllipsizeMode.END
        meta_row.append(self._meta)
        self._repeat = Gtk.Label()
        self._repeat.add_css_class("repeat-badge")
        self._repeat.set_visible(False)
        meta_row.append(self._repeat)
        body.append(meta_row)

        self._detail = Gtk.Expander(label="Show details")
        self._detail_label = Gtk.Label(xalign=0.0)
        self._detail_label.add_css_class("problem-detail")
        self._detail_label.set_selectable(True)
        self._detail_label.set_wrap(True)
        self._detail.set_child(self._detail_label)
        self._detail.set_visible(False)
        body.append(self._detail)

        top.append(body)

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=2)
        buttons.set_valign(Gtk.Align.START)

        self._open_button = Gtk.Button(icon_name=resolve_icon("go-jump-symbolic"))
        self._open_button.add_css_class("flat")
        self._open_button.set_tooltip_text("Show in the full log")
        self._open_button.connect("clicked", self._activate_open)
        buttons.append(self._open_button)

        self._copy_button = Gtk.Button(icon_name=resolve_icon("edit-copy-symbolic"))
        self._copy_button.add_css_class("flat")
        self._copy_button.set_tooltip_text("Copy this entry")
        self._copy_button.connect("clicked", self._activate_copy)
        buttons.append(self._copy_button)

        top.append(buttons)
        self.append(top)

    def bind(
        self,
        group: ProblemGroup,
        *,
        on_copy: Callable[[ProblemGroup], None],
        on_open: Callable[[ProblemGroup], None],
    ) -> None:
        self._group = group
        self._on_copy = on_copy
        self._on_open = on_open

        severity = group.severity
        self._pill.set_text(severity.short_label or severity.label.upper())
        for name in ("sev-critical", "sev-error", "sev-warning", "sev-notice", "sev-info", "sev-debug", "sev-unknown"):
            self._pill.remove_css_class(name)
        self._pill.add_css_class(severity.css_class)
        self.remove_css_class("is-error")
        self.remove_css_class("is-warning")
        self.add_css_class("is-error" if severity.is_error else "is-warning")

        self._message.set_text(group.sample.message.strip() or group.sample.raw.strip())

        meta_parts: list[str] = []
        when = group.when()
        if when:
            meta_parts.append(when)
        if group.sample.source:
            meta_parts.append(group.sample.source)
        if group.sample.pid:
            meta_parts.append(f"PID {group.sample.pid}")
        if group.sample.guessed:
            meta_parts.append("severity inferred from the message")
        self._meta.set_text(" · ".join(meta_parts) or f"Line {group.sample.line_no}")

        if group.is_repeat:
            self._repeat.set_text(f"×{format_count(group.count)}")
            self._repeat.set_visible(True)
            self._repeat.set_tooltip_text(f"This message appears {format_count(group.count)} times")
        else:
            self._repeat.set_visible(False)

        extra = group.sample.extra_lines
        if extra:
            shown = extra[:_MAX_DETAIL_LINES]
            text = "\n".join(shown)
            if len(extra) > _MAX_DETAIL_LINES:
                text += f"\n… {len(extra) - _MAX_DETAIL_LINES} more lines"
            self._detail_label.set_text(text)
            self._detail.set_label(f"Show {len(extra)} more lines")
            self._detail.set_expanded(False)
            self._detail.set_visible(True)
        else:
            self._detail.set_visible(False)

        self._open_button.set_visible(bool(group.positions))

    def _activate_copy(self, _button: Gtk.Button) -> None:
        if self._group is not None and self._on_copy is not None:
            self._on_copy(self._group)

    def _activate_open(self, _button: Gtk.Button) -> None:
        if self._group is not None and self._on_open is not None:
            self._on_open(self._group)


def build_card(group: ProblemGroup, on_copy, on_open) -> Gtk.Widget:
    """A single non-virtualised card, used on the overview page."""
    card = _ProblemCard()
    card.bind(group, on_copy=on_copy, on_open=on_open)
    return card
