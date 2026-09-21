"""The Overview: what this log says, before you read any of it.

Four numbers, an activity strip, the problems that repeat most, and the facts
about the file itself. Everything here is derived, never typed by the user, so
it stays honest about logs that have no timestamps or no severities at all.
"""

from __future__ import annotations

from gi.repository import Adw, Gdk, GObject, Gtk

from ..core.analysis import ProblemGroup, rank_groups
from ..core.document import LogDocument
from . import timeline as timeline_module
from .format import clock, duration, file_size, plural, relative_time
from .format import count as format_count
from .icons import resolve as resolve_icon
from .problems import build_card
from .timeline import TimelineStrip

__all__ = ["OverviewPage"]


class OverviewPage(Gtk.Box):
    """Scrollable summary of a single log."""

    __gtype_name__ = "LogReadOverviewPage"

    __gsignals__ = {
        "entry-activated": (GObject.SignalFlags.RUN_FIRST, None, (int,)),
        "show-highlights": (GObject.SignalFlags.RUN_FIRST, None, ()),
        "copied": (GObject.SignalFlags.RUN_FIRST, None, (str,)),
    }

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self._document: LogDocument | None = None

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_vexpand(True)

        clamp = Adw.Clamp(maximum_size=760, tightening_threshold=560)
        column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=22)
        column.set_margin_top(24)
        column.set_margin_bottom(32)
        column.set_margin_start(18)
        column.set_margin_end(18)

        column.append(self._build_verdict())
        column.append(self._build_tiles())
        column.append(self._build_activity())
        column.append(self._build_problems())
        column.append(self._build_facts())

        clamp.set_child(column)
        scroller.set_child(clamp)
        self.append(scroller)

    # -- construction ---------------------------------------------------
    def _build_verdict(self) -> Gtk.Widget:
        self._verdict = Adw.StatusPage()
        self._verdict.set_vexpand(False)
        # A compact heading rather than a full-page state.
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self._verdict_title = Gtk.Label(xalign=0.0)
        self._verdict_title.add_css_class("title-2")
        self._verdict_title.set_wrap(True)
        self._verdict_subtitle = Gtk.Label(xalign=0.0)
        self._verdict_subtitle.add_css_class("dim-label")
        self._verdict_subtitle.set_wrap(True)
        box.append(self._verdict_title)
        box.append(self._verdict_subtitle)
        return box

    def _build_tiles(self) -> Gtk.Widget:
        self._tiles = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10, homogeneous=True)
        self._tile_widgets: dict[str, tuple[Gtk.Box, Gtk.Label, Gtk.Label]] = {}
        for key, label in (
            ("errors", "Errors"),
            ("warnings", "Warnings"),
            ("total", "Messages"),
            ("span", "Covers"),
        ):
            tile = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            tile.add_css_class("stat-tile")
            value = Gtk.Label(label="0", xalign=0.0)
            value.add_css_class("stat-value")
            caption = Gtk.Label(label=label, xalign=0.0)
            caption.add_css_class("stat-label")
            tile.append(value)
            tile.append(caption)
            self._tiles.append(tile)
            self._tile_widgets[key] = (tile, value, caption)
        return self._tiles

    def _build_activity(self) -> Gtk.Widget:
        self._activity_group = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        heading = Gtk.Label(label="Activity over time", xalign=0.0)
        heading.add_css_class("section-heading")
        self._activity_group.append(heading)

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        card.add_css_class("card")
        card.set_margin_top(2)
        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        inner.set_margin_top(14)
        inner.set_margin_bottom(14)
        inner.set_margin_start(14)
        inner.set_margin_end(14)

        self._timeline = TimelineStrip()
        self._timeline.connect("bucket-activated", self._on_bucket)
        inner.append(self._timeline)

        self._activity_caption = Gtk.Label(xalign=0.0)
        self._activity_caption.add_css_class("activity-axis")
        self._activity_caption.set_wrap(True)
        inner.append(self._activity_caption)
        inner.append(timeline_module.legend())

        card.append(inner)
        self._activity_group.append(card)
        return self._activity_group

    def _build_problems(self) -> Gtk.Widget:
        self._problems_group = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        heading = Gtk.Label(label="Most frequent problems", xalign=0.0)
        heading.add_css_class("section-heading")
        heading.set_hexpand(True)
        header.append(heading)
        self._all_button = Gtk.Button(label="See all")
        self._all_button.add_css_class("flat")
        self._all_button.connect("clicked", lambda _b: self.emit("show-highlights"))
        header.append(self._all_button)
        self._problems_group.append(header)

        self._problem_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._problems_group.append(self._problem_box)
        return self._problems_group

    def _build_facts(self) -> Gtk.Widget:
        self._facts = Adw.PreferencesGroup(title="About this log")
        self._fact_rows: dict[str, Adw.ActionRow] = {}
        for key, title in (
            ("format", "Format"),
            ("entries", "Entries read"),
            ("size", "Size"),
            ("encoding", "Text encoding"),
            ("read", "Read"),
        ):
            row = Adw.ActionRow(title=title)
            row.set_subtitle_selectable(True)
            self._facts.add(row)
            self._fact_rows[key] = row

        self._path_row = Adw.ActionRow(title="Location")
        self._path_row.set_subtitle_selectable(True)
        copy_path = Gtk.Button(icon_name=resolve_icon("edit-copy-symbolic"))
        copy_path.add_css_class("flat")
        copy_path.set_valign(Gtk.Align.CENTER)
        copy_path.set_tooltip_text("Copy the location")
        copy_path.connect("clicked", self._copy_path)
        self._path_row.add_suffix(copy_path)
        self._facts.add(self._path_row)
        return self._facts

    # -- population -----------------------------------------------------
    def set_document(self, document: LogDocument | None) -> None:
        self._document = document
        if document is None:
            return

        self._set_verdict(document)
        self._set_tiles(document)

        if document.buckets.usable:
            self._activity_group.set_visible(True)
            self._timeline.set_buckets(document.buckets)
            caption = timeline_module.summary_caption(document.buckets)
            if not document.buckets.time_based:
                caption += " This log has no usable timestamps, so slices measure position in the file."
            self._activity_caption.set_text(caption)
        else:
            self._activity_group.set_visible(False)

        self._set_problems(document)
        self._set_facts(document)

    def _set_verdict(self, document: LogDocument) -> None:
        summary = document.summary
        if summary.errors and summary.warnings:
            title = f"{plural(summary.errors, 'error')} and {plural(summary.warnings, 'warning')}"
        elif summary.errors:
            title = plural(summary.errors, "error")
        elif summary.warnings:
            title = plural(summary.warnings, "warning")
        elif summary.total:
            title = "Nothing looks wrong here"
        else:
            title = "Nothing logged"
        self._verdict_title.set_text(title)

        parts: list[str] = []
        if summary.total:
            parts.append(f"{plural(summary.total, 'message')} read")
        if summary.has_timestamps and summary.last:
            parts.append(f"latest {relative_time(summary.last)}")
        if document.truncated:
            parts.append("showing the most recent part of a larger log")
        if summary.guessed:
            parts.append(f"{format_count(summary.guessed)} classified from the message text")
        self._verdict_subtitle.set_text(" · ".join(parts))

    def _set_tiles(self, document: LogDocument) -> None:
        summary = document.summary
        health = summary.health
        values = {
            "errors": (format_count(summary.errors), "Errors", "is-error" if summary.errors else None),
            "warnings": (format_count(summary.warnings), "Warnings", "is-warning" if summary.warnings else None),
            "total": (format_count(summary.total), "Messages", None),
            "span": (
                duration(summary.span) if summary.span else ("—" if not summary.has_timestamps else "Instant"),
                "Covers" if summary.has_timestamps else "No timestamps",
                None,
            ),
        }
        for key, (value, caption, css_class) in values.items():
            tile, value_label, caption_label = self._tile_widgets[key]
            value_label.set_text(value)
            caption_label.set_text(caption)
            for name in ("is-error", "is-warning", "is-clear"):
                tile.remove_css_class(name)
            if css_class:
                tile.add_css_class(css_class)
            elif key == "errors" and health == "clear":
                tile.add_css_class("is-clear")

    def _set_problems(self, document: LogDocument) -> None:
        child = self._problem_box.get_first_child()
        while child is not None:
            following = child.get_next_sibling()
            self._problem_box.remove(child)
            child = following

        ranked = rank_groups(document.groups, limit=5)
        if not ranked:
            self._problems_group.set_visible(False)
            return
        self._problems_group.set_visible(True)
        total = len(document.groups)
        self._all_button.set_label(
            "See all" if total <= len(ranked) else f"See all {format_count(total)}"
        )
        self._all_button.set_visible(total > len(ranked))
        for group in ranked:
            self._problem_box.append(build_card(group, self._copy_group, self._open_group))

    def _set_facts(self, document: LogDocument) -> None:
        summary = document.summary
        self._fact_rows["format"].set_subtitle(document.format_name or "Unrecognised")
        entries_text = plural(summary.total, "entry", "entries")
        if document.truncated:
            entries_text += " (most recent part only)"
        self._fact_rows["entries"].set_subtitle(entries_text)
        self._fact_rows["size"].set_subtitle(
            file_size(document.total_bytes) if document.total_bytes else "Streamed from the journal"
        )
        self._fact_rows["encoding"].set_subtitle(document.encoding or "Unknown")
        self._fact_rows["read"].set_subtitle(
            clock(document.loaded_at, with_date=True)
            + (" · with administrator access" if document.used_privilege else "")
        )
        self._path_row.set_subtitle(document.path or document.subtitle)
        self._path_row.set_visible(bool(document.path or document.subtitle))

    # -- callbacks ------------------------------------------------------
    def _on_bucket(self, _strip: TimelineStrip, position: int) -> None:
        self.emit("entry-activated", position)

    def _copy_group(self, group: ProblemGroup) -> None:
        display = Gdk.Display.get_default()
        if display is not None:
            display.get_clipboard().set(group.copy_text())
        self.emit("copied", "Entry copied")

    def _open_group(self, group: ProblemGroup) -> None:
        if group.positions:
            self.emit("entry-activated", group.positions[0])

    def _copy_path(self, _button: Gtk.Button) -> None:
        if self._document is None:
            return
        display = Gdk.Display.get_default()
        if display is not None:
            display.get_clipboard().set(self._document.path or self._document.subtitle)
        self.emit("copied", "Location copied")
