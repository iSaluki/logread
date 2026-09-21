"""The activity strip.

One column per slice of the log, stacked by severity. It answers "when did this
start going wrong" before a single line has been read, and clicking a column
jumps the raw view to that moment.

It is built from real widgets rather than a drawing area so it picks up the
system accent and dark-mode colours from CSS, gets keyboard focus for free, and
reads correctly to a screen reader.
"""

from __future__ import annotations

from gi.repository import GObject, Gtk

from ..core.analysis import TimeBucket, TimeBuckets
from .format import count as format_count

__all__ = ["TimelineStrip"]

_PROBLEM_HEIGHT = 52
_VOLUME_HEIGHT = 16
_MIN_SEGMENT = 3
_PROBLEM_SCALE_FLOOR = 6


class TimelineStrip(Gtk.Box):
    """A horizontal severity histogram over the whole log.

    Two strips share one x axis. The tall one charts errors and warnings only,
    scaled against the worst slice, so a burst of failures is unmissable even
    when it is 40 entries out of 40,000. The short one underneath charts total
    message volume, so a quiet period is not mistaken for a healthy one.
    """

    __gtype_name__ = "LogReadTimelineStrip"

    __gsignals__ = {
        # Emitted with the entry index the clicked slice starts at.
        "bucket-activated": (GObject.SignalFlags.RUN_FIRST, None, (int,)),
    }

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.add_css_class("activity-strip")
        self._buckets: TimeBuckets | None = None
        self._selected: int | None = None
        self._columns: list[Gtk.Button] = []

        self._bars = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, homogeneous=True)
        self._bars.set_size_request(-1, _PROBLEM_HEIGHT + _VOLUME_HEIGHT + 10)

        # Fifty-odd columns are each a button, and a button carries a minimum
        # width. The stylesheet trims that to a couple of pixels, but the
        # window must stay resizable even if the stylesheet is ever missing,
        # so the strip sits in a viewport that is allowed to be narrower than
        # its contents rather than forcing the whole window wider.
        viewport = Gtk.ScrolledWindow()
        viewport.set_policy(Gtk.PolicyType.EXTERNAL, Gtk.PolicyType.NEVER)
        viewport.set_propagate_natural_width(True)
        viewport.set_propagate_natural_height(True)
        viewport.set_child(self._bars)
        self.append(viewport)

        self._axis = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self._start_label = Gtk.Label(xalign=0.0)
        self._start_label.add_css_class("activity-axis")
        self._end_label = Gtk.Label(xalign=1.0)
        self._end_label.add_css_class("activity-axis")
        self._start_label.set_hexpand(True)
        self._end_label.set_hexpand(True)
        self._axis.append(self._start_label)
        self._axis.append(self._end_label)
        self.append(self._axis)

    # -- public ---------------------------------------------------------
    def set_buckets(self, buckets: TimeBuckets) -> None:
        self._buckets = buckets
        self._selected = None
        self._rebuild()

    def clear(self) -> None:
        self.set_buckets(TimeBuckets())

    def select_bucket(self, index: int | None) -> None:
        self._selected = index
        for position, column in enumerate(self._columns):
            if position == index:
                column.add_css_class("is-selected")
            else:
                column.remove_css_class("is-selected")

    # -- internals ------------------------------------------------------
    def _clear_bars(self) -> None:
        child = self._bars.get_first_child()
        while child is not None:
            following = child.get_next_sibling()
            self._bars.remove(child)
            child = following
        self._columns.clear()

    def _rebuild(self) -> None:
        self._clear_bars()
        buckets = self._buckets
        if buckets is None or not buckets.buckets:
            self._start_label.set_text("")
            self._end_label.set_text("")
            return

        volume_peak = max(buckets.peak, 1)
        # A log with one stray warning per slice should not draw a full-height
        # wall of bars, so the problem scale never starts below a small floor.
        problem_peak = max(buckets.peak_problems, _PROBLEM_SCALE_FLOOR)
        for bucket in buckets.buckets:
            column = self._make_column(bucket, problem_peak, volume_peak, buckets.time_based)
            self._columns.append(column)
            self._bars.append(column)

        first, last = buckets.buckets[0], buckets.buckets[-1]
        if buckets.time_based and first.start and last.end:
            same_day = first.start.date() == last.end.date()
            fmt = "%H:%M" if same_day else "%-d %b, %H:%M"
            self._start_label.set_text(first.start.strftime(fmt))
            self._end_label.set_text(last.end.strftime(fmt))
        else:
            self._start_label.set_text("Start of log")
            self._end_label.set_text("End of log")

    def _make_column(
        self, bucket: TimeBucket, problem_peak: int, volume_peak: int, time_based: bool
    ) -> Gtk.Button:
        column = Gtk.Button()
        column.add_css_class("activity-bucket")
        column.set_has_frame(False)
        column.set_valign(Gtk.Align.FILL)
        column.set_vexpand(True)

        layout = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        layout.set_vexpand(True)

        problem_frame, problems = _slot(_PROBLEM_HEIGHT)
        if bucket.errors:
            problems.append(_segment("seg-error", _scaled(bucket.errors, problem_peak, _PROBLEM_HEIGHT)))
        if bucket.warnings:
            problems.append(
                _segment("seg-warning", _scaled(bucket.warnings, problem_peak, _PROBLEM_HEIGHT))
            )
        if not bucket.problems:
            problems.append(_segment("seg-empty", 2))
        layout.append(problem_frame)

        volume_frame, volume = _slot(_VOLUME_HEIGHT)
        height = _scaled(bucket.total, volume_peak, _VOLUME_HEIGHT) if bucket.total else 2
        volume.append(_segment("seg-other" if bucket.total else "seg-empty", height))
        layout.append(volume_frame)

        column.set_child(layout)
        description = bucket.describe(time_based=time_based)
        column.set_tooltip_text(description)
        column.update_property([Gtk.AccessibleProperty.LABEL], [description])
        column.connect("clicked", self._on_clicked, bucket)
        return column

    def _on_clicked(self, _button: Gtk.Button, bucket: TimeBucket) -> None:
        self.select_bucket(bucket.index)
        self.emit("bucket-activated", bucket.first_entry)


def _slot(height: int) -> tuple[Gtk.Box, Gtk.Box]:
    """A fixed-height area whose bars grow upward from its baseline.

    Both boxes are returned: the frame to place, and the stack to fill. The
    frame has to stay referenced by the caller until it is parented, or its
    floating reference is dropped and the stack loses its parent.
    """
    frame = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    frame.set_size_request(-1, height)
    stack = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
    stack.set_valign(Gtk.Align.END)
    stack.set_vexpand(True)
    frame.append(stack)
    return frame, stack


def _scaled(value: int, peak: int, available: int) -> int:
    """Height for `value`, never so small that a real count disappears."""
    if value <= 0:
        return 0
    return max(_MIN_SEGMENT, min(available, round(value / peak * available)))


def _segment(css_class: str, height: int) -> Gtk.Widget:
    segment = Gtk.Box()
    segment.add_css_class("activity-segment")
    segment.add_css_class(css_class)
    segment.set_size_request(-1, height)
    return segment


def legend() -> Gtk.Widget:
    """Key for the strip: which colour is which severity."""
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
    row.set_halign(Gtk.Align.START)
    for css_class, label in (
        ("seg-error", "Errors"),
        ("seg-warning", "Warnings"),
        ("seg-other", "Messages in total"),
    ):
        item = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        swatch = Gtk.Box()
        swatch.add_css_class("legend-swatch")
        swatch.add_css_class(css_class)
        swatch.set_valign(Gtk.Align.CENTER)
        item.append(swatch)
        caption = Gtk.Label(label=label)
        caption.add_css_class("activity-axis")
        item.append(caption)
        row.append(item)
    return row


def summary_caption(buckets: TimeBuckets) -> str:
    """One line under the strip saying where the trouble is concentrated."""
    if not buckets.buckets:
        return ""
    busiest = buckets.busiest
    if busiest is None:
        return "No errors or warnings in any part of this log."
    slice_label = busiest.label(time_based=buckets.time_based)
    problems = format_count(busiest.problems)
    noun = "problem" if busiest.problems == 1 else "problems"
    return f"Busiest slice: {slice_label} with {problems} {noun}."
