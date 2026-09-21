#!/usr/bin/env python3
"""Build the whole window headlessly and walk through it.

The unit tests cover the core, which has no GTK in it. This covers the part
they cannot: that every widget actually constructs, realises and draws. GTK
reports that kind of mistake as a runtime warning rather than an exception, so
this script turns warnings into failures and drives the real window.

Run it under a display: ``xvfb-run -a python3 tests/smoke_window.py``.
"""

from __future__ import annotations

import gzip
import os
import sys
import tempfile
import traceback
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from logread.app import install_styles  # noqa: E402
from logread.config import Settings  # noqa: E402
from logread.core.discovery import ScanOptions, scan  # noqa: E402
from logread.core.document import load_file  # noqa: E402
from logread.ui.window import LogReadWindow  # noqa: E402

FAILURES: list[str] = []
FATAL_LEVELS = GLib.LogLevelFlags.LEVEL_CRITICAL | GLib.LogLevelFlags.LEVEL_WARNING

# Warnings GTK emits for reasons outside this application's control.
_IGNORED = (
    "accessibility bus",
    "GTK_A11Y",
    "Unable to acquire",
    "not able to create and bind an EGL",
    "Failed to create EGL",
    "No GL implementation",
    "gl_area",
)


def _log_handler(domain: str | None, level, message: str, _data) -> None:
    text = message or ""
    if any(fragment in text for fragment in _IGNORED):
        return
    FAILURES.append(f"{domain or 'GLib'}: {text}")


def make_fixtures(root: Path) -> None:
    """A spread of formats, severities, sizes and awkward cases."""
    now = datetime.now()

    nginx = root / "nginx"
    nginx.mkdir(parents=True)
    with (nginx / "error.log").open("w") as handle:
        for index in range(400):
            stamp = (now - timedelta(minutes=400 - index)).strftime("%Y/%m/%d %H:%M:%S")
            if index % 23 == 0:
                handle.write(f"{stamp} [error] 1#0: *{index} open() failed (2: No such file)\n")
            elif index % 11 == 0:
                handle.write(f"{stamp} [warn] 1#0: *{index} upstream temporarily disabled\n")
            else:
                handle.write(f"{stamp} [notice] 1#0: signal process started\n")
    with gzip.open(nginx / "error.log.1.gz", "wb") as handle:
        handle.write(b"2024/01/01 00:00:00 [error] 1#0: *1 connect() failed\n")

    app = root / "coolnotes"
    app.mkdir(parents=True)
    with (app / "coolnotes.log").open("w") as handle:
        for index in range(200):
            stamp = (now - timedelta(seconds=(200 - index) * 30)).strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
            if index % 37 == 0:
                handle.write(f"{stamp} - coolnotes.sync - ERROR - Failed to sync notebook\n")
                handle.write("Traceback (most recent call last):\n")
                handle.write('  File "/app/sync.py", line 88, in push\n')
                handle.write("ConnectionResetError: [Errno 104] Connection reset by peer\n")
            else:
                handle.write(f"{stamp} - coolnotes.ui - INFO - Rendered note {index}\n")

    plain = root / "mystery"
    plain.mkdir(parents=True)
    # No timestamps and no levels: the position-based activity strip path.
    (plain / "mystery.log").write_text("".join(f"something happened {n}\n" for n in range(120)))
    # A log with nothing wrong in it: the "nothing to flag" empty state.
    (plain / "quiet.log").write_text("2024-01-01T00:00:00Z INFO all is well\n" * 40)
    # Binary records, which must be named rather than shown.
    (plain / "wtmp").write_bytes(b"\x00\x01\x02\x03" * 64)


def main() -> int:
    for level in (
        GLib.LogLevelFlags.LEVEL_CRITICAL,
        GLib.LogLevelFlags.LEVEL_WARNING,
        GLib.LogLevelFlags.LEVEL_ERROR,
    ):
        GLib.log_set_handler(None, level, _log_handler, None)
    for domain in ("Gtk", "Adwaita", "Gdk", "GLib", "GLib-GObject", "Pango"):
        GLib.log_set_handler(domain, FATAL_LEVELS, _log_handler, None)

    workspace = tempfile.TemporaryDirectory()
    root = Path(workspace.name)
    make_fixtures(root)

    # Keep the run away from the real machine's logs and the user's settings.
    os.environ["XDG_CONFIG_HOME"] = str(root / "config")

    application = Adw.Application(application_id="io.github.isaluki.LogRead.Smoke")
    state: dict[str, object] = {"code": 0}

    def fail(what: str) -> None:
        FAILURES.append(f"{what}\n{traceback.format_exc()}")
        state["code"] = 1

    def on_activate(app: Adw.Application) -> None:
        try:
            if not install_styles():
                FAILURES.append("the stylesheet could not be loaded")
                state["code"] = 1

            settings = Settings()
            settings.scan_system_logs = False
            settings.scan_user_logs = False
            settings.use_journal = False
            settings.extra_locations = [str(root)]

            window = LogReadWindow(app, settings)
            window.set_default_size(1200, 800)
            window.present()
        except Exception:
            fail("building the window")
            app.quit()
            return

        options = ScanOptions(
            include_journal=False,
            include_user_logs=False,
            include_system_logs=False,
            extra_roots=[str(root)],
            include_empty=True,
        )
        result = scan(options)
        if not result.sources:
            FAILURES.append("the scan found none of the fixture logs")
            state["code"] = 1

        documents = [
            load_file(str(root / "nginx" / "error.log")),
            load_file(str(root / "nginx" / "error.log.1.gz")),
            load_file(str(root / "coolnotes" / "coolnotes.log")),
            load_file(str(root / "mystery" / "mystery.log")),
            load_file(str(root / "mystery" / "quiet.log")),
            load_file(str(root / "mystery" / "wtmp")),
            load_file(str(root / "does-not-exist.log")),
        ]

        steps: list = []

        def show(document):
            def step() -> None:
                window._log_page.set_document(document)
            return step

        def view(name: str):
            def step() -> None:
                window._log_page.show_view(name)
            return step

        for document in documents:
            steps.append(show(document))
            for name in ("overview", "highlights", "raw"):
                steps.append(view(name))

        steps.append(lambda: window._sidebar.set_result(result))
        steps.append(lambda: window._sidebar.open_source(result.sources[0]))
        steps.append(lambda: window._sidebar.focus_search())
        steps.append(lambda: window._log_page.set_narrow(True))
        steps.append(lambda: window._log_page.set_narrow(False))
        steps.append(lambda: window._log_page.set_wrap(False))
        steps.append(lambda: window._log_page.set_wrap(True))
        steps.append(lambda: window._log_page.show_placeholder())

        def check_minimum_width() -> None:
            minimum = window.measure(Gtk.Orientation.HORIZONTAL, -1)[0]
            if minimum > 400:
                FAILURES.append(
                    f"the window cannot be narrower than {minimum} px, "
                    "so it will not adapt to small screens"
                )
                state["code"] = 1

        steps.append(check_minimum_width)

        queue = iter(steps)

        def pump() -> bool:
            try:
                step = next(queue)
            except StopIteration:
                app.quit()
                return GLib.SOURCE_REMOVE
            try:
                step()
            except Exception:
                fail("driving the window")
                app.quit()
                return GLib.SOURCE_REMOVE
            return GLib.SOURCE_CONTINUE

        GLib.timeout_add(60, pump)
        # Never let a stuck run hold up a build.
        GLib.timeout_add_seconds(120, lambda: (app.quit(), GLib.SOURCE_REMOVE)[1])

    application.connect("activate", on_activate)
    application.run([])
    workspace.cleanup()

    if FAILURES:
        counted: dict[str, int] = {}
        for failure in FAILURES:
            counted[failure] = counted.get(failure, 0) + 1
        print("Smoke test found problems:", file=sys.stderr)
        for failure, times in counted.items():
            suffix = f"  (x{times})" if times > 1 else ""
            print(f"  - {failure}{suffix}", file=sys.stderr)
        return 1
    if state["code"]:
        return 1
    print("Window built, every view rendered, no GTK warnings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
