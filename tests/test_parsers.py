"""Format coverage: every rule, plus the awkward cases in between."""

from __future__ import annotations

import unittest
from datetime import datetime

from logread.core.parsers import LogParser, parse_lines
from logread.core.severity import Severity


class TestFormatRules(unittest.TestCase):
    def parse_one(self, line: str):
        entries = parse_lines([line])
        self.assertEqual(len(entries), 1, line)
        return entries[0]

    def test_rfc5424(self) -> None:
        entry = self.parse_one(
            "<34>1 2003-10-11T22:14:15.003Z host su - ID47 - 'su root' failed for lonvick"
        )
        self.assertEqual(entry.severity, Severity.CRITICAL)
        self.assertEqual(entry.source, "su")
        self.assertIn("failed for lonvick", entry.message)

    def test_bsd_syslog(self) -> None:
        entry = self.parse_one("Oct 11 22:14:15 myhost sshd[1234]: Failed password for root")
        self.assertEqual(entry.source, "sshd")
        self.assertEqual(entry.pid, 1234)
        self.assertEqual(entry.severity, Severity.ERROR)
        self.assertTrue(entry.guessed)

    def test_iso_syslog(self) -> None:
        entry = self.parse_one(
            "2024-03-01T09:10:11.123456+00:00 host systemd[1]: Started Daily cleanup."
        )
        self.assertEqual(entry.source, "systemd")
        self.assertEqual(entry.pid, 1)
        self.assertIsNotNone(entry.timestamp)

    def test_nginx_error(self) -> None:
        entry = self.parse_one('2024/01/01 12:00:00 [error] 2318#0: *5 open() failed')
        self.assertEqual(entry.severity, Severity.ERROR)
        self.assertEqual(entry.source, "nginx")
        self.assertEqual(entry.pid, 2318)

    def test_apache_error(self) -> None:
        entry = self.parse_one(
            "[Wed Oct 11 14:32:52.123456 2000] [core:error] [pid 123] client denied by server"
        )
        self.assertEqual(entry.severity, Severity.ERROR)
        self.assertEqual(entry.pid, 123)

    def test_access_log_status_becomes_severity(self) -> None:
        error = self.parse_one(
            '10.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /a HTTP/1.0" 500 2326'
        )
        warning = self.parse_one(
            '10.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /a HTTP/1.0" 404 120'
        )
        fine = self.parse_one(
            '10.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /a HTTP/1.0" 200 120'
        )
        self.assertEqual(error.severity, Severity.ERROR)
        self.assertEqual(warning.severity, Severity.WARNING)
        self.assertEqual(fine.severity, Severity.INFO)

    def test_xorg_levels(self) -> None:
        self.assertEqual(self.parse_one("[    12.345] (EE) no screens found").severity, Severity.ERROR)
        self.assertEqual(self.parse_one("[    12.345] (WW) slow device").severity, Severity.WARNING)
        self.assertEqual(self.parse_one("[    12.345] (II) loading driver").severity, Severity.INFO)

    def test_kernel_priority(self) -> None:
        entry = self.parse_one("<3>[ 1234.567890] EXT4-fs error on sda1")
        self.assertEqual(entry.severity, Severity.ERROR)
        self.assertEqual(entry.source, "kernel")

    def test_json_line(self) -> None:
        entry = self.parse_one(
            '{"level":"error","ts":"2024-01-01T00:00:00Z","msg":"boom","logger":"api"}'
        )
        self.assertEqual(entry.severity, Severity.ERROR)
        self.assertEqual(entry.source, "api")
        self.assertEqual(entry.message, "boom")

    def test_json_numeric_levels_pick_the_right_scale(self) -> None:
        python_style = self.parse_one('{"level":40,"message":"db down"}')
        bunyan_style = self.parse_one('{"level":40,"msg":"db slow","hostname":"a","v":0}')
        self.assertEqual(python_style.severity, Severity.ERROR)
        self.assertEqual(bunyan_style.severity, Severity.WARNING)

    def test_logfmt(self) -> None:
        entry = self.parse_one('level=warn ts=2024-01-01T00:00:00Z msg="disk almost full"')
        self.assertEqual(entry.severity, Severity.WARNING)
        self.assertIn("disk almost full", entry.message)

    def test_logfmt_does_not_eat_prose(self) -> None:
        entry = self.parse_one("the value a=b was rejected by the server for being invalid")
        self.assertNotEqual(entry.message, "")

    def test_pacman(self) -> None:
        entry = self.parse_one("[2024-01-01T12:00:00+0000] [ALPM] upgraded bash (5.2-1 -> 5.2-2)")
        self.assertEqual(entry.source, "alpm")
        self.assertIsNotNone(entry.timestamp)

    def test_dnf_style(self) -> None:
        entry = self.parse_one("2024-01-01T12:00:00+0000 INFO Loaded plugins: builddep")
        self.assertEqual(entry.severity, Severity.INFO)

    def test_python_logging(self) -> None:
        entry = self.parse_one("2024-01-01 12:00:00,123 - myapp.db - ERROR - connection lost")
        self.assertEqual(entry.severity, Severity.ERROR)
        self.assertEqual(entry.source, "myapp.db")
        self.assertEqual(entry.message, "connection lost")

    def test_bracketed_level(self) -> None:
        self.assertEqual(self.parse_one("[ERROR] something went wrong").severity, Severity.ERROR)
        self.assertEqual(self.parse_one("WARNING: disk is nearly full").severity, Severity.WARNING)

    def test_unknown_lines_are_kept(self) -> None:
        entries = parse_lines(["gibberish one", "gibberish two"])
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].raw, "gibberish one")

    def test_blank_lines_do_not_create_entries(self) -> None:
        self.assertEqual(len(parse_lines(["a line", "", "   ", "another"])), 2)


class TestContinuations(unittest.TestCase):
    def test_python_traceback_stays_with_its_error(self) -> None:
        entries = parse_lines(
            [
                "2024-01-01 12:00:00,123 - app - ERROR - sync failed",
                "Traceback (most recent call last):",
                '  File "/app/sync.py", line 88, in push',
                "    resp = session.post(url)",
                "ConnectionResetError: [Errno 104] Connection reset by peer",
                "2024-01-01 12:00:01,000 - app - INFO - carrying on",
            ]
        )
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].line_count, 5)
        self.assertIn("ConnectionResetError", entries[0].full_raw)

    def test_java_stack_trace(self) -> None:
        entries = parse_lines(
            [
                "2024-01-01 12:00:00,000 - app - ERROR - request failed",
                "\tat com.example.Foo.bar(Foo.java:42)",
                "Caused by: java.io.IOException: disk gone",
                "\t... 3 more",
                "2024-01-01 12:00:01,000 - app - INFO - done",
            ]
        )
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].line_count, 4)

    def test_exception_line_alone_is_its_own_entry(self) -> None:
        # Without a traceback above it, a bare exception name is a real entry.
        entries = parse_lines(["ValueError: bad input", "next line"])
        self.assertEqual(len(entries), 2)


class TestFormatDetection(unittest.TestCase):
    def test_dominant_format_is_reported(self) -> None:
        lines = [
            f"2024/01/01 12:00:{second:02d} [error] 1#0: *{second} open() failed"
            for second in range(40)
        ]
        parser = LogParser()
        list(parser.parse(lines))
        self.assertEqual(parser.format_name, "nginx error log")

    def test_year_hint_is_used_for_syslog(self) -> None:
        entries = parse_lines(["Jan  2 03:04:05 host app: hello"], year_hint=2019)
        self.assertEqual(entries[0].timestamp, datetime(2019, 1, 2, 3, 4, 5))


if __name__ == "__main__":
    unittest.main()
