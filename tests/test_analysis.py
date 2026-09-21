"""Summaries, the activity strip, and problem grouping."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta

from logread.core.analysis import bucket_entries, problem_groups, rank_groups, summarise
from logread.core.entry import LogEntry, signature_of
from logread.core.severity import Severity


def entry(message: str, severity: Severity, when: datetime | None = None) -> LogEntry:
    return LogEntry(raw=message, message=message, severity=severity, timestamp=when)


class TestSummary(unittest.TestCase):
    def test_counts_and_span(self) -> None:
        base = datetime(2024, 1, 1, 12, 0, 0)
        entries = [
            entry("a", Severity.ERROR, base),
            entry("b", Severity.WARNING, base + timedelta(minutes=30)),
            entry("c", Severity.INFO, base + timedelta(hours=2)),
            entry("d", Severity.CRITICAL, base + timedelta(hours=1)),
        ]
        summary = summarise(entries)
        self.assertEqual(summary.total, 4)
        self.assertEqual(summary.errors, 2)  # ERROR and CRITICAL
        self.assertEqual(summary.warnings, 1)
        self.assertEqual(summary.span, timedelta(hours=2))
        self.assertEqual(summary.health, "error")

    def test_health_without_errors(self) -> None:
        self.assertEqual(summarise([entry("a", Severity.WARNING)]).health, "warning")
        self.assertEqual(summarise([entry("a", Severity.INFO)]).health, "clear")

    def test_empty_log(self) -> None:
        summary = summarise([])
        self.assertEqual(summary.total, 0)
        self.assertIsNone(summary.span)
        self.assertFalse(summary.has_timestamps)


class TestBuckets(unittest.TestCase):
    def test_time_based_bucketing(self) -> None:
        base = datetime(2024, 1, 1, 0, 0, 0)
        entries = [
            entry(f"m{index}", Severity.ERROR if index >= 90 else Severity.INFO,
                  base + timedelta(minutes=index))
            for index in range(100)
        ]
        buckets = bucket_entries(entries, 10)
        self.assertTrue(buckets.time_based)
        self.assertEqual(len(buckets.buckets), 10)
        self.assertEqual(sum(item.total for item in buckets.buckets), 100)
        busiest = buckets.busiest
        self.assertIsNotNone(busiest)
        self.assertEqual(busiest.index, 9)

    def test_falls_back_to_position_without_timestamps(self) -> None:
        entries = [entry(f"m{index}", Severity.INFO) for index in range(50)]
        buckets = bucket_entries(entries, 10)
        self.assertFalse(buckets.time_based)
        self.assertEqual(sum(item.total for item in buckets.buckets), 50)

    def test_all_entries_at_one_instant(self) -> None:
        when = datetime(2024, 1, 1)
        buckets = bucket_entries([entry("a", Severity.INFO, when) for _ in range(5)], 10)
        self.assertEqual(sum(item.total for item in buckets.buckets), 5)

    def test_empty_input(self) -> None:
        self.assertFalse(bucket_entries([], 10).usable)

    def test_bucket_describes_itself(self) -> None:
        base = datetime(2024, 1, 1)
        entries = [entry("a", Severity.ERROR, base + timedelta(minutes=index)) for index in range(20)]
        buckets = bucket_entries(entries, 4)
        text = buckets.buckets[0].describe(time_based=True)
        self.assertIn("error", text)


class TestProblemGroups(unittest.TestCase):
    def test_repeats_collapse_with_a_count(self) -> None:
        entries = [entry(f"disk {index} failed to mount", Severity.ERROR) for index in range(40)]
        groups = problem_groups(entries)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].count, 40)
        self.assertTrue(groups[0].is_repeat)

    def test_different_severities_stay_apart(self) -> None:
        entries = [entry("same text", Severity.ERROR), entry("same text", Severity.WARNING)]
        self.assertEqual(len(problem_groups(entries)), 2)

    def test_info_is_excluded_by_default(self) -> None:
        entries = [entry("fine", Severity.INFO), entry("bad", Severity.ERROR)]
        self.assertEqual(len(problem_groups(entries)), 1)

    def test_debug_can_be_included(self) -> None:
        entries = [entry("noisy", Severity.DEBUG), entry("bad", Severity.ERROR)]
        self.assertEqual(len(problem_groups(entries, include_debug=True)), 2)

    def test_ranking_puts_errors_first(self) -> None:
        entries = [entry("warn me", Severity.WARNING)] * 100 + [entry("break", Severity.ERROR)]
        ranked = rank_groups(problem_groups(entries), limit=2)
        self.assertEqual(ranked[0].severity, Severity.ERROR)

    def test_copy_text_mentions_repeats(self) -> None:
        groups = problem_groups([entry("boom", Severity.ERROR) for _ in range(3)])
        self.assertIn("repeated 3 times", groups[0].copy_text())

    def test_positions_allow_jumping_to_the_line(self) -> None:
        entries = [entry("ok", Severity.INFO), entry("bad", Severity.ERROR)]
        self.assertEqual(problem_groups(entries)[0].positions, [1])


class TestSignatures(unittest.TestCase):
    def test_volatile_parts_are_normalised(self) -> None:
        self.assertEqual(
            signature_of("connection to 10.0.0.1:8080 failed after 32ms"),
            signature_of("connection to 192.168.4.7:9090 failed after 7ms"),
        )

    def test_paths_and_uuids_collapse(self) -> None:
        self.assertEqual(
            signature_of("could not open /var/lib/a/b.sock"),
            signature_of("could not open /run/user/1000/x.sock"),
        )

    def test_genuinely_different_messages_stay_apart(self) -> None:
        self.assertNotEqual(signature_of("disk is full"), signature_of("network is down"))


if __name__ == "__main__":
    unittest.main()
