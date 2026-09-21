"""The escalation path must never widen beyond log directories."""

from __future__ import annotations

import unittest

from logread.core import privileged


class TestTargetChecks(unittest.TestCase):
    def test_log_directories_are_allowed(self) -> None:
        for path in ("/var/log/messages", "/var/log/nginx/error.log", "/run/log/journal/x"):
            self.assertTrue(privileged.is_elevation_root(path), path)

    def test_everything_else_is_refused(self) -> None:
        for path in ("/etc/shadow", "/root/.ssh/id_rsa", "/home/someone/notes.txt", "/proc/1/mem"):
            self.assertFalse(privileged.is_elevation_root(path), path)

    def test_check_target_rejects_relative_paths(self) -> None:
        with self.assertRaises(privileged.PrivilegeError):
            privileged._check_target("var/log/messages")

    def test_check_target_rejects_outside_paths(self) -> None:
        with self.assertRaises(privileged.PrivilegeError):
            privileged._check_target("/etc/shadow")

    def test_check_target_rejects_nul_bytes(self) -> None:
        with self.assertRaises(privileged.PrivilegeError):
            privileged._check_target("/var/log/a\0b")

    def test_traversal_cannot_escape(self) -> None:
        with self.assertRaises(privileged.PrivilegeError):
            privileged._check_target("/var/log/../../etc/shadow")

    def test_only_known_binaries_resolve(self) -> None:
        self.assertIsNone(privileged._which("rm"))
        self.assertIsNone(privileged._which("sh"))


class TestAvailability(unittest.TestCase):
    def test_reason_is_a_sentence_or_none(self) -> None:
        reason = privileged.unavailable_reason()
        self.assertTrue(reason is None or reason.endswith("."))


if __name__ == "__main__":
    unittest.main()
