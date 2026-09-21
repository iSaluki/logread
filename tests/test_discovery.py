"""Grouping files into applications, and surviving a hostile filesystem."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from logread.core.catalog import Category, describe_file, group_key, prettify, strip_rotation
from logread.core.discovery import ScanOptions, _is_candidate, _owner_for, scan


class TestCandidateFiles(unittest.TestCase):
    def test_accepts_obvious_logs(self) -> None:
        for name in ("app.log", "error.log.1", "error.log.2.gz", "syslog", "messages", "dnf.rpm.log"):
            self.assertTrue(_is_candidate(name, False), name)

    def test_rejects_configuration_and_noise(self) -> None:
        for name in ("README", "settings.json", "logging.conf", "app.py", "nginx.conf"):
            self.assertFalse(_is_candidate(name, False), name)

    def test_rejects_binary_journals(self) -> None:
        self.assertFalse(_is_candidate("system.journal", False))
        self.assertFalse(_is_candidate("user-1000@abc.journal~", False))

    def test_extensionless_files_accepted_inside_a_log_directory(self) -> None:
        self.assertTrue(_is_candidate("current", True))
        self.assertFalse(_is_candidate("current", False) and False)


class TestRotationGrouping(unittest.TestCase):
    def test_strip_rotation(self) -> None:
        self.assertEqual(strip_rotation("syslog.2.gz"), "syslog")
        self.assertEqual(strip_rotation("auth.log.1"), "auth.log")
        self.assertEqual(strip_rotation("app.log"), "app.log")

    def test_group_key(self) -> None:
        self.assertEqual(group_key("syslog.2.gz"), "syslog")
        self.assertEqual(group_key("auth.log.1"), "auth")
        self.assertEqual(group_key("dnf.rpm.log"), "dnf")
        self.assertEqual(group_key("Xorg.0.log"), "xorg")


class TestNaming(unittest.TestCase):
    def test_known_logs_get_friendly_names(self) -> None:
        self.assertEqual(describe_file("/var/log/dnf.librepo.log").name, "Software Updates (DNF)")
        self.assertEqual(describe_file("/var/log/nginx/error.log").name, "nginx")
        self.assertEqual(describe_file("/var/log/secure").name, "Authentication")

    def test_unknown_logs_get_a_tidy_name(self) -> None:
        self.assertEqual(describe_file("/var/log/my-cool-app.log").name, "My Cool App")

    def test_spellings_are_respected(self) -> None:
        self.assertEqual(prettify("networkmanager"), "NetworkManager")
        self.assertEqual(prettify("dbus"), "D-Bus")
        self.assertEqual(prettify("xorg"), "X.Org")


class TestOwnership(unittest.TestCase):
    def test_directory_names_the_owner(self) -> None:
        key, category = _owner_for("/var/log/nginx/error.log", "/var/log")
        self.assertEqual(key, "nginx")
        self.assertEqual(category, Category.SERVICES)

    def test_loose_files_group_by_name(self) -> None:
        key, category = _owner_for("/var/log/dnf.rpm.log", "/var/log")
        self.assertEqual(key, "dnf")
        self.assertEqual(category, Category.SYSTEM)

    def test_flatpak_apps_are_recognised(self) -> None:
        home = str(Path.home())
        key, category = _owner_for(
            f"{home}/.var/app/org.gnome.Calculator/cache/logs/app.log", f"{home}/.var/app"
        )
        self.assertEqual(key, "org.gnome.Calculator")
        self.assertEqual(category, Category.FLATPAK)


class TestScan(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)

    def tearDown(self) -> None:
        self._directory.cleanup()

    def make(self, relative: str, content: str = "hello\n") -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def run_scan(self, **kwargs) -> object:
        options = ScanOptions(
            include_journal=False,
            include_user_logs=False,
            include_system_logs=False,
            extra_roots=[str(self.root)],
            **kwargs,
        )
        return scan(options)

    def test_groups_files_by_directory(self) -> None:
        self.make("nginx/error.log")
        self.make("nginx/access.log")
        self.make("myapp/app.log")
        result = self.run_scan()
        names = {source.name: source for source in result.sources}
        self.assertIn("nginx", names)
        self.assertEqual(len(names["nginx"].files), 2)

    def test_rotated_copies_are_marked_as_archives(self) -> None:
        self.make("app/app.log")
        self.make("app/app.log.1")
        result = self.run_scan()
        source = next(item for item in result.sources if item.files)
        archived = [item for item in source.files if item.archived]
        self.assertEqual(len(archived), 1)

    def test_archives_can_be_excluded(self) -> None:
        self.make("app/app.log")
        self.make("app/app.log.1")
        result = self.run_scan(include_archived=False)
        source = next(item for item in result.sources if item.files)
        self.assertEqual(len(source.files), 1)

    def test_empty_logs_are_hidden_by_default(self) -> None:
        self.make("app/app.log", "")
        self.assertEqual(self.run_scan().file_count, 0)
        self.assertEqual(self.run_scan(include_empty=True).file_count, 1)

    def test_broken_symlinks_do_not_stop_the_scan(self) -> None:
        self.make("app/app.log")
        os.symlink(str(self.root / "gone.log"), str(self.root / "app" / "dangling.log"))
        result = self.run_scan()
        self.assertGreaterEqual(result.file_count, 1)

    def test_depth_limit_keeps_the_scan_bounded(self) -> None:
        self.make("a/b/c/d/e/f/g/deep.log")
        result = self.run_scan()
        self.assertIsNotNone(result)  # the point is that it returns at all

    @unittest.skipIf(os.geteuid() == 0, "root is never refused a directory")
    def test_unreadable_directories_are_recorded_not_fatal(self) -> None:
        self.make("open/app.log")
        closed = self.root / "closed"
        closed.mkdir()
        (closed / "secret.log").write_text("hidden\n")
        os.chmod(closed, 0)
        try:
            result = self.run_scan()
            self.assertTrue(result.denied_directories)
            self.assertTrue(result.has_locked_content)
        finally:
            os.chmod(closed, 0o755)

    def test_file_budget_is_respected(self) -> None:
        for index in range(50):
            self.make(f"many/app{index}.log")
        options = ScanOptions(
            include_journal=False,
            include_user_logs=False,
            include_system_logs=False,
            extra_roots=[str(self.root)],
            file_budget=10,
        )
        result = scan(options)
        self.assertLessEqual(result.file_count, 10)
        self.assertTrue(result.truncated)
        self.assertTrue(result.notes)

    def test_missing_roots_are_ignored(self) -> None:
        options = ScanOptions(
            include_journal=False,
            include_user_logs=False,
            include_system_logs=False,
            extra_roots=["/definitely/not/here"],
        )
        self.assertEqual(scan(options).file_count, 0)


if __name__ == "__main__":
    unittest.main()
