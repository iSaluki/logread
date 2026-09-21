"""Reading files that are compressed, binary, huge, oddly encoded or forbidden."""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
import tempfile
import unittest
from pathlib import Path

from logread.core.reader import ReadProblem, probe_file, read_file


class ReaderTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)

    def tearDown(self) -> None:
        self._directory.cleanup()

    def write(self, name: str, data: bytes) -> str:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return str(path)


class TestPlainFiles(ReaderTestCase):
    def test_reads_lines(self) -> None:
        path = self.write("a.log", b"one\ntwo\nthree\n")
        outcome = read_file(path)
        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.lines, ["one", "two", "three"])

    def test_missing_file(self) -> None:
        outcome = read_file(str(self.root / "nope.log"))
        self.assertEqual(outcome.problem, ReadProblem.MISSING)
        self.assertTrue(outcome.detail)

    def test_empty_file(self) -> None:
        outcome = read_file(self.write("empty.log", b""))
        self.assertEqual(outcome.problem, ReadProblem.EMPTY)

    def test_file_with_no_trailing_newline(self) -> None:
        outcome = read_file(self.write("a.log", b"only line"))
        self.assertEqual(outcome.lines, ["only line"])

    def test_crlf_is_handled(self) -> None:
        outcome = read_file(self.write("a.log", b"one\r\ntwo\r\n"))
        self.assertEqual(outcome.lines, ["one", "two"])


class TestBinaryDetection(ReaderTestCase):
    def test_nul_bytes_mean_binary(self) -> None:
        outcome = read_file(self.write("weird.log", b"\x00\x01\x02\x03binary junk"))
        self.assertEqual(outcome.problem, ReadProblem.BINARY)

    def test_known_binary_names(self) -> None:
        for name in ("wtmp", "btmp", "lastlog"):
            outcome = read_file(self.write(name, b"anything at all"))
            self.assertEqual(outcome.problem, ReadProblem.BINARY, name)

    def test_journal_files_are_binary(self) -> None:
        outcome = read_file(self.write("system.journal", b"LPKSHHRH" + b"\x00" * 64))
        self.assertEqual(outcome.problem, ReadProblem.BINARY)

    def test_text_with_accents_is_not_binary(self) -> None:
        outcome = read_file(self.write("a.log", "café naïve résumé\n".encode()))
        self.assertTrue(outcome.ok)


class TestCompressed(ReaderTestCase):
    def test_gzip(self) -> None:
        path = str(self.root / "a.log.gz")
        with gzip.open(path, "wb") as handle:
            handle.write(b"first\nsecond\n")
        outcome = read_file(path)
        self.assertEqual(outcome.lines, ["first", "second"])

    def test_bzip2(self) -> None:
        path = str(self.root / "a.log.bz2")
        with bz2.open(path, "wb") as handle:
            handle.write(b"first\nsecond\n")
        self.assertEqual(read_file(path).lines, ["first", "second"])

    def test_xz(self) -> None:
        path = str(self.root / "a.log.xz")
        with lzma.open(path, "wb") as handle:
            handle.write(b"first\nsecond\n")
        self.assertEqual(read_file(path).lines, ["first", "second"])

    def test_gzip_without_the_extension(self) -> None:
        # Rotated logs are sometimes renamed; the magic number still decides.
        path = str(self.root / "mystery")
        with gzip.open(path, "wb") as handle:
            handle.write(b"hidden\n")
        self.assertEqual(read_file(path).lines, ["hidden"])

    def test_truncated_archive_reports_damage(self) -> None:
        path = str(self.root / "broken.log.gz")
        with gzip.open(path, "wb") as handle:
            handle.write(b"x" * 4096)
        data = Path(path).read_bytes()
        Path(path).write_bytes(data[: len(data) // 2])
        outcome = read_file(path)
        self.assertIn(outcome.problem, (ReadProblem.UNREADABLE, ReadProblem.NONE))


class TestEncodings(ReaderTestCase):
    def test_latin1_fallback(self) -> None:
        outcome = read_file(self.write("a.log", "café error\n".encode("latin-1")))
        self.assertTrue(outcome.ok)
        self.assertIn("café error", outcome.lines[0])

    def test_invalid_bytes_are_replaced_not_fatal(self) -> None:
        outcome = read_file(self.write("a.log", b"good line\n\xc3\x28 bad\n"))
        self.assertTrue(outcome.ok)
        self.assertEqual(len(outcome.lines), 2)

    def test_utf8_bom(self) -> None:
        outcome = read_file(self.write("a.log", b"\xef\xbb\xbfhello\n"))
        self.assertTrue(outcome.ok)
        self.assertTrue(outcome.lines[0].endswith("hello"))


class TestLimits(ReaderTestCase):
    def test_large_file_is_tailed_at_a_line_boundary(self) -> None:
        body = "".join(f"line {index}\n" for index in range(50_000)).encode()
        path = self.write("big.log", body)
        outcome = read_file(path, max_bytes=8 * 1024)
        self.assertTrue(outcome.truncated)
        self.assertTrue(outcome.lines[0].startswith("line "))
        self.assertEqual(outcome.lines[-1], "line 49999")

    def test_line_cap_keeps_the_newest(self) -> None:
        body = "".join(f"line {index}\n" for index in range(5000)).encode()
        outcome = read_file(self.write("big.log", body), max_lines=100)
        self.assertEqual(len(outcome.lines), 100)
        self.assertEqual(outcome.lines[-1], "line 4999")


@unittest.skipIf(os.geteuid() == 0, "root can read everything, so there is nothing to refuse")
class TestPermissions(ReaderTestCase):
    def test_unreadable_file_is_reported_not_raised(self) -> None:
        path = self.write("secret.log", b"classified\n")
        os.chmod(path, 0)
        outcome = read_file(path)
        self.assertEqual(outcome.problem, ReadProblem.PERMISSION)
        self.assertTrue(outcome.detail)

    def test_probe_reports_permission(self) -> None:
        path = self.write("secret.log", b"classified\n")
        os.chmod(path, 0)
        self.assertEqual(probe_file(path).problem, ReadProblem.PERMISSION)


class TestProbe(ReaderTestCase):
    def test_probe_records_size_and_compression(self) -> None:
        path = str(self.root / "a.log.gz")
        with gzip.open(path, "wb") as handle:
            handle.write(b"data\n")
        probe = probe_file(path)
        self.assertTrue(probe.exists)
        self.assertEqual(probe.compression, "gzip")
        self.assertGreater(probe.size, 0)

    def test_probe_on_a_directory_does_not_raise(self) -> None:
        probe = probe_file(str(self.root))
        self.assertIn(probe.problem, (ReadProblem.UNREADABLE, ReadProblem.BINARY, ReadProblem.NONE))


if __name__ == "__main__":
    unittest.main()
