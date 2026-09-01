from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "archive-package-snapshot.py"
SPEC = importlib.util.spec_from_file_location("archive_package_snapshot", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
archive = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(archive)


def _canonical_checksum(header: bytearray) -> None:
    block = bytearray(header[:512])
    block[148:156] = b"        "
    block[148:156] = f"{sum(block):06o}".encode() + b"\0 "
    header[:512] = block


def _raw_archive(members: list[tuple[str, str, bytes]]) -> bytes:
    result = bytearray()
    for name, kind, payload in members:
        size = len(payload) if kind == "file" else 0
        result.extend(archive._header(name, kind, size))
        result.extend(payload if kind == "file" else b"")
        result.extend(b"\0" * ((-size) % archive.BLOCK_SIZE))
    result.extend(b"\0" * (2 * archive.BLOCK_SIZE))
    return bytes(result)


class ArchivePackageSnapshotTest(unittest.TestCase):
    def _site(self, temporary: str) -> Path:
        site = Path(temporary) / "site"
        (site / "apt" / "dists").mkdir(parents=True)
        (site / "rpm").mkdir()
        (site / "apt" / "dists" / "Release").write_bytes(b"release\n")
        (site / "rpm" / "repomd.xml").write_bytes(b"<repomd/>\n")
        (site / "index.html").write_bytes(b"ready\n")
        return site

    def _write_archive(self, temporary: str, data: bytes, name: str = "snapshot.tar") -> Path:
        path = Path(temporary) / name
        path.write_bytes(data)
        return path

    def _assert_rejected(self, data: bytes, pattern: str) -> None:
        with TemporaryDirectory() as temporary:
            path = self._write_archive(temporary, data)
            with self.assertRaisesRegex(archive.ArchiveError, pattern):
                archive.inspect_snapshot(archive_path=path)

    def test_create_is_deterministic_canonical_ustar_and_extracts_safely(self) -> None:
        with TemporaryDirectory() as temporary:
            site = self._site(temporary)
            first = Path(temporary) / "first.tar"
            second = Path(temporary) / "second.tar"
            os.chmod(site / "index.html", 0o777)
            os.utime(site / "index.html", (2_000_000_000, 2_000_000_000))
            first_receipt = archive.create_snapshot(
                source_dir=site, archive_path=first
            )
            os.chmod(site / "index.html", 0o600)
            os.utime(site / "index.html", (1_000_000_000, 1_000_000_000))
            second_receipt = archive.create_snapshot(
                source_dir=site, archive_path=second
            )

            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_receipt["sha256"], second_receipt["sha256"])
            self.assertEqual(archive.ARCHIVE_SCHEMA, first_receipt["schema"])
            self.assertEqual(6, first_receipt["member_count"])
            self.assertEqual(
                sorted(item["name"] for item in first_receipt["members"]),
                [item["name"] for item in first_receipt["members"]],
            )
            self.assertTrue(first.read_bytes().endswith(b"\0" * 1024))
            self.assertFalse(first.read_bytes().endswith(b"\0" * 1536))

            output = Path(temporary) / "output"
            extracted = archive.extract_snapshot(
                archive_path=first, output_dir=output
            )
            self.assertEqual(first_receipt, extracted)
            self.assertEqual(b"ready\n", (output / "index.html").read_bytes())
            self.assertEqual(0o644, stat.S_IMODE((output / "index.html").stat().st_mode))
            self.assertEqual(0o755, stat.S_IMODE((output / "apt").stat().st_mode))

    def test_long_paths_use_only_standard_ustar_name_and_prefix_fields(self) -> None:
        with TemporaryDirectory() as temporary:
            site = Path(temporary) / "site"
            long_directory = "d" * 70
            nested = site / long_directory / ("e" * 70)
            nested.mkdir(parents=True)
            (nested / "payload.txt").write_text("payload", encoding="utf-8")
            path = Path(temporary) / "snapshot.tar"
            receipt = archive.create_snapshot(source_dir=site, archive_path=path)
            self.assertEqual(3, receipt["member_count"])
            self.assertIn(
                f"{long_directory}/{'e' * 70}/payload.txt",
                [member["name"] for member in receipt["members"]],
            )

    def test_create_rejects_symlink_hardlink_special_and_output_inside_source(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)

            site = root / "symlink-site"
            site.mkdir()
            (site / "target").write_text("x", encoding="utf-8")
            (site / "link").symlink_to("target")
            with self.assertRaisesRegex(archive.ArchiveError, "symbolic link"):
                archive.create_snapshot(source_dir=site, archive_path=root / "symlink.tar")

            site = root / "hardlink-site"
            site.mkdir()
            (site / "first").write_text("x", encoding="utf-8")
            os.link(site / "first", site / "second")
            with self.assertRaisesRegex(archive.ArchiveError, "hard-linked"):
                archive.create_snapshot(source_dir=site, archive_path=root / "hardlink.tar")

            site = root / "special-site"
            site.mkdir()
            os.mkfifo(site / "pipe")
            with self.assertRaisesRegex(archive.ArchiveError, "special file type"):
                archive.create_snapshot(source_dir=site, archive_path=root / "special.tar")

            site = root / "inside-site"
            site.mkdir()
            with self.assertRaisesRegex(archive.ArchiveError, "must not be inside"):
                archive.create_snapshot(source_dir=site, archive_path=site / "snapshot.tar")

    def test_create_and_inspect_enforce_member_and_total_size_limits(self) -> None:
        with TemporaryDirectory() as temporary:
            site = Path(temporary) / "site"
            site.mkdir()
            (site / "one").write_bytes(b"1234")
            (site / "two").write_bytes(b"56")
            with self.assertRaisesRegex(archive.ArchiveError, "member-count limit"):
                archive.create_snapshot(
                    source_dir=site,
                    archive_path=Path(temporary) / "members.tar",
                    max_members=1,
                )
            with self.assertRaisesRegex(archive.ArchiveError, "total-size limit"):
                archive.create_snapshot(
                    source_dir=site,
                    archive_path=Path(temporary) / "size.tar",
                    max_total_size=5,
                )
            path = Path(temporary) / "valid.tar"
            archive.create_snapshot(source_dir=site, archive_path=path)
            with self.assertRaisesRegex(archive.ArchiveError, "member-count limit"):
                archive.inspect_snapshot(archive_path=path, max_members=1)
            with self.assertRaisesRegex(archive.ArchiveError, "total-size limit"):
                archive.extract_snapshot(
                    archive_path=path,
                    output_dir=Path(temporary) / "out",
                    max_total_size=5,
                )
            self.assertFalse((Path(temporary) / "out").exists())

    def test_rejects_all_link_special_pax_and_gnu_member_types(self) -> None:
        valid = bytearray(_raw_archive([("payload", "file", b"x")]))
        for typeflag in (b"1", b"2", b"3", b"4", b"6", b"x", b"g", b"L", b"K"):
            with self.subTest(typeflag=typeflag):
                mutated = bytearray(valid)
                mutated[156:157] = typeflag
                _canonical_checksum(mutated)
                self._assert_rejected(
                    bytes(mutated), "link, special, PAX, or GNU"
                )

        gnu = bytearray(valid)
        gnu[257:263] = b"ustar "
        gnu[263:265] = b" \0"
        _canonical_checksum(gnu)
        self._assert_rejected(bytes(gnu), "not canonical POSIX USTAR")

    def test_rejects_path_traversal_absolute_backslash_duplicate_and_missing_parent(self) -> None:
        cases = (
            (_raw_archive([("../escape", "file", b"x")]), "unsafe archive path"),
            (_raw_archive([("/absolute", "file", b"x")]), "unsafe archive path"),
            (_raw_archive([("a\\..\\escape", "file", b"x")]), "unsafe archive path"),
            (
                _raw_archive(
                    [("duplicate", "file", b"x"), ("duplicate", "file", b"y")]
                ),
                "strict bytewise path order",
            ),
            (_raw_archive([("missing/child", "file", b"x")]), "parent is missing"),
        )
        for data, pattern in cases:
            with self.subTest(pattern=pattern):
                self._assert_rejected(data, pattern)

    def test_rejects_noncanonical_identity_metadata_order_and_padding(self) -> None:
        base = bytearray(_raw_archive([("payload", "file", b"x")]))
        mutations: list[tuple[str, bytes]] = []
        for label, field, replacement in (
            ("mode", slice(100, 108), b"0000600\0"),
            ("uid", slice(108, 116), b"0000001\0"),
            ("gid", slice(116, 124), b"0000001\0"),
            ("mtime", slice(136, 148), b"00000000001\0"),
        ):
            mutated = bytearray(base)
            mutated[field] = replacement
            _canonical_checksum(mutated)
            mutations.append((label, bytes(mutated)))
        for label, data in mutations:
            with self.subTest(label=label):
                self._assert_rejected(data, label)

        unsorted = _raw_archive(
            [("z", "file", b"z"), ("a", "file", b"a")]
        )
        self._assert_rejected(unsorted, "strict bytewise path order")

        nonzero_padding = bytearray(base)
        nonzero_padding[513] = 1
        self._assert_rejected(bytes(nonzero_padding), "padding is not zero")

    def test_rejects_truncation_single_end_marker_and_any_trailing_bytes(self) -> None:
        valid = _raw_archive([("payload", "file", b"x")])
        self._assert_rejected(valid[:-1024], "truncated")
        self._assert_rejected(valid[:-512], "end-of-archive marker")
        self._assert_rejected(valid + b"\0" * 512, "trailing bytes")
        self._assert_rejected(valid + b"attacker", "trailing bytes")

    def test_path_traversal_is_rejected_before_any_output_is_created(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._write_archive(
                temporary, _raw_archive([("../escape", "file", b"owned")])
            )
            output = root / "output"
            with self.assertRaisesRegex(archive.ArchiveError, "unsafe archive path"):
                archive.extract_snapshot(archive_path=path, output_dir=output)
            self.assertFalse(output.exists())
            self.assertFalse((root / "escape").exists())

    def test_extract_rejects_nonempty_or_symlink_output_directory(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._write_archive(
                temporary, _raw_archive([("payload", "file", b"x")])
            )
            nonempty = root / "nonempty"
            nonempty.mkdir()
            (nonempty / "keep").write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(archive.ArchiveError, "empty real directory"):
                archive.extract_snapshot(archive_path=path, output_dir=nonempty)
            self.assertEqual("keep", (nonempty / "keep").read_text(encoding="utf-8"))

            target = root / "target"
            target.mkdir()
            symlink = root / "symlink"
            symlink.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(archive.ArchiveError, "empty real directory"):
                archive.extract_snapshot(archive_path=path, output_dir=symlink)
            self.assertEqual([], list(target.iterdir()))

    def test_cli_can_write_an_exclusive_receipt_and_print_the_same_json(self) -> None:
        with TemporaryDirectory() as temporary:
            site = self._site(temporary)
            path = Path(temporary) / "snapshot.tar"
            receipt_path = Path(temporary) / "receipt.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = archive.main(
                    [
                        "create",
                        "--source-dir",
                        str(site),
                        "--archive",
                        str(path),
                        "--receipt-output",
                        str(receipt_path),
                    ]
                )
            self.assertEqual(0, exit_code)
            self.assertEqual(
                json.loads(stdout.getvalue()),
                json.loads(receipt_path.read_text(encoding="utf-8")),
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                exit_code = archive.main(
                    [
                        "create",
                        "--source-dir",
                        str(site),
                        "--archive",
                        str(Path(temporary) / "other.tar"),
                        "--receipt-output",
                        str(receipt_path),
                    ]
                )
            self.assertEqual(1, exit_code)
            self.assertIn("must not already exist", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
