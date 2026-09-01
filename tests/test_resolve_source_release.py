from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "source-release"
SCRIPT = ROOT / "scripts" / "resolve-source-release.py"
SPEC = importlib.util.spec_from_file_location("resolve_source_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
resolver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolver)

RELEASE_ID = 4242
SOURCE_SHA = "1" * 40
MAIN_SHA = "2" * 40
TAG_OBJECT_SHA = "3" * 40
OTHER_SHA = "4" * 40
ADVANCED_MAIN_SHA = "5" * 40
TAG = "v3.1.0-rc.1"


class FixtureState:
    def __init__(self) -> None:
        names = sorted(path.name for path in FIXTURES.iterdir())
        self.asset_bytes = {name: (FIXTURES / name).read_bytes() for name in names}
        self.assets = []
        self.asset_name_by_id: dict[int, str] = {}
        for offset, name in enumerate(names, start=1):
            asset_id = 1000 + offset
            data = self.asset_bytes[name]
            self.assets.append(
                {
                    "id": asset_id,
                    "name": name,
                    "size": len(data),
                    "digest": f"sha256:{hashlib.sha256(data).hexdigest()}",
                }
            )
            self.asset_name_by_id[asset_id] = name
        self.tag = TAG
        self.prerelease = True
        self.draft = False
        self.immutable = True
        self.published_at = "2026-09-01T00:00:00Z"
        self.ancestry_valid = True
        self.main_branch_calls = 0
        self.advance_main_after_download = False
        self.break_ancestry_after_download = False
        self.release_calls = 0
        self.tag_object_calls = 0
        self.change_release_after_download = False
        self.change_tag_after_download = False
        self.lightweight_tag = False
        self.requests: list[tuple[str, str]] = []

    def replace_asset_bytes(self, name: str, data: bytes) -> None:
        self.asset_bytes[name] = data
        for index, asset in enumerate(self.assets):
            if asset["name"] == name:
                self.assets[index] = {
                    **asset,
                    "size": len(data),
                    "digest": f"sha256:{hashlib.sha256(data).hexdigest()}",
                }
                return
        raise AssertionError(f"unknown fixture asset: {name}")

    def release(self) -> dict[str, Any]:
        self.release_calls += 1
        published_at = self.published_at
        if self.change_release_after_download and self.release_calls > 1:
            published_at = "2026-09-01T00:00:01Z"
        return {
            "id": RELEASE_ID,
            "tag_name": self.tag,
            "draft": self.draft,
            "immutable": self.immutable,
            "prerelease": self.prerelease,
            "published_at": published_at,
            "assets": self.assets,
        }


class FixtureHandler(BaseHTTPRequestHandler):
    server: "FixtureServer"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _json(self, value: dict[str, Any]) -> None:
        data = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        state = self.server.state
        state.requests.append(("GET", self.path))
        api_prefix = f"/api/repos/{resolver.SOURCE_REPOSITORY}"
        download_prefix = f"/downloads/repos/{resolver.SOURCE_REPOSITORY}/releases/assets/"
        if self.path == f"{api_prefix}/releases/{RELEASE_ID}":
            self._json(state.release())
            return
        if self.path == f"{api_prefix}/git/ref/tags/{TAG}":
            if state.lightweight_tag:
                obj = {"type": "commit", "sha": SOURCE_SHA}
            else:
                obj = {"type": "tag", "sha": TAG_OBJECT_SHA}
            self._json({"ref": f"refs/tags/{TAG}", "object": obj})
            return
        if self.path == f"{api_prefix}/git/tags/{TAG_OBJECT_SHA}":
            state.tag_object_calls += 1
            commit_sha = SOURCE_SHA
            if state.change_tag_after_download and state.tag_object_calls > 1:
                commit_sha = OTHER_SHA
            self._json(
                {"sha": TAG_OBJECT_SHA, "object": {"type": "commit", "sha": commit_sha}}
            )
            return
        if self.path == f"{api_prefix}/branches/main":
            state.main_branch_calls += 1
            main_sha = MAIN_SHA
            if state.advance_main_after_download and state.main_branch_calls > 1:
                main_sha = ADVANCED_MAIN_SHA
            self._json({"commit": {"sha": main_sha}})
            return
        if self.path in {
            f"{api_prefix}/compare/{SOURCE_SHA}...{MAIN_SHA}",
            f"{api_prefix}/compare/{SOURCE_SHA}...{ADVANCED_MAIN_SHA}",
        }:
            final_comparison = self.path.endswith(ADVANCED_MAIN_SHA)
            valid = state.ancestry_valid and not (
                final_comparison and state.break_ancestry_after_download
            )
            merge_base = SOURCE_SHA if valid else OTHER_SHA
            status = "ahead" if valid else "diverged"
            self._json({"status": status, "merge_base_commit": {"sha": merge_base}})
            return
        if self.path.startswith(download_prefix):
            try:
                asset_id = int(self.path.removeprefix(download_prefix))
                name = state.asset_name_by_id[asset_id]
                data = state.asset_bytes[name]
            except (KeyError, ValueError):
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_error(404)


class FixtureServer(ThreadingHTTPServer):
    def __init__(self, state: FixtureState) -> None:
        super().__init__(("127.0.0.1", 0), FixtureHandler)
        self.state = state


@contextlib.contextmanager
def serve(state: FixtureState):
    server = FixtureServer(state)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        yield f"{base}/api", f"{base}/downloads"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


class ResolveSourceReleaseTest(unittest.TestCase):
    def resolve(self, state: FixtureState) -> tuple[dict[str, Any], Path, TemporaryDirectory[str]]:
        temporary = TemporaryDirectory()
        output = Path(temporary.name) / "assets"
        with serve(state) as (api_base, download_base):
            receipt = resolver.resolve_source_release(
                release_id=RELEASE_ID,
                output_dir=output,
                api_base_url=api_base,
                download_base_url=download_base,
                token=None,
            )
        return receipt, output, temporary

    def assert_resolution_error(self, state: FixtureState, pattern: str) -> None:
        with TemporaryDirectory() as temporary, serve(state) as (api_base, download_base):
            output = Path(temporary) / "assets"
            with self.assertRaisesRegex(resolver.ResolutionError, pattern):
                resolver.resolve_source_release(
                    release_id=RELEASE_ID,
                    output_dir=output,
                    api_base_url=api_base,
                    download_base_url=download_base,
                    token=None,
                )

    def test_resolver_has_no_execution_unpacking_or_http_write_primitive(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in (
            'method="POST"',
            'method="PATCH"',
            'method="DELETE"',
            "subprocess",
            "tarfile",
            "zipfile",
            "os.system",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_resolves_annotated_tag_and_exact_seven_asset_closure(self) -> None:
        state = FixtureState()
        receipt, output, temporary = self.resolve(state)
        self.addCleanup(temporary.cleanup)

        self.assertEqual(resolver.RECEIPT_SCHEMA, receipt["schema"])
        self.assertEqual(resolver.SOURCE_REPOSITORY, receipt["repository"])
        self.assertEqual(RELEASE_ID, receipt["release_id"])
        self.assertEqual(TAG, receipt["tag"])
        self.assertEqual("3.1.0-rc.1", receipt["version"])
        self.assertTrue(receipt["prerelease"])
        self.assertEqual(SOURCE_SHA, receipt["source_sha"])
        self.assertEqual(MAIN_SHA, receipt["main_sha"])
        self.assertEqual(MAIN_SHA, receipt["initial_main_sha"])
        self.assertEqual(MAIN_SHA, receipt["final_main_sha"])
        self.assertEqual(7, receipt["asset_count"])
        self.assertEqual(sum(map(len, state.asset_bytes.values())), receipt["total_size"])
        self.assertEqual(6, len(receipt["checksum_entries"]))
        self.assertTrue(receipt["release_revalidated"])
        self.assertTrue(receipt["tag_revalidated"])
        self.assertTrue(receipt["main_ancestry_revalidated"])
        self.assertEqual(
            sorted(state.asset_bytes), sorted(path.name for path in output.iterdir())
        )
        for name, expected in state.asset_bytes.items():
            self.assertEqual(expected, (output / name).read_bytes())
        release_path = f"/api/repos/{resolver.SOURCE_REPOSITORY}/releases/{RELEASE_ID}"
        self.assertEqual(2, state.requests.count(("GET", release_path)))
        branch_path = f"/api/repos/{resolver.SOURCE_REPOSITORY}/branches/main"
        self.assertEqual(2, state.requests.count(("GET", branch_path)))
        self.assertFalse(any(method != "GET" for method, _ in state.requests))
        self.assertFalse(any("/releases/tags/" in path for _, path in state.requests))

    def test_supports_lightweight_tag(self) -> None:
        state = FixtureState()
        state.lightweight_tag = True
        receipt, _, temporary = self.resolve(state)
        self.addCleanup(temporary.cleanup)
        self.assertEqual(SOURCE_SHA, receipt["source_sha"])

    def test_rejects_non_strict_semver_and_build_metadata(self) -> None:
        for tag, pattern in (
            ("3.1.0", "strict SemVer"),
            ("v03.1.0", "strict SemVer"),
            ("v3.1.0-rc.01", "leading zeroes"),
            ("v3.1.0+build.1", "build metadata"),
            ("v3.1.0", "must be a SemVer pre-release"),
        ):
            with self.subTest(tag=tag):
                state = FixtureState()
                state.tag = tag
                self.assert_resolution_error(state, pattern)

    def test_rejects_unpublished_mutable_or_misclassified_release(self) -> None:
        cases = (
            ("draft", True, "already be published"),
            ("immutable", False, "must be immutable"),
            ("prerelease", False, "classification conflicts"),
        )
        for field, value, pattern in cases:
            with self.subTest(field=field):
                state = FixtureState()
                setattr(state, field, value)
                self.assert_resolution_error(state, pattern)

    def test_rejects_non_exact_or_non_unique_asset_identity(self) -> None:
        state = FixtureState()
        state.assets.pop()
        self.assert_resolution_error(state, "exactly seven assets")

        state = FixtureState()
        state.assets[1] = {**state.assets[1], "name": state.assets[0]["name"]}
        self.assert_resolution_error(state, "duplicate asset name")

        state = FixtureState()
        state.assets[1] = {**state.assets[1], "id": state.assets[0]["id"]}
        self.assert_resolution_error(state, "duplicate asset id")

        state = FixtureState()
        state.assets[0] = {**state.assets[0], "name": "unexpected.txt"}
        self.assert_resolution_error(state, "unexpected asset")

    def test_rejects_api_or_download_size_and_digest_conflicts(self) -> None:
        state = FixtureState()
        state.assets[0] = {**state.assets[0], "digest": f"sha256:{'0' * 64}"}
        self.assert_resolution_error(state, "digest conflicts with API")

        state = FixtureState()
        state.assets[0] = {**state.assets[0], "size": state.assets[0]["size"] + 1}
        self.assert_resolution_error(state, "size conflicts with API")

        state = FixtureState()
        state.assets[0] = {**state.assets[0], "digest": None}
        self.assert_resolution_error(state, "must be a non-empty string")

    def test_rejects_checksum_manifest_without_exact_payload_closure(self) -> None:
        state = FixtureState()
        checksum_name = next(name for name in state.asset_bytes if name.endswith("_checksums.txt"))
        checksum = state.asset_bytes[checksum_name].decode()
        first_line, remainder = checksum.split("\n", 1)
        bad_checksum = (f"{'0' * 64}{first_line[64:]}\n{remainder}").encode()
        state.replace_asset_bytes(checksum_name, bad_checksum)
        self.assert_resolution_error(state, "checksum asset digest conflicts")

        for mutation, pattern in (
            ("\n".join(checksum.splitlines()[:-1]) + "\n", "exactly six"),
            (
                checksum.replace(
                    "wukongim_3.1.0-rc.1_linux_arm64.tar.gz", "unexpected.tar.gz"
                ),
                "does not exactly cover",
            ),
            (
                checksum.replace(checksum.splitlines()[1], checksum.splitlines()[0]),
                "duplicate entry",
            ),
            (checksum.replace("\n", "\r\n"), "canonical LF"),
        ):
            with self.subTest(pattern=pattern):
                state = FixtureState()
                state.replace_asset_bytes(checksum_name, mutation.encode())
                self.assert_resolution_error(state, pattern)

    def test_rejects_source_not_reachable_from_main(self) -> None:
        state = FixtureState()
        state.ancestry_valid = False
        self.assert_resolution_error(state, "not reachable from main")

    def test_allows_main_to_advance_while_preserving_source_ancestry(self) -> None:
        state = FixtureState()
        state.advance_main_after_download = True
        receipt, _, temporary = self.resolve(state)
        self.addCleanup(temporary.cleanup)
        self.assertEqual(MAIN_SHA, receipt["initial_main_sha"])
        self.assertEqual(ADVANCED_MAIN_SHA, receipt["final_main_sha"])
        self.assertEqual(ADVANCED_MAIN_SHA, receipt["main_sha"])

    def test_rejects_main_ancestry_change_after_download(self) -> None:
        state = FixtureState()
        state.advance_main_after_download = True
        state.break_ancestry_after_download = True
        self.assert_resolution_error(state, "not reachable from main")

    def test_rejects_release_or_tag_change_after_download(self) -> None:
        state = FixtureState()
        state.change_release_after_download = True
        self.assert_resolution_error(state, "Release identity or asset set changed")

        state = FixtureState()
        state.change_tag_after_download = True
        self.assert_resolution_error(state, "source tag changed during resolution")

    def test_cli_prints_receipt_without_writing_it_as_an_asset(self) -> None:
        state = FixtureState()
        with TemporaryDirectory() as temporary, serve(state) as (api_base, download_base):
            output = Path(temporary) / "assets"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = resolver.main(
                    [
                        "--release-id",
                        str(RELEASE_ID),
                        "--output-dir",
                        str(output),
                        "--api-base-url",
                        api_base,
                        "--download-base-url",
                        download_base,
                        "--token-env",
                        "",
                    ]
                )
            self.assertEqual(0, exit_code)
            receipt = json.loads(stdout.getvalue())
            self.assertEqual(RELEASE_ID, receipt["release_id"])
            self.assertEqual(7, len(list(output.iterdir())))


if __name__ == "__main__":
    unittest.main()
