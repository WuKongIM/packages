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
SCRIPT = ROOT / "scripts" / "resolve-audit-release.py"
SPEC = importlib.util.spec_from_file_location("resolve_audit_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
resolver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolver)

RELEASE_ID = 4242
ARCHIVE_NAME, RECEIPT_NAME = resolver.expected_asset_names(RELEASE_ID)


class FixtureState:
    def __init__(self) -> None:
        self.asset_bytes = {
            ARCHIVE_NAME: b"canonical site archive\0\0",
            RECEIPT_NAME: b'{"schema":"audit-receipt/v1"}\n',
        }
        self.asset_ids = {ARCHIVE_NAME: 9001, RECEIPT_NAME: 9002}
        self.asset_names: list[str] = []
        self.draft = True
        self.immutable = False
        self.published_at: str | None = None
        self.tag_name, self.name = resolver.expected_release_identity(RELEASE_ID)
        self.target_commitish = "a" * 40
        self.prerelease = True
        self.tag_sha = self.target_commitish
        self.tag_exists = True
        self.change_tag_sha_after_download = False
        self.release_id = RELEASE_ID
        self.asset_overrides: dict[str, dict[str, Any]] = {}
        self.raw_assets_override: list[dict[str, Any]] | None = None
        self.release_calls = 0
        self.change_tag_after_download = False
        self.change_assets_after_download = False
        self.invalid_json = False
        self.redirect_location: str | None = None
        self.download_overrides: dict[int, bytes] = {}
        self.requests: list[tuple[str, str, str | None]] = []

    def asset(self, name: str) -> dict[str, Any]:
        data = self.asset_bytes[name]
        value = {
            "id": self.asset_ids[name],
            "name": name,
            "state": "uploaded",
            "size": len(data),
            "digest": f"sha256:{hashlib.sha256(data).hexdigest()}",
            "browser_download_url": f"https://attacker.invalid/{name}",
        }
        return {**value, **self.asset_overrides.get(name, {})}

    def release(self) -> dict[str, Any]:
        self.release_calls += 1
        tag_name = self.tag_name
        if self.change_tag_after_download and self.release_calls > 1:
            tag_name = f"{self.tag_name}-changed"
        if self.raw_assets_override is not None:
            assets = self.raw_assets_override
        else:
            names = list(self.asset_names)
            if self.change_assets_after_download and self.release_calls > 1:
                names = []
            assets = [self.asset(name) for name in names]
        return {
            "id": self.release_id,
            "tag_name": tag_name,
            "name": self.name,
            "target_commitish": self.target_commitish,
            "draft": self.draft,
            "immutable": self.immutable,
            "published_at": self.published_at,
            "prerelease": self.prerelease,
            "assets": assets,
        }


class FixtureHandler(BaseHTTPRequestHandler):
    server: "FixtureServer"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        state = self.server.state
        state.requests.append(("GET", self.path, self.headers.get("Authorization")))
        release_path = (
            f"/api/repos/{resolver.AUDIT_REPOSITORY}/releases/{RELEASE_ID}"
        )
        download_prefix = (
            f"/downloads/repos/{resolver.AUDIT_REPOSITORY}/releases/assets/"
        )
        if self.path == release_path:
            if state.invalid_json:
                data = b"not-json"
            else:
                data = json.dumps(state.release()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        tag_path = (
            f"/api/repos/{resolver.AUDIT_REPOSITORY}/git/ref/tags/{state.tag_name}"
        )
        if self.path == tag_path:
            if not state.tag_exists:
                self.send_error(404)
                return
            tag_sha = state.tag_sha
            if state.change_tag_sha_after_download and state.release_calls > 1:
                tag_sha = "b" * 40
            data = json.dumps(
                {
                    "ref": f"refs/tags/{state.tag_name}",
                    "object": {"type": "commit", "sha": tag_sha},
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path.startswith(download_prefix):
            if state.redirect_location is not None:
                self.send_response(302)
                self.send_header("Location", state.redirect_location)
                self.end_headers()
                return
            try:
                asset_id = int(self.path.removeprefix(download_prefix))
                name = next(
                    name for name, candidate in state.asset_ids.items() if candidate == asset_id
                )
                data = state.download_overrides.get(asset_id, state.asset_bytes[name])
            except (StopIteration, ValueError):
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
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        daemon=True,
    )
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        yield f"{base}/api", f"{base}/downloads"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


class ResolveAuditReleaseTest(unittest.TestCase):
    def resolve(
        self, state: FixtureState, *, expected_tag_state: str = "auto"
    ) -> tuple[dict[str, Any], Path, TemporaryDirectory[str]]:
        temporary = TemporaryDirectory()
        output = Path(temporary.name) / "assets"
        with serve(state) as (api_base, download_base):
            receipt = resolver.resolve_audit_release(
                release_id=RELEASE_ID,
                expected_control_sha=state.target_commitish,
                output_dir=output,
                api_base_url=api_base,
                download_base_url=download_base,
                token=None,
                expected_tag_state=expected_tag_state,
            )
        return receipt, output, temporary

    def assert_resolution_error(
        self,
        state: FixtureState,
        pattern: str,
        *,
        expected_tag_state: str = "auto",
    ) -> None:
        with TemporaryDirectory() as temporary, serve(state) as (
            api_base,
            download_base,
        ):
            output = Path(temporary) / "assets"
            with self.assertRaisesRegex(resolver.ResolutionError, pattern):
                resolver.resolve_audit_release(
                    release_id=RELEASE_ID,
                    expected_control_sha=state.target_commitish,
                    output_dir=output,
                    api_base_url=api_base,
                    download_base_url=download_base,
                    token=None,
                    expected_tag_state=expected_tag_state,
                )
            self.assertFalse(output.exists())

    def test_classifies_exact_four_recoverable_states(self) -> None:
        cases = (
            ([], True, False, None, resolver.EMPTY_DRAFT),
            ([ARCHIVE_NAME], True, False, None, resolver.ARCHIVE_ONLY_DRAFT),
            (
                [ARCHIVE_NAME, RECEIPT_NAME],
                True,
                False,
                None,
                resolver.COMPLETE_DRAFT,
            ),
            (
                [ARCHIVE_NAME, RECEIPT_NAME],
                False,
                True,
                "2026-09-01T00:00:00Z",
                resolver.IMMUTABLE_COMPLETE,
            ),
        )
        for names, draft, immutable, published_at, classification in cases:
            with self.subTest(classification=classification):
                state = FixtureState()
                state.asset_names = list(names)
                state.draft = draft
                state.immutable = immutable
                state.published_at = published_at
                receipt, output, temporary = self.resolve(state)
                self.addCleanup(temporary.cleanup)
                self.assertEqual(classification, receipt["classification"])
                self.assertEqual(resolver.RECEIPT_SCHEMA, receipt["schema"])
                self.assertEqual(resolver.AUDIT_REPOSITORY, receipt["repository"])
                self.assertEqual(RELEASE_ID, receipt["release_id"])
                self.assertEqual(len(names), receipt["asset_count"])
                self.assertTrue(receipt["release_revalidated"])
                self.assertTrue(receipt["id_bound_downloads"])
                self.assertEqual(state.target_commitish, receipt["control_sha"])
                self.assertEqual(
                    classification == resolver.IMMUTABLE_COMPLETE,
                    receipt["tag_commit_verified"],
                )
                self.assertEqual(2, state.release_calls)
                self.assertEqual(
                    sorted(names), sorted(path.name for path in output.iterdir())
                )

    def test_downloads_only_by_numeric_asset_id_and_checks_local_bytes(self) -> None:
        state = FixtureState()
        state.asset_names = [ARCHIVE_NAME, RECEIPT_NAME]
        receipt, output, temporary = self.resolve(state)
        self.addCleanup(temporary.cleanup)
        for asset in receipt["assets"]:
            data = (output / asset["name"]).read_bytes()
            self.assertEqual(asset["size"], len(data))
            self.assertEqual(asset["sha256"], hashlib.sha256(data).hexdigest())
        download_paths = {
            path
            for method, path, _ in state.requests
            if path.startswith("/downloads/")
        }
        self.assertEqual(
            {
                f"/downloads/repos/{resolver.AUDIT_REPOSITORY}/releases/assets/9001",
                f"/downloads/repos/{resolver.AUDIT_REPOSITORY}/releases/assets/9002",
            },
            download_paths,
        )
        self.assertFalse(any("attacker.invalid" in path for _, path, _ in state.requests))
        self.assertFalse(any(method != "GET" for method, _, _ in state.requests))

    def test_rejects_receipt_only_extra_and_conflicting_asset_sets(self) -> None:
        state = FixtureState()
        state.asset_names = [RECEIPT_NAME]
        self.assert_resolution_error(state, "receipt-only")

        state = FixtureState()
        extra = {
            "id": 9999,
            "name": "unexpected.tar",
            "state": "uploaded",
            "size": 1,
            "digest": f"sha256:{'0' * 64}",
        }
        state.raw_assets_override = [extra]
        self.assert_resolution_error(state, "unexpected asset")

        state = FixtureState()
        state.draft = False
        state.immutable = True
        state.published_at = "2026-09-01T00:00:00Z"
        state.asset_names = [ARCHIVE_NAME]
        self.assert_resolution_error(state, "exactly the archive and receipt")

    def test_rejects_published_mutable_draft_immutable_and_timestamp_conflicts(self) -> None:
        cases = (
            (False, False, "2026-09-01T00:00:00Z", "must be immutable"),
            (True, True, None, "both draft and immutable"),
            (True, False, "2026-09-01T00:00:00Z", "must not have published_at"),
            (False, True, None, "must be a non-empty string"),
        )
        for draft, immutable, published_at, pattern in cases:
            with self.subTest(pattern=pattern):
                state = FixtureState()
                state.draft = draft
                state.immutable = immutable
                state.published_at = published_at
                if immutable and not draft:
                    state.asset_names = [ARCHIVE_NAME, RECEIPT_NAME]
                self.assert_resolution_error(state, pattern)

    def test_rejects_noncanonical_release_identity_and_wrong_control(self) -> None:
        cases = (
            ("tag_name", "package-preview-r4242", "canonical numeric tag"),
            ("name", "Native package audit draft", "canonical numeric name"),
            ("prerelease", False, "must be a prerelease"),
            ("target_commitish", "b" * 40, "expected control commit"),
        )
        for field, value, pattern in cases:
            with self.subTest(field=field):
                state = FixtureState()
                setattr(state, field, value)
                if field == "target_commitish":
                    with TemporaryDirectory() as temporary, serve(state) as (
                        api_base,
                        download_base,
                    ):
                        with self.assertRaisesRegex(resolver.ResolutionError, pattern):
                            resolver.resolve_audit_release(
                                release_id=RELEASE_ID,
                                expected_control_sha="a" * 40,
                                output_dir=Path(temporary) / "assets",
                                api_base_url=api_base,
                                download_base_url=download_base,
                                token=None,
                            )
                    continue
                self.assert_resolution_error(state, pattern)

    def test_rejects_immutable_tag_target_conflict_and_change(self) -> None:
        state = FixtureState()
        state.draft = False
        state.immutable = True
        state.published_at = "2026-09-01T00:00:00Z"
        state.asset_names = [ARCHIVE_NAME, RECEIPT_NAME]
        state.tag_sha = "b" * 40
        self.assert_resolution_error(state, "does not peel")

        state = FixtureState()
        state.draft = False
        state.immutable = True
        state.published_at = "2026-09-01T00:00:00Z"
        state.asset_names = [ARCHIVE_NAME, RECEIPT_NAME]
        state.change_tag_sha_after_download = True
        self.assert_resolution_error(state, "does not peel")

    def test_explicit_draft_tag_state_is_fail_closed_and_revalidated(self) -> None:
        state = FixtureState()
        state.tag_exists = False
        receipt, _, temporary = self.resolve(state, expected_tag_state="absent")
        self.addCleanup(temporary.cleanup)
        self.assertFalse(receipt["tag_commit_verified"])

        state = FixtureState()
        receipt, _, temporary = self.resolve(state, expected_tag_state="exact")
        self.addCleanup(temporary.cleanup)
        self.assertTrue(receipt["tag_commit_verified"])

        state = FixtureState()
        self.assert_resolution_error(
            state, "must remain absent", expected_tag_state="absent"
        )

        state = FixtureState()
        state.tag_exists = False
        self.assert_resolution_error(
            state, "GitHub API read failed", expected_tag_state="exact"
        )

    def test_rejects_wrong_release_id_duplicate_names_ids_and_unfinished_assets(self) -> None:
        state = FixtureState()
        state.release_id = RELEASE_ID + 1
        self.assert_resolution_error(state, "does not match")

        state = FixtureState()
        duplicate = state.asset(ARCHIVE_NAME)
        state.raw_assets_override = [duplicate, duplicate]
        self.assert_resolution_error(state, "duplicate asset name")

        state = FixtureState()
        state.asset_names = [ARCHIVE_NAME, RECEIPT_NAME]
        state.asset_overrides[RECEIPT_NAME] = {"id": state.asset_ids[ARCHIVE_NAME]}
        self.assert_resolution_error(state, "duplicate asset id")

        state = FixtureState()
        state.asset_names = [ARCHIVE_NAME]
        state.asset_overrides[ARCHIVE_NAME] = {"state": "starter"}
        self.assert_resolution_error(state, "not fully uploaded")

    def test_rejects_invalid_api_size_digest_and_download_conflicts(self) -> None:
        state = FixtureState()
        state.asset_names = [ARCHIVE_NAME]
        state.asset_overrides[ARCHIVE_NAME] = {"size": 0}
        self.assert_resolution_error(state, "invalid size")

        state = FixtureState()
        state.asset_names = [ARCHIVE_NAME]
        state.asset_overrides[ARCHIVE_NAME] = {"digest": None}
        self.assert_resolution_error(state, "non-empty string")

        state = FixtureState()
        state.asset_names = [ARCHIVE_NAME]
        state.asset_overrides[ARCHIVE_NAME] = {"digest": f"sha256:{'0' * 64}"}
        self.assert_resolution_error(state, "digest conflicts with API")

        state = FixtureState()
        state.asset_names = [ARCHIVE_NAME]
        state.asset_overrides[ARCHIVE_NAME] = {
            "size": len(state.asset_bytes[ARCHIVE_NAME]) + 1
        }
        self.assert_resolution_error(state, "size conflicts with API")

        state = FixtureState()
        state.asset_names = [ARCHIVE_NAME]
        state.asset_overrides[ARCHIVE_NAME] = {
            "size": len(state.asset_bytes[ARCHIVE_NAME]) - 1
        }
        self.assert_resolution_error(state, "exceeds API size")

    def test_rejects_release_identity_or_asset_conflict_after_download_and_cleans_up(self) -> None:
        state = FixtureState()
        state.asset_names = [ARCHIVE_NAME]
        state.change_tag_after_download = True
        self.assert_resolution_error(state, "canonical numeric tag")

        state = FixtureState()
        state.asset_names = [ARCHIVE_NAME]
        state.change_assets_after_download = True
        self.assert_resolution_error(state, "changed during resolution")

    def test_rejects_unsafe_redirect_and_invalid_json(self) -> None:
        state = FixtureState()
        state.asset_names = [ARCHIVE_NAME]
        state.redirect_location = "http://attacker.invalid/archive"
        self.assert_resolution_error(state, "unsafe URL")

        state = FixtureState()
        state.invalid_json = True
        self.assert_resolution_error(state, "invalid JSON")

    def test_rejects_invalid_release_id_and_nonempty_or_symlink_output(self) -> None:
        state = FixtureState()
        with TemporaryDirectory() as temporary, serve(state) as (
            api_base,
            download_base,
        ):
            for release_id in (0, -1, True):
                with self.subTest(release_id=release_id):
                    with self.assertRaisesRegex(resolver.ResolutionError, "positive integer"):
                        resolver.resolve_audit_release(
                            release_id=release_id,
                            expected_control_sha=state.target_commitish,
                            output_dir=Path(temporary) / f"out-{release_id}",
                            api_base_url=api_base,
                            download_base_url=download_base,
                            token=None,
                        )

            nonempty = Path(temporary) / "nonempty"
            nonempty.mkdir()
            (nonempty / "keep").write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(resolver.ResolutionError, "empty real directory"):
                resolver.resolve_audit_release(
                    release_id=RELEASE_ID,
                    expected_control_sha=state.target_commitish,
                    output_dir=nonempty,
                    api_base_url=api_base,
                    download_base_url=download_base,
                    token=None,
                )
            self.assertEqual("keep", (nonempty / "keep").read_text(encoding="utf-8"))

            target = Path(temporary) / "target"
            target.mkdir()
            symlink = Path(temporary) / "symlink"
            symlink.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(resolver.ResolutionError, "empty real directory"):
                resolver.resolve_audit_release(
                    release_id=RELEASE_ID,
                    expected_control_sha=state.target_commitish,
                    output_dir=symlink,
                    api_base_url=api_base,
                    download_base_url=download_base,
                    token=None,
                )

    def test_source_contains_no_write_tag_lookup_or_browser_download_primitive(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in (
            'method="POST"',
            'method="PATCH"',
            'method="PUT"',
            'method="DELETE"',
            "/releases/tags/",
            'asset.get("browser_download_url")',
            "subprocess",
            "os.system",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_cli_prints_resolution_receipt(self) -> None:
        state = FixtureState()
        state.asset_names = [ARCHIVE_NAME, RECEIPT_NAME]
        with TemporaryDirectory() as temporary, serve(state) as (
            api_base,
            download_base,
        ):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = resolver.main(
                    [
                        "--release-id",
                        str(RELEASE_ID),
                        "--expected-control-sha",
                        state.target_commitish,
                        "--output-dir",
                        str(Path(temporary) / "assets"),
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
            self.assertEqual(resolver.COMPLETE_DRAFT, receipt["classification"])
            self.assertEqual(RELEASE_ID, receipt["release_id"])


if __name__ == "__main__":
    unittest.main()
