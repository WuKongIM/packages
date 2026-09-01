from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "seal-audit-release.py"
SPEC = importlib.util.spec_from_file_location("seal_audit_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
sealer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sealer)

RELEASE_ID = 8123
CONTROL_SHA = "a" * 40
ARCHIVE_NAME, RECEIPT_NAME = sealer.resolver.expected_asset_names(RELEASE_ID)
TAG_NAME, RELEASE_NAME = sealer.resolver.expected_release_identity(RELEASE_ID)


class FixtureState:
    def __init__(self) -> None:
        self.draft = True
        self.immutable = False
        self.published_at: str | None = None
        self.assets: dict[str, bytes] = {}
        self.asset_ids = {ARCHIVE_NAME: 6001, RECEIPT_NAME: 6002}
        self.upload_host: str | None = None
        self.requests: list[tuple[str, str]] = []
        self.uploads: list[str] = []
        self.patches = 0
        self.tag_sha = CONTROL_SHA
        self.main_sha = CONTROL_SHA
        self.change_main_after_upload = False
        self.asset_downloads = 0
        self.pollute_after_asset_downloads = False
        self.target_commitish = CONTROL_SHA
        self.prerelease = True
        self.immutable_releases_enabled = True

    def release(self) -> dict[str, Any]:
        assert self.upload_host is not None
        return {
            "id": RELEASE_ID,
            "tag_name": TAG_NAME,
            "name": RELEASE_NAME,
            "target_commitish": self.target_commitish,
            "draft": self.draft,
            "immutable": self.immutable,
            "prerelease": self.prerelease,
            "published_at": self.published_at,
            "upload_url": (
                f"{self.upload_host}/repos/{sealer.resolver.AUDIT_REPOSITORY}/"
                f"releases/{RELEASE_ID}/assets{{?name,label}}"
            ),
            "assets": [
                {
                    "id": self.asset_ids[name],
                    "name": name,
                    "state": "uploaded",
                    "size": len(data),
                    "digest": f"sha256:{hashlib.sha256(data).hexdigest()}",
                }
                for name, data in self.assets.items()
            ],
        }


class FixtureHandler(BaseHTTPRequestHandler):
    server: "FixtureServer"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _json(self, status: int, value: dict[str, Any]) -> None:
        raw = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        state = self.server.state
        state.requests.append(("GET", self.path))
        release_path = (
            f"/repos/{sealer.resolver.AUDIT_REPOSITORY}/releases/{RELEASE_ID}"
        )
        if self.path == release_path:
            self._json(200, state.release())
            return
        main_path = (
            f"/repos/{sealer.resolver.AUDIT_REPOSITORY}/git/ref/heads/main"
        )
        if self.path == main_path:
            self._json(
                200,
                {
                    "ref": "refs/heads/main",
                    "object": {"type": "commit", "sha": state.main_sha},
                },
            )
            return
        immutable_policy_path = (
            f"/repos/{sealer.resolver.AUDIT_REPOSITORY}/immutable-releases"
        )
        if self.path == immutable_policy_path:
            self._json(
                200,
                {
                    "enabled": state.immutable_releases_enabled,
                    "enforced_by_owner": False,
                },
            )
            return
        tag_path = (
            f"/repos/{sealer.resolver.AUDIT_REPOSITORY}/git/ref/tags/{TAG_NAME}"
        )
        if self.path == tag_path:
            self._json(
                200,
                {
                    "ref": f"refs/tags/{TAG_NAME}",
                    "object": {"type": "commit", "sha": state.tag_sha},
                },
            )
            return
        asset_prefix = (
            f"/repos/{sealer.resolver.AUDIT_REPOSITORY}/releases/assets/"
        )
        if self.path.startswith(asset_prefix):
            try:
                asset_id = int(self.path.removeprefix(asset_prefix))
                name = next(
                    candidate
                    for candidate, candidate_id in state.asset_ids.items()
                    if candidate_id == asset_id
                )
                data = state.assets[name]
            except (ValueError, StopIteration, KeyError):
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            state.asset_downloads += 1
            if state.pollute_after_asset_downloads and state.asset_downloads == 2:
                state.asset_ids["unexpected.bin"] = 6003
                state.assets["unexpected.bin"] = b"unreviewed concurrent asset"
            return
        self.send_error(404)

    def do_POST(self) -> None:
        state = self.server.state
        state.requests.append(("POST", self.path))
        parsed = urllib.parse.urlsplit(self.path)
        expected_path = (
            f"/repos/{sealer.resolver.AUDIT_REPOSITORY}/releases/{RELEASE_ID}/assets"
        )
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
        if parsed.path != expected_path or set(query) != {"name"}:
            self.send_error(404)
            return
        name = query["name"][0]
        if name not in state.asset_ids or name in state.assets:
            self.send_error(422)
            return
        length = int(self.headers["Content-Length"])
        data = self.rfile.read(length)
        state.assets[name] = data
        state.uploads.append(name)
        if state.change_main_after_upload:
            state.main_sha = "b" * 40
        self._json(201, {"id": state.asset_ids[name], "name": name})

    def do_PATCH(self) -> None:
        state = self.server.state
        state.requests.append(("PATCH", self.path))
        expected_path = (
            f"/repos/{sealer.resolver.AUDIT_REPOSITORY}/releases/{RELEASE_ID}"
        )
        if self.path != expected_path:
            self.send_error(404)
            return
        length = int(self.headers["Content-Length"])
        body = json.loads(self.rfile.read(length))
        if body != {"draft": False, "make_latest": "false", "prerelease": True}:
            self.send_error(422)
            return
        state.draft = False
        state.immutable = True
        state.published_at = "2026-09-01T00:00:00Z"
        state.patches += 1
        self._json(200, state.release())


class FixtureServer(ThreadingHTTPServer):
    def __init__(self, state: FixtureState) -> None:
        super().__init__(("127.0.0.1", 0), FixtureHandler)
        self.state = state


@contextlib.contextmanager
def serve(state: FixtureState):
    server = FixtureServer(state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        state.upload_host = base
        yield base
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


class SealAuditReleaseTest(unittest.TestCase):
    def artifacts(self, directory: Path) -> tuple[Path, Path, bytes, bytes]:
        archive_data = b"canonical package site archive\0\0"
        receipt_data = b'{"schema":"wukongim/package-audit-receipt/v1"}\n'
        archive = directory / ARCHIVE_NAME
        receipt = directory / RECEIPT_NAME
        archive.write_bytes(archive_data)
        receipt.write_bytes(receipt_data)
        return archive, receipt, archive_data, receipt_data

    def seal(self, state: FixtureState) -> tuple[dict[str, Any], bytes, bytes]:
        with TemporaryDirectory() as temporary, serve(state) as base:
            archive, receipt, archive_data, receipt_data = self.artifacts(Path(temporary))
            result = sealer.seal_audit_release(
                release_id=RELEASE_ID,
                expected_control_sha=CONTROL_SHA,
                archive_path=archive,
                receipt_path=receipt,
                api_base_url=base,
                download_base_url=base,
                token="test-token",
                max_polls=1,
                poll_seconds=0,
            )
        return result, archive_data, receipt_data

    def test_fills_empty_draft_in_order_and_seals(self) -> None:
        state = FixtureState()
        result, archive_data, receipt_data = self.seal(state)
        self.assertEqual([ARCHIVE_NAME, RECEIPT_NAME], state.uploads)
        self.assertEqual(1, state.patches)
        self.assertEqual(archive_data, state.assets[ARCHIVE_NAME])
        self.assertEqual(receipt_data, state.assets[RECEIPT_NAME])
        self.assertEqual(sealer.resolver.EMPTY_DRAFT, result["initial_classification"])
        self.assertEqual(
            sealer.resolver.IMMUTABLE_COMPLETE, result["final_classification"]
        )
        self.assertTrue(result["id_bound_downloads_verified"])
        self.assertTrue(result["immutable_releases_revalidated"])
        self.assertTrue(result["remote_control_revalidated"])

    def test_rejects_disabled_immutable_releases_without_publication(self) -> None:
        state = FixtureState()
        with TemporaryDirectory() as temporary:
            archive, receipt, archive_data, receipt_data = self.artifacts(Path(temporary))
            state.assets = {ARCHIVE_NAME: archive_data, RECEIPT_NAME: receipt_data}
            state.immutable_releases_enabled = False
            with serve(state) as base:
                with self.assertRaisesRegex(
                    sealer.SealError, "immutable Releases must remain enabled"
                ):
                    sealer.seal_audit_release(
                        release_id=RELEASE_ID,
                        expected_control_sha=CONTROL_SHA,
                        archive_path=archive,
                        receipt_path=receipt,
                        api_base_url=base,
                        download_base_url=base,
                        token="test-token",
                        max_polls=1,
                        poll_seconds=0,
                    )
        self.assertEqual(0, state.patches)

    def test_detects_main_change_between_asset_writes_and_never_publishes(self) -> None:
        state = FixtureState()
        state.change_main_after_upload = True
        with TemporaryDirectory() as temporary, serve(state) as base:
            archive, receipt, _, _ = self.artifacts(Path(temporary))
            with self.assertRaisesRegex(
                sealer.SealError, "main no longer points to the reviewed control"
            ):
                sealer.seal_audit_release(
                    release_id=RELEASE_ID,
                    expected_control_sha=CONTROL_SHA,
                    archive_path=archive,
                    receipt_path=receipt,
                    api_base_url=base,
                    download_base_url=base,
                    token="test-token",
                    max_polls=1,
                    poll_seconds=0,
                )
        self.assertEqual([ARCHIVE_NAME], state.uploads)
        self.assertEqual(0, state.patches)

    def test_rejects_asset_added_after_downloads_before_publish(self) -> None:
        state = FixtureState()
        state.pollute_after_asset_downloads = True
        with TemporaryDirectory() as temporary, serve(state) as base:
            archive, receipt, _, _ = self.artifacts(Path(temporary))
            with self.assertRaisesRegex(
                sealer.SealError, "unexpected asset: unexpected.bin"
            ):
                sealer.seal_audit_release(
                    release_id=RELEASE_ID,
                    expected_control_sha=CONTROL_SHA,
                    archive_path=archive,
                    receipt_path=receipt,
                    api_base_url=base,
                    download_base_url=base,
                    token="test-token",
                    max_polls=1,
                    poll_seconds=0,
                )
        self.assertEqual([ARCHIVE_NAME, RECEIPT_NAME], state.uploads)
        self.assertEqual(0, state.patches)

    def test_recovers_archive_only_and_complete_drafts_without_overwrite(self) -> None:
        for initial_names, expected_uploads in (
            ([ARCHIVE_NAME], [RECEIPT_NAME]),
            ([ARCHIVE_NAME, RECEIPT_NAME], []),
        ):
            with self.subTest(initial_names=initial_names):
                state = FixtureState()
                with TemporaryDirectory() as temporary:
                    archive, receipt, archive_data, receipt_data = self.artifacts(
                        Path(temporary)
                    )
                    values = {ARCHIVE_NAME: archive_data, RECEIPT_NAME: receipt_data}
                    state.assets = {name: values[name] for name in initial_names}
                    with serve(state) as base:
                        sealer.seal_audit_release(
                            release_id=RELEASE_ID,
                            expected_control_sha=CONTROL_SHA,
                            archive_path=archive,
                            receipt_path=receipt,
                            api_base_url=base,
                            download_base_url=base,
                            token="test-token",
                            max_polls=1,
                            poll_seconds=0,
                        )
                self.assertEqual(expected_uploads, state.uploads)
                self.assertEqual(1, state.patches)

    def test_reverifies_immutable_release_without_writes(self) -> None:
        state = FixtureState()
        with TemporaryDirectory() as temporary:
            archive, receipt, archive_data, receipt_data = self.artifacts(Path(temporary))
            state.assets = {ARCHIVE_NAME: archive_data, RECEIPT_NAME: receipt_data}
            state.draft = False
            state.immutable = True
            state.published_at = "2026-09-01T00:00:00Z"
            with serve(state) as base:
                result = sealer.seal_audit_release(
                    release_id=RELEASE_ID,
                    expected_control_sha=CONTROL_SHA,
                    archive_path=archive,
                    receipt_path=receipt,
                    api_base_url=base,
                    download_base_url=base,
                    token="test-token",
                    max_polls=1,
                    poll_seconds=0,
                )
        self.assertEqual([], state.uploads)
        self.assertEqual(0, state.patches)
        self.assertEqual(
            sealer.resolver.IMMUTABLE_COMPLETE, result["initial_classification"]
        )

    def test_rejects_conflicting_existing_asset_without_write(self) -> None:
        state = FixtureState()
        state.assets = {ARCHIVE_NAME: b"conflicting archive"}
        with TemporaryDirectory() as temporary, serve(state) as base:
            archive, receipt, _, _ = self.artifacts(Path(temporary))
            with self.assertRaisesRegex(sealer.SealError, "conflicts with local bytes"):
                sealer.seal_audit_release(
                    release_id=RELEASE_ID,
                    expected_control_sha=CONTROL_SHA,
                    archive_path=archive,
                    receipt_path=receipt,
                    api_base_url=base,
                    download_base_url=base,
                    token="test-token",
                    max_polls=1,
                    poll_seconds=0,
                )
        self.assertEqual([], state.uploads)
        self.assertEqual(0, state.patches)

    def test_rejects_wrong_control_and_tag_target(self) -> None:
        state = FixtureState()
        state.target_commitish = "b" * 40
        with TemporaryDirectory() as temporary, serve(state) as base:
            archive, receipt, _, _ = self.artifacts(Path(temporary))
            with self.assertRaisesRegex(sealer.SealError, "expected control commit"):
                sealer.seal_audit_release(
                    release_id=RELEASE_ID,
                    expected_control_sha=CONTROL_SHA,
                    archive_path=archive,
                    receipt_path=receipt,
                    api_base_url=base,
                    download_base_url=base,
                    token="test-token",
                    max_polls=1,
                    poll_seconds=0,
                )

        state = FixtureState()
        with TemporaryDirectory() as temporary:
            archive, receipt, archive_data, receipt_data = self.artifacts(Path(temporary))
            state.assets = {ARCHIVE_NAME: archive_data, RECEIPT_NAME: receipt_data}
            state.draft = False
            state.immutable = True
            state.published_at = "2026-09-01T00:00:00Z"
            state.tag_sha = "b" * 40
            with serve(state) as base:
                with self.assertRaisesRegex(sealer.SealError, "does not peel"):
                    sealer.seal_audit_release(
                        release_id=RELEASE_ID,
                        expected_control_sha=CONTROL_SHA,
                        archive_path=archive,
                        receipt_path=receipt,
                        api_base_url=base,
                        download_base_url=base,
                        token="test-token",
                        max_polls=1,
                        poll_seconds=0,
                    )

    def test_rejects_unsafe_upload_origin_and_unrecoverable_remote_states(self) -> None:
        state = FixtureState()
        with TemporaryDirectory() as temporary, serve(state) as base:
            archive, receipt, _, _ = self.artifacts(Path(temporary))
            state.upload_host = "http://127.0.0.1:1"
            with self.assertRaisesRegex(sealer.SealError, "must use the API origin"):
                sealer.seal_audit_release(
                    release_id=RELEASE_ID,
                    expected_control_sha=CONTROL_SHA,
                    archive_path=archive,
                    receipt_path=receipt,
                    api_base_url=base,
                    download_base_url=base,
                    token="test-token",
                    max_polls=1,
                    poll_seconds=0,
                )

        state = FixtureState()
        state.draft = False
        state.immutable = False
        state.published_at = "2026-09-01T00:00:00Z"
        with TemporaryDirectory() as temporary, serve(state) as base:
            archive, receipt, _, _ = self.artifacts(Path(temporary))
            with self.assertRaisesRegex(sealer.SealError, "must be immutable"):
                sealer.seal_audit_release(
                    release_id=RELEASE_ID,
                    expected_control_sha=CONTROL_SHA,
                    archive_path=archive,
                    receipt_path=receipt,
                    api_base_url=base,
                    download_base_url=base,
                    token="test-token",
                    max_polls=1,
                    poll_seconds=0,
                )

        state = FixtureState()
        state.assets = {RECEIPT_NAME: b"receipt-only"}
        with TemporaryDirectory() as temporary, serve(state) as base:
            archive, receipt, _, _ = self.artifacts(Path(temporary))
            with self.assertRaisesRegex(sealer.SealError, "receipt-only"):
                sealer.seal_audit_release(
                    release_id=RELEASE_ID,
                    expected_control_sha=CONTROL_SHA,
                    archive_path=archive,
                    receipt_path=receipt,
                    api_base_url=base,
                    download_base_url=base,
                    token="test-token",
                    max_polls=1,
                    poll_seconds=0,
                )


if __name__ == "__main__":
    unittest.main()
