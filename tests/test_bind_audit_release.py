from __future__ import annotations

import contextlib
import importlib.util
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bind-audit-release.py"
SPEC = importlib.util.spec_from_file_location("bind_audit_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
binder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binder)

RELEASE_ID = 4242
OLD_SHA = "a" * 40
NEW_SHA = "b" * 40


class FixtureState:
    def __init__(self) -> None:
        self.release_id = RELEASE_ID
        self.tag_name, self.name = binder.expected_release_identity(RELEASE_ID)
        self.target_commitish = OLD_SHA
        self.draft = True
        self.prerelease = True
        self.immutable = False
        self.published_at: str | None = None
        self.assets: list[dict[str, Any]] = []
        self.patch_payloads: list[dict[str, Any]] = []
        self.post_payloads: list[dict[str, Any]] = []
        self.tag_sha: str | None = None
        self.authorization: list[str | None] = []
        self.change_after_patch = False

    def release(self) -> dict[str, Any]:
        return {
            "id": self.release_id,
            "tag_name": self.tag_name,
            "name": self.name,
            "target_commitish": self.target_commitish,
            "draft": self.draft,
            "prerelease": self.prerelease,
            "immutable": self.immutable,
            "published_at": self.published_at,
            "assets": self.assets,
        }


class Handler(BaseHTTPRequestHandler):
    server: "FixtureServer"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _response(self, value: dict[str, Any]) -> None:
        data = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self.server.state.authorization.append(self.headers.get("Authorization"))
        if self.path == f"/repos/{binder.AUDIT_REPOSITORY}/git/ref/tags/{self.server.state.tag_name}":
            if self.server.state.tag_sha is None:
                self.send_error(404)
                return
            self._response({
                "ref": f"refs/tags/{self.server.state.tag_name}",
                "object": {"type": "commit", "sha": self.server.state.tag_sha},
            })
            return
        if self.path != f"/repos/{binder.AUDIT_REPOSITORY}/releases/{RELEASE_ID}":
            self.send_error(404)
            return
        if self.server.state.change_after_patch and self.server.state.patch_payloads:
            self.server.state.assets = [{"id": 9, "name": "unexpected"}]
        self._response(self.server.state.release())

    def do_POST(self) -> None:
        self.server.state.authorization.append(self.headers.get("Authorization"))
        if self.path != f"/repos/{binder.AUDIT_REPOSITORY}/git/refs":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        self.server.state.post_payloads.append(payload)
        if self.server.state.tag_sha is not None:
            self.send_error(422)
            return
        self.server.state.tag_sha = payload["sha"]
        self._response({
            "ref": payload["ref"],
            "object": {"type": "commit", "sha": payload["sha"]},
        })

    def do_PATCH(self) -> None:
        self.server.state.authorization.append(self.headers.get("Authorization"))
        if self.path != f"/repos/{binder.AUDIT_REPOSITORY}/releases/{RELEASE_ID}":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        self.server.state.patch_payloads.append(payload)
        if set(payload) == {"target_commitish"}:
            self.server.state.target_commitish = payload["target_commitish"]
        self._response(self.server.state.release())


class FixtureServer(ThreadingHTTPServer):
    def __init__(self, state: FixtureState) -> None:
        super().__init__(("127.0.0.1", 0), Handler)
        self.state = state


@contextlib.contextmanager
def serve(state: FixtureState):
    server = FixtureServer(state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


class BindAuditReleaseTest(unittest.TestCase):
    def bind(
        self,
        state: FixtureState,
        *,
        old: str = OLD_SHA,
        new: str = NEW_SHA,
    ) -> dict[str, Any]:
        with serve(state) as base:
            return binder.bind_audit_release(
                release_id=RELEASE_ID,
                expected_previous_control_sha=old,
                expected_control_sha=new,
                api_base_url=base,
                token="fixture-token",
            )

    def assert_rejected(self, state: FixtureState, pattern: str) -> None:
        with self.assertRaisesRegex(binder.BindingError, pattern):
            self.bind(state)
        self.assertEqual(state.patch_payloads, [])

    def test_updates_only_target_commitish_and_revalidates(self) -> None:
        state = FixtureState()
        result = self.bind(state)
        self.assertEqual(state.patch_payloads, [{"target_commitish": NEW_SHA}])
        self.assertEqual(
            state.post_payloads,
            [{"ref": f"refs/tags/{state.tag_name}", "sha": NEW_SHA}],
        )
        self.assertEqual(state.tag_sha, NEW_SHA)
        self.assertEqual(state.target_commitish, NEW_SHA)
        self.assertTrue(result["updated"])
        self.assertTrue(result["audit_tag_created"])
        self.assertTrue(result["audit_tag_reserved"])
        self.assertTrue(result["empty_draft_revalidated"])
        self.assertEqual(result["previous_control_sha"], OLD_SHA)
        self.assertEqual(result["control_sha"], NEW_SHA)
        self.assertTrue(all(value == "Bearer fixture-token" for value in state.authorization))

    def test_same_commit_is_idempotent_without_patch(self) -> None:
        state = FixtureState()
        result = self.bind(state, old=OLD_SHA, new=OLD_SHA)
        self.assertEqual(state.patch_payloads, [])
        self.assertFalse(result["updated"])
        self.assertTrue(result["audit_tag_created"])

    def test_retry_accepts_only_an_already_exact_tag_and_binding(self) -> None:
        state = FixtureState()
        state.target_commitish = NEW_SHA
        state.tag_sha = NEW_SHA
        result = self.bind(state)
        self.assertEqual(state.patch_payloads, [])
        self.assertFalse(result["updated"])
        self.assertFalse(result["audit_tag_created"])
        self.assertTrue(result["audit_tag_reserved"])

    def test_conflicting_tag_fails_before_release_patch(self) -> None:
        state = FixtureState()
        state.tag_sha = "c" * 40
        with self.assertRaisesRegex(
            binder.BindingError, "does not point to the reviewed control"
        ):
            self.bind(state)
        self.assertEqual(state.patch_payloads, [])
        self.assertEqual(state.target_commitish, OLD_SHA)

    def test_rejects_noncanonical_or_nonempty_release(self) -> None:
        mutations = (
            ("tag_name", "wrong", "tag must"),
            ("name", "wrong", "name must"),
            ("draft", False, "remain a draft"),
            ("prerelease", False, "remain a prerelease"),
            ("immutable", True, "must not be immutable"),
            ("published_at", "2026-01-01T00:00:00Z", "must not be published"),
            ("assets", [{"id": 1}], "must be empty"),
        )
        for attribute, value, pattern in mutations:
            with self.subTest(attribute=attribute):
                state = FixtureState()
                setattr(state, attribute, value)
                self.assert_rejected(state, pattern)

    def test_rejects_unexpected_previous_commit(self) -> None:
        state = FixtureState()
        state.target_commitish = "c" * 40
        self.assert_rejected(state, "previous control commit")

    def test_detects_state_change_after_patch(self) -> None:
        state = FixtureState()
        state.change_after_patch = True
        with self.assertRaisesRegex(binder.BindingError, "must be empty"):
            self.bind(state)
        self.assertEqual(state.patch_payloads, [{"target_commitish": NEW_SHA}])

    def test_rejects_unsafe_api_origin_and_missing_token(self) -> None:
        with self.assertRaisesRegex(binder.BindingError, "HTTPS or loopback"):
            binder.GitHubWriter("http://example.com", "token")
        with self.assertRaisesRegex(binder.BindingError, "token is required"):
            binder.GitHubWriter("https://api.github.com", "")

    def test_validates_numeric_id_and_commit_shas_before_network(self) -> None:
        cases = (
            ({"release_id": 0}, "positive integer"),
            ({"expected_previous_control_sha": "A" * 40}, "lowercase 40-hex"),
            ({"expected_control_sha": "main"}, "lowercase 40-hex"),
        )
        defaults = {
            "release_id": RELEASE_ID,
            "expected_previous_control_sha": OLD_SHA,
            "expected_control_sha": NEW_SHA,
            "api_base_url": "https://api.github.com",
            "token": "token",
        }
        for override, pattern in cases:
            with self.subTest(override=override):
                with self.assertRaisesRegex(binder.BindingError, pattern):
                    binder.bind_audit_release(**{**defaults, **override})


if __name__ == "__main__":
    unittest.main()
