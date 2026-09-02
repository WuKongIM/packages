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
        self.release_tag_name = self.tag_name
        self.target_commitish = OLD_SHA
        self.draft = True
        self.prerelease = True
        self.immutable = False
        self.published_at: str | None = None
        self.assets: list[dict[str, Any]] = []
        self.patch_payloads: list[dict[str, Any]] = []
        self.post_payloads: list[dict[str, Any]] = []
        self.tag_sha: str | None = None
        self.detached_tag_sha: str | None = None
        self.authorization: list[str | None] = []
        self.change_after_patch = False
        self.detach_release_on_tag_create = False
        self.detach_release_on_target_patch = False
        self.change_detached_on_target_patch = False
        self.change_release_tag_after_initial_get = False
        self.release_get_count = 0

    def release(self) -> dict[str, Any]:
        return {
            "id": self.release_id,
            "tag_name": self.release_tag_name,
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
        tag_prefix = f"/repos/{binder.AUDIT_REPOSITORY}/git/ref/tags/"
        if self.path.startswith(tag_prefix):
            tag_name = self.path.removeprefix(tag_prefix)
            if tag_name == self.server.state.tag_name:
                tag_sha = self.server.state.tag_sha
            elif tag_name == self.server.state.release_tag_name:
                tag_sha = self.server.state.detached_tag_sha
            else:
                tag_sha = None
            if tag_sha is None:
                self.send_error(404)
                return
            self._response({
                "ref": f"refs/tags/{tag_name}",
                "object": {"type": "commit", "sha": tag_sha},
            })
            return
        if self.path != f"/repos/{binder.AUDIT_REPOSITORY}/releases/{RELEASE_ID}":
            self.send_error(404)
            return
        if (
            self.server.state.change_release_tag_after_initial_get
            and self.server.state.release_get_count > 0
        ):
            self.server.state.release_tag_name = f"untagged-{'f' * 20}"
        self.server.state.release_get_count += 1
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
        if self.server.state.detach_release_on_tag_create:
            self.server.state.release_tag_name = f"untagged-{'d' * 20}"
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
            if self.server.state.detach_release_on_target_patch:
                self.server.state.release_tag_name = f"untagged-{'d' * 20}"
            elif self.server.state.change_detached_on_target_patch:
                self.server.state.release_tag_name = f"untagged-{'f' * 20}"
        elif set(payload) == {"tag_name"}:
            self.server.state.release_tag_name = payload["tag_name"]
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
        self.assertFalse(result["release_tag_repaired"])
        self.assertTrue(result["audit_tag_reserved"])
        self.assertTrue(result["empty_draft_revalidated"])
        self.assertEqual(result["previous_control_sha"], OLD_SHA)
        self.assertEqual(result["control_sha"], NEW_SHA)
        self.assertTrue(all(value == "Bearer fixture-token" for value in state.authorization))

    def test_repairs_github_detachment_after_reserving_tag(self) -> None:
        state = FixtureState()
        state.detach_release_on_tag_create = True

        result = self.bind(state)

        self.assertEqual(
            state.patch_payloads,
            [
                {"target_commitish": NEW_SHA},
                {"tag_name": state.tag_name},
            ],
        )
        self.assertEqual(state.release_tag_name, state.tag_name)
        self.assertEqual(state.target_commitish, NEW_SHA)
        self.assertTrue(result["release_tag_repaired"])

    def test_repairs_github_detachment_during_target_patch(self) -> None:
        state = FixtureState()
        state.detach_release_on_target_patch = True

        result = self.bind(state)

        self.assertEqual(
            state.patch_payloads,
            [
                {"target_commitish": NEW_SHA},
                {"tag_name": state.tag_name},
            ],
        )
        self.assertEqual(state.release_tag_name, state.tag_name)
        self.assertEqual(state.target_commitish, NEW_SHA)
        self.assertTrue(result["release_tag_repaired"])

    def test_retry_repairs_only_an_exact_detached_release(self) -> None:
        state = FixtureState()
        state.release_tag_name = f"untagged-{'e' * 20}"
        state.target_commitish = NEW_SHA
        state.tag_sha = NEW_SHA

        result = self.bind(state)

        self.assertEqual(state.post_payloads, [])
        self.assertEqual(state.patch_payloads, [{"tag_name": state.tag_name}])
        self.assertFalse(result["updated"])
        self.assertFalse(result["audit_tag_created"])
        self.assertTrue(result["release_tag_repaired"])

    def test_retry_finishes_target_update_before_repairing_detachment(self) -> None:
        state = FixtureState()
        state.release_tag_name = f"untagged-{'e' * 20}"
        state.tag_sha = NEW_SHA

        result = self.bind(state)

        self.assertEqual(state.post_payloads, [])
        self.assertEqual(
            state.patch_payloads,
            [
                {"target_commitish": NEW_SHA},
                {"tag_name": state.tag_name},
            ],
        )
        self.assertTrue(result["updated"])
        self.assertTrue(result["release_tag_repaired"])

    def test_rejects_detached_release_without_exact_reserved_tag(self) -> None:
        for tag_sha, pattern in (
            (None, "GET failed"),
            ("c" * 40, "does not point to the reviewed control"),
        ):
            with self.subTest(tag_sha=tag_sha):
                state = FixtureState()
                state.release_tag_name = f"untagged-{'e' * 20}"
                state.target_commitish = NEW_SHA
                state.tag_sha = tag_sha
                with self.assertRaisesRegex(binder.BindingError, pattern):
                    self.bind(state)
                self.assertEqual(state.post_payloads, [])
                self.assertEqual(state.patch_payloads, [])

    def test_rejects_noncanonical_detached_tag_pattern_without_writes(self) -> None:
        state = FixtureState()
        state.release_tag_name = "untagged-not-a-github-placeholder"
        state.target_commitish = NEW_SHA
        state.tag_sha = NEW_SHA

        with self.assertRaisesRegex(binder.BindingError, "tag must"):
            self.bind(state)

        self.assertEqual(state.post_payloads, [])
        self.assertEqual(state.patch_payloads, [])

    def test_rejects_detached_release_name_that_is_also_a_git_ref(self) -> None:
        state = FixtureState()
        state.release_tag_name = f"untagged-{'e' * 20}"
        state.target_commitish = NEW_SHA
        state.tag_sha = NEW_SHA
        state.detached_tag_sha = NEW_SHA

        with self.assertRaisesRegex(binder.BindingError, "must not have a Git ref"):
            self.bind(state)

        self.assertEqual(state.post_payloads, [])
        self.assertEqual(state.patch_payloads, [])

    def test_rejects_concurrent_detached_name_change_between_reads(self) -> None:
        state = FixtureState()
        state.release_tag_name = f"untagged-{'e' * 20}"
        state.target_commitish = NEW_SHA
        state.tag_sha = NEW_SHA
        state.change_release_tag_after_initial_get = True

        with self.assertRaisesRegex(binder.BindingError, "changed concurrently"):
            self.bind(state)

        self.assertEqual(state.post_payloads, [])
        self.assertEqual(state.patch_payloads, [])

    def test_rejects_detachment_without_this_run_creating_the_tag(self) -> None:
        state = FixtureState()
        state.target_commitish = NEW_SHA
        state.tag_sha = NEW_SHA
        state.change_release_tag_after_initial_get = True

        with self.assertRaisesRegex(binder.BindingError, "without this run"):
            self.bind(state)

        self.assertEqual(state.post_payloads, [
            {"ref": f"refs/tags/{state.tag_name}", "sha": NEW_SHA},
        ])
        self.assertEqual(state.patch_payloads, [])

    def test_rejects_detached_name_change_during_target_patch(self) -> None:
        state = FixtureState()
        state.release_tag_name = f"untagged-{'e' * 20}"
        state.tag_sha = NEW_SHA
        state.change_detached_on_target_patch = True

        with self.assertRaisesRegex(binder.BindingError, "changed during binding"):
            self.bind(state)

        self.assertEqual(state.post_payloads, [])
        self.assertEqual(state.patch_payloads, [{"target_commitish": NEW_SHA}])

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
            ("release_tag_name", "wrong", "tag must"),
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
