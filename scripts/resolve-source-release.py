#!/usr/bin/env python3
"""Resolve and download one immutable WuKongIM source Release.

The resolver treats every Release asset as opaque data. It never executes or
unpacks an asset, and it performs no GitHub write operation.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, BinaryIO


SOURCE_REPOSITORY = "WuKongIM/WuKongIM"
RECEIPT_SCHEMA = "wukongim/source-release-resolution/v1"
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SEMVER_RE = re.compile(
    r"^v(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
CHECKSUM_LINE_RE = re.compile(r"^([0-9a-f]{64})  ([0-9A-Za-z._-]+)$")
MAX_JSON_BYTES = 8 * 1024 * 1024


class ResolutionError(RuntimeError):
    """A source Release failed a fail-closed resolution check."""


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ResolutionError(f"{label} must be a JSON object")
    return value


def _require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ResolutionError(f"{label} must be a boolean")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ResolutionError(f"{label} must be a non-empty string")
    return value


def _require_sha1(value: Any, label: str) -> str:
    text = _require_string(value, label)
    if not SHA1_RE.fullmatch(text):
        raise ResolutionError(f"{label} must be a lowercase 40-hex SHA")
    return text


def parse_version(tag: str) -> tuple[str, bool]:
    if "+" in tag:
        raise ResolutionError("source tag must not contain SemVer build metadata")
    match = SEMVER_RE.fullmatch(tag)
    if match is None:
        raise ResolutionError("source tag must be strict SemVer prefixed with v")
    prerelease = match.group(4)
    if prerelease is None:
        raise ResolutionError("preview source tag must be a SemVer pre-release")
    for identifier in prerelease.split("."):
        if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
            raise ResolutionError(
                "numeric SemVer pre-release identifiers must not have leading zeroes"
            )
    return tag[1:], True


def expected_asset_names(version: str) -> tuple[tuple[str, ...], str]:
    prefix = f"wukongim_{version}"
    payloads = (
        f"{prefix}_darwin_amd64.tar.gz",
        f"{prefix}_darwin_arm64.tar.gz",
        f"{prefix}_linux_amd64.deb",
        f"{prefix}_linux_amd64.rpm",
        f"{prefix}_linux_amd64.tar.gz",
        f"{prefix}_linux_arm64.tar.gz",
    )
    return payloads, f"{prefix}_checksums.txt"


def _validated_base_url(value: str, label: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ResolutionError(f"{label} must be an absolute HTTP(S) URL")
    if parsed.query or parsed.fragment:
        raise ResolutionError(f"{label} must not contain a query or fragment")
    return value.rstrip("/")


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlsplit(url)
    return parsed.scheme, parsed.hostname or "", parsed.port


def _is_loopback_host(hostname: str) -> bool:
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class GitHubReader:
    def __init__(self, api_base_url: str, download_base_url: str, token: str | None) -> None:
        self.api_base_url = _validated_base_url(api_base_url, "API base URL")
        self.download_base_url = _validated_base_url(download_base_url, "download base URL")
        self.token = token
        self._no_redirect = urllib.request.build_opener(_NoRedirect())
        parsed_api = urllib.parse.urlsplit(self.api_base_url)
        if token and parsed_api.scheme != "https" and not _is_loopback_host(parsed_api.hostname or ""):
            raise ResolutionError("a GitHub token may be sent only over HTTPS or loopback HTTP")

    def _headers(self, *, authorize: bool, accept: str) -> dict[str, str]:
        headers = {
            "Accept": accept,
            "User-Agent": "wukongim-package-source-resolver/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if authorize and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def api_json(self, path: str) -> dict[str, Any]:
        url = f"{self.api_base_url}/{path.lstrip('/')}"
        request = urllib.request.Request(
            url,
            headers=self._headers(authorize=True, accept="application/vnd.github+json"),
            method="GET",
        )
        try:
            with self._no_redirect.open(request, timeout=30) as response:
                data = response.read(MAX_JSON_BYTES + 1)
        except (OSError, urllib.error.HTTPError) as error:
            raise ResolutionError(f"GitHub API read failed for {path}: {error}") from error
        if len(data) > MAX_JSON_BYTES:
            raise ResolutionError(f"GitHub API response is too large for {path}")
        try:
            return _require_object(json.loads(data), f"GitHub API response for {path}")
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ResolutionError(f"GitHub API returned invalid JSON for {path}") from error

    def open_asset(self, asset_id: int) -> BinaryIO:
        path = f"repos/{SOURCE_REPOSITORY}/releases/assets/{asset_id}"
        url = f"{self.download_base_url}/{path}"
        authorize = _origin(url) == _origin(self.api_base_url)
        request = urllib.request.Request(
            url,
            headers=self._headers(authorize=authorize, accept="application/octet-stream"),
            method="GET",
        )
        try:
            return self._no_redirect.open(request, timeout=60)
        except urllib.error.HTTPError as error:
            if error.code not in {301, 302, 303, 307, 308}:
                raise ResolutionError(f"asset {asset_id} download failed: HTTP {error.code}") from error
            location = error.headers.get("Location")
            if not location:
                raise ResolutionError(f"asset {asset_id} redirect omitted Location") from error
            redirected = urllib.parse.urljoin(url, location)
            parsed = urllib.parse.urlsplit(redirected)
            if parsed.scheme != "https" or not parsed.netloc:
                raise ResolutionError(f"asset {asset_id} redirected to an unsafe URL") from error
            redirected_request = urllib.request.Request(
                redirected,
                headers=self._headers(authorize=False, accept="application/octet-stream"),
                method="GET",
            )
            try:
                return urllib.request.urlopen(redirected_request, timeout=60)
            except (OSError, urllib.error.HTTPError) as redirected_error:
                raise ResolutionError(f"asset {asset_id} redirected download failed") from redirected_error
        except OSError as error:
            raise ResolutionError(f"asset {asset_id} download failed: {error}") from error


def _release_snapshot(release: dict[str, Any], release_id: int) -> dict[str, Any]:
    if release.get("id") != release_id:
        raise ResolutionError("source Release id does not match the requested numeric id")
    tag = _require_string(release.get("tag_name"), "source Release tag_name")
    version, tag_is_prerelease = parse_version(tag)
    if _require_bool(release.get("draft"), "source Release draft"):
        raise ResolutionError("source Release must already be published")
    if not _require_bool(release.get("immutable"), "source Release immutable"):
        raise ResolutionError("source Release must be immutable")
    if _require_bool(release.get("prerelease"), "source Release prerelease") != tag_is_prerelease:
        raise ResolutionError("source Release prerelease classification conflicts with SemVer")
    published_at = _require_string(release.get("published_at"), "source Release published_at")

    payload_names, checksum_name = expected_asset_names(version)
    expected_names = set(payload_names) | {checksum_name}
    assets_value = release.get("assets")
    if not isinstance(assets_value, list):
        raise ResolutionError("source Release assets must be an array")
    if len(assets_value) != len(expected_names):
        raise ResolutionError("source Release must contain exactly seven assets")

    assets: dict[str, dict[str, Any]] = {}
    asset_ids: set[int] = set()
    for raw_asset in assets_value:
        asset = _require_object(raw_asset, "source Release asset")
        name = _require_string(asset.get("name"), "source Release asset name")
        asset_id = asset.get("id")
        if not isinstance(asset_id, int) or isinstance(asset_id, bool) or asset_id <= 0:
            raise ResolutionError(f"source Release asset {name} has an invalid numeric id")
        if name in assets:
            raise ResolutionError(f"source Release contains duplicate asset name: {name}")
        if asset_id in asset_ids:
            raise ResolutionError(f"source Release contains duplicate asset id: {asset_id}")
        if name not in expected_names:
            raise ResolutionError(f"source Release contains unexpected asset: {name}")
        size = asset.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ResolutionError(f"source Release asset {name} has an invalid size")
        digest = _require_string(asset.get("digest"), f"source Release asset {name} digest")
        if not digest.startswith("sha256:") or not SHA256_RE.fullmatch(digest[7:]):
            raise ResolutionError(f"source Release asset {name} must have an API SHA-256 digest")
        assets[name] = {"id": asset_id, "name": name, "size": size, "sha256": digest[7:]}
        asset_ids.add(asset_id)
    if set(assets) != expected_names:
        raise ResolutionError("source Release asset names do not match the exact expected set")

    return {
        "id": release_id,
        "tag": tag,
        "version": version,
        "prerelease": tag_is_prerelease,
        "published_at": published_at,
        "payload_names": payload_names,
        "checksum_name": checksum_name,
        "assets": assets,
    }


def _peel_tag(reader: GitHubReader, tag: str) -> str:
    encoded_tag = urllib.parse.quote(tag, safe="")
    tag_ref = reader.api_json(f"repos/{SOURCE_REPOSITORY}/git/ref/tags/{encoded_tag}")
    if tag_ref.get("ref") != f"refs/tags/{tag}":
        raise ResolutionError("source tag ref does not match the Release tag")
    obj = _require_object(tag_ref.get("object"), "source tag object")
    seen: set[str] = set()
    for _ in range(8):
        object_type = _require_string(obj.get("type"), "source tag object type")
        object_sha = _require_sha1(obj.get("sha"), "source tag object sha")
        if object_sha in seen:
            raise ResolutionError("source tag object chain contains a cycle")
        seen.add(object_sha)
        if object_type == "commit":
            return object_sha
        if object_type != "tag":
            raise ResolutionError(f"source tag resolves to unsupported object type: {object_type}")
        tag_object = reader.api_json(f"repos/{SOURCE_REPOSITORY}/git/tags/{object_sha}")
        if _require_sha1(tag_object.get("sha"), "annotated source tag sha") != object_sha:
            raise ResolutionError("annotated source tag response does not match its requested sha")
        obj = _require_object(tag_object.get("object"), "annotated source tag object")
    raise ResolutionError("source tag object chain is too deep")


def _verify_main_ancestry(reader: GitHubReader, source_sha: str) -> str:
    branch = reader.api_json(f"repos/{SOURCE_REPOSITORY}/branches/main")
    commit = _require_object(branch.get("commit"), "main branch commit")
    main_sha = _require_sha1(commit.get("sha"), "main branch commit sha")
    comparison = reader.api_json(
        f"repos/{SOURCE_REPOSITORY}/compare/{source_sha}...{main_sha}"
    )
    merge_base = _require_object(comparison.get("merge_base_commit"), "comparison merge base")
    merge_base_sha = _require_sha1(merge_base.get("sha"), "comparison merge base sha")
    status_value = _require_string(comparison.get("status"), "comparison status")
    if merge_base_sha != source_sha or status_value not in {"ahead", "identical"}:
        raise ResolutionError("source tag commit is not reachable from main")
    return main_sha


def _download_asset(
    reader: GitHubReader, asset: dict[str, Any], destination: Path
) -> dict[str, Any]:
    expected_size = asset["size"]
    digest = hashlib.sha256()
    total = 0
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(destination, flags, 0o600)
    except OSError as error:
        raise ResolutionError(f"cannot create downloaded asset {asset['name']}: {error}") from error
    try:
        with os.fdopen(descriptor, "wb") as output, reader.open_asset(asset["id"]) as response:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > expected_size:
                    raise ResolutionError(f"downloaded asset exceeds API size: {asset['name']}")
                digest.update(chunk)
                output.write(chunk)
    except OSError as error:
        destination.unlink(missing_ok=True)
        raise ResolutionError(f"asset {asset['name']} local download write failed: {error}") from error
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    actual_sha256 = digest.hexdigest()
    if total != expected_size:
        destination.unlink(missing_ok=True)
        raise ResolutionError(f"downloaded asset size conflicts with API: {asset['name']}")
    if actual_sha256 != asset["sha256"]:
        destination.unlink(missing_ok=True)
        raise ResolutionError(f"downloaded asset digest conflicts with API: {asset['name']}")
    return {**asset, "downloaded_file": asset["name"]}


def _parse_checksum_closure(
    checksum_path: Path, payload_names: tuple[str, ...], downloaded: dict[str, dict[str, Any]]
) -> dict[str, str]:
    try:
        with checksum_path.open("r", encoding="utf-8", newline="") as stream:
            text = stream.read()
    except (OSError, UnicodeDecodeError) as error:
        raise ResolutionError("checksum asset must be valid UTF-8 text") from error
    if "\r" in text or not text.endswith("\n"):
        raise ResolutionError("checksum asset must use canonical LF-terminated lines")
    lines = text.splitlines()
    if len(lines) != len(payload_names):
        raise ResolutionError("checksum asset must contain exactly six payload entries")
    checksums: dict[str, str] = {}
    for line in lines:
        match = CHECKSUM_LINE_RE.fullmatch(line)
        if match is None:
            raise ResolutionError("checksum asset contains a non-canonical entry")
        sha256, name = match.groups()
        if name in checksums:
            raise ResolutionError(f"checksum asset contains duplicate entry: {name}")
        checksums[name] = sha256
    if set(checksums) != set(payload_names):
        raise ResolutionError("checksum asset does not exactly cover the six payload assets")
    for name in payload_names:
        if checksums[name] != downloaded[name]["sha256"]:
            raise ResolutionError(f"checksum asset digest conflicts with downloaded asset: {name}")
    return checksums


def resolve_source_release(
    *,
    release_id: int,
    output_dir: Path,
    api_base_url: str,
    download_base_url: str,
    token: str | None,
) -> dict[str, Any]:
    if not isinstance(release_id, int) or isinstance(release_id, bool) or release_id <= 0:
        raise ResolutionError("release id must be a positive integer")
    try:
        if os.path.lexists(output_dir):
            mode = output_dir.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode) or any(output_dir.iterdir()):
                raise ResolutionError(
                    "output directory must not exist or must be an empty real directory"
                )
            created_output = False
        else:
            output_dir.mkdir(mode=0o700, parents=False)
            created_output = True
    except OSError as error:
        raise ResolutionError(f"cannot prepare output directory: {error}") from error

    reader = GitHubReader(api_base_url, download_base_url, token)
    try:
        release_path = f"repos/{SOURCE_REPOSITORY}/releases/{release_id}"
        initial = _release_snapshot(reader.api_json(release_path), release_id)
        source_sha = _peel_tag(reader, initial["tag"])
        initial_main_sha = _verify_main_ancestry(reader, source_sha)

        downloaded: dict[str, dict[str, Any]] = {}
        for name in sorted(initial["assets"]):
            destination = output_dir / name
            downloaded[name] = _download_asset(reader, initial["assets"][name], destination)

        checksums = _parse_checksum_closure(
            output_dir / initial["checksum_name"], initial["payload_names"], downloaded
        )

        final = _release_snapshot(reader.api_json(release_path), release_id)
        if final != initial:
            raise ResolutionError("source Release identity or asset set changed during resolution")
        final_source_sha = _peel_tag(reader, final["tag"])
        if final_source_sha != source_sha:
            raise ResolutionError("source tag changed during resolution")
        final_main_sha = _verify_main_ancestry(reader, source_sha)

        receipt_assets = [downloaded[name] for name in sorted(downloaded)]
        return {
            "schema": RECEIPT_SCHEMA,
            "repository": SOURCE_REPOSITORY,
            "release_id": release_id,
            "tag": initial["tag"],
            "version": initial["version"],
            "prerelease": initial["prerelease"],
            "published_at": initial["published_at"],
            "source_sha": source_sha,
            "initial_main_sha": initial_main_sha,
            "final_main_sha": final_main_sha,
            "main_sha": final_main_sha,
            "asset_count": len(receipt_assets),
            "total_size": sum(asset["size"] for asset in receipt_assets),
            "assets": receipt_assets,
            "checksum_asset": initial["checksum_name"],
            "checksum_entries": [
                {"name": name, "sha256": checksums[name]}
                for name in sorted(checksums)
            ],
            "release_revalidated": True,
            "tag_revalidated": True,
            "main_ancestry_revalidated": True,
        }
    except Exception:
        if created_output:
            shutil.rmtree(output_dir, ignore_errors=True)
        else:
            for child in output_dir.iterdir():
                if child.is_file() and not child.is_symlink():
                    child.unlink(missing_ok=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Resolve one published immutable WuKongIM source Release without executing assets."
    )
    parser.add_argument("--release-id", required=True, type=int, help="numeric GitHub Release id")
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="new or empty directory that receives the seven opaque assets",
    )
    parser.add_argument(
        "--api-base-url",
        default="https://api.github.com",
        help="GitHub API base URL; override only for a controlled test fixture",
    )
    parser.add_argument(
        "--download-base-url",
        default=None,
        help="asset API base URL; defaults to --api-base-url",
    )
    parser.add_argument(
        "--token-env",
        default="GITHUB_TOKEN",
        help="environment variable containing a read-only GitHub token",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    download_base_url = args.download_base_url or args.api_base_url
    token = os.environ.get(args.token_env) if args.token_env else None
    try:
        receipt = resolve_source_release(
            release_id=args.release_id,
            output_dir=args.output_dir,
            api_base_url=args.api_base_url,
            download_base_url=download_base_url,
            token=token,
        )
    except ResolutionError as error:
        print(f"source Release resolution failed: {error}", file=sys.stderr)
        return 1
    json.dump(receipt, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
