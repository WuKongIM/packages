#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT_DIR/manifests/channels.json"
WORKFLOW="$ROOT_DIR/.github/workflows/pages.yml"

jq -e '
  .schema == "wukongim.native_package_channels/v1" and
  .site_limit_bytes == 786432000 and
  .max_online_versions == 4 and
  .architectures == ["amd64"] and
  (.channels.preview.enabled == false) and
  (.channels.preview.releases == []) and
  (.channels.stable.enabled == false) and
  (.channels.stable.releases == []) and
  (((.channels.preview.releases + .channels.stable.releases) | length) <= .max_online_versions)
' "$MANIFEST" >/dev/null

grep -Fq 'permissions: {}' "$WORKFLOW"
grep -Fq 'pages: write' "$WORKFLOW"
grep -Fq 'id-token: write' "$WORKFLOW"
grep -Fq 'cancel-in-progress: false' "$WORKFLOW"
grep -Fq 'persist-credentials: false' "$WORKFLOW"
grep -Fq 'pull_request:' "$WORKFLOW"
grep -Fq "github.event_name != 'pull_request'" "$WORKFLOW"

if grep -REI --exclude=README.md --exclude=contract.sh \
  'BEGIN (PGP|OPENSSH|RSA|EC|DSA) PRIVATE KEY|BEGIN PGP PRIVATE KEY BLOCK|secret[-_ ]?(key|subkey)|passphrase' \
  "$ROOT_DIR/keys" "$ROOT_DIR/manifests" "$ROOT_DIR/site"; then
  echo 'private signing material is forbidden in tracked publication inputs' >&2
  exit 1
fi

python3 - "$ROOT_DIR/site" "$(jq -r '.site_limit_bytes' "$MANIFEST")" <<'PY'
import json
import os
import stat
import sys

root, limit_text = sys.argv[1:]
limit = int(limit_text)
total = 0
relative_files = []
for directory, directories, files in os.walk(root, followlinks=False):
    for name in directories + files:
        path = os.path.join(directory, name)
        mode = os.lstat(path).st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise SystemExit(f"site contains a link or special file: {path}")
    for name in files:
        path = os.path.join(directory, name)
        total += os.lstat(path).st_size
        relative_files.append(os.path.relpath(path, root))

if total > limit:
    raise SystemExit(f"site snapshot is {total} bytes; limit is {limit} bytes")

relative_files.sort()
if relative_files == ["index.html", "status.json"]:
    with open(os.path.join(root, "status.json"), encoding="utf-8") as stream:
        status = json.load(stream)
    if status != {
        "schema": "wukongim.native_package_repository_status/v1",
        "apt": False,
        "rpm": False,
        "reason": "signing_not_provisioned",
    }:
        raise SystemExit("bootstrap status must remain signing_not_provisioned")
else:
    raise SystemExit(
        "publication content is forbidden while signing is not provisioned: "
        + ", ".join(relative_files)
    )
PY

echo 'package repository contracts passed'
