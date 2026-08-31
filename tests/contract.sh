#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT_DIR/manifests/channels.json"
WORKFLOW="$ROOT_DIR/.github/workflows/pages.yml"

jq -e '
  .schema == "wukongim.native_package_channels/v1" and
  .site_limit_bytes == 943718400 and
  .max_online_versions == 3 and
  .architectures == ["amd64"] and
  (.channels.preview.enabled == false) and
  (.channels.stable.enabled == false) and
  (.channels.preview.releases == []) and
  (.channels.stable.releases == [])
' "$MANIFEST" >/dev/null

grep -Fq 'permissions: {}' "$WORKFLOW"
grep -Fq 'pages: write' "$WORKFLOW"
grep -Fq 'id-token: write' "$WORKFLOW"
grep -Fq 'cancel-in-progress: false' "$WORKFLOW"
grep -Fq 'persist-credentials: false' "$WORKFLOW"

if grep -REI --exclude=README.md --exclude=contract.sh \
  'BEGIN (PGP|OPENSSH|RSA|EC|DSA) PRIVATE KEY|BEGIN PGP PRIVATE KEY BLOCK|secret[-_ ]?(key|subkey)|passphrase' \
  "$ROOT_DIR/keys" "$ROOT_DIR/manifests" "$ROOT_DIR/site"; then
  echo 'private signing material is forbidden in tracked publication inputs' >&2
  exit 1
fi

limit_bytes="$(jq -r '.site_limit_bytes' "$MANIFEST")"
site_kib="$(du -sk "$ROOT_DIR/site" | awk '{print $1}')"
limit_kib="$((limit_bytes / 1024))"
((site_kib <= limit_kib)) || {
  echo "site snapshot is ${site_kib} KiB; limit is ${limit_kib} KiB" >&2
  exit 1
}

echo 'package repository contracts passed'
