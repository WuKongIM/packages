#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT_DIR/manifests/channels.json"
WORKFLOW="$ROOT_DIR/.github/workflows/pages.yml"
DRILL_WORKFLOW="$ROOT_DIR/.github/workflows/native-package-repository-drill.yml"
SOURCE_PREFLIGHT="$ROOT_DIR/.github/workflows/source-release-preflight.yml"

"$ROOT_DIR/scripts/validate-control.py"

jq -e '
  .schema == "wukongim.native_package_channels/v2" and
  .source_repository == "WuKongIM/WuKongIM" and
  .site_limit_bytes == 786432000 and
  .site_warning_bytes == 629145600 and
  .max_online_versions == 4 and
  .architectures == ["amd64"]
' "$MANIFEST" >/dev/null

grep -Fq 'permissions: {}' "$WORKFLOW"
grep -Fq 'pages: write' "$WORKFLOW"
grep -Fq 'id-token: write' "$WORKFLOW"
grep -Fq 'cancel-in-progress: false' "$WORKFLOW"
grep -Fq 'persist-credentials: false' "$WORKFLOW"
grep -Fq 'pull_request:' "$WORKFLOW"
grep -Fq "github.event_name != 'pull_request'" "$WORKFLOW"
grep -Fq 'deploy_bootstrap: ${{ steps.control.outputs.deploy_bootstrap }}' "$WORKFLOW"
grep -Fq "if: steps.control.outputs.deploy_bootstrap == 'true'" "$WORKFLOW"
grep -Fq "needs.build.outputs.deploy_bootstrap == 'true'" "$WORKFLOW"

grep -Fq 'permissions:' "$DRILL_WORKFLOW"
grep -Fq 'contents: read' "$DRILL_WORKFLOW"
grep -Fq 'persist-credentials: false' "$DRILL_WORKFLOW"
grep -Fq 'ref: ${{ steps.toolchain.outputs.commit }}' "$DRILL_WORKFLOW"
grep -Fq 'sha256sum --check --strict' "$DRILL_WORKFLOW"
grep -Fq 'go-version: "1.27.0"' "$DRILL_WORKFLOW"
grep -Fq 'go-version-file: .trusted/wukongim/go.mod' "$DRILL_WORKFLOW"
grep -Fq 'go install github.com/goreleaser/goreleaser/v2@v2.18.0' "$DRILL_WORKFLOW"
grep -Fq '"$install_dir/goreleaser" release --snapshot --clean --config .goreleaser.packages.yaml' "$DRILL_WORKFLOW"
grep -Fq 'validate-native-package-repositories-container.sh' "$DRILL_WORKFLOW"
grep -Fq 'TEST ONLY' "$DRILL_WORKFLOW"
drill_install_line="$(grep -nF 'go install github.com/goreleaser/goreleaser/v2@v2.18.0' "$DRILL_WORKFLOW" | cut -d: -f1)"
drill_source_go_line="$(grep -nF 'go-version-file: .trusted/wukongim/go.mod' "$DRILL_WORKFLOW" | cut -d: -f1)"
drill_build_line="$(grep -nF '"$install_dir/goreleaser" release --snapshot --clean --config .goreleaser.packages.yaml' "$DRILL_WORKFLOW" | cut -d: -f1)"
if (( drill_install_line >= drill_source_go_line || drill_source_go_line >= drill_build_line )); then
  echo 'repository drill must restore the source Go toolchain after installing GoReleaser and before building' >&2
  exit 1
fi
if grep -Eq 'secrets\.|contents: write|pages: write|id-token: write|goreleaser/goreleaser-action@' "$DRILL_WORKFLOW"; then
  echo 'TEST ONLY repository drill must remain credential-free' >&2
  exit 1
fi

grep -Fq "github.ref == 'refs/heads/main'" "$SOURCE_PREFLIGHT"
grep -Fq 'ref: ${{ github.sha }}' "$SOURCE_PREFLIGHT"
grep -Fq 'persist-credentials: false' "$SOURCE_PREFLIGHT"
grep -Fq 'environment: native-package-source-read' "$SOURCE_PREFLIGHT"
grep -Fq 'actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1' "$SOURCE_PREFLIGHT"
grep -Fq 'client-id: ${{ secrets.WK_SOURCE_READ_APP_CLIENT_ID }}' "$SOURCE_PREFLIGHT"
grep -Fq 'private-key: ${{ secrets.WK_SOURCE_READ_APP_PRIVATE_KEY }}' "$SOURCE_PREFLIGHT"
grep -Fq 'repositories: WuKongIM' "$SOURCE_PREFLIGHT"
grep -Fq 'permission-contents: read' "$SOURCE_PREFLIGHT"
grep -Fq 'permission-attestations: read' "$SOURCE_PREFLIGHT"
grep -Fq 'GH_TOKEN: ${{ steps.source-token.outputs.token }}' "$SOURCE_PREFLIGHT"
grep -Fq './scripts/resolve-source-release.py' "$SOURCE_PREFLIGHT"
grep -Fq './scripts/verify-source-attestations.py' "$SOURCE_PREFLIGHT"
grep -Fq "test \"\$(rpm -qp --queryformat '%{SIGPGP:pgpsig}'" "$SOURCE_PREFLIGHT"
grep -Fq 'retention-days: 30' "$SOURCE_PREFLIGHT"
if grep -Eq 'contents: write|pages: write|id-token: write' "$SOURCE_PREFLIGHT"; then
  echo 'source Release preflight must remain read-only' >&2
  exit 1
fi

echo 'package repository contracts passed'
