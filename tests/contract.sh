#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT_DIR/manifests/channels.json"
WORKFLOW="$ROOT_DIR/.github/workflows/pages.yml"
DRILL_WORKFLOW="$ROOT_DIR/.github/workflows/native-package-repository-drill.yml"
SOURCE_PREFLIGHT="$ROOT_DIR/.github/workflows/source-release-preflight.yml"
AUDIT_DRAFT_WORKFLOW="$ROOT_DIR/.github/workflows/native-package-audit-draft.yml"
AUDIT_BIND_WORKFLOW="$ROOT_DIR/.github/workflows/native-package-audit-bind.yml"
PUBLISH_WORKFLOW="$ROOT_DIR/.github/workflows/native-package-publish.yml"
TOOLCHAIN_WORKFLOW="$ROOT_DIR/.github/workflows/native-package-signing-toolchain.yml"
TOOLCHAIN_DOCKERFILE="$ROOT_DIR/toolchain/native-package-signing/Dockerfile"

"$ROOT_DIR/scripts/validate-control.py"

jq -e '
  .schema == "wukongim.native_package_channels/v3" and
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
grep -Fq "format('packages-pages-pr-{0}', github.event.pull_request.number)" "$WORKFLOW"
grep -Fq "|| 'packages-pages'" "$WORKFLOW"
grep -Fq "github.event_name != 'pull_request'" "$WORKFLOW"
grep -Fq 'deploy_bootstrap: ${{ steps.control.outputs.deploy_bootstrap }}' "$WORKFLOW"
grep -Fq "if: steps.control.outputs.deploy_bootstrap == 'true'" "$WORKFLOW"
grep -Fq "needs.build.outputs.deploy_bootstrap == 'true'" "$WORKFLOW"
if (( $(grep -cF 'git ls-remote https://github.com/WuKongIM/packages.git refs/heads/main' "$WORKFLOW") != 2 )); then
  echo 'bootstrap deployment must fence protected main immediately before and after Pages deployment' >&2
  exit 1
fi

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

for workflow in \
  "$AUDIT_DRAFT_WORKFLOW" \
  "$AUDIT_BIND_WORKFLOW" \
  "$PUBLISH_WORKFLOW" \
  "$TOOLCHAIN_WORKFLOW"; do
  test -f "$workflow"
  grep -Fq 'workflow_dispatch:' "$workflow"
  grep -Fq 'permissions: {}' "$workflow"
  grep -Fq "github.repository == 'WuKongIM/packages'" "$workflow"
  grep -Fq "github.ref == 'refs/heads/main'" "$workflow"
  grep -Fq 'ref: ${{ github.sha }}' "$workflow"
  grep -Fq 'persist-credentials: false' "$workflow"
done

python3 - "$ROOT_DIR/.github/workflows" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
for workflow in sorted(root.glob("*.yml")):
    for line_number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), 1):
        match = re.search(r"\buses:\s*([^\s#]+)", line)
        if match and re.search(r"@[0-9a-f]{40}$", match.group(1)) is None:
            raise SystemExit(
                f"{workflow.name}:{line_number}: Action must use a 40-hex commit pin"
            )
PY

grep -Fq 'concurrency:' "$AUDIT_DRAFT_WORKFLOW"
grep -Fq 'group: packages-pages' "$AUDIT_DRAFT_WORKFLOW"
grep -Fq 'cancel-in-progress: false' "$AUDIT_DRAFT_WORKFLOW"
grep -Fq 'environment: native-package-preview-audit' "$AUDIT_DRAFT_WORKFLOW"
grep -Fq 'contents: write' "$AUDIT_DRAFT_WORKFLOW"
grep -Fq 'actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1' "$AUDIT_DRAFT_WORKFLOW"
grep -Fq 'client-id: ${{ secrets.WK_PACKAGE_PUBLISHER_APP_CLIENT_ID }}' "$AUDIT_DRAFT_WORKFLOW"
grep -Fq 'private-key: ${{ secrets.WK_PACKAGE_PUBLISHER_APP_PRIVATE_KEY }}' "$AUDIT_DRAFT_WORKFLOW"
grep -Fq 'permission-administration: read' "$AUDIT_DRAFT_WORKFLOW"
grep -Fq 'GH_TOKEN: ${{ steps.publisher-token.outputs.token }}' "$AUDIT_DRAFT_WORKFLOW"
grep -Fq 'expected_main_sha:' "$AUDIT_DRAFT_WORKFLOW"
grep -Fq 'native-package-preview-r${release_id}' "$AUDIT_DRAFT_WORKFLOW"
grep -Fq -- '--expected-control-sha "$GITHUB_SHA"' "$AUDIT_DRAFT_WORKFLOW"
grep -Fq -- '--expected-tag-state absent' "$AUDIT_DRAFT_WORKFLOW"
grep -Fq 'repos/WuKongIM/packages/immutable-releases' "$AUDIT_DRAFT_WORKFLOW"
grep -Fq './scripts/resolve-audit-release.py' "$AUDIT_DRAFT_WORKFLOW"
if grep -Eq 'gh release delete|--method DELETE|git push|refs/tags/v' "$AUDIT_DRAFT_WORKFLOW"; then
  echo 'audit draft workflow must not delete Releases or create product version tags' >&2
  exit 1
fi
if grep -Fq 'GH_TOKEN: ${{ github.token }}' "$AUDIT_DRAFT_WORKFLOW"; then
  echo 'audit draft writes and immutable policy checks require the package App token' >&2
  exit 1
fi

grep -Fq 'group: packages-pages' "$AUDIT_BIND_WORKFLOW"
grep -Fq 'cancel-in-progress: false' "$AUDIT_BIND_WORKFLOW"
grep -Fq 'environment: native-package-preview-audit' "$AUDIT_BIND_WORKFLOW"
grep -Fq 'contents: write' "$AUDIT_BIND_WORKFLOW"
grep -Fq 'actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1' "$AUDIT_BIND_WORKFLOW"
grep -Fq 'client-id: ${{ secrets.WK_PACKAGE_PUBLISHER_APP_CLIENT_ID }}' "$AUDIT_BIND_WORKFLOW"
grep -Fq 'private-key: ${{ secrets.WK_PACKAGE_PUBLISHER_APP_PRIVATE_KEY }}' "$AUDIT_BIND_WORKFLOW"
grep -Fq 'permission-administration: read' "$AUDIT_BIND_WORKFLOW"
grep -Fq 'GH_TOKEN: ${{ steps.publisher-token.outputs.token }}' "$AUDIT_BIND_WORKFLOW"
grep -Fq 'repos/WuKongIM/packages/immutable-releases' "$AUDIT_BIND_WORKFLOW"
grep -Fq 'git merge-base --is-ancestor' "$AUDIT_BIND_WORKFLOW"
grep -Fq '.channels.preview.publication.audit_release_id == $id' "$AUDIT_BIND_WORKFLOW"
grep -Fq './scripts/bind-audit-release.py' "$AUDIT_BIND_WORKFLOW"
grep -Fq -- '--expected-previous-control-sha "$EXPECTED_PREVIOUS_CONTROL_SHA"' "$AUDIT_BIND_WORKFLOW"
grep -Fq -- '--expected-control-sha "$GITHUB_SHA"' "$AUDIT_BIND_WORKFLOW"
grep -Fq -- '--expected-tag-state exact' "$AUDIT_BIND_WORKFLOW"
grep -Fq '.audit_tag_reserved == true' "$AUDIT_BIND_WORKFLOW"
grep -Fq '.classification == "empty_draft"' "$AUDIT_BIND_WORKFLOW"
if grep -Eq 'gh release delete|--method DELETE|git push|draft:[[:space:]]*false' "$AUDIT_BIND_WORKFLOW"; then
  echo 'audit bind workflow may only rebind an empty draft target' >&2
  exit 1
fi
if grep -Fq 'GH_TOKEN: ${{ github.token }}' "$AUDIT_BIND_WORKFLOW"; then
  echo 'audit bind writes and immutable policy checks require the package App token' >&2
  exit 1
fi

grep -Fq 'group: packages-pages' "$PUBLISH_WORKFLOW"
grep -Fq 'cancel-in-progress: false' "$PUBLISH_WORKFLOW"
grep -Fq 'environment: native-package-preview-apt-signing' "$PUBLISH_WORKFLOW"
grep -Fq 'environment: native-package-preview-rpm-signing' "$PUBLISH_WORKFLOW"
grep -Fq 'environment: native-package-preview-audit' "$PUBLISH_WORKFLOW"
grep -Fq 'environment: native-package-source-read' "$PUBLISH_WORKFLOW"
grep -Fq 'name: github-pages' "$PUBLISH_WORKFLOW"
grep -Fq 'actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1' "$PUBLISH_WORKFLOW"
grep -Fq 'permission-contents: read' "$PUBLISH_WORKFLOW"
grep -Fq 'permission-attestations: read' "$PUBLISH_WORKFLOW"
if (( $(grep -cF 'client-id: ${{ secrets.WK_PACKAGE_PUBLISHER_APP_CLIENT_ID }}' "$PUBLISH_WORKFLOW") != 3 ||
      $(grep -cF 'private-key: ${{ secrets.WK_PACKAGE_PUBLISHER_APP_PRIVATE_KEY }}' "$PUBLISH_WORKFLOW") != 3 ||
      $(grep -cF 'permission-administration: read' "$PUBLISH_WORKFLOW") != 3 ||
      $(grep -cF 'GH_TOKEN: ${{ steps.publisher-token.outputs.token }}' "$PUBLISH_WORKFLOW") != 4 ||
      $(grep -cF 'environment: native-package-preview-audit' "$PUBLISH_WORKFLOW") != 3 )); then
  echo 'publisher audit control, writer, and replay jobs must use scoped package App tokens' >&2
  exit 1
fi
grep -Fq 'WK_PACKAGE_PUBLISHER_APP_CLIENT_ID' "$ROOT_DIR/docs/release-contract.md"
grep -Fq 'Administration read and Contents' "$ROOT_DIR/docs/release-contract.md"
grep -Fq 'verify-production-package-site.py' "$PUBLISH_WORKFLOW"
grep -Fq 'validate-production-package-clients.py' "$PUBLISH_WORKFLOW"
grep -Fq 'seal-audit-release.py' "$PUBLISH_WORKFLOW"
grep -Fq 'resolve-audit-release.py' "$PUBLISH_WORKFLOW"
grep -Fq 'archive-package-snapshot.py' "$PUBLISH_WORKFLOW"
grep -Fq 'package-audit-receipt.py' "$PUBLISH_WORKFLOW"
grep -Fq -- '--network none' "$PUBLISH_WORKFLOW"
grep -Fq 'repos/WuKongIM/packages/immutable-releases' "$PUBLISH_WORKFLOW"
grep -Fq 'immutable Releases must remain enabled' "$ROOT_DIR/scripts/seal-audit-release.py"
grep -Fq 'source-attestations' "$PUBLISH_WORKFLOW"
grep -Fq -- '--signing-toolchain' "$PUBLISH_WORKFLOW"
grep -Fq 'native-package-public-snapshot-' "$PUBLISH_WORKFLOW"
grep -Fq -- '--snapshot "$snapshot"' "$PUBLISH_WORKFLOW"
grep -Fq '.snapshot_verified == true and .status_revalidated == true' "$PUBLISH_WORKFLOW"
if (( $(grep -cF -- '--expected-version "$TARGET_VERSION"' "$PUBLISH_WORKFLOW") != 2 )); then
  echo 'local and remote add_release clients must download the exact target version' >&2
  exit 1
fi
grep -Fq '.expected_version == $target and .expected_version_verified == true' "$PUBLISH_WORKFLOW"
grep -Fq 'https://raw.githubusercontent.com/WuKongIM/WuKongIM/${commit}/${relative}' "$PUBLISH_WORKFLOW"
grep -Fq -- '--connect-timeout 10 --max-time 30 --max-filesize 1048576' "$PUBLISH_WORKFLOW"
grep -Fq 'install --downloadonly' "$ROOT_DIR/scripts/validate-production-package-clients.py"
grep -Fq 'test "$(gh api repos/WuKongIM/packages/git/ref/heads/main --jq .object.sha)" = "$GITHUB_SHA"' "$PUBLISH_WORKFLOW"
grep -Fq 'actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e' "$PUBLISH_WORKFLOW"
if grep -Eq 'gh release delete|--method DELETE|git push|refs/tags/v|source-attestation-summary|--source-attestation-summary|repos/WuKongIM/WuKongIM/contents' "$PUBLISH_WORKFLOW"; then
  echo 'publisher must not delete Releases or create product version tags' >&2
  exit 1
fi

resolve_count="$(grep -cF 'resolve-audit-release.py' "$PUBLISH_WORKFLOW")"
exact_tag_count="$(grep -cF -- '--expected-tag-state exact' "$PUBLISH_WORKFLOW")"
if (( resolve_count == 0 || resolve_count != exact_tag_count )); then
  echo 'every publisher audit Release resolution must require the exact reserved tag' >&2
  exit 1
fi

python3 - "$PUBLISH_WORKFLOW" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
jobs = {}
current = None
for line in text.splitlines():
    match = re.match(r"^  ([a-zA-Z0-9_-]+):$", line)
    if match:
        current = match.group(1)
        jobs[current] = []
    elif current is not None:
        jobs[current].append(line)
for job, lines in jobs.items():
    body = "\n".join(lines)
    apt = "secrets.WK_APT_PREVIEW_" in body
    rpm = "secrets.WK_RPM_PREVIEW_" in body
    if apt and rpm:
        raise SystemExit(f"publisher job {job} exposes both APT and RPM signing secrets")
if set(job for job, lines in jobs.items() if "secrets.WK_APT_PREVIEW_" in "\n".join(lines)) != {"apt_sign"}:
    raise SystemExit("only apt_sign may read APT signing secrets")
if set(job for job, lines in jobs.items() if "secrets.WK_RPM_PREVIEW_" in "\n".join(lines)) != {"rpm_sign"}:
    raise SystemExit("only rpm_sign may read RPM signing secrets")
for job in ("apt_sign", "rpm_sign"):
    body = "\n".join(jobs[job])
    if body.count(
        "git ls-remote https://github.com/WuKongIM/packages.git refs/heads/main"
    ) != 2:
        raise SystemExit(
            f"publisher {job} must fence protected main immediately before and after signing"
        )
trusted = "\n".join(jobs.get("trusted_source_tools", []))
if "GH_TOKEN" in trusted or "gh api" in trusted:
    raise SystemExit("trusted source tools must be fetched without cross-repository credentials")
for required in (
    "scripts/build-native-package-repositories.sh",
    "scripts/verify-native-package-repositories.sh",
    "scripts/verify-native-package-metadata.py",
):
    if required not in trusted:
        raise SystemExit(f"trusted source tool boundary omits {required}")
for forbidden in (
    "scripts/generate-native-package-test-keyring.sh",
    "scripts/sign-native-package-repositories.sh",
    "scripts/validate-native-package-repositories-container.sh",
):
    if forbidden in trusted:
        raise SystemExit(f"production source tool boundary includes TEST ONLY file {forbidden}")
PY

test -f "$ROOT_DIR/scripts/verify-production-package-site.py"
grep -Fq 'RSAHEADER:armor' "$ROOT_DIR/scripts/verify-production-package-site.py"
grep -Fq 'SHA-256' "$ROOT_DIR/scripts/verify-production-package-site.py"
grep -Fq 'SHA-256' "$ROOT_DIR/scripts/sign-package-family.py"

grep -Fq 'environment: native-package-toolchain-publish' "$TOOLCHAIN_WORKFLOW"
grep -Fq 'artifact-metadata: write' "$TOOLCHAIN_WORKFLOW"
grep -Fq 'attestations: write' "$TOOLCHAIN_WORKFLOW"
grep -Fq 'id-token: write' "$TOOLCHAIN_WORKFLOW"
grep -Fq 'packages: write' "$TOOLCHAIN_WORKFLOW"
grep -Fq 'test "$CONFIRM_CONTROL_SHA" = "$GITHUB_SHA"' "$TOOLCHAIN_WORKFLOW"
grep -Fq 'actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6' "$TOOLCHAIN_WORKFLOW"
grep -Fq 'native-package-toolchain-push.log' "$TOOLCHAIN_WORKFLOW"
grep -Fq 'awk -v tag="control-$GITHUB_SHA:"' "$TOOLCHAIN_WORKFLOW"
grep -Fq 'NF == 5 && $1 == tag && $2 == "digest:" && $3 ~ /^sha256:[0-9a-f]{64}$/' "$TOOLCHAIN_WORKFLOW"
grep -Fq '{print $3}' "$TOOLCHAIN_WORKFLOW"
grep -Fq 'test "${#pushed_digests[@]}" -eq 1' "$TOOLCHAIN_WORKFLOW"
fixture_sha='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
fixture_digest='sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
parse_push_digest() {
  awk -v tag="control-$fixture_sha:" \
    'NF == 5 && $1 == tag && $2 == "digest:" && $3 ~ /^sha256:[0-9a-f]{64}$/ &&
     $4 == "size:" && $5 ~ /^[1-9][0-9]*$/ {print $3}'
}
test "$(printf 'control-%s: digest: %s size: 1234\n' \
  "$fixture_sha" "$fixture_digest" | parse_push_digest)" = "$fixture_digest"
test -z "$(printf 'control-%s: pushed %s size: 1234\n' \
  "$fixture_sha" "$fixture_digest" | parse_push_digest)"
test -z "$(printf 'control-%s: digest: %s size: 1234 trailing\n' \
  "$fixture_sha" "$fixture_digest" | parse_push_digest)"
if (( $(printf 'control-%s: digest: %s size: 1234\ncontrol-%s: digest: %s size: 1234\n' \
  "$fixture_sha" "$fixture_digest" "$fixture_sha" "$fixture_digest" \
  | parse_push_digest | wc -l) != 2 )); then
  echo 'toolchain push digest fixture did not preserve ambiguous duplicate summaries' >&2
  exit 1
fi
grep -Fq 'docker logout ghcr.io' "$TOOLCHAIN_WORKFLOW"
if (( $(grep -cF 'git ls-remote https://github.com/WuKongIM/packages.git refs/heads/main' "$TOOLCHAIN_WORKFLOW") != 4 )); then
  echo 'toolchain publication must fence protected main around image and provenance writes' >&2
  exit 1
fi
grep -Eq '^FROM ubuntu:24\.04@sha256:[0-9a-f]{64}$' "$TOOLCHAIN_DOCKERFILE"
grep -Fq 'USER 65532:65532' "$TOOLCHAIN_DOCKERFILE"

echo 'package repository contracts passed'
