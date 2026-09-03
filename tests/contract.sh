#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT_DIR/manifests/channels.json"
AUDIT_ACCESS_MANIFEST="$ROOT_DIR/manifests/audit-access.json"
WORKFLOW="$ROOT_DIR/.github/workflows/pages.yml"
DRILL_WORKFLOW="$ROOT_DIR/.github/workflows/native-package-repository-drill.yml"
SOURCE_PREFLIGHT="$ROOT_DIR/.github/workflows/source-release-preflight.yml"
AUDIT_DRAFT_WORKFLOW="$ROOT_DIR/.github/workflows/native-package-audit-draft.yml"
AUDIT_BIND_WORKFLOW="$ROOT_DIR/.github/workflows/native-package-audit-bind.yml"
PUBLISH_WORKFLOW="$ROOT_DIR/.github/workflows/native-package-publish.yml"
IMMUTABLE_REVERIFY_WORKFLOW="$ROOT_DIR/.github/workflows/native-package-immutable-public-reverify.yml"
TOOLCHAIN_WORKFLOW="$ROOT_DIR/.github/workflows/native-package-signing-toolchain.yml"
SIGNING_PREFLIGHT_WORKFLOW="$ROOT_DIR/.github/workflows/native-package-signing-preflight.yml"
TOOLCHAIN_DOCKERFILE="$ROOT_DIR/toolchain/native-package-signing/Dockerfile"
SOURCE_RESOLVER="$ROOT_DIR/scripts/resolve-source-release.py"
SNAPSHOT_ARCHIVER="$ROOT_DIR/scripts/archive-package-snapshot.py"
SITE_COMPOSER="$ROOT_DIR/scripts/compose-package-site.py"
BOOTSTRAP_MANIFEST="$ROOT_DIR/manifests/bootstrap-packages.json"
BOOTSTRAP_BUILDER="$ROOT_DIR/scripts/build-repository-bootstrap-packages.py"
CLIENT_VALIDATOR="$ROOT_DIR/scripts/validate-production-package-clients.py"

"$ROOT_DIR/scripts/validate-control.py"

[[ -x "$BOOTSTRAP_BUILDER" ]]
jq -e '
  . == {
    schema: "wukongim.native_package_bootstrap/v1",
    enabled: true,
    version: "1.0.0"
  }
' "$BOOTSTRAP_MANIFEST" >/dev/null

jq -e '
  .schema == "wukongim.native_package_channels/v3" and
  .source_repository == "WuKongIM/WuKongIM" and
  .site_limit_bytes == 786432000 and
  .site_warning_bytes == 629145600 and
  .max_online_versions == 4 and
  .architectures == ["amd64"]
' "$MANIFEST" >/dev/null

jq -e '
  .schema == "wukongim.native_package_audit_access/v1" and
  (.enabled | type) == "boolean" and
  .reader == {
    environment: "native-package-preview-audit-read",
    app_client_id_secret: "WK_PACKAGE_AUDIT_READER_APP_CLIENT_ID",
    app_private_key_secret: "WK_PACKAGE_AUDIT_READER_APP_PRIVATE_KEY",
    owner: "WuKongIM",
    repositories: ["packages"],
    permissions: {administration: "read"}
  } and
  .writer == {
    environment: "native-package-preview-audit",
    app_client_id_secret: "WK_PACKAGE_PUBLISHER_APP_CLIENT_ID",
    app_private_key_secret: "WK_PACKAGE_PUBLISHER_APP_PRIVATE_KEY",
    owner: "WuKongIM",
    repositories: ["packages"],
    permissions: {administration: "read", contents: "write"}
  }
' "$AUDIT_ACCESS_MANIFEST" >/dev/null

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
grep -Fq 'assert_metadata() {' "$SOURCE_PREFLIGHT"
grep -Fq 'release_core="${version%%-*}"' "$SOURCE_PREFLIGHT"
grep -Fq 'prerelease="${version#*-}"' "$SOURCE_PREFLIGHT"
grep -Fq 'expected_deb_version="${release_core}~${prerelease}"' "$SOURCE_PREFLIGHT"
grep -Fq "assert_metadata 'DEB version' \"\$expected_deb_version\" \"\$deb_version\"" "$SOURCE_PREFLIGHT"
grep -Fq "assert_metadata 'RPM SIGPGP' '(none)' \"\$rpm_signature_pgp\"" "$SOURCE_PREFLIGHT"
grep -Fq 'export LC_ALL=C' "$SOURCE_PREFLIGHT"
grep -Fq 'retention-days: 30' "$SOURCE_PREFLIGHT"
if grep -Fq '${version/-/~}' "$SOURCE_PREFLIGHT"; then
  echo 'source Release preflight must not use Bash tilde-expanding replacement syntax' >&2
  exit 1
fi
(
  version='3.1.0-rc.1-hotfix'
  release_core="${version%%-*}"
  prerelease="${version#*-}"
  expected_deb_version="${release_core}~${prerelease}"
  expected_rpm_version="${expected_deb_version//-/_}"
  test "$expected_deb_version" = '3.1.0~rc.1-hotfix'
  test "$expected_rpm_version" = '3.1.0~rc.1_hotfix'
)
if grep -Eq 'contents: write|pages: write|id-token: write' "$SOURCE_PREFLIGHT"; then
  echo 'source Release preflight must remain read-only' >&2
  exit 1
fi

for workflow in \
  "$AUDIT_DRAFT_WORKFLOW" \
  "$AUDIT_BIND_WORKFLOW" \
  "$PUBLISH_WORKFLOW" \
  "$IMMUTABLE_REVERIFY_WORKFLOW" \
  "$TOOLCHAIN_WORKFLOW" \
  "$SIGNING_PREFLIGHT_WORKFLOW"; do
  test -f "$workflow"
  grep -Fq 'workflow_dispatch:' "$workflow"
  grep -Fq 'permissions: {}' "$workflow"
  grep -Fq "github.repository == 'WuKongIM/packages'" "$workflow"
  grep -Fq "github.ref == 'refs/heads/main'" "$workflow"
  grep -Fq 'ref: ${{ github.sha }}' "$workflow"
  grep -Fq 'persist-credentials: false' "$workflow"
done

python3 - "$IMMUTABLE_REVERIFY_WORKFLOW" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
workflow = path.read_text(encoding="utf-8")

if workflow.count("\npermissions: {}\n") != 1:
    raise SystemExit("immutable public reverify must default to no token permissions")
dispatch = workflow.split("  workflow_dispatch:\n", 1)[1].split(
    "\npermissions: {}", 1
)[0]
inputs = re.findall(r"(?m)^      ([a-z][a-z0-9_]+):$", dispatch)
if inputs != ["expected_verifier_sha", "audit_release_id"]:
    raise SystemExit(
        f"immutable public reverify inputs must be exact and caller-minimal: {inputs}"
    )

jobs_text = workflow.split("\njobs:\n", 1)[1]
jobs = re.findall(r"(?m)^  ([a-z][a-z0-9_]*):$", jobs_text)
if jobs != ["reverify"]:
    raise SystemExit(f"immutable public reverify must contain one exact job: {jobs}")
job = jobs_text.split("  reverify:\n", 1)[1]
permission_match = re.search(
    r"(?m)^    permissions:\n((?:      [a-z-]+: (?:read|write)\n)+)", job
)
if permission_match is None:
    raise SystemExit("immutable public reverify lacks explicit job permissions")
permissions = dict(
    re.findall(r"(?m)^      ([a-z-]+): (read|write)$", permission_match.group(1))
)
if permissions != {"attestations": "read", "contents": "read", "packages": "read"}:
    raise SystemExit(
        f"immutable public reverify permissions escaped the read-only boundary: {permissions}"
    )

actions = re.findall(r"(?m)^\s+uses: ([^\s#]+)", job)
expected_actions = [
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
]
if actions != expected_actions:
    raise SystemExit(
        f"immutable public reverify actions must remain exact: {actions}"
    )

forbidden = re.compile(
    r"secrets\.|^[ \t]+environment:|(?:contents|packages|attestations|pages|id-token): write|"
    r"read-all|write-all|actions/(?:download-artifact|configure-pages|upload-pages-artifact|deploy-pages)@|"
    r"actions/create-github-app-token@|gh release|--method\s+(?:POST|PATCH|PUT|DELETE)|"
    r"git push|seal-audit-release|bind-audit-release|sign-package-family|"
    r"compose-package-site|archive-package-snapshot\.py create",
    re.MULTILINE,
)
match = forbidden.search(job)
if match is not None:
    raise SystemExit(
        f"immutable public reverify contains a forbidden write or credential path: {match.group(0)!r}"
    )

required = (
    "group: packages-pages",
    "cancel-in-progress: false",
    "ref: ${{ github.sha }}",
    "fetch-depth: 0",
    "persist-credentials: false",
    'test "$EXPECTED_VERIFIER_SHA" = "$GITHUB_SHA"',
    'git merge-base --is-ancestor "$snapshot_control_sha" "$GITHUB_SHA"',
    'snapshot_control_sha="$(jq -er \'.object.sha\' "$root/evidence/tag-initial.json")"',
    'test "$(jq -er \'.target_commitish\' "$release")" = "$snapshot_control_sha"',
    'git diff --name-status --no-renames "$snapshot_control_sha" "$GITHUB_SHA"',
    "$'A\\t.github/workflows/native-package-immutable-public-reverify.yml'",
    "$'M\\tscripts/validate-production-package-clients.py'",
    "$'M\\ttests/contract.sh'",
    "$'M\\ttests/test_validate_production_package_clients.py'",
    './scripts/validate-control.py --root "$historical"',
    'git show "$snapshot_control_sha:$path" >"$historical/$path"',
    'cmp -- "$historical/$path" "$path"',
    './scripts/resolve-audit-release.py',
    '--expected-control-sha "$snapshot_control_sha"',
    "--expected-tag-state exact",
    '.classification == "immutable_complete"',
    "./scripts/archive-package-snapshot.py extract",
    "./scripts/package-audit-receipt.py verify",
    "gh attestation verify",
    "--network none --read-only --cap-drop ALL",
    "python3 /current/scripts/verify-production-package-site.py",
    "fetch_and_compare status.json",
    "fetch_and_compare apt/dists/preview/Release",
    "fetch_and_compare rpm/preview/el/9/x86_64/repodata/repomd.xml",
    "fetch_and_compare keys/apt-preview.asc",
    "fetch_and_compare keys/rpm-preview.asc",
    "python3 scripts/validate-production-package-clients.py",
    "--base-url https://packages.githubim.com",
    '.control_sha == $control and .snapshot_sha256 == $snapshot',
    '(.apt | length) == 2 and (.rpm | length) == 2',
    'artifact_control_sha:$artifact_control_sha',
    'verifier_sha:$verifier_sha',
    'cmp -- "$root/evidence/release-initial.json" "$root/evidence/release-final.json"',
    'cmp -- "$root/evidence/tag-initial.json" "$root/evidence/tag-final.json"',
    "retention-days: 90",
    "git diff --exit-code HEAD --",
)
missing = [value for value in required if value not in workflow]
if missing:
    raise SystemExit(
        f"immutable public reverify omits required fail-closed evidence: {missing}"
    )

if workflow.count(
    'test "$(gh api repos/WuKongIM/packages/git/ref/heads/main --jq .object.sha)" = "$GITHUB_SHA"'
) != 2:
    raise SystemExit("immutable public reverify must fence protected main twice")
final_tag_cmp = workflow.index(
    'cmp -- "$root/evidence/tag-initial.json" "$root/evidence/tag-final.json"'
)
final_main_fence = workflow.rindex(
    'test "$(gh api repos/WuKongIM/packages/git/ref/heads/main --jq .object.sha)" = "$GITHUB_SHA"'
)
if final_main_fence <= final_tag_cmp:
    raise SystemExit(
        "immutable public reverify must fence main after its final Release and tag reads"
    )
if workflow.count("./scripts/resolve-audit-release.py") != 1:
    raise SystemExit("immutable public reverify must resolve the numeric Release exactly once")
if '--expected-control-sha "$GITHUB_SHA"' in workflow:
    raise SystemExit("immutable artifact resolution must not conflate artifact and verifier SHAs")
if "/artifact-control/scripts" in workflow or "/artifact-control/tests" in workflow:
    raise SystemExit("immutable public reverify may not execute historical code")
if workflow.count("https://packages.githubim.com") != 2:
    raise SystemExit("immutable public reverify must use only the fixed production endpoint")

historical_match = re.search(
    r"historical_paths=\(\n(?P<body>.*?)^          \)\n", workflow, re.MULTILINE | re.DOTALL
)
if historical_match is None:
    raise SystemExit("immutable public reverify lacks its historical data allowlist")
historical_paths = [line.strip() for line in historical_match.group("body").splitlines()]
expected_historical_paths = [
    "keys/README.md",
    "keys/apt-preview.asc",
    "keys/rpm-preview.asc",
    "manifests/audit-access.json",
    "manifests/channels.json",
    "manifests/preview-signing.json",
    "manifests/signing-toolchain.json",
    "manifests/source-read.json",
    "manifests/trusted-toolchain.json",
    "site/index.html",
    "site/status.json",
]
if historical_paths != expected_historical_paths:
    raise SystemExit(
        f"immutable public reverify historical data allowlist changed: {historical_paths}"
    )

identity_match = re.search(
    r"identity_paths=\(\n(?P<body>.*?)^          \)\n", workflow, re.MULTILINE | re.DOTALL
)
if identity_match is None:
    raise SystemExit("immutable public reverify lacks its byte-identity allowlist")
identity_paths = [line.strip() for line in identity_match.group("body").splitlines()]
expected_identity_paths = [
    "manifests/channels.json",
    "manifests/preview-signing.json",
    "manifests/signing-toolchain.json",
    "manifests/trusted-toolchain.json",
    "keys/apt-preview.asc",
    "keys/rpm-preview.asc",
]
if identity_paths != expected_identity_paths:
    raise SystemExit(
        f"immutable public reverify identity allowlist changed: {identity_paths}"
    )
PY

grep -Fq 'group: native-package-preview-signing-preflight' "$SIGNING_PREFLIGHT_WORKFLOW"
grep -Fq 'cancel-in-progress: false' "$SIGNING_PREFLIGHT_WORKFLOW"
grep -Fq 'confirm_control_sha:' "$SIGNING_PREFLIGHT_WORKFLOW"
grep -Fq '[[ "$CONFIRM_CONTROL_SHA" =~ ^[0-9a-f]{40}$ ]]' "$SIGNING_PREFLIGHT_WORKFLOW"
if (( $(grep -cF 'test "$CONFIRM_CONTROL_SHA" = "$GITHUB_SHA"' "$SIGNING_PREFLIGHT_WORKFLOW") != 1 )); then
  echo 'signing-material preflight control must confirm the exact control commit' >&2
  exit 1
fi
if (( $(grep -cF 'environment: native-package-preview-apt-signing' "$SIGNING_PREFLIGHT_WORKFLOW") != 1 ||
      $(grep -cF 'environment: native-package-preview-rpm-signing' "$SIGNING_PREFLIGHT_WORKFLOW") != 1 ||
      $(grep -cF 'validate-signing-material.py' "$SIGNING_PREFLIGHT_WORKFLOW") != 2 ||
      $(grep -cF 'gh attestation verify' "$SIGNING_PREFLIGHT_WORKFLOW") != 2 ||
      $(grep -cF -- '--deny-self-hosted-runners' "$SIGNING_PREFLIGHT_WORKFLOW") != 2 ||
      $(grep -cF -- '--pull never' "$SIGNING_PREFLIGHT_WORKFLOW") != 2 ||
      $(grep -cF -- '--network none' "$SIGNING_PREFLIGHT_WORKFLOW") != 2 ||
      $(grep -cF -- '--read-only --cap-drop ALL' "$SIGNING_PREFLIGHT_WORKFLOW") != 2 ||
      $(grep -cF -- '--volume "$GITHUB_WORKSPACE:/control:ro"' "$SIGNING_PREFLIGHT_WORKFLOW") != 2 ||
      $(grep -cF 'git ls-remote https://github.com/WuKongIM/packages.git refs/heads/main' "$SIGNING_PREFLIGHT_WORKFLOW") != 5 )); then
  echo 'signing-material preflight must preserve exact family isolation, provenance, offline validation, and main fences' >&2
  exit 1
fi
grep -Fq 'trap '\''docker logout ghcr.io >/dev/null 2>&1 || true'\'' EXIT' "$SIGNING_PREFLIGHT_WORKFLOW"
if (( $(grep -cF 'test "$(git rev-parse HEAD)" = "$CONTROL_SHA"' "$SIGNING_PREFLIGHT_WORKFLOW") != 4 ||
      $(grep -cF 'git diff --exit-code HEAD --' "$SIGNING_PREFLIGHT_WORKFLOW") != 5 ||
      $(grep -cF 'test -z "$(git status --short --untracked-files=all)"' "$SIGNING_PREFLIGHT_WORKFLOW") != 2 )); then
  echo 'signing-material preflight must prove a clean exact checkout before exposing either secret' >&2
  exit 1
fi
if grep -Eq 'actions/(upload|download)-artifact@|actions/upload-pages-artifact@|actions/deploy-pages@|actions/create-github-app-token@|gh release|gh api|git push|refs/tags/|contents: write|packages: write|attestations: write|artifact-metadata: write|id-token: write|pages: write|secrets\.WK_PACKAGE_|sign-package-family\.py|GITHUB_STEP_SUMMARY' "$SIGNING_PREFLIGHT_WORKFLOW"; then
  echo 'signing-material preflight must remain proof-only and read-only' >&2
  exit 1
fi
if grep -Eq -- '--volume [^[:space:]]+:rw' "$SIGNING_PREFLIGHT_WORKFLOW"; then
  echo 'signing-material preflight must not persist secret-step output through a writable bind mount' >&2
  exit 1
fi

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
grep -Fq 'Validate reviewed audit access before credentials' "$AUDIT_DRAFT_WORKFLOW"
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
grep -Fq 'Validate reviewed audit access before credentials' "$AUDIT_BIND_WORKFLOW"
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
grep -Fq '.release_tag_repaired | type' "$AUDIT_BIND_WORKFLOW"
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
grep -Fq 'Validate reviewed audit access before credentials' "$PUBLISH_WORKFLOW"
grep -Fq 'environment: native-package-preview-apt-signing' "$PUBLISH_WORKFLOW"
grep -Fq 'environment: native-package-preview-rpm-signing' "$PUBLISH_WORKFLOW"
grep -Eq '^[[:space:]]+environment: native-package-preview-audit-read$' "$PUBLISH_WORKFLOW"
grep -Eq '^[[:space:]]+environment: native-package-preview-audit$' "$PUBLISH_WORKFLOW"
grep -Fq 'environment: native-package-source-read' "$PUBLISH_WORKFLOW"
grep -Fq 'name: github-pages' "$PUBLISH_WORKFLOW"
grep -Fq 'release_core="${TARGET_VERSION%%-*}"' "$PUBLISH_WORKFLOW"
grep -Fq 'prerelease="${TARGET_VERSION#*-}"' "$PUBLISH_WORKFLOW"
grep -Fq 'deb_version="${release_core}~${prerelease}"' "$PUBLISH_WORKFLOW"
grep -Fq 'rpm_version="${deb_version//-/_}"' "$PUBLISH_WORKFLOW"
if grep -Fq '${TARGET_VERSION/-/~}' "$PUBLISH_WORKFLOW"; then
  echo 'publisher must not use Bash tilde-expanding replacement syntax' >&2
  exit 1
fi
for TARGET_VERSION in '3.0.0-beta.6' '3.1.0-rc.1-hotfix'; do
  release_core="${TARGET_VERSION%%-*}"
  prerelease="${TARGET_VERSION#*-}"
  deb_version="${release_core}~${prerelease}"
  rpm_version="${deb_version//-/_}"
  case "$TARGET_VERSION" in
    3.0.0-beta.6)
      test "$deb_version" = '3.0.0~beta.6'
      test "$rpm_version" = '3.0.0~beta.6'
      ;;
    3.1.0-rc.1-hotfix)
      test "$deb_version" = '3.1.0~rc.1-hotfix'
      test "$rpm_version" = '3.1.0~rc.1_hotfix'
      ;;
  esac
done
grep -Fq 'actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1' "$PUBLISH_WORKFLOW"
grep -Fq 'permission-contents: read' "$PUBLISH_WORKFLOW"
grep -Fq 'permission-attestations: read' "$PUBLISH_WORKFLOW"
if (( $(grep -cF 'client-id: ${{ secrets.WK_PACKAGE_AUDIT_READER_APP_CLIENT_ID }}' "$PUBLISH_WORKFLOW") != 2 ||
      $(grep -cF 'private-key: ${{ secrets.WK_PACKAGE_AUDIT_READER_APP_PRIVATE_KEY }}' "$PUBLISH_WORKFLOW") != 2 ||
      $(grep -cF 'environment: native-package-preview-audit-read' "$PUBLISH_WORKFLOW") != 2 ||
      $(grep -cF 'IMMUTABLE_POLICY_TOKEN: ${{ steps.audit-reader-token.outputs.token }}' "$PUBLISH_WORKFLOW") != 2 ||
      $(grep -cF 'client-id: ${{ secrets.WK_PACKAGE_PUBLISHER_APP_CLIENT_ID }}' "$PUBLISH_WORKFLOW") != 2 ||
      $(grep -cF 'private-key: ${{ secrets.WK_PACKAGE_PUBLISHER_APP_PRIVATE_KEY }}' "$PUBLISH_WORKFLOW") != 2 ||
      $(grep -cF 'permission-administration: read' "$PUBLISH_WORKFLOW") != 3 ||
      $(grep -cF 'GH_TOKEN: ${{ steps.publisher-token.outputs.token }}' "$PUBLISH_WORKFLOW") != 3 ||
      $(grep -cE '^[[:space:]]+environment: native-package-preview-audit$' "$PUBLISH_WORKFLOW") != 2 )); then
  echo 'publisher reader and writer jobs must use isolated package App credentials' >&2
  exit 1
fi
grep -Fq 'WK_PACKAGE_AUDIT_READER_APP_CLIENT_ID' "$ROOT_DIR/docs/release-contract.md"
grep -Fq 'WK_PACKAGE_PUBLISHER_APP_CLIENT_ID' "$ROOT_DIR/docs/release-contract.md"
grep -Fq 'Administration read permission only' "$ROOT_DIR/docs/release-contract.md"
grep -Fq 'Administration read and Contents' "$ROOT_DIR/docs/release-contract.md"
grep -Fq 'distinct private keys' "$ROOT_DIR/docs/release-contract.md"
grep -Fq 'verify-production-package-site.py' "$PUBLISH_WORKFLOW"
grep -Fq 'validate-production-package-clients.py' "$PUBLISH_WORKFLOW"
grep -Fq 'seal-audit-release.py' "$PUBLISH_WORKFLOW"
grep -Fq 'resolve-audit-release.py' "$PUBLISH_WORKFLOW"
grep -Fq 'archive-package-snapshot.py' "$PUBLISH_WORKFLOW"
grep -Fq 'package-audit-receipt.py' "$PUBLISH_WORKFLOW"
grep -Fq -- '--network none' "$PUBLISH_WORKFLOW"
grep -Fq -- '--volume "$source_dir:/source:ro"' "$PUBLISH_WORKFLOW"
grep -Fq 'os.chmod(asset, 0o444)' "$SOURCE_RESOLVER"
grep -Fq 'os.chmod(output_dir, 0o555)' "$SOURCE_RESOLVER"
grep -Fq 'os.fchmod(output_root_descriptor, 0o755)' "$SNAPSHOT_ARCHIVER"
grep -Fq 'os.chmod(stage, 0o755)' "$SITE_COMPOSER"
python3 - "$PUBLISH_WORKFLOW" <<'PY'
import pathlib
import re
import sys

pattern = re.compile(
    r"(?:^|[ \t])--user(?:=|[ \t])"
    r"|^[ \t]*-u(?:=|[ \t])"
    r"|docker(?:[ \t]+container)?[ \t]+run[^\n]*[ \t]-u(?:=|[ \t])",
    re.MULTILINE,
)
examples = (
    "docker run --user=0:0 image",
    "docker run --user nobody image",
    "docker run -u 0 image",
    "docker container run -u 1001:1001 image",
    "docker run \\\n  -u=65532:65532 image",
)
if any(pattern.search(example) is None for example in examples):
    raise SystemExit("container USER override detector misses a required spelling")
workflow = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
if pattern.search(workflow) is not None:
    raise SystemExit(
        "publisher must not override the fixed non-root signing toolchain USER"
    )
PY
python3 - "$PUBLISH_WORKFLOW" <<'PY'
import pathlib
import re
import sys

workflow = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
job_markers = list(re.finditer(r"(?m)^  ([a-z][a-z0-9_]*):\n", workflow))
jobs = {}
for index, marker in enumerate(job_markers):
    end = job_markers[index + 1].start() if index + 1 < len(job_markers) else len(workflow)
    jobs[marker.group(1)] = workflow[marker.start():end]

required_conditions = {
    "apt_sign": (
        "always() && needs.control.result == 'success' && "
        "needs.prepare.result == 'success' && "
        "needs.control.outputs.classification == 'empty_draft'"
    ),
    "rpm_sign": (
        "always() && needs.control.result == 'success' && "
        "needs.prepare.result == 'success' && "
        "needs.control.outputs.classification == 'empty_draft'"
    ),
    "pages_artifact": (
        "always() && needs.control.result == 'success' && "
        "needs.sealed.result == 'success'"
    ),
    "deploy": (
        "always() && needs.control.result == 'success' && "
        "needs.pages_artifact.result == 'success' && "
        "needs.pages_artifact.outputs.deploy_needed == 'true'"
    ),
    "postverify": (
        "always() && needs.control.result == 'success' && "
        "needs.pages_artifact.result == 'success' && "
        "(needs.pages_artifact.outputs.deploy_needed != 'true' || "
        "needs.deploy.result == 'success')"
    ),
}
required_needs = {
    "apt_sign": {"control", "prepare"},
    "rpm_sign": {"control", "prepare"},
    "pages_artifact": {"control", "sealed"},
    "deploy": {"control", "pages_artifact"},
    "postverify": {"control", "pages_artifact", "deploy"},
}
for job, expected_condition in required_conditions.items():
    block = jobs.get(job)
    if block is None:
        raise SystemExit(f"publisher is missing required job: {job}")
    needs_match = re.search(r"(?m)^    needs:\n((?:      - [a-z][a-z0-9_]*\n)+)", block)
    if needs_match is None:
        raise SystemExit(f"publisher job must have a multiline needs list: {job}")
    needs = set(re.findall(r"(?m)^      - ([a-z][a-z0-9_]*)$", needs_match.group(1)))
    if needs != required_needs[job]:
        raise SystemExit(
            f"publisher job {job} has unexpected dependencies: {sorted(needs)}"
        )
    condition_match = re.search(r"(?m)^    if: >-\n((?:      .*\n)+)", block)
    if condition_match is None:
        raise SystemExit(f"publisher job must have a multiline condition: {job}")
    condition = " ".join(condition_match.group(1).split())
    if condition != expected_condition:
        raise SystemExit(
            f"publisher job {job} has an unexpected condition: {condition}"
        )
PY
grep -Fq 'repos/WuKongIM/packages/immutable-releases' "$PUBLISH_WORKFLOW"
grep -Fq 'immutable Releases must remain enabled' "$ROOT_DIR/scripts/seal-audit-release.py"
grep -Fq 'source-attestations' "$PUBLISH_WORKFLOW"
grep -Fq -- '--signing-toolchain' "$PUBLISH_WORKFLOW"
grep -Fq 'native-package-public-snapshot-' "$PUBLISH_WORKFLOW"
grep -Fq -- '--snapshot "$snapshot"' "$PUBLISH_WORKFLOW"
grep -Fq '.snapshot_verified == true and .status_revalidated == true' "$PUBLISH_WORKFLOW"
python3 - "$PUBLISH_WORKFLOW" <<'PY'
import json
import pathlib
import re
import subprocess
import sys

workflow = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
start = '          elif [[ -z "$BASE_AUDIT_RELEASE_ID" ]] && jq -e \\\n'
end = '            "$remote" >/dev/null; then'
if workflow.count(start) != 1:
    raise SystemExit("publisher must contain exactly one first-bootstrap jq gate")
fragment = workflow.split(start, 1)[1].split(end, 1)[0]
match = re.fullmatch(r"\s*'(?P<predicate>[^']+)' \\\n", fragment, re.DOTALL)
if match is None:
    raise SystemExit("publisher first-bootstrap jq gate has an unexpected shape")
predicate = match.group("predicate")
expected = (
    'keys == ["apt", "reason", "rpm", "schema"] and '
    '.schema == "wukongim.native_package_repository_status/v1" and '
    '.apt == false and .rpm == false and .reason == "awaiting_first_release"'
)
if " ".join(predicate.split()) != expected:
    raise SystemExit("publisher first-bootstrap jq predicate is not the exact reviewed contract")

cases = (
    ({"schema": "wukongim.native_package_repository_status/v1", "apt": False,
      "rpm": False, "reason": "awaiting_first_release"}, True),
    ({"schema": "wukongim.native_package_repository_status/v1", "apt": False,
      "rpm": False, "reason": "signing_not_provisioned"}, False),
    ({"schema": "wukongim.native_package_repository_status/v1", "apt": False,
      "rpm": False, "reason": "ready"}, False),
    ({"schema": "wukongim.native_package_repository_status/v2", "apt": False,
      "rpm": False, "reason": "awaiting_first_release"}, False),
    ({"schema": "wukongim.native_package_repository_status/v1", "apt": False,
      "rpm": False, "reason": "awaiting_first_release", "extra": True}, False),
)
for value, accepted in cases:
    result = subprocess.run(
        ["jq", "-e", predicate],
        input=json.dumps(value),
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    if (result.returncode == 0) != accepted:
        raise SystemExit(f"first-bootstrap predicate misclassified {value!r}")
PY
if (( $(grep -cF -- '--expected-version "$TARGET_VERSION"' "$PUBLISH_WORKFLOW") != 4 )); then
  echo 'local and remote add_release/update_bootstrap clients must download the exact target version' >&2
  exit 1
fi
grep -Fq '.expected_version == $target and .expected_version_verified == true' "$PUBLISH_WORKFLOW"
grep -Fq '.schema == "wukongim/production-package-client-validation/v3"' "$PUBLISH_WORKFLOW"
grep -Fq '.bootstrap_verified == true and .bootstrap != null' "$PUBLISH_WORKFLOW"
grep -Fq 'all((.apt[], .rpm[]); .bootstrap_installed == true)' "$PUBLISH_WORKFLOW"
grep -Fq -- '--bootstrap-builder /control/scripts/build-repository-bootstrap-packages.py' "$PUBLISH_WORKFLOW"
grep -Fq -- '--bootstrap-inventory /metadata/bootstrap-inventory.json' "$PUBLISH_WORKFLOW"
grep -Fq 'fetch_and_check bootstrap/manifest.json "$BOOTSTRAP_MANIFEST_SHA256"' "$PUBLISH_WORKFLOW"
grep -Fq 'update_bootstrap' "$AUDIT_DRAFT_WORKFLOW"
grep -Fq 'update_bootstrap' "$PUBLISH_WORKFLOW"
grep -Fq 'https://raw.githubusercontent.com/WuKongIM/WuKongIM/${commit}/${relative}' "$PUBLISH_WORKFLOW"
grep -Fq -- '--connect-timeout 10 --max-time 30 --max-filesize 1048576' "$PUBLISH_WORKFLOW"
grep -Fq 'install --downloadonly' "$CLIENT_VALIDATOR"
grep -Fq 'APT_CA_BUNDLE_PATH = "/etc/ssl/certs/ca-certificates.crt"' \
  "$CLIENT_VALIDATOR"
grep -Fq 'Acquire::https::CaInfo="$WK_CA_BUNDLE"' \
  "$CLIENT_VALIDATOR"
grep -Fq 'command.extend(("--env", f"WK_CA_BUNDLE={APT_CA_BUNDLE_PATH}"))' \
  "$CLIENT_VALIDATOR"
grep -Fq 'list(command), check=True, stdout=sys.stderr, stderr=sys.stderr' \
  "$CLIENT_VALIDATOR"
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

python3 - "$ROOT_DIR/.github/workflows" "$PUBLISH_WORKFLOW" \
  "$ROOT_DIR/scripts/resolve-audit-release.py" <<'PY'
import ast
import pathlib
import re
import sys

workflow_root = pathlib.Path(sys.argv[1])
publish_path = pathlib.Path(sys.argv[2])
audit_resolver_path = pathlib.Path(sys.argv[3])

resolver_tree = ast.parse(
    audit_resolver_path.read_text(encoding="utf-8"), filename=str(audit_resolver_path)
)
request_calls = [
    node
    for node in ast.walk(resolver_tree)
    if isinstance(node, ast.Call)
    and isinstance(node.func, ast.Attribute)
    and node.func.attr == "Request"
]
if len(request_calls) != 3:
    raise SystemExit("audit resolver must contain exactly three reviewed HTTP requests")
for call in request_calls:
    methods = [keyword.value for keyword in call.keywords if keyword.arg == "method"]
    if len(methods) != 1 or not isinstance(methods[0], ast.Constant) or methods[0].value != "GET":
        raise SystemExit("every audit resolver HTTP request must be an explicit GET")


def parse_jobs(path):
    jobs = {}
    current = None
    in_jobs = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "jobs:":
            in_jobs = True
            continue
        if not in_jobs:
            continue
        match = re.match(r"^  ([a-zA-Z0-9_-]+):$", line)
        if match:
            current = match.group(1)
            jobs[current] = []
        elif current is not None:
            jobs[current].append(line)
    return jobs


def has_environment(body, name):
    return re.search(
        rf"^\s+environment:\s+{re.escape(name)}\s*$", body, re.MULTILINE
    ) is not None


workflow_jobs = {
    path.name: parse_jobs(path) for path in sorted(workflow_root.glob("*.yml"))
}
all_jobs = {
    (workflow, job): "\n".join(lines)
    for workflow, jobs in workflow_jobs.items()
    for job, lines in jobs.items()
}

reader_expected = {
    ("native-package-publish.yml", "policy"),
    ("native-package-publish.yml", "immutable_passthrough"),
}
reader_jobs = {
    identity
    for identity, body in all_jobs.items()
    if has_environment(body, "native-package-preview-audit-read")
    or "WK_PACKAGE_AUDIT_READER_APP_CLIENT_ID" in body
    or "WK_PACKAGE_AUDIT_READER_APP_PRIVATE_KEY" in body
}
if reader_jobs != reader_expected:
    raise SystemExit(
        f"package Audit Reader credentials escaped exact read jobs: {sorted(reader_jobs)}"
    )

writer_expected = {
    ("native-package-audit-draft.yml", "prepare"),
    ("native-package-audit-bind.yml", "bind"),
    ("native-package-publish.yml", "audit_release"),
    ("native-package-publish.yml", "seal_draft"),
}
writer_jobs = {
    identity
    for identity, body in all_jobs.items()
    if has_environment(body, "native-package-preview-audit")
    or "WK_PACKAGE_PUBLISHER_APP_CLIENT_ID" in body
    or "WK_PACKAGE_PUBLISHER_APP_PRIVATE_KEY" in body
}
if writer_jobs != writer_expected:
    raise SystemExit(
        f"package Publisher credentials escaped exact write jobs: {sorted(writer_jobs)}"
    )

credential_jobs = reader_expected | writer_expected
for identity in credential_jobs:
    body = all_jobs[identity]
    gate = "Validate reviewed audit access before credentials"
    mint = "actions/create-github-app-token@"
    if body.count(gate) != 1 or body.count("validate-control.py") != 1:
        raise SystemExit(f"credential job {identity} lacks one audit-access validator gate")
    if body.count("audit-access.json") != 1 or ".enabled == true" not in body:
        raise SystemExit(f"credential job {identity} lacks fail-closed audit enablement")
    if body.index(gate) > body.index(mint):
        raise SystemExit(f"credential job {identity} validates audit access after minting")

for identity in reader_expected:
    body = all_jobs[identity]
    if not has_environment(body, "native-package-preview-audit-read"):
        raise SystemExit(f"Audit Reader job {identity} lacks its protected Environment")
    reader_client = "client-id: ${{ secrets.WK_PACKAGE_AUDIT_READER_APP_CLIENT_ID }}"
    reader_key = "private-key: ${{ secrets.WK_PACKAGE_AUDIT_READER_APP_PRIVATE_KEY }}"
    if body.count(reader_client) != 1 or body.count(reader_key) != 1:
        raise SystemExit(f"Audit Reader job {identity} must pass each secret only to token minting")
    if "WK_PACKAGE_PUBLISHER_APP_" in body:
        raise SystemExit(f"Audit Reader job {identity} can access the Publisher private key")
    app_permissions = re.findall(
        r"^\s+permission-([a-z-]+):\s+(\S+)\s*$", body, re.MULTILINE
    )
    if app_permissions != [("administration", "read")]:
        raise SystemExit(f"Audit Reader job {identity} must request Administration read only")
    if body.count("contents: read") != 1:
        raise SystemExit(f"Audit Reader job {identity} must retain job-token Contents read")
    if body.count("GH_TOKEN: ${{ github.token }}") != 1:
        raise SystemExit(f"Audit Reader job {identity} must use its job token for contents")
    if body.count(
        "IMMUTABLE_POLICY_TOKEN: ${{ steps.audit-reader-token.outputs.token }}"
    ) != 1:
        raise SystemExit(f"Audit Reader job {identity} must isolate its policy token")

control_job = all_jobs[("native-package-publish.yml", "control")]
if control_job.count("            site/") != 1:
    raise SystemExit("publisher control artifact must carry the bootstrap site for validation")
if "WK_PACKAGE_AUDIT_READER_APP_" in control_job or "WK_PACKAGE_PUBLISHER_APP_" in control_job:
    raise SystemExit("publisher control must not receive package App credentials")
if control_job.count("    needs: audit_release") != 1:
    raise SystemExit("publisher control must consume the protected draft classification")
if "empty_draft|archive_only_draft|complete_draft|immutable_complete) ;;" not in control_job:
    raise SystemExit("publisher control must accept only the resolver's four exact states")
policy_reader = all_jobs[("native-package-publish.yml", "policy")]
if policy_reader.count('gh api "repos/WuKongIM/packages/immutable-releases"') != 1:
    raise SystemExit("publisher policy job must read immutable policy exactly once")
if policy_reader.count('GH_TOKEN="$IMMUTABLE_POLICY_TOKEN"') != 1:
    raise SystemExit("publisher policy job must scope the policy token to its policy read")
immutable_reader = all_jobs[("native-package-publish.yml", "immutable_passthrough")]
if immutable_reader.count("--policy-token-env IMMUTABLE_POLICY_TOKEN") != 1:
    raise SystemExit("immutable replay must pass a separate policy token to the sealer")

draft_reader = all_jobs[("native-package-publish.yml", "audit_release")]
if draft_reader.count("    needs: policy") != 1:
    raise SystemExit("draft classification must follow the immutable policy fence")
if draft_reader.count('GH_TOKEN: ${{ steps.publisher-token.outputs.token }}') != 1:
    raise SystemExit("draft classification must use the package Publisher token exactly once")
if "GH_TOKEN: ${{ github.token }}" in draft_reader:
    raise SystemExit("draft classification must not use the read-only workflow token")
if draft_reader.count('gh api "repos/WuKongIM/packages/releases/$audit_id"') != 1:
    raise SystemExit("draft classification must read the exact numeric Release once")
if draft_reader.count("./scripts/resolve-audit-release.py") != 1:
    raise SystemExit("draft classification must use the revalidating resolver exactly once")
if draft_reader.count("      contents: read") != 1:
    raise SystemExit("draft classification workflow token must remain Contents read-only")
if draft_reader.index("Validate enabled production contracts and exact current main") > draft_reader.index(
    "actions/create-github-app-token@"
):
    raise SystemExit("draft classification mints its Publisher token before full validation")
if re.search(
    r"--method\s+(?:POST|PATCH|PUT|DELETE)|gh\s+release\s+(?:create|edit|upload|delete)|"
    r"git\s+push|draft:\s*false",
    draft_reader,
):
    raise SystemExit("draft classification job may not mutate Releases, tags, or Git")

for identity in writer_expected:
    body = all_jobs[identity]
    if not has_environment(body, "native-package-preview-audit"):
        raise SystemExit(f"Publisher job {identity} lacks its protected Environment")
    writer_client = "client-id: ${{ secrets.WK_PACKAGE_PUBLISHER_APP_CLIENT_ID }}"
    writer_key = "private-key: ${{ secrets.WK_PACKAGE_PUBLISHER_APP_PRIVATE_KEY }}"
    if body.count(writer_client) != 1 or body.count(writer_key) != 1:
        raise SystemExit(f"Publisher job {identity} must pass each secret only to token minting")
    if "WK_PACKAGE_AUDIT_READER_APP_" in body:
        raise SystemExit(f"Publisher job {identity} can access the Audit Reader private key")
    app_permissions = re.findall(
        r"^\s+permission-([a-z-]+):\s+(\S+)\s*$", body, re.MULTILINE
    )
    expected_permissions = (
        [("contents", "write")]
        if identity == ("native-package-publish.yml", "audit_release")
        else [("administration", "read"), ("contents", "write")]
    )
    if app_permissions != expected_permissions:
        raise SystemExit(f"Publisher job {identity} lacks exact bounded token permissions")

for identity in credential_jobs:
    body = all_jobs[identity]
    if body.count("owner: WuKongIM") != 1 or body.count("repositories: packages") != 1:
        raise SystemExit(f"credential job {identity} must mint only for WuKongIM/packages")
    if "skip-token-revoke: true" in body:
        raise SystemExit(f"credential job {identity} must revoke its installation token")

if sum(
    has_environment(body, "native-package-preview-audit-read")
    for body in all_jobs.values()
) != 2:
    raise SystemExit("Audit Reader Environment must appear in exactly two workflow jobs")
if sum(
    has_environment(body, "native-package-preview-audit")
    for body in all_jobs.values()
) != 4:
    raise SystemExit("Publisher Environment must appear in exactly four workflow jobs")
for secret in (
    "WK_PACKAGE_AUDIT_READER_APP_CLIENT_ID",
    "WK_PACKAGE_AUDIT_READER_APP_PRIVATE_KEY",
):
    if sum(body.count(secret) for body in all_jobs.values()) != 2:
        raise SystemExit(f"{secret} must appear in exactly two workflow jobs")
for secret in (
    "WK_PACKAGE_PUBLISHER_APP_CLIENT_ID",
    "WK_PACKAGE_PUBLISHER_APP_PRIVATE_KEY",
):
    if sum(body.count(secret) for body in all_jobs.values()) != 4:
        raise SystemExit(f"{secret} must appear in exactly four workflow jobs")

signing_expected = {
    "apt": {
        ("native-package-publish.yml", "apt_sign"),
        ("native-package-signing-preflight.yml", "apt"),
    },
    "rpm": {
        ("native-package-publish.yml", "rpm_sign"),
        ("native-package-signing-preflight.yml", "rpm"),
    },
}
for family, expected in signing_expected.items():
    upper = family.upper()
    environment = f"native-package-preview-{family}-signing"
    other = "RPM" if family == "apt" else "APT"
    actual = {
        identity
        for identity, body in all_jobs.items()
        if has_environment(body, environment)
        or f"secrets.WK_{upper}_PREVIEW_" in body
    }
    if actual != expected:
        raise SystemExit(
            f"{upper} signing credentials escaped exact jobs: {sorted(actual)}"
        )
    for identity in expected:
        body = all_jobs[identity]
        if not has_environment(body, environment):
            raise SystemExit(f"{upper} signing job {identity} lacks its protected Environment")
        for secret in (
            f"secrets.WK_{upper}_PREVIEW_SECRET_SUBKEY_B64",
            f"secrets.WK_{upper}_PREVIEW_PASSPHRASE",
        ):
            if body.count(secret) != 1:
                raise SystemExit(
                    f"{upper} signing job {identity} must reference {secret} exactly once"
                )
        if f"secrets.WK_{other}_PREVIEW_" in body:
            raise SystemExit(
                f"{upper} signing job {identity} exposes the other family credential"
            )

preflight_jobs = workflow_jobs["native-package-signing-preflight.yml"]
for family in ("apt", "rpm"):
    body = "\n".join(preflight_jobs[family])
    provenance = f"Verify toolchain provenance before exposing either {family.upper()} secret"
    secret = f"secrets.WK_{family.upper()}_PREVIEW_SECRET_SUBKEY_B64"
    if body.index(provenance) > body.index(secret):
        raise SystemExit(f"{family.upper()} preflight exposes its secret before provenance verification")
    if body.count(
        "git ls-remote https://github.com/WuKongIM/packages.git refs/heads/main"
    ) != 2:
        raise SystemExit(
            f"{family.upper()} preflight must fence protected main immediately before and after secret validation"
        )
    if "actions/upload-artifact@" in body or "actions/upload-pages-artifact@" in body:
        raise SystemExit(f"{family.upper()} preflight must not upload its validation receipt")

jobs = workflow_jobs[publish_path.name]
for job in ("apt_sign", "rpm_sign"):
    body = "\n".join(jobs[job])
    if body.count(
        "git ls-remote https://github.com/WuKongIM/packages.git refs/heads/main"
    ) != 2:
        raise SystemExit(
            f"publisher {job} must fence protected main immediately before and after signing"
        )
family_path_contracts = {
    "apt_sign": (
        '--volume "$RUNNER_TEMP/apt-input/tree:/input:ro"',
        "--family apt --input-root /input --output-root /work/deliver/tree",
        "--apt-release dists/preview/Release",
    ),
    "rpm_sign": (
        '--volume "$RUNNER_TEMP/rpm-input/tree:/input:ro"',
        "--family rpm --input-root /input --output-root /work/deliver/tree",
        "--rpm-repository preview/el/9/x86_64",
    ),
}
for job, required_paths in family_path_contracts.items():
    body = "\n".join(jobs[job])
    if any(body.count(value) != 1 for value in required_paths):
        raise SystemExit(
            f"publisher {job} must strip the prepared family prefix before signing"
        )
prepare_body = "\n".join(jobs["prepare"])
for family in ("apt", "rpm"):
    family_copy = (
        f"cp -a /work/prepared-repository/{family} "
        f"/work/artifacts/{family}/tree"
    )
    if prepare_body.count(family_copy) != 1:
        raise SystemExit(
            f"publisher prepare must flatten the {family.upper()} family-only boundary "
            "by letting the container create the family tree root"
        )
    forbidden_root_copy = f"cp -a /work/prepared-repository/{family}/."
    if forbidden_root_copy in prepare_body:
        raise SystemExit(
            f"publisher prepare must not preserve the {family.upper()} source root "
            "metadata onto a runner-owned bind-mount root"
        )
    runner_created_tree = f'"$work/artifacts/{family}/tree"'
    if runner_created_tree in prepare_body:
        raise SystemExit(
            f"publisher prepare must leave the {family.upper()} tree absent so the "
            "fixed cross-UID container creates and owns it"
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
if [[ $(grep -cF '"--no-database"' "$ROOT_DIR/scripts/sign-package-family.py") != 1 ]]; then
  echo 'production RPM signer must suppress unverified createrepo_c SQLite metadata' >&2
  exit 1
fi

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
python3 - "$TOOLCHAIN_WORKFLOW" <<'PY'
import pathlib
import sys

workflow = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
receipt = workflow.split("- name: Record public toolchain receipt", 1)[1]
receipt = receipt.split("- name: Upload public toolchain evidence", 1)[0]
if "bash -euo pipefail -c" in receipt:
    raise SystemExit("toolchain receipt must not expand dpkg-query placeholders in bash -u")
expected = "dpkg-query -W '-f=${Package}\\t${Version}\\n'"
if expected not in receipt:
    raise SystemExit("toolchain receipt must pass the dpkg-query format as one literal argument")
PY
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
