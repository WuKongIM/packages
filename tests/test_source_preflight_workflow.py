from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SourcePreflightWorkflowTest(unittest.TestCase):
    def test_one_explicit_channel_is_passed_to_the_entire_read_only_chain(self) -> None:
        workflow = (ROOT / ".github/workflows/source-release-preflight.yml").read_text()
        self.assertRegex(workflow, r"source_channel:\n(?:[^\n]*\n){0,4}\s+type: choice\n\s+default: preview\n\s+options:\n\s+- preview\n\s+- stable")
        self.assertIn("source_channel: ${{ steps.request.outputs.source_channel }}", workflow)
        self.assertIn("SOURCE_CHANNEL: ${{ inputs.source_channel }}", workflow)
        self.assertIn('case "$SOURCE_CHANNEL" in preview|stable) ;;', workflow)
        self.assertIn('echo "source_channel=$SOURCE_CHANNEL" >> "$GITHUB_OUTPUT"', workflow)
        for tool in ("resolve-source-release.py", "verify-source-attestations.py", "verify-source-package-metadata.py"):
            step = next(s for s in workflow.split("      - name:") if f"./scripts/{tool}" in s)
            self.assertIn("SOURCE_CHANNEL: ${{ needs.control.outputs.source_channel }}", step)
            self.assertIn('--channel "$SOURCE_CHANNEL"', step)
        self.assertLess(workflow.index("./scripts/resolve-source-release.py"), workflow.index("./scripts/verify-source-attestations.py"))
        self.assertLess(workflow.index("./scripts/verify-source-attestations.py"), workflow.index("./scripts/verify-source-package-metadata.py"))
        self.assertNotIn("assert_metadata()", workflow)
        self.assertNotRegex(workflow, r"contents: write|pages: write|id-token: write|deploy-pages|rpmsign|sign-package-family")
        self.assertEqual(2, workflow.count("secrets."))
        metadata = next(s for s in workflow.split("      - name:") if "./scripts/verify-source-package-metadata.py" in s)
        self.assertNotRegex(metadata, r"GH_TOKEN|secrets\.|source-token")

    def test_native_drill_uses_existing_fixed_toolchain_without_credentials_or_network(self) -> None:
        workflow = (ROOT / ".github/workflows/native-package-repository-drill.yml").read_text()
        step = next((s for s in workflow.split("      - name:") if "tests/native_source_metadata_drill.py" in s), "")
        self.assertTrue(step, "missing real native metadata drill")
        self.assertIn("manifests/signing-toolchain.json", step)
        for argument in ("--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges", ":/control:ro", "--output-dir /evidence"):
            self.assertIn(argument, step)
        self.assertNotRegex(step, r"secrets\.|GH_TOKEN|GITHUB_TOKEN|id-token: write|contents: write")
        self.assertIn("source-metadata-native/", workflow)
        self.assertIn("if: always()", workflow)

    def test_local_signing_drill_remains_bounded_private_and_read_only(self) -> None:
        workflow = (ROOT / ".github/workflows/native-package-repository-drill.yml").read_text()
        step = next((s for s in workflow.split("      - name:")
                     if "tests/native_local_signing_drill.py" in s), "")
        self.assertTrue(step, "missing real native local signing drill")
        for argument in ("manifests/signing-toolchain.json", "--network none", "--read-only",
                         "--cap-drop ALL", "--security-opt no-new-privileges",
                         "--user 65532:65532", "--cpus 1", "--memory 512m", "--pids-limit 128",
                         ":/control:ro", "--output-dir /evidence", "--kill-after=10s 8m",
                         'docker rm --force "$container"', "trap 'exit 130' INT",
                         "trap 'exit 143' TERM"):
            self.assertIn(argument, step)
        self.assertNotRegex(workflow, r"secrets\.|GH_TOKEN|GITHUB_TOKEN|id-token: write|contents: write|environment:")
        self.assertIn("contents: read", workflow)
        self.assertIn("(.cases | length) == 10", step)
        upload = next((s for s in workflow.split("      - name:")
                       if "name: native-local-signing-test-only" in s), "")
        self.assertIn("if: always()", upload)
        self.assertIn("path: ${{ runner.temp }}/local-signing-native/native-local-signing.json", upload)


    def test_bootstrap_preparation_drill_uses_only_isolated_native_package_databases(self) -> None:
        workflow = (ROOT / ".github/workflows/native-package-repository-drill.yml").read_text()
        step = next((s for s in workflow.split("      - name:")
                     if "tests/native_bootstrap_preparation_drill.py" in s), "")
        self.assertTrue(step, "missing real bootstrap preparation drill")
        for argument in ("manifests/signing-toolchain.json", "--network none", "--read-only",
                         "--cap-drop ALL", "--cap-add SYS_CHROOT", "--security-opt no-new-privileges",
                         "--user 0:0", "--cpus 1", "--memory 512m", "--pids-limit 128",
                         ":/control:ro", "--output-dir /evidence", "--kill-after=10s 5m",
                         'docker rm --force "$container"', "trap 'exit 130' INT",
                         "trap 'exit 143' TERM"):
            self.assertIn(argument, step)
        self.assertNotRegex(step, r"secrets\.|GH_TOKEN|GITHUB_TOKEN|environment:|--privileged|--cap-add (?!SYS_CHROOT)")
        self.assertIn("(.cases | length) == 6", step)
        upload = next((s for s in workflow.split("      - name:")
                       if "name: native-bootstrap-preparation-test-only" in s), "")
        self.assertIn("if: always()", upload)
        self.assertIn("path: ${{ runner.temp }}/bootstrap-preparation-native/native-bootstrap-preparation.json", upload)


if __name__ == "__main__":
    unittest.main()
