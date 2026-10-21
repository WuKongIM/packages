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


if __name__ == "__main__":
    unittest.main()
