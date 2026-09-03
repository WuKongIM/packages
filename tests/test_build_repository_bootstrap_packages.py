from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/build-repository-bootstrap-packages.py"
SPEC = importlib.util.spec_from_file_location("build_repository_bootstrap_packages", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


class BootstrapPackageBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.manifest = self.root / "bootstrap-packages.json"
        self.manifest.write_text(
            json.dumps({
                "schema": MODULE.MANIFEST_SCHEMA,
                "enabled": True,
                "version": "1.0.0",
            }) + "\n",
            encoding="utf-8",
        )
        self.apt_certificate = ROOT / "keys/apt-preview.asc"
        self.rpm_certificate = ROOT / "keys/rpm-preview.asc"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def args(self, output: Path) -> Namespace:
        return Namespace(
            manifest=self.manifest,
            apt_public_cert=self.apt_certificate,
            rpm_public_cert=self.rpm_certificate,
            output_dir=output,
        )

    def write_manifest(self, value: object) -> None:
        self.manifest.write_text(json.dumps(value) + "\n", encoding="utf-8")

    def fake_toolchain(self) -> Path:
        binary = self.root / "bin"
        binary.mkdir()
        rpm_cert_sha = hashlib.sha256(self.rpm_certificate.read_bytes()).hexdigest()
        repo_sha = hashlib.sha256(MODULE.RPM_REPOSITORY).hexdigest()
        rpmbuild = binary / "rpmbuild"
        rpmbuild.write_text(
            f"""#!{sys.executable}
import pathlib, re, sys

arguments = sys.argv[1:]
definitions = [arguments[index + 1] for index, value in enumerate(arguments[:-1]) if value == '--define']
top_definition = [value for value in definitions if value.startswith('_topdir ')]
assert len(top_definition) == 1
top = pathlib.Path(top_definition[0][len('_topdir '):])
spec = pathlib.Path(arguments[-1]).read_text(encoding='utf-8')
required = [
    'Name: wukongim-release',
    'Release: 1',
    'BuildArch: noarch',
    'AutoReqProv: no',
    'baseurl=https://packages.githubim.com/rpm/preview/el/9/x86_64',
    'includepkgs=wukongim,wukongim-release',
    'metadata_expire=0',
    '%config(noreplace) /etc/yum.repos.d/wukongim-preview.repo',
]
for value in required:
    if value.startswith(('baseurl=', 'includepkgs=', 'metadata_expire=')):
        assert value in (top / 'SOURCES/wukongim-preview.repo').read_text(encoding='utf-8')
    else:
        assert value in spec
assert not re.search(r'^%(pre|post|preun|postun|trigger|transfiletrigger)(?:\\s|$)', spec, re.MULTILINE)
assert spec.count('%config(noreplace)') == 1
assert (top / 'SOURCES/RPM-GPG-KEY-wukongim-preview').read_bytes() != b''
version = re.search(r'^Version: ([0-9]+\\.[0-9]+\\.[0-9]+)$', spec, re.MULTILINE)
assert version is not None
output = top / f'RPMS/noarch/wukongim-release-{{version.group(1)}}-1.noarch.rpm'
output.parent.mkdir(parents=True)
output.write_bytes(b'fake deterministic unsigned rpm\\n')
""",
            encoding="utf-8",
        )
        rpm = binary / "rpm"
        rpm.write_text(
            f"""#!{sys.executable}
import pathlib, re, sys

arguments = sys.argv[1:]
package = pathlib.Path(arguments[-1]).name
version = re.fullmatch(r'wukongim-release-([0-9]+\\.[0-9]+\\.[0-9]+)-1\\.noarch\\.rpm', package)
assert version is not None
if '-qpl' in arguments:
    sys.stdout.write('/etc/pki/rpm-gpg/RPM-GPG-KEY-wukongim-preview\\n')
    sys.stdout.write('/etc/yum.repos.d/wukongim-preview.repo\\n')
elif '--scripts' in arguments:
    pass
elif '--queryformat' in arguments:
    query = arguments[arguments.index('--queryformat') + 1]
    if query.startswith('%{{NAME}}'):
        sys.stdout.write(f'wukongim-release\\t0\\t{{version.group(1)}}\\t1\\tnoarch\\n')
    elif query == '%{{FILEDIGESTALGO}}\\\\n':
        sys.stdout.write('8\\n')
    elif query.startswith('[%{{FILENAMES}}'):
        sys.stdout.write('/etc/pki/rpm-gpg/RPM-GPG-KEY-wukongim-preview\\t{rpm_cert_sha}\\t0\\t-rw-r--r--\\n')
        sys.stdout.write('/etc/yum.repos.d/wukongim-preview.repo\\t{repo_sha}\\t17\\t-rw-r--r--\\n')
    else:
        raise SystemExit('unexpected query: ' + query)
elif '-K' in arguments:
    pass
else:
    raise SystemExit('unexpected rpm arguments: ' + repr(arguments))
""",
            encoding="utf-8",
        )
        rpmbuild.chmod(0o755)
        rpm.chmod(0o755)
        return binary

    def test_manifest_contract_is_exact_and_fail_closed(self) -> None:
        self.assertEqual("1.0.0", MODULE.load_manifest(self.manifest)["version"])
        valid = {
            "schema": MODULE.MANIFEST_SCHEMA,
            "enabled": True,
            "version": "1.0.0",
        }
        cases = [
            ({**valid, "extra": True}, "fields must be exactly"),
            ({**valid, "schema": "wukongim.native_package_bootstrap/v2"}, "schema must be"),
            ({**valid, "enabled": 1}, "must be enabled"),
            ({**valid, "version": "v1.0.0"}, "strict release SemVer"),
            ({**valid, "version": "1.0.0-rc.1"}, "strict release SemVer"),
            ({**valid, "version": "1.0.0+rotation.1"}, "strict release SemVer"),
            ({**valid, "version": "01.0.0"}, "strict release SemVer"),
        ]
        for value, message in cases:
            with self.subTest(value=value), self.assertRaisesRegex(MODULE.BootstrapBuildError, message):
                self.write_manifest(value)
                MODULE.load_manifest(self.manifest)

        self.manifest.write_text(
            '{"schema":"wukongim.native_package_bootstrap/v1",'
            '"enabled":true,"enabled":true,"version":"1.0.0"}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(MODULE.BootstrapBuildError, "duplicate JSON key"):
            MODULE.load_manifest(self.manifest)

        for version in ("0.0.0", "1.0.1", "10.20.30"):
            with self.subTest(accepted_version=version):
                self.write_manifest({**valid, "version": version})
                self.assertEqual(version, MODULE.load_manifest(self.manifest)["version"])

    def test_public_certificate_dearmor_checks_crc_and_packet_type(self) -> None:
        raw = self.apt_certificate.read_bytes()
        packets = MODULE.dearmor_public_certificate(raw, "APT public certificate")
        self.assertGreater(len(packets), 1000)
        self.assertNotIn(MODULE.ARMOR_BEGIN.encode(), packets)

        changed = raw.replace(b"=be8M", b"=be8N")
        with self.assertRaisesRegex(MODULE.BootstrapBuildError, "checksum"):
            MODULE.dearmor_public_certificate(changed, "APT public certificate")

        private = raw.replace(b"PGP PUBLIC KEY", b"PGP PRIVATE KEY")
        with self.assertRaisesRegex(MODULE.BootstrapBuildError, "private key"):
            MODULE.dearmor_public_certificate(private, "APT public certificate")

    def test_deb_is_deterministic_data_only_and_contains_binary_keyring(self) -> None:
        keyring = MODULE.dearmor_public_certificate(
            self.apt_certificate.read_bytes(), "APT public certificate"
        )
        first = self.root / "first.deb"
        second = self.root / "second.deb"
        MODULE.build_deb(first, "1.0.0", keyring)
        MODULE.build_deb(second, "1.0.0", keyring)
        MODULE.inspect_deb(first, "1.0.0", keyring)
        self.assertEqual(first.read_bytes(), second.read_bytes())

        ar_members = MODULE._parse_ar(first.read_bytes())
        control = MODULE._inspect_tar_gzip(ar_members["control.tar.gz"], "control")
        data = MODULE._inspect_tar_gzip(ar_members["data.tar.gz"], "data")
        self.assertEqual({"./control", "./conffiles"}, set(control))
        self.assertEqual(
            keyring,
            data["./usr/share/keyrings/wukongim-archive-keyring.pgp"][1],
        )
        self.assertEqual(
            MODULE.APT_SOURCE,
            data["./etc/apt/sources.list.d/wukongim-preview.sources"][1],
        )
        self.assertEqual(
            b"/etc/apt/sources.list.d/wukongim-preview.sources\n",
            control["./conffiles"][1],
        )
        self.assertNotIn(b"-----BEGIN PGP", keyring)
        self.assertNotIn("./postinst", control)
        self.assertNotIn("./prerm", control)

    def test_build_emits_exact_canonical_inventory_and_deterministic_packages(self) -> None:
        toolchain = self.fake_toolchain()
        first = self.root / "output-one"
        second = self.root / "output-two"
        environment = os.environ.copy()
        environment["PATH"] = f"{toolchain}{os.pathsep}{environment.get('PATH', '')}"
        command = [
            sys.executable,
            str(SCRIPT),
            "--manifest", str(self.manifest),
            "--apt-public-cert", str(self.apt_certificate),
            "--rpm-public-cert", str(self.rpm_certificate),
        ]
        first_result = subprocess.run(
            [*command, "--output-dir", str(first)],
            check=False,
            capture_output=True,
            env=environment,
        )
        self.assertEqual(b"", first_result.stderr)
        self.assertEqual(0, first_result.returncode)
        second_result = subprocess.run(
            [*command, "--output-dir", str(second)],
            check=False,
            capture_output=True,
            env=environment,
        )
        self.assertEqual(0, second_result.returncode, second_result.stderr.decode())
        self.assertEqual(first_result.stdout, second_result.stdout)

        inventory = json.loads(first_result.stdout)
        self.assertEqual(canonical(inventory), first_result.stdout)
        self.assertEqual(
            {"schema", "version", "packages"}, set(inventory)
        )
        self.assertEqual(MODULE.INVENTORY_SCHEMA, inventory["schema"])
        self.assertEqual("1.0.0", inventory["version"])
        expected_fields = {
            "name", "version", "architecture", "filename", "repository_path",
            "download_path", "source_sha256", "source_size", "published_sha256",
            "published_size", "new",
        }
        apt = inventory["packages"]["apt"]
        rpm = inventory["packages"]["rpm"]
        self.assertEqual(expected_fields, set(apt))
        self.assertEqual(expected_fields, set(rpm))
        self.assertEqual("wukongim-archive-keyring_1.0.0_all.deb", apt["filename"])
        self.assertEqual(
            "apt/pool/main/w/wukongim/wukongim-archive-keyring_1.0.0_all.deb",
            apt["repository_path"],
        )
        self.assertEqual(
            "rpm/preview/el/9/x86_64/Packages/wukongim-release-1.0.0-1.noarch.rpm",
            rpm["repository_path"],
        )
        for package in (apt, rpm):
            self.assertTrue(package["new"])
            self.assertEqual(package["source_sha256"], package["published_sha256"])
            self.assertEqual(package["source_size"], package["published_size"])
            payload = first / package["filename"]
            self.assertEqual(package["source_size"], payload.stat().st_size)
            self.assertEqual(package["source_sha256"], hashlib.sha256(payload.read_bytes()).hexdigest())
            self.assertEqual(payload.read_bytes(), (second / package["filename"]).read_bytes())
        self.assertEqual({apt["filename"], rpm["filename"]}, {item.name for item in first.iterdir()})

    def test_future_release_semver_flows_to_both_package_identities(self) -> None:
        self.write_manifest({
            "schema": MODULE.MANIFEST_SCHEMA,
            "enabled": True,
            "version": "1.0.1",
        })
        toolchain = self.fake_toolchain()
        output = self.root / "future-output"
        path = f"{toolchain}{os.pathsep}{os.environ.get('PATH', '')}"
        with mock.patch.dict(os.environ, {"PATH": path}):
            inventory = MODULE.build(self.args(output))
        self.assertEqual("1.0.1", inventory["version"])
        self.assertEqual(
            "wukongim-archive-keyring_1.0.1_all.deb",
            inventory["packages"]["apt"]["filename"],
        )
        self.assertEqual(
            "wukongim-release-1.0.1-1.noarch.rpm",
            inventory["packages"]["rpm"]["filename"],
        )
        self.assertEqual(
            {"wukongim-archive-keyring_1.0.1_all.deb", "wukongim-release-1.0.1-1.noarch.rpm"},
            {item.name for item in output.iterdir()},
        )

    def test_missing_rpm_tool_rolls_back_every_staged_output(self) -> None:
        output = self.root / "output"
        original = {entry.name for entry in self.root.iterdir()}
        with mock.patch.object(MODULE.shutil, "which", return_value=None):
            with self.assertRaisesRegex(MODULE.BootstrapBuildError, "rpmbuild"):
                MODULE.build(self.args(output))
        self.assertFalse(os.path.lexists(output))
        self.assertEqual(original, {entry.name for entry in self.root.iterdir()})

    def test_existing_output_is_never_replaced(self) -> None:
        output = self.root / "output"
        output.mkdir()
        sentinel = output / "owned-by-caller"
        sentinel.write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.BootstrapBuildError, "must not already exist"):
            MODULE.build(self.args(output))
        self.assertEqual("keep", sentinel.read_text(encoding="utf-8"))

    @unittest.skipUnless(
        shutil.which("rpmbuild") is not None and shutil.which("rpm") is not None,
        "real RPM build tools are unavailable",
    )
    def test_real_toolchain_build_is_byte_for_byte_reproducible(self) -> None:
        first = self.root / "real-one"
        second = self.root / "real-two"
        first_inventory = MODULE.build(self.args(first))
        second_inventory = MODULE.build(self.args(second))
        self.assertEqual(canonical(first_inventory), canonical(second_inventory))
        for family in ("apt", "rpm"):
            filename = first_inventory["packages"][family]["filename"]
            self.assertEqual((first / filename).read_bytes(), (second / filename).read_bytes())
        if shutil.which("dpkg-deb"):
            result = subprocess.run(
                [
                    shutil.which("dpkg-deb"), "--show",
                    "--showformat=${Package}\\t${Version}\\t${Architecture}\\n",
                    str(first / "wukongim-archive-keyring_1.0.0_all.deb"),
                ],
                check=True,
                capture_output=True,
            )
            self.assertEqual(b"wukongim-archive-keyring\t1.0.0\tall\n", result.stdout)


if __name__ == "__main__":
    unittest.main()
