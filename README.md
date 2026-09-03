# WuKongIM Linux packages

This repository owns the public APT and RPM repository metadata for WuKongIM.
The intended public endpoint is `https://packages.githubim.com`.

The signed preview channel publishes amd64/x86_64 packages. Preview releases
are prereleases and should be validated outside production before rollout.

## Install with the package manager

On Debian or Ubuntu, use three steps: add the repository once, refresh the
package index, then install WuKongIM by package name. Future installs and
upgrades no longer require downloading a WuKongIM deb file manually:

```bash
# 1. Add the WuKongIM preview repository
curl -fsSL https://packages.githubim.com/repo | sudo sh

# 2. Refresh the package index
sudo apt update

# 3. Install WuKongIM
sudo apt install -y wukongim
```

On Rocky Linux, AlmaLinux, or RHEL 9, use the same three steps with DNF (or the
compatible `yum` command):

```bash
# 1. Add the WuKongIM preview repository
curl -fsSL https://packages.githubim.com/repo | sudo sh

# 2. Refresh the package index
sudo dnf -y --disablerepo='*' --enablerepo=wukongim-preview makecache --refresh

# 3. Install WuKongIM
sudo dnf install -y wukongim
```

The `/repo` entrypoint is POSIX `sh`. It detects Debian/Ubuntu amd64 or
RHEL/Rocky/AlmaLinux 9 x86_64, downloads the matching reviewed bootstrap
package, verifies its exact published SHA-256, and installs only that package.
It does not refresh package indexes or install WuKongIM. Temporary downloads
are removed on exit. The RPM path additionally verifies the reviewed public
certificate bytes and package signature while keeping every other DNF
repository disabled.

The first `/repo` download necessarily trusts the HTTPS origin. Its bytes and
the exact bootstrap package identities are closed over by the immutable audit
snapshot. The bootstrap package installs only the reviewed repository key and
dedicated source file; it does not start services or weaken signature checks.
After that first step, APT/DNF authenticates repository metadata and packages,
and upgrades the bootstrap package through the same signed repository.

The checked-in `site/` directory is deliberately only the disabled bootstrap
page. Once preview publishing is enabled, the publisher builds and verifies a
complete repository snapshot in temporary storage and deploys that artifact
directly. Generated package indexes, metadata, signatures, and payloads are
never committed to Git.

## Trust boundary

- `WuKongIM/WuKongIM` builds an exact tagged source revision without signing
  credentials.
- This repository independently verifies the immutable source release before
  accepting a publication request.
- Once provisioned, preview APT and RPM signing use separate certificates and
  separate protected GitHub Environments. Each certificate pre-distributes a
  current and a next short-lived signing subkey.
- Preview primary and next private keys currently use an explicitly accepted
  single-operator online-workstation custody model. CI still receives only the
  encrypted current sign-only subkey for the applicable package family.
- Stable signing keys remain outside GitHub-hosted CI.
- GitHub Pages will receive only complete, verified preview snapshots. Stable
  publication requires migration to object storage and a CDN.
- `manifests/channels.json`, `manifests/preview-signing.json`, and
  `manifests/bootstrap-packages.json` are the reviewed, fail-closed
  publication controls. GitHub variables and dispatch payloads are not trust
  anchors.
- `manifests/source-read.json` keeps cross-repository verification disabled
  until a source-only GitHub App and protected Environment are provisioned.
- `manifests/audit-access.json` keeps both package audit Apps fail-closed until
  their exact installations, isolated Environments, secrets, and permissions
  are provisioned and a separate reviewed change enables the manifest. Every
  reader or writer job checks it before minting an App token.
- Immutable Release policy reads and audit Release/tag writes use separate
  package-only GitHub Apps. The Immutable Policy Reader credentials live only
  in the protected read Environment and have no Contents permission; ordinary
  reads of published Releases, tags, and assets use the workflow token. GitHub
  exposes draft Releases only to push-capable identities, so the numeric draft
  classification job uses a repository-limited Publisher token while its
  reviewed workflow contract forbids every write operation. The Publisher
  credentials live only in the protected write Environment and are exposed to
  exactly draft creation, draft classification, audit-tag binding, and
  sealing. All three App private keys are distinct and remain isolated to
  their own Environment.
- `manifests/trusted-toolchain.json` pins the exact source commit and SHA-256
  bytes of the repository builder, supplemental legacy verifiers, and TEST
  ONLY drill. Production signing, snapshot composition, and final verification
  use this repository's exact reviewed control inside the separately
  digest-pinned and attested signing image. A source tag never selects
  executable publishing code.

The manual source preflight accepts only a numeric immutable source Release
ID. It independently resolves the tag to a commit reachable from `main`,
downloads all seven assets by numeric asset ID, verifies their exact checksum
closure and fixed-workflow GitHub attestations, and inspects DEB/RPM metadata
without executing either package payload.

See [docs/release-contract.md](docs/release-contract.md) for the release,
retention, signing, and recovery contracts.

Reviewed public certificates are published at the stable URLs
`https://packages.githubim.com/keys/apt-preview.asc` and
`https://packages.githubim.com/keys/rpm-preview.asc`. The APT
`wukongim-archive-keyring` and RPM `wukongim-release` packages distribute those
certificates and dedicated repository definitions. Their indexed bytes and
friendly `/bootstrap/` downloads are identical. The stable `/repo` entrypoint
is generated from those exact paths and digests; all three are closed over by
each immutable package audit snapshot.
