# WuKongIM Linux packages

This repository owns the public APT and RPM repository metadata for WuKongIM.
The intended public endpoint is `https://packages.githubim.com`.

The distribution channel is being bootstrapped. Until the signing manifests
contain reviewed public-key fingerprints and the publishing workflow has
completed, do not configure this endpoint as a package source. Unsigned or
test-signed packages are never public releases.

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
- Stable signing keys remain outside GitHub-hosted CI.
- GitHub Pages will receive only complete, verified preview snapshots. Stable
  publication requires migration to object storage and a CDN.
- `manifests/channels.json` and `manifests/preview-signing.json` are the
  reviewed, fail-closed publication controls. GitHub variables and dispatch
  payloads are not trust anchors.
- `manifests/source-read.json` keeps cross-repository verification disabled
  until a source-only GitHub App and protected Environment are provisioned.
- Immutable Release policy checks and audit Release/tag writes use a separate
  package-only GitHub App. Its credentials live only in the protected audit
  Environment; read paths mint read-scoped tokens and only the three audit
  writer paths request Contents write.
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
`https://packages.githubim.com/keys/rpm-preview.asc`. This repository does not
yet publish an APT or RPM keyring package. Existing clients therefore do not
receive certificate updates automatically and must refresh the applicable
certificate before a newly added successor subkey is promoted.
