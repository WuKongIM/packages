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
- Once provisioned, preview APT and RPM signing will use separate short-lived
  signing subkeys in a protected GitHub Environment.
- Stable signing keys remain outside GitHub-hosted CI.
- GitHub Pages will receive only complete, verified preview snapshots. Stable
  publication requires migration to object storage and a CDN.
- `manifests/channels.json` and `manifests/preview-signing.json` are the
  reviewed, fail-closed publication controls. GitHub variables and dispatch
  payloads are not trust anchors.
- `manifests/source-read.json` keeps cross-repository verification disabled
  until a source-only GitHub App and protected Environment are provisioned.
- `manifests/trusted-toolchain.json` pins the exact source commit and SHA-256
  bytes of the repository builder, signer, verifier, and TEST ONLY drill. A
  source tag never selects executable publishing code.

The manual source preflight accepts only a numeric immutable source Release
ID. It independently resolves the tag to a commit reachable from `main`,
downloads all seven assets by numeric asset ID, verifies their exact checksum
closure and fixed-workflow GitHub attestations, and inspects DEB/RPM metadata
without executing either package payload.

See [docs/release-contract.md](docs/release-contract.md) for the release,
retention, signing, and recovery contracts.
