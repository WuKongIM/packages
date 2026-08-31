# WuKongIM Linux packages

This repository owns the public APT and RPM repository metadata for WuKongIM.
The intended public endpoint is `https://packages.githubim.com`.

The distribution channel is being bootstrapped. Until the signing manifests
contain reviewed public-key fingerprints and the publishing workflow has
completed, do not configure this endpoint as a package source. Unsigned or
test-signed packages are never public releases.

## Trust boundary

- `WuKongIM/WuKongIM` builds an exact tagged source revision without signing
  credentials.
- This repository independently verifies the immutable source release before
  accepting a publication request.
- Preview APT and RPM signing use separate short-lived signing subkeys in a
  protected GitHub Environment.
- Stable signing keys remain outside GitHub-hosted CI.
- GitHub Pages receives one complete, verified repository snapshot. It never
  receives a partially updated index.

See [docs/release-contract.md](docs/release-contract.md) for the release,
retention, signing, and recovery contracts.
