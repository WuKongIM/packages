# Native package release contract

## Source identity

Only a strict SemVer tag whose commit is reachable from
`WuKongIM/WuKongIM@main` may enter the repository. A dispatch payload is only a
hint: the target workflow must re-read the tag, release, source commit, asset
set, checksums, attestations, and immutable-release state from GitHub.

The source repository remains responsible for building and testing the deb/rpm
payload without signing credentials. Signing jobs treat those artifacts as
data and never execute files from them.

## Reviewed control plane

`manifests/channels.json` fixes the source repository, preview releases,
capacity bounds, and any in-progress retirement. `manifests/preview-signing.json`
fixes the protected Environment, public-key paths, fingerprints, secret names,
and key-lifetime policy. `manifests/source-read.json` keeps cross-repository
access disabled until a GitHub App restricted to source Contents and
Attestations read access has been provisioned. These manifests reject unknown
fields and duplicate JSON keys. Workflow inputs, repository variables,
dispatch payloads, and release titles must not override reviewed values.

The checked-in `site/` tree always remains the disabled bootstrap page. Live
APT/RPM content is generated from reviewed control plus immutable Releases,
verified as a complete snapshot, and sent directly as one Pages artifact. It
is not committed to `main` or a generated branch.

The package-repository builder, signer, verifier, and TEST ONLY integration
driver are loaded only from the exact source commit and file digests recorded
in `manifests/trusted-toolchain.json`. The source Release tag and its assets
cannot choose executable publishing logic. Updating this pin is an ordinary
protected control-plane review.

## Source preflight

The read-only source preflight accepts a numeric Release ID, never a release
name or download URL. It requires a published immutable prerelease with the
exact four archives, unsigned amd64 DEB and RPM, and checksum asset. It peels
the Git tag, proves the source commit remains reachable from `main`, downloads
each asset by numeric asset ID, checks API and local SHA-256 values plus the
checksum closure, then repeats the Release, tag, and ancestry checks after the
downloads.

All seven downloaded files must also verify against GitHub provenance signed
by `.github/workflows/binary-release-publish.yml` at the exact source tag and
commit on GitHub-hosted runners. DEB/RPM inspection is metadata-only: target
automation never runs a binary or maintainer script taken from the source
Release. Preflight evidence is retained temporarily but does not publish or
sign anything.

## Channels and retention

The intended public layouts are:

- `/apt/dists/preview` and `/rpm/preview/el/9/x86_64` for pre-releases on
  GitHub Pages;
- `/apt/dists/stable` and `/rpm/stable/el/9/x86_64` for stable releases only
  after publication has migrated to object storage and a CDN.

GitHub Pages documents a 1 GB published-site limit. The preview publisher keeps
at most four amd64 versions online and treats 750 MiB as a mandatory migration
threshold rather than consuming the remaining platform capacity. It emits an
operator warning at 600 MiB. Stable
publication is never enabled on Pages. Release assets remain immutable audit
evidence even after a version ages out of the installable window. Adding
another architecture requires a new capacity decision before changing this
limit.

Retirement is a two-run operation because package and metadata objects can
remain in the Pages CDN cache for roughly ten minutes. The first reviewed run
removes the oldest version from APT and RPM indexes while retaining its payload
and dependency closure, then records an `indexes_removed` state and an absolute
`not_before` at least twenty minutes later. A separate run after that timestamp
may remove the bytes and clear the retirement state. A workflow never sleeps
through the cache interval.

## Signing

APT and RPM use separate OpenPGP certificates for each channel. APT signs the
same `Release` bytes as both `InRelease` and `Release.gpg`; individual deb files
do not receive a non-standard signature. RPM packages are signed before
`createrepo_c` builds metadata, and the same channel RPM certificate signs
`repodata/repomd.xml`.

After it is provisioned, preview CI may import only an encrypted sign-only
subkey from the protected `native-package-preview-signing` Environment. Its
offline certify-only primary key must not be present. The workflow accepts exact
40-hex primary and signing-subkey fingerprints only from the reviewed manifest and
fails when the key is revoked, expired, has less than 30 days remaining, or
has any unexpected secret material. The APT and RPM primary and subkey
fingerprints must all differ. Preview subkeys last at most 180 days; rotation
begins 45 days before expiry.

Before any signing command, each encrypted secret-subkey export is independently
loaded into a fresh isolated GnuPG home. Validation rejects a private primary,
an extra or token-backed private subkey, an unprotected subkey, the wrong
passphrase, a public-key topology change, a subkey lifetime over 180 days, or
less than 30 days of remaining validity. A proof signature must use the exact
reviewed signing-subkey fingerprint.

Stable private keys never enter GitHub-hosted CI. Stable publication uses an
offline or hardware-backed signing ceremony. Promoting an RPM preserves the
same unsigned payload, NEVRA, and provenance, but its bytes change when it is
signed with the independent stable key.

## Atomic publication and recovery

Every run materializes a complete snapshot in a temporary directory, verifies
APT signatures, RPM package signatures, repodata signatures, metadata hashes,
and clean-client repository update plus authenticated download, then uploads
one Pages artifact. Production target automation never installs or runs a
source Release payload. The credential-free TEST ONLY drill may install the
packages it builds from the immutable trusted-tool commit. There is no in-place
mutation of the live repository.

Exact release assets are never overwritten. A retry may finish an exact
matching draft or redeploy an already verified immutable snapshot. A mutable
published release, a digest conflict, unexpected assets, or an unverifiable
source identity fails closed.

Each successful publication also creates an immutable Release in this
repository containing the exact signed snapshot inputs and audit receipt. That
Release, rather than Git history or the live CDN, is the durable rebuild and
rollback source.

Suspected key compromise freezes publication. Maintainers revoke the affected
subkey, publish the updated public certificate and incident notice, remove
affected versions from indexes, and publish new signed bytes under a
pre-distributed successor key. Audit artifacts remain retained.
