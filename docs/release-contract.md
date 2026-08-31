# Native package release contract

## Source identity

Only a strict SemVer tag whose commit is reachable from
`WuKongIM/WuKongIM@main` may enter the repository. A dispatch payload is only a
hint: the target workflow must re-read the tag, release, source commit, asset
set, checksums, attestations, and immutable-release state from GitHub.

The source repository remains responsible for building and testing the deb/rpm
payload without signing credentials. Signing jobs treat those artifacts as
data and never execute files from them.

## Channels and retention

The public layouts are:

- `/apt/dists/preview` and `/rpm/preview/el/9/x86_64` for pre-releases;
- `/apt/dists/stable` and `/rpm/stable/el/9/x86_64` for stable releases.

GitHub Pages has a 1 GiB published-site limit. The publisher therefore keeps
at most three amd64 versions online and rejects any snapshot larger than
900 MiB. Release assets remain immutable audit evidence even after a version
ages out of the installable window. Adding another architecture requires a new
capacity decision before changing this limit.

## Signing

APT and RPM use separate OpenPGP certificates for each channel. APT signs the
same `Release` bytes as both `InRelease` and `Release.gpg`; individual deb files
do not receive a non-standard signature. RPM packages are signed before
`createrepo_c` builds metadata, and the same channel RPM certificate signs
`repodata/repomd.xml`.

Preview CI may import only an encrypted sign-only subkey. Its offline
certify-only primary key must not be present. The workflow accepts exact
40-hex primary and signing-subkey fingerprints from a reviewed manifest and
fails when the key is revoked, expired, has less than 30 days remaining, or
has any unexpected secret material. Preview subkeys last at most 180 days;
rotation begins 45 days before expiry.

Stable private keys never enter GitHub-hosted CI. Stable publication uses an
offline or hardware-backed signing ceremony. Promoting an RPM preserves the
same unsigned payload, NEVRA, and provenance, but its bytes change when it is
signed with the independent stable key.

## Atomic publication and recovery

Every run materializes a complete snapshot in a temporary directory, verifies
APT signatures, RPM package signatures, repodata signatures, metadata hashes,
and clean-client installation, then uploads one Pages artifact. There is no
in-place mutation of the live repository.

Exact release assets are never overwritten. A retry may finish an exact
matching draft or redeploy an already verified immutable snapshot. A mutable
published release, a digest conflict, unexpected assets, or an unverifiable
source identity fails closed.

Suspected key compromise freezes publication. Maintainers revoke the affected
subkey, publish the updated public certificate and incident notice, remove
affected versions from indexes, and publish new signed bytes under a
pre-distributed successor key. Audit artifacts remain retained.
