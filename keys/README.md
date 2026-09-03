# Public signing keys

Only reviewed public certificates and binary public keyrings belong here.
Secret keys, secret subkeys, passphrases, revocation certificates, temporary
GnuPG homes, and test keys must never be committed or uploaded as artifacts.

Publication remains disabled until a reviewed signing manifest names exact
40-hex primary, current, and next signing-subkey fingerprints for both the APT
and RPM preview certificates. Historical fingerprints, when present, must be
sorted and must name public-only former current sign-only subkeys contained in
the same certificate. They may still be valid, expired, or revoked, but cannot
expire after the current subkey and must never be disabled, invalid, or
future-created. Expired or revoked historical keys remain audit topology only;
a live RPM payload must be retired before its actual signing subkey ceases to
be usable. Only a currently usable historical key may authorize a preserved
RPM payload.

The fingerprints and public certificates are committed review inputs. GitHub
variables must not override them. Every APT and RPM primary, current, next, and
historical fingerprint must be distinct so that one credential cannot silently
cross a trust boundary. Their trailing 16-hex and 8-hex key IDs must also be
globally distinct because RPM tooling may report only a shortened key ID.

The RPM certificate has an additional non-negotiable algorithm contract: its
primary plus every current, next, and historical signing subkey must be RSA
(GnuPG colon public-key algorithm `1`) with exactly 3072 or 4096 bits. RSA2048,
ECC, and every other algorithm or key size are rejected both by reviewed
control validation and by the isolated signer before and after secret-subkey
import. APT keys do not inherit this RPM-specific RSA restriction. RPM package
and repository-metadata signatures use SHA-256 (OpenPGP hash algorithm `8`).

While `manifests/preview-signing.json` has `enabled: false`, its primary,
current, and next fingerprints remain `null`, `historical` remains an empty
array, and the public certificate files may be absent. Enabling signing
requires adding the reviewed `apt-preview.asc` and `rpm-preview.asc` files and
their exact uppercase fingerprints in the same protected change. Each first
production certificate must already include its next subkey. Private primary
keys, private subkeys, passphrases, revocation certificates, and test keys
remain forbidden here.

Production APT and RPM secret subkeys and passphrases may exist only as the
fixed secrets in their corresponding protected signing Environment. They must
not be copied to repository-level or organization-level secrets, or into the
other package-family Environment.

The publisher copies these exact certificate bytes to the stable public paths
`/keys/apt-preview.asc` and `/keys/rpm-preview.asc` and records their SHA-256,
size, and topology in the snapshot and audit receipt. The reviewed bootstrap
builder also embeds the complete APT certificate in
`wukongim-archive-keyring` and the complete RPM certificate in
`wukongim-release`. Both packages are indexed in their signed repositories, so
an installed client can receive a later certificate before a newly added
successor subkey is promoted. The first direct bootstrap-package download
still trusts the HTTPS origin; automatic updates begin only after that package
has installed its dedicated key and repository definition.
