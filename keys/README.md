# Public signing keys

Only reviewed public certificates and binary public keyrings belong here.
Secret keys, secret subkeys, passphrases, revocation certificates, temporary
GnuPG homes, and test keys must never be committed or uploaded as artifacts.

Publication remains disabled until a reviewed signing manifest names exact
40-hex primary and signing-subkey fingerprints for both the APT and RPM preview
certificates.

The fingerprints and public certificates are committed review inputs. GitHub
variables must not override them. The APT primary, APT signing subkey, RPM
primary, and RPM signing subkey fingerprints must be four distinct values so
that one credential cannot silently cross a trust boundary.

While `manifests/preview-signing.json` has `enabled: false`, its fingerprints
remain `null` and the public certificate files may be absent. Enabling signing
requires adding the reviewed `apt-preview.asc` and `rpm-preview.asc` files and
their exact uppercase fingerprints in the same protected change. Private
primary keys, private subkeys, passphrases, revocation certificates, and test
keys remain forbidden here.
