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
access disabled until the private `WuKongIM Source Release Reader` GitHub App
has been installed only on `WuKongIM/WuKongIM` with Contents and Attestations
read access. Its client ID and private key exist only in the protected
`native-package-source-read` Environment as `WK_SOURCE_READ_APP_CLIENT_ID` and
`WK_SOURCE_READ_APP_PRIVATE_KEY`. These manifests reject unknown fields and
duplicate JSON keys. Workflow inputs, repository variables, dispatch payloads,
and release titles must not override reviewed values.

`manifests/audit-access.json` fixes the two package App Environments, secret
names, installation owner and repository, and exact permissions. It remains
disabled until both Apps and their isolated protected Environments have been
provisioned. Every package audit reader or writer job validates the complete
control plane and requires this manifest to be enabled before minting an App
token. The initial control change therefore remains fail-closed with
`enabled: false`; enabling access is a separate reviewed control change after
external provisioning succeeds.

GitHub's Immutable Releases status endpoint requires repository
Administration read access, which the workflow `GITHUB_TOKEN` cannot request.
The private `WuKongIM Package Policy Reader` GitHub App is installed only on
`WuKongIM/packages` with Administration read permission only; GitHub supplies
the implicit Metadata read permission. Its client ID and private key exist
only in the protected
`native-package-preview-audit-read` Environment as
`WK_PACKAGE_AUDIT_READER_APP_CLIENT_ID` and
`WK_PACKAGE_AUDIT_READER_APP_PRIVATE_KEY`. Only the publisher control and
immutable replay jobs use this App, and only for the Immutable Releases policy
endpoint. Release, tag, and asset reads use those jobs' ordinary read-only
workflow tokens instead.

The separate private `WuKongIM Package Publisher` GitHub App is installed only
on `WuKongIM/packages` with Administration read and Contents write permissions.
Its client ID and private key exist only in the protected
`native-package-preview-audit` Environment as
`WK_PACKAGE_PUBLISHER_APP_CLIENT_ID` and
`WK_PACKAGE_PUBLISHER_APP_PRIVATE_KEY`. Only draft creation, audit-tag binding,
and sealing use this App and request Contents write. The three Apps use three
distinct private keys; a key must never be copied into another App's
Environment. None of the Apps has webhook, OAuth, workflow, secret,
environment, or organization permission. The ordinary workflow token remains
read-only in these jobs.

The checked-in `site/` tree always remains the disabled bootstrap page. Live
APT/RPM content is generated from reviewed control plus immutable Releases,
verified as a complete snapshot, and sent directly as one Pages artifact. It
is not committed to `main` or a generated branch.

The production repository builder and two supplemental legacy verifiers are
loaded only from the exact source commit and file digests recorded in
`manifests/trusted-toolchain.json`. The TEST ONLY integration drill uses the
other files in that same reviewed manifest, but they are not copied into the
production tool boundary. Production signing, snapshot composition, audit
receipt validation, and final cryptographic verification come from this
repository's exact protected control commit and execute inside the separately
digest-pinned, GitHub-attested signing image recorded by
`manifests/signing-toolchain.json`. The source Release tag and its assets
cannot choose executable publishing logic. Updating either pin is an ordinary
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
Release. For an `add_release` publication, the exact eight-file evidence set
(seven per-asset attestations plus its canonical summary) is carried through
the publisher and preserved below `audit/source-attestations/` in the immutable
package snapshot. The manual preflight remains read-only and does not publish
or sign anything.

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

An `add_release` target must rank strictly above every active base version under
strict SemVer precedence and under the exact DEB and RPM version mappings used
by the fixed signing toolchain. The planner calls both `dpkg --compare-versions`
and RPM's native `rpm.vercmp`; disagreement or a non-increase fails closed. A
`remove_indexes` transition may remove only the oldest active version. For an
addition, all four clean-client checks must download bytes mapped exclusively
to the reviewed target version, so successfully refreshing metadata without
selecting the new package is not publication success.

Retirement is a two-run operation because package and metadata objects can
remain in the Pages CDN cache for roughly ten minutes. The first reviewed run
removes the oldest version from APT and RPM indexes while retaining its payload
and dependency closure, then records an `indexes_removed` state and an absolute
`not_before` at least thirty minutes later. A separate run after that timestamp
may remove the bytes and clear the retirement state. A workflow never sleeps
through the cache interval.

## Signing

APT and RPM use separate OpenPGP certificates for each channel. APT signs the
same `Release` bytes as both `InRelease` and `Release.gpg`; individual deb files
do not receive a non-standard signature. RPM packages are signed before
`createrepo_c` builds metadata, and the same channel RPM certificate signs
`repodata/repomd.xml`.

After it is provisioned, preview CI may import only the encrypted current,
sign-only subkey for that family. APT uses the protected
`native-package-preview-apt-signing` Environment and the
`WK_APT_PREVIEW_SECRET_SUBKEY_B64` / `WK_APT_PREVIEW_PASSPHRASE` secrets. RPM
uses `native-package-preview-rpm-signing` and the
`WK_RPM_PREVIEW_SECRET_SUBKEY_B64` / `WK_RPM_PREVIEW_PASSPHRASE` secrets. The
two operator-retained certify-only primary keys must never be present in either
environment.

Each reviewed certificate contains one certify-only primary and an exact
`current`, `next`, and `historical` signing-subkey set. Only `current` private
material may enter CI. `next` is public-only, may have a future creation time,
and must extend the current subkey's expiry by at least the 45-day rotation
runway. `historical` contains former current sign-only subkeys, which may still
be valid, expired, or revoked, but must be public-only in CI, must not expire
after the current subkey, and must never be disabled, invalid, or future-created.
An expired or revoked historical key remains audit topology only and cannot
authorize any deployable payload. A currently usable historical key can
authorize only byte-for-byte preserved RPM payloads. New RPMs and all newly generated
repository metadata remain restricted to the current subkey. Every listed APT and RPM fingerprint is
globally distinct. Their trailing 16-hex and 8-hex key IDs are also globally
distinct because RPM verification output may identify a signer by a shortened
key ID. Subkeys last at most 180 days, and the current subkey must have at least
30 days remaining.

The signed APT `Release` header set is closed to the exact source-builder
output: `Origin`, `Label`, `Suite`, `Codename`, `Architectures`, `Components`,
`Acquire-By-Hash`, a canonical UTC `Date`, and the four standard checksum
sections. The verifier rejects additional client-policy headers, including
`NotAutomatic`, `ButAutomaticUpgrades`, `Valid-Until`, and `Signed-By`, and
rejects a `Date` more than 60 seconds in the future. There is intentionally no
maximum age because an immutable audited snapshot must remain reproducible.

Because an RPM signature changes the package bytes, an old package is never
silently re-signed during rotation. Operators must complete the normal
`remove_indexes` then `remove_payloads` retirement before its actual signing
subkey expires or is revoked. The publisher independently isolates each
candidate signing subkey in its own RPM database and requires exactly one
currently usable reviewed key to verify; the packet's hashed issuer fingerprint
must agree with that cryptographic result and is not trusted as identity by
itself.

Every RPM-family primary, current, next, and historical key is RSA: its GnuPG
colon record must report public-key algorithm `1`, and its key size must be
exactly 3072 or 4096 bits. This RSA restriction does not apply to the APT
family. The control-plane certificate check enforces the RPM rule before any
signing job starts, and the isolated signer repeats it against both the public
topology and imported secret-key records before and after secret-subkey import.

Every RPM package-header signature and `repomd.xml` signature must use
SHA-256. New RPM payload signing fixes rpmsign's `_gpg_digest_algo` to `sha256`;
repository-metadata signing fixes GnuPG's digest to `SHA256`; and the isolated
signer proof rejects a `VALIDSIG` status whose OpenPGP hash algorithm is not
`8` (SHA-256). Verification of preserved signed RPMs likewise rejects a
header-signature packet that declares any other digest algorithm.

Before any signing command, each encrypted secret-subkey export is independently
loaded into a fresh isolated GnuPG home. Validation rejects a private primary,
an extra or token-backed private subkey, an unprotected subkey, the wrong
passphrase, a public-key topology change, a subkey lifetime over 180 days, or
less than 30 days of remaining validity. A proof signature must use the exact
reviewed signing-subkey fingerprint and SHA-256.

The manual signing-material preflight verifies the two GitHub Environment
secret pairs without creating or uploading any package, artifact, tag,
Release, or Pages snapshot. Its APT and RPM jobs remain separate, require the
exact current protected `main` commit, verify the digest-pinned toolchain's
GitHub provenance before referencing either family secret, and run the same
isolated proof-signature validator with networking disabled. The validation
output contains public certificate metadata only and is discarded rather than
stored or uploaded. Success proves only that, at that run, each Environment's
encrypted current subkey and passphrase match the protected manifest and public
certificate and can create a SHA-256 proof signature. CI does not validate the
operator-retained primary or next private key, revocation certificate, or
backup recoverability.

The public certificates are part of every composed snapshot and audit archive,
and are published at `/keys/apt-preview.asc` and `/keys/rpm-preview.asc`. The
minimal rotation keeps the same family primary: the old current moves to
`historical`, the pre-distributed next becomes current, and the
operator-retained primary certifies a new next. This promotion may happen at
the 45-day rotation boundary without waiting for expiry or revoking a healthy
former current. The next subkey must be present in the public certificate
before the first signed publication. There is currently no repository keyring
package, so this is not an automatic client key-rotation system. The initially
pre-distributed next permits one promotion without a client update; clients
must manually refresh the stable certificate URL while the current subkey is
still valid to learn each later successor. Automatic ongoing delivery requires
a separately designed and signed keyring package.

Preview primary-key generation currently uses an explicitly accepted
single-operator online-workstation custody model. The named operator is
`tangtaoit`. The operator retains one encrypted full-secret backup and its
revocation certificate outside the repository in a mode-0700 local directory
with mode-0600 files, stores each distinct passphrase in the operating-system
credential store, and completes a restore check before CI secrets are
provisioned. Only the encrypted current sign-only subkey is copied to its
package-family Environment; the primary and next private keys never enter
GitHub. This lower-assurance model does not claim resistance to compromise of
the generation workstation. Moving preview signing to an offline or
multi-custodian trust model requires generating new primary certificates under
that model and distributing their public certificates; an online-generated
primary cannot become retroactively offline.

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

The first `add_release` deployment accepts only the exact four-field v1
provisioned bootstrap status with both package families disabled and reason
`awaiting_first_release`. A stale `signing_not_provisioned` bootstrap is not a
valid predecessor for production publication; operators must first complete
the reviewed signing-provisioning bootstrap deployment.

Exact release assets are never overwritten. A retry may finish an exact
matching draft or redeploy an already verified immutable snapshot. A mutable
published release, a digest conflict, unexpected assets, or an unverifiable
source identity fails closed.

Audit Releases use an explicit two-control state machine. The preparation run
creates one canonical empty draft and reports its numeric ID while its final
non-version tag is still absent. A protected control change records that ID;
the bind run then creates the lightweight
`native-package-preview-r<ID>` tag once at that exact control commit and changes
only the empty draft's `target_commitish`. GitHub may detach a draft to a
generated `untagged-<20hex>` identity when the real tag is materialized. The
binder accepts that intermediate identity only while the Release remains the
exact empty draft and the canonical lightweight tag already points to the
reviewed control commit. The generated name must have no corresponding Git ref
and must remain byte-for-byte stable across recovery reads; the binder then
restores only the canonical `tag_name` and revalidates both objects. The
publisher accepts only the exact reserved tag and
numeric ID. The tag namespace must forbid deletion and force updates. Two
active, aggregating tag rulesets must match
`refs/tags/native-package-preview-r*`: a creation-only ruleset grants its sole
bypass to the numeric Integration ID of the Package Publisher App, while an
immutability ruleset denies update, deletion, and non-fast-forward operations
without any bypass actor. The rules stay separate so the App that creates a
reserved tag can never bypass its immutability. If protected `main` advances
after binding, that draft/tag pair is abandoned and a new numeric draft must be
prepared and reviewed; it is never rebound to a later control commit.

Repository immutable Releases must remain enabled. Immediately before making
a draft immutable, the writer re-downloads both canonical assets, re-reads the
exact two-asset draft state, and re-fences protected `main` plus the create-only
audit tag. It also re-reads the repository immutable-Release policy immediately
before and after the publication write. The publish response and final ID-bound
downloads are verified again. GitHub does not offer an atomic conditional
Release PATCH, so an administrator changing this policy inside the final API
race can still burn the reserved audit ID; the strict response check prevents
that mutable Release from reaching Pages. These checks detect interference;
they never delete, replace, or rename remote assets.

Each successful publication also creates an immutable Release in this
repository containing the exact signed snapshot inputs and audit receipt. That
Release, rather than Git history or the live CDN, is the durable rebuild and
rollback source.

GitHub Pages does not expose a conditional deploy primitive that atomically
asserts `main == control_sha`. The publisher fences `main` immediately before
and after deployment and again during public verification, so a concurrent
control change is detected, but a stale reviewed snapshot could be visible
briefly inside that platform race window. Operators must not merge a package
control change while any draft, bind, publisher, or bootstrap deployment is in
progress. Pull-request validation uses a separate concurrency group and cannot
replace a queued production run.

Suspected key compromise freezes publication. Using the operator-retained
family primary, maintainers revoke the affected subkey, promote the already
distributed next subkey, certify and publish a new next, publish an incident
notice, and remove affected versions from indexes or rebuild signed bytes as
required. A preserved
RPM whose issuer is revoked must fail verification and cannot remain published
under the normal historical-key exception. The
updated certificate, manifest, snapshot, and audit receipt must agree before
publication resumes. Audit artifacts remain retained.
