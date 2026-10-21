# Offline object-storage planning

`plan-object-storage-publication.py` prepares a deterministic transport inventory
for existing **preview `add_release` audit snapshots**. It reads local files,
writes a new plan and prints a digest receipt. It does not connect to GitHub or a
cloud account, access credentials, sign packages, upload objects, activate CDN
routing, or delete files from a repository. Stable remains disabled.

```sh
python3 scripts/plan-object-storage-publication.py \
  --inputs /path/to/reviewed-inputs.json \
  --output /path/to/new-transport-plan.json
```

The output must not already exist. Input paths may be absolute or relative to
the input JSON file. Repeating the same inputs with another output path produces
identical plan bytes, including when retained descriptors are reordered.

## Input trust and format

An operator supplies independently reviewed identity anchors. The planner does
not authenticate who reviewed them. In particular, a matching self-reported
receipt digest is not proof of a GitHub immutable Release, tag ancestry, control
commit identity, or valid signatures. Run the existing provenance and
cryptographic verification separately; this plan never replaces those gates.

The top-level object has exactly these fields:

```json
{
  "schema": "wukongim.object_storage_plan_inputs/v1",
  "channel": "preview",
  "current": { "...": "one snapshot descriptor below" },
  "retain": []
}
```

`current` and every member of `retain` use the same descriptor fields:

| Field | Value |
| --- | --- |
| `archive` | Local canonical `wukongim-preview-r<ID>-site.tar` path. |
| `receipt` | Local canonical `wukongim-preview-r<ID>-receipt.json` path. |
| `control_dir` | Real directory containing the six reviewed control files below. |
| `audit_release_id` | Independently reviewed positive numeric audit Release ID. |
| `control_sha` | Exact lowercase 40-hex control commit identity. |
| `archive_sha256`, `archive_size` | Expected archive SHA-256 and positive byte size. |
| `receipt_sha256`, `snapshot_sha256` | Expected external receipt and archived `audit/snapshot.json` SHA-256. |
| `source` | Exact `repository`, `version`, `release_id`, `source_sha` object for the added source release. Repository must be `WuKongIM/WuKongIM`. |
| `control_files_sha256` | Exact six-path to SHA-256 mapping listed below. |

The control mapping names are `manifests/channels.json`,
`manifests/preview-signing.json`, `manifests/signing-toolchain.json`,
`manifests/bootstrap-packages.json`, `keys/apt-preview.asc`, and
`keys/rpm-preview.asc`. Supply each retained snapshot's own control files and
anchors. Do not substitute the current control for historical inputs.

No unknown fields, duplicate JSON keys, repeated audit IDs, symlink input files,
hard-linked input files or symlink control roots are accepted. The fixed local
resource bounds are eight snapshots and 2 GiB of total declared archive bytes;
actual sizes must match before opening archives. Receipts and JSON control files
are capped at 8 MiB; public certificates and signing-toolchain controls at 1 MiB,
before hashing. Existing canonical archive bounds
also apply to each snapshot. These are planner resource limits, not a new
production retention policy.

## What is checked

The planner reuses the canonical archive extractor and reconstructs the existing
package audit receipt using the independent control files, public certificate
bytes and archived recovery copies. It checks the strict preview channel and
version scope, source identity, bootstrap identities, generated `/repo`, status,
APT indexes and by-hash objects, RPM metadata references and decompressed hashes,
and the exact allowed site file set. No package or maintainer script executes.

RPM metadata is classified as a shared immutable alias only when its filename
begins with its full byte SHA-256. Referenced metadata with ordinary filenames,
including the published `primary.xml.gz`, `filelists.xml.gz` and `other.xml.gz`
layout, undergoes the same complete receipt/reference/compressed/open hash
checks and remains a current `no-store` entrypoint. Native zstd decompression
is explicitly unsupported in this first pure-Python slice;
such input fails before invoking any decoder. Plain metadata and the existing
bounded Python gzip, bzip2 and xz paths are available through the composer.

This remains **structural and byte consistency verification**. The output marks
`signatures_verified`, `github_provenance_verified`, `control_commit_verified`,
`cloud_verified` and `activation_authorized` false. It cannot establish key
expiry/revocation status, whether an audit is still eligible for rollback, or
whether a reviewed cloud role/configuration exists.

## Plan layout and retention

- `snapshot_objects` inventories every original site/audit file below
  `snapshots/preview/r<ID>-<snapshot-sha>/`, preserving the canonical bytes.
- `immutable_aliases` maps versioned payloads/bootstrap downloads, APT by-hash
  indexes and digest-named RPM metadata to `public/<original-public-path>`.
  Across all supplied generations, an immutable public URI must keep the same
  bytes, size and cache classification.
- `entrypoints` lists only the current snapshot's floating public URLs, mapped
  to its immutable snapshot keys. They use `no-store`; in particular,
  `Packages.gz`, `repomd.xml` and its detached signature are not permanent aliases.
  Their physical snapshot objects also use `no-store`, so a future origin
  integration does not accidentally long-cache these floating URLs.
  Ordinary RPM metadata filenames follow the same rule; each retained generation
  keeps its own original bytes under its separate snapshot key.
- `retention` preserves every explicitly supplied old snapshot and the union of
  its immutable aliases. `delete_objects` is always empty. No elapsed-time or
  garbage-collection decision is inferred.

The plan has `status: "plan_only"` and `plan_only: true`. It contains no bucket,
region, credentials, API request or executable activation instruction. A future
uploader must still enforce create-only writes and verify remote bytes; a
future CDN adapter must implement and verify routing and cache behavior. The
plan does not claim whole-site atomic switching, consistency of a client's
multiple requests, or a completed stable repository.

With the existing fixed RPM base URL, requests spanning generations can still
mix `repomd.xml`, its signature and ordinary metadata filenames. A client may
safely reject that mix on signature or hash verification. This plan does not
provide atomic or seamless activation; an independent A/B publication rehearsal
is still needed for a future routing/activation adapter.

Stable/multiple channels, `update_bootstrap`, retirement operations, mirrorlist
changes, signing, upload/activation and deletion are intentionally rejected or
absent in this first slice. Preview installation and publication defaults are
unchanged.

## Repeatable local validation

```sh
python3 -m unittest tests.test_plan_object_storage_publication -v
```

The tests build small canonical snapshots through existing fixture builders,
then call the planner's CLI boundary. Their signatures and public certificates
are TEST ONLY synthetic bytes. They prove the plan's deterministic transport
and rejection behavior, not cryptographic publication readiness.
