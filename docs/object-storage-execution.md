# Object delivery execution: staging slice

The production `run_delivery(request)` entry refuses before importing or
constructing any SDK. No protected execution job is connected, and stable remains
disabled. This first slice implements the internal staging path that a future
reviewed composition root will call after real platform authority. Request JSON,
credentials, a saved receipt, or a callback cannot grant that authority.

`_stage_immutable(request, provider=...)` uses the existing materializer, fresh
input verifier, source/audit resolvers, and concrete official SDK Provider. It
never calls the CDN configuration or refresh methods. The disabled resource
intent in the original preparation remains unchanged; the exact actual resource
descriptor has a separate execution digest.

The strict v1 request names its operation, executor SHA, absolute input/output
paths, original input and plan SHA-256 values, exact Provider resource descriptor
and finite limits. The output must be new. Limits cover time, HTTP request count,
objects, public routes, upload/read bytes and evidence. This initial execution
subset permits at most 2,048 objects, 1,000 routes, 2 GiB upload bytes and 8 MiB
combined journal/receipt evidence. Preparation's broader 10,000-route capability
does not imply execution support.

## Identity fences and cost

A complete `verify_delivery_inputs` runs before staging and again after all
objects, comparing the original observation. It authenticates the original
plan, historical controls, numeric immutable source/audit identities, seven
source assets, attestations and native metadata through the existing helpers.

Before each next PUT, `revalidate_delivery_anchors` checks the exact original
input/plan binding, current protected main, clean executor, source Release/tag,
main ancestry, and source/audit numeric asset IDs, names, sizes and API digests.
It does not download source assets or claim a new native/provenance check. The
current prepared inventory and object bytes are checked again. A changed light
anchor stops the next PUT. A change first detected by the final complete check
cannot undo preceding uploads; it leaves staging incomplete and prevents any
later activation.

This avoids downloading all seven source assets for every object. The counter
contract runs 153 actual metadata fences between two complete verifications:
there are 14 source-asset downloads and two executions of each existing native
helper at the test subprocess seam. The positive SDK staging fixture currently
contains 49 real materialized objects; it does not claim a 153-object stable
production rehearsal.

## Bounds and evidence

One per-invocation `RunBudget` reaches each GitHub reader instance, direct and
redirect asset opens, native-helper subprocess timeouts, SDK session send, and
provider response/object-body reads. Timeouts are clamped to remaining time;
request/read/upload counts are finite. Instance controls preserve all default
reader/SDK behavior when no budget is supplied. A budget restricts effects and
never authorizes them.

`effects.jsonl` persists and fsyncs each sanitized request before transport. It
binds the exact request, resource, prepared inventory and initial identity facts.
PUT facts name only the frozen object key, length, digest and cache policy. It
records response observations or an unknown outcome, never tokens, signed URLs,
Authorization headers or raw SDK exceptions. `execution.json` binds the final
journal digest. Evidence overflow produces a bounded incomplete summary.

An unknown PUT is never retried. Existing Provider behavior performs a complete
GET; exact bytes can establish the object's present state while the original
request outcome remains unknown in the journal. Failed readback stops staging.

The current budget stops new requests and checks stream reads but cannot revoke
an in-flight remote request atomically. The v2 design's outer owned-process
watchdog/cancellation lifecycle is still a later execution slice. This code does
not claim that a blocked read is interrupted at an exact global deadline.

## Read-only reconciliation

`_reconcile_staging` requires the exact original request, input/plan/resource,
prepared inventory and independently supplied prior-journal SHA-256. It reads
only the original attempted keys and complete current CDN configuration through
a read-only budget. An unmatched request or journal fails before Provider
requests. Partial trailing journal bytes remain explicitly recorded.

Current main/source/input drift is recorded as `fresh_anchor_status: unverified`
and keeps the result incomplete; it does not prevent exact prior-key/config
reads after the independently bound prior request/journal/preparation checks.
It grants no wider scope.

A later matching object is `observed_now: exact`; it never rewrites an original
unknown request into success. Reconciliation performs no PUT, configuration
change, refresh, rollback or automatic resume and cannot report publication
completion. A missing or mismatched read remains unknown.

## Repeatable local validation

Install the existing hash-locked SDK dependencies in a separate virtualenv, then
run the SDK execution contracts with networking forbidden by their fixture:

```sh
PYTHONDONTWRITEBYTECODE=1 python tests/provider_sdk/test_object_storage_execution.py -v
PYTHONDONTWRITEBYTECODE=1 python tests/provider_sdk/test_aliyun_object_storage_provider.py -v
```

The tests reuse `FreshPreviewWire` and the existing official SDK `Wire`, not a
method-by-method cloud facade. Actual planner/resolver/fresh-verifier code and
SDK signing/serialization run. GitHub HTTP and native-helper subprocess results
are fixtures. No real attestation/native tool, Go, Docker, cloud resource,
public DNS, signing private key or production credential is used. All fixture
production/publication/cloud/provenance flags remain false.

Full gateway, canonical-edge rehearsal, controlled generation transitions,
public observer/four-client completion, protected entrypoint and real live
acceptance remain subsequent work in this same execution module. Staging success
is not a stable package release.
