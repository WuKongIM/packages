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

## Owned Linux execution

The internal `supervise_staging` capability accepts strict request schema v2.
It adds `process_limits` with finite `max_process_output_bytes` (at most 64 MiB)
and `max_processes` (at most 10,000); HTTP limits retain their v1 meaning.
The public `run_delivery` entry still refuses. Neither request data, an inherited
FD nor temporary credentials establish production authorization.

A dedicated, single-thread Linux supervisor rejects existing unrelated children,
becomes a subreaper and starts one worker in its own session/process group.
Source helpers, `gh` and native metadata inspectors inherit that group. One
absolute deadline covers input verification, materialization, SDK traffic and
helpers; a reserve inside the same timeout covers TERM, KILL and reaping.
Cancellation sets the shared numeric token without blocking the owner on a held
lock; a worker signal also stops its next SDK request. Shutdown starts no cloud
readback, retry or rollback. The exact owned group is terminated and adopted
children are reaped. An unverified cleanup or invalid journal/budget leaves an
incomplete result. OS scheduling, uninterruptible I/O and host/filesystem loss do
not provide a universal real-time or durable-host-recovery guarantee.

Temporary credentials cross an anonymous pipe and enter the concrete Provider
constructor. They never enter request JSON, argv, evidence or helper environments.
Only an explicitly supplied source token reaches the isolated `gh` environment.
Helper commands come from reviewed code; request JSON cannot choose executable
code. Streams are drained concurrently with per-command and aggregate byte caps;
raw stderr is discarded. Process-output counts do not count HTTP calls hidden
inside `gh`.

The numeric budget FD is unlinked, private and inherited only by reviewed Python
helpers. Traditional POSIX process-associated record locks protect explicit
`pread`/`pwrite` updates and checksum validation. Inherited-OFD `flock` is not used.
Each PID has one context/FD and one owning thread; no duplicate/reopened budget
FD may be closed during its short critical section. A busy parent lock never
blocks process cancellation. Corruption refuses further grants.

V2 output is `supervision-start.json`, `supervision.json` and
`staging/{prepared/,effects.jsonl,execution.json}` under a new private root.
The worker checks its inherited directory FD identity. Supervisor evidence uses
the same exact journal-binding parser as read-only reconciliation; raw HTTP
headers or a later matching GET cannot clear an original unknown PUT. Evidence
space for supervisor output is reserved before effects. Original v1 direct
staging and its portable fixtures retain their layout.

Explicit process acceptance is separate from default quick tests:

```sh
python tests/provider_sdk/owned_budget_process_integration.py --receipt /tmp/owned-budget.json
python tests/provider_sdk/owned_runtime_process_integration.py --receipt /tmp/owned-runtime.json
python tests/provider_sdk/owned_execution_integration.py --receipt /tmp/owned-staging.json
```

The last suite requires Linux and returns a failing unsupported receipt elsewhere.
The contents-read SDK workflow invokes all three with fixed timeouts and uploads
source-bound receipts. Zero tests, skipped cases, changed source, errors or
failures cannot pass. Linux SDK fixtures use the actual staging/materializer,
existing GitHub/native-tool seams and official SDK HTTP Wire with networking
forbidden; they do not establish live provenance, platform authority or public
package delivery.

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
unknown request into success. `original_unknown_outcomes` counts each original
PUT unless its unique object attempt has a completed `object_observed` record
bound to the prepared key, byte/hash/cache facts and full readback, with outcome
`created` or `already_exists`. HTTP status/headers alone, missing completion and
`unknown_readback_verified` remain unknown. Duplicate attempts, request IDs or
completions and inconsistent object facts are rejected before Provider reads;
one successful record cannot erase a different unknown attempt. Raw transport
observations remain unchanged in the prior journal.

Reconciliation performs no PUT, configuration
change, refresh, rollback or automatic resume and cannot report publication
completion. A missing or mismatched read remains unknown.

The private CDN journal uses `run_start_v2`; the legacy staging parser rejects
that discriminator. It adds exact configuration/refresh scopes while preserving
the default staging format and its unknown-PUT accounting. The shared parser is
also used by owned summaries, so unknown counting cannot diverge from reconciliation.
Production `run_delivery`/`activate` and the owned staging worker remain unchanged
and cannot initiate this private CDN path.
The journal remains attached to the same RunBudget instance, not a replacement
with equal limit values. Original deadlines, counters and evidence credit cannot
be renewed by rebinding Provider or the transport. Responses are closed even when
recording their headers fails; the original request remains unknown.
Transport acquisition failures are recorded once. A failure recording known
headers is not a second transport failure. SDK exceptions carrying a Response
and urllib HTTPError bodies are closed on failure, including journal/owner
rejection. A successfully returned wrapper transfers body ownership to the
caller's existing context manager, which closes it even when a read guard fails.

`_reconcile_cdn_effects` first validates the exact prior request, intent,
preparation and journal before any Provider reads. It uses a new finite read-only
budget and records the original effect deadline without reviving it. Complete
current configuration and allowlisted task-ID/URL/status observations are current
state only. Original unknown counts remain split into PUT/configuration/refresh
requests; no matching current value changes those counts. A submission whose
response supplied no valid task IDs stays explicitly unobservable. Only recorded
positive IDs are queried, in groups of at most ten and within the original finite
URL universe. Reconciliation never searches task history or retries a submission.

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
