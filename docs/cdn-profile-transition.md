# Controlled CDN profile and transition design

This is preparatory design with failure-first SDK tests, not an implemented
gateway. `Provider.activate` and `run_delivery` remain closed. No resource,
credential, permission, channel, workflow or SDK pin changes are included.

The first increment validates an exact controlled profile through the existing
`read_configuration` / `apply_rewrites` interface and official SDK instance HTTP
Wire. Any controlled-only facet requires the whole supported profile. Raw
observations, drift checks, server-assigned IDs and no-deletion behavior remain
unchanged. The legacy four-function primitive keeps its limited library contract;
it must not be relabeled as complete profile or activation acceptance. This
validation does not implement activation or a production composition root.

## Profile observations

A supported controlled profile must retain the complete resource-bound raw
domain/config observation, including every function, argument, ConfigId,
ParentId, status and order. Unknown functions/arguments, duplicate identities,
conditional groups, incomplete responses and unexpected differences refuse.
Do not discard fields to make a digest match.

The fixture specifies one private OSS HTTPS origin, exact origin HOST/SNI,
canonical domain/CNAME, enabled server-certificate status, HTTPS redirection
and TLS1.2/1.3 with older TLS disabled. A same-account `l2_oss_key` observation
has private authentication enabled and no permanent access-token arguments.
This is an observation of pre-existing configuration, never permission to grant
CDN access. The rewrite request must not emit private-origin authorization or
certificate setup functions.

For the candidate query policy, `set_hashkey_args` uses an empty retained list,
`disable=on` and `keep_oss_args=off`: cache and origin receive no query-selected
object variant. The root cache rule prioritizes the origin's policy and does
not ignore no-store/no-cache; its fallback TTL is one second. The materializer's
exact no-store floating objects and immutable object cache values remain the
authority for their intended metadata. Extra cache, query, rewrite, compression
or normalization behavior is rejected rather than silently combined.

These function values are documented Alibaba parameters, but serialized
configuration is not live semantic proof. A future observer must still test
query/encoded URI/normalization and negative-path behavior over the finite route
set, canonical Host/SNI and normal TLS validation. Certificate-enabled status
does not establish the actual certificate's SAN, lifetime or served chain;
fresh certificate identity and an actual TLS observation remain required.
No private certificate key is an execution input.

The feature parameter definitions are documented in the official
[function reference](https://www.alibabacloud.com/help/en/cdn/developer-reference/parameters-for-configuring-features-for-domain-names).
Private-origin first-use authorization is a separate protected setup action,
not an automatic repair of a missing role.

## Data and ownership for the next implementation

Keep the real execution module and concrete Provider. The engine owns the
overall run; Provider owns its bounded CDN apply/readback/refresh subsequence.
Neither delegates the overall run back to the other.

An internal transition description must bind:

- Original input/plan, prepared inventory, source/audit/control and resource
  digests. The finite target route table retains each URI's physical key,
  size, digest, cache value and immutable source generation.
- Complete C0 raw observation and digest, supported profile semantics, and
  the exact managed ConfigId/function/source map observed in C0.
- Target semantic digest independent of server-generated IDs, ordered update,
  add and exact-ID removal steps, and the finite intermediate-state safety proof.
- Per-step request/time/evidence limits and expected unchanged configuration;
  observed server-managed metadata changes require explicit validation rules
  and must remain in both raw observations and the recorded diff.

This description is data, not authority. Caller JSON, `managed_ids`, credentials
or a receipt cannot approve deletion or publication. A later reviewed protected
composition must supply the applicable capability for its exact resource and
transition; the public entries stay closed until that composition exists.
Ordinary preparatory code does not need production resources to be implemented.

Fresh resource and original input/main/source/audit fences precede every effect
phase. Re-read complete C0 immediately before its first effect. After each
attempt, read complete actual configuration, including ConfigIds. New IDs are
unknown until the API returns and the independent full readback agrees. C1 is
the resulting raw observation plus its target semantic digest, not a copy of C0
or an invented ID assignment. Later activation must freshly revalidate C1.
The first-bootstrap sequence remains immutable staging/full GET, authorized
canonical-edge rehearsal with the full target composite, then ordinary public
routing proof. Its reviewed DNS/non-use prerequisites are separate observations;
this slice does not create an edge, shadow domain or probe resource.

## Managed transitions and finite capacity

Existing `apply_rewrites` must continue refusing unbound source removal or
rechunking. A future controlled transition is a separate explicit operation in
the same Provider, not a relaxed boolean on that primitive. Exact-ID updates
use `BatchSetCdnDomainConfig`. Exact-ID removal uses `DeleteSpecificConfig`
with the single bound domain and observed ConfigId list; do not use
`BatchDeleteCdnDomainConfig`, whose selector is an entire function name.
[ConfigId contract](https://www.alibabacloud.com/help/en/cdn/developer-reference/usage-notes-on-configid),
[exact deletion](https://www.alibabacloud.com/help/en/cdn/developer-reference/api-cdn-2018-05-10-deletespecificconfig),
[function deletion](https://www.alibabacloud.com/help/en/cdn/developer-reference/api-cdn-2018-05-10-batchdeletecdndomainconfig).
The pinned SDK's exact deletion request/serialization still needs a focused
fixture check before that implementation; no pin update is proposed here.

At most 50 rewrite rules may coexist and at most 20 functions enter one request.
The initial execution remains at most 1,000 public routes. Check target and
peak intermediate capacities before any write. The retained native fixture's
178 routes compile to 17 rules; this is not capacity evidence for an arbitrary
production materialization. Its original 153-object inventory, archive/plan
anchors and route facts must not be regenerated or weakened to fit a test.

For rechunking, reason over all finite old/new inverse route maps and every
intermediate step. If duplicate expressions may match in unspecified order,
every possible resulting value must remain safe: canonical aliases may select
an authenticated complete old or new generation, while retained APT by-hash and
RPM mirrorlist/payload paths must still resolve to the complete uploaded/readable
immutable generations they promise. URL coverage or HTTP200 is insufficient.
If priority/visibility cannot be proved safe, refuse before writes. Do not
assume atomic POP switching or temporarily remove coverage to fit the cap.

## Attempts, observations and remaining tests

The default effect journal still admits staging only. Its private `cdn_effects`
evidence version binds the complete C0, prepared routes, compiled functions and
exact File URL set to the original request/plan/resource/preparation digests.
Provider opens one scope immediately around each SDK submission. Before Wire,
the actual signed POST's unique business fields must match the domain, action
and exact ordered batch; unknown/deletion actions and conflicting query/body
fields are refused. The sanitized unknown attempt is written and fsynced before
transport. Neither an intent nor a budget or journal grants publication authority.

The same RunBudget instance owns the journal throughout the invocation. Attaching
it to a new budget with equal limits cannot renew its deadline or request/read
credit. Ownership is checked at binding, before SDK/urllib dispatch and reads,
and through response consumption and acknowledgement. Late headers and scope
cleanup remain observations by the original owner; they do not extend its deadline.

Headers, bounded EOF/JSON consumption, validated acknowledgement and later
state are separate observations. Configuration IDs are acknowledged only after
matching their batch functions in the complete raw C1 observation. A known
earlier batch can stay acknowledged when a later batch is unknown. Valid refresh
submission IDs may span batches; acknowledgement does not mean task completion.
Timeout, malformed IDs, partial responses or interrupted bodies stay unknown
even if later state matches. Journal write/fsync failure stops further effects;
it never triggers retry. No rollback, deletion repair or resume follows.

The versioned `run_start_v2` discriminator makes legacy staging parsers refuse
CDN journals. The strict shared parser rejects unknown/duplicate/conflicting
events and records a partial trailing line as incomplete. Read-only reconciliation
binds the original request, intent, preparation and journal; it queries only
recorded valid task IDs within the finite URL set. A lost submission response
without IDs remains unobservable: no history scan, synthetic ID or resubmission.
Current matching configuration/tasks never clear original unknown counts.

The six new `test_controlled_profile_*` methods are the small first increment:
full A/B profile preservation with actual observed IDs; unsafe/incomplete facets;
complete body/ID drift; partial/unknown writes; unbound deletion/rechunk refusal;
and production-entry refusal. Existing finite grammar, neighboring-URI, 50-rule,
1,024-byte expression and 17-rule native tests remain unchanged. Every new case
uses the existing official SDK HTTP Wire and independently requires zero socket
connect attempts, even if an expected exception absorbs a transport failure.

Positive authorized removal/rechunk, server-managed metadata evolution,
certificate identity observation and actual edge URI semantics are not
implemented or covered by these six tests. Private journal/reconciliation uses
additional `test_cdn_effect_journal_*` SDK contracts, including actual serialized
request binding, body/ID/fsync faults, shared task IDs and read-only unknowns.
Their next failure-first cases must use the agreed transition data contract and
real SDK request/response path. Do not fabricate caller approval or substitute
a method-by-method cloud facade to make them pass. Final public observer and
unchanged four-client installed-CLI acceptance remain separate required work.
