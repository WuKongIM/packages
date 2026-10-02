# Installed CLI acceptance fixtures

All data is synthetic. No server runs during acceptance. `original-v2-empty.tar.gz`
is copied byte-for-byte from WuKongIM/WuKongIM at commit
`c0dc9148d23c7d61072d29f2c3fcad6b642aa2c5`, path
`internal/infra/migrationv2/testdata/original-v2-empty.tar.gz`. Despite its name,
it contains the user `emptyalice`, one device, and one empty group.

`native-v3-unregistered.tar.gz` preserves the previous native archive byte-for-byte
(SHA-256 `6bfc89f1dbe171b2f3a09998709fe9bfb0c406b962ee0f031ca66425b22377eb`).
It was produced by the original source commit above and has no directory marker.
Format-2 releases must reject it without writing or adopting the data.

`native-v3.tar.gz` contains `DATA-FORMAT.json`, `messages/` and `slotmeta/`
from a fresh generation produced by the published `v3.0.0-beta.22` macOS arm64
CLI, source commit `e12d13cdc797c53315f703445d5f4a950e064d6b`, using
`wkcli migrate prepare`, `export`, `import` and independent `verify`.
The CLI archive SHA-256 is
`025b6e13e8193674f76f5167e28c7b9937b6d0c85034eda5daf091b62eb310ea`.
The original v2 fixture is the source; its bytes remain unchanged. The importer
creates and registers a new format-2 directory. No marker is added to historical
native data. A private copy with its marker changed to format 1 is another
negative case and must also remain byte-identical after rejection.

The fixed single-node cluster plan uses source node 1, source shard_count 2,
source commit a888f89533d0e7d1b2030e06504ca97f1ad891d4, cluster_id cli-acceptance,
created_at 2026-09-09T00:00:00Z, slot_count 4, hash_slot_count 256, replicas 1,
channel_replicas 1, target node 101 at 127.0.0.1:57881. All source, workspace,
archive and target directories are separate temporary paths. Tar entries are
sorted, regular files only, mode 0600, zero owner/time; gzip mtime is zero.
Native database engine bytes may contain build-specific metadata, so the
checked-in digest is the authority for the fixture, not a claim of reproducible
Pebble output.

The three benchmark YAML files come from `docs-site/public/examples/wkbench/`
at that same commit. Only `bench validate` is invoked; no worker or traffic runs.
`sha256.json` fixes all six data files. Acceptance checks archive paths and
size/count bounds before unpacking private copies. The archives remain fixed within their declared format to detect compatibility
regressions. A deliberate format change requires a new positive generation and
retention of the historical fixture as a rejection case, with reviewed digests.
