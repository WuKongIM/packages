# Installed CLI acceptance fixtures

All data is synthetic. No server runs during acceptance. `original-v2-empty.tar.gz`
is copied byte-for-byte from WuKongIM/WuKongIM at commit
`c0dc9148d23c7d61072d29f2c3fcad6b642aa2c5`, path
`internal/infra/migrationv2/testdata/original-v2-empty.tar.gz`. Despite its name,
it contains the user `emptyalice`, one device, and one empty group.

`native-v3.tar.gz` contains only `messages/` and `slotmeta/` produced by the
same source commit's wkcli migrate prepare, export and import commands.
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
`sha256.json` fixes all five data files. Acceptance checks archive paths and
size/count bounds before unpacking private copies. These fixtures deliberately
remain fixed when testing newer CLI versions to detect compatibility regressions.
