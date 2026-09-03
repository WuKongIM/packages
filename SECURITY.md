# Security policy

Report suspected package-repository or signing-key compromise privately to
`security@githubim.com`. Do not open a public issue with exploit details or
private key material.

The public `/repo` script is part of the immutable package-site snapshot. It
must remain byte-derived from reviewed bootstrap package and RPM certificate
digests, and must never disable package or repository signature verification.
Report a missing, redirected, or byte-mismatched entrypoint as a repository
integrity incident.

On suspected compromise, maintainers freeze publication, remove the affected
CI signing secrets, revoke the affected signing subkey with its retained
primary certificate, publish an incident notice, and rebuild repository
metadata with a pre-distributed successor key. Existing release assets are
never overwritten or silently replaced.
