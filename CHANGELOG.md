# Changelog

## Unreleased

- Accept encrypted current-subkey and passphrase files for local family signing,
  retaining the existing CI environment inputs and verification, with native
  TEST ONLY signing regression coverage. Document Mac local stable-key custody;
  stable publication remains disabled.

- Add an offline, preview-only object-storage transport planner with explicit
  identity anchors and cross-generation dependency retention. It does not sign,
  upload, activate or enable stable publication.

- Allow explicit read-only stable source identity and provenance checks with
  `--channel stable`; existing commands and production workflows retain their
  preview default, and stable package publication remains disabled.

- Extend read-only source preflight through exact stable/preview DEB/RPM metadata
  verification and preserve source identity in its evidence. Stable publication
  stays disabled; the TEST ONLY drill now checks real native package metadata.
