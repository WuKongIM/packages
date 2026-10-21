# Changelog

## Unreleased

- Allow explicit read-only stable source identity and provenance checks with
  `--channel stable`; existing commands and production workflows retain their
  preview default, and stable package publication remains disabled.

- Extend read-only source preflight through exact stable/preview DEB/RPM metadata
  verification and preserve source identity in its evidence. Stable publication
  stays disabled; the TEST ONLY drill now checks real native package metadata.
