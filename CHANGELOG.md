# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This
project uses pre-release versioning while in early development and has not
been published to npm.

## [Unreleased]

### Added

- Secure CLI foundation with an executable `procseal` command:
  `procseal --help`, `procseal --version`, `procseal audit`,
  `procseal audit --help`, `procseal audit --json`.
- Shared core types for findings, severities, and the eight stable rule
  identifiers (PS001–PS008).
- Keyed HMAC-SHA-256 fingerprinting (`core/fingerprint.ts`) using a random,
  run-scoped, in-memory-only comparison key.
- Error and output redaction utilities (`core/redaction.ts`) that strip
  known raw values from messages before they can reach stderr.
- A dotenv-style parser (`parsers/dotenv.ts`) that never mutates
  `process.env`.
- Terminal and JSON reporters that only ever emit structured, redacted
  findings.
- `docs/THREAT_MODEL.md` describing the redaction contract, fingerprint
  design, and its limitations.
- GitHub Actions CI running install, format check, lint, typecheck, tests,
  build, and a package dry-run on Node.js 20 and 22.

### Notes

- `procseal audit` does not yet inspect any real machine or PM2 process. It
  always reports an explicit `not_implemented` status and produces zero
  findings. Live PM2 inspection is deferred to a following milestone.
- Documentation was updated to use `npx procseal audit` instead of the
  earlier planned `scan` subcommand name.
