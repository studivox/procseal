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

### Security

A follow-up review of the CLI foundation identified several correctness and
defense-in-depth gaps before findings and live process data exist at all.
Corrected here, ahead of the PM2 adapter that will actually produce them:

- `Finding` no longer has a free-form `message` field. Displayed titles are
  always derived from the fixed rule catalog (`getRuleTitle`), and
  `details` may only hold values validated against a conservative character
  set and length limit (`core/label.ts`, `createFinding` in
  `core/types.ts`).
- Both reporters now pass every string-bearing output field — including the
  audit-level message, status, and finding metadata — through a final,
  independent sanitization boundary (`core/output-safety.ts`) immediately
  before writing it, backed by a run-scoped `SecretRegistry`
  (`core/secret-registry.ts`). This does not assume upstream validation
  already happened.
- The CLI's top-level error handler no longer attempts substring redaction
  with an empty known-values list (which redacted nothing). It now prints a
  static message and a coarse, pattern-validated error code only —
  `Error.message` and stack are never shown (`core/internal-error.ts`).
- `Fingerprinter` no longer exposes a single `fingerprint()` method that
  could be mistaken for an equality check. It now exposes
  `displayFingerprint()` (truncated, display-only) and `equals()` (full
  HMAC-SHA-256 digest, compared with `timingSafeEqual`) as separate
  operations; neither the key nor the full digest is ever returned.
- The dotenv parser was rewritten as a small hand-written scanner to
  correctly handle trailing comments after quoted values, a `#` inside
  quotes, escaped double quotes, empty quoted values, CRLF input, and
  `export KEY=value`, and to report malformed/unterminated quotes as a
  structured diagnostic (line, key, reason) instead of a misleading value.
- README no longer shows `npx procseal ...` under "Try it now" as if it
  currently works; the package is private and not published. Local-clone
  instructions are the only currently-working path, with `npx` clearly
  labeled as the future, post-publication command.

Adversarial tests were added proving that a sentinel value placed in the
audit-level message, a finding's metadata key or value, or a value nested
inside metadata does not appear in terminal or JSON output once registered
with the run's `SecretRegistry`; and that a thrown error containing a
sentinel never reaches the CLI's stderr output, with or without that
sentinel being known to any registry.

A second, final hardening pass fixed four remaining gaps:

- `SecretRegistry.scrub()` now sorts registered values longest-first before
  replacing them, independent of registration order. Previously, if a
  shorter value (e.g. `abc`) was registered before a longer, overlapping
  one (e.g. `abcdef`), scrubbing the shorter value first could leave the
  longer secret's remainder (`def`) visible in output.
- `renderTerminalReport` and `renderJsonReport` no longer default their
  `registry` parameter to a fresh, empty `SecretRegistry` — it is now a
  required argument, so omitting it is a compile-time error rather than a
  silently unprotected report. `commands/audit.ts` creates exactly one
  run-scoped registry per invocation and threads it through result creation
  (`runPlaceholderAudit`) and whichever reporter renders the output.
- The CLI now routes reflected command-line arguments (an unrecognized
  command or option, echoed back in a usage error) through the same
  `sanitizeForDisplay` boundary the reporters use, so a hostile argument
  containing a newline or ANSI escape sequence cannot forge extra terminal
  lines or manipulate the terminal when reflected into stderr.
- The dotenv parser's unquoted `#` handling is now documented and
  consistent: outside quotes, the first unescaped `#` always begins a
  comment (whitespace before it or not); inside either quote style, `#` is
  always literal.

Further adversarial tests were added: overlapping/prefix/suffix/repeated
secret scrubbing in both registration orders; a compile-time check that
reporters cannot be called without an explicit registry; hostile
newline/ANSI command-line arguments; and the five documented dotenv hash
cases.

### Notes

- `procseal audit` does not yet inspect any real machine or PM2 process. It
  always reports an explicit `not_implemented` status and produces zero
  findings. Live PM2 inspection is deferred to a following milestone.
- Documentation was updated to use `npx procseal audit` instead of the
  earlier planned `scan` subcommand name.
