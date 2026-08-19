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

## [Unreleased] — PM2 adapter milestone

### Added

- A read-only PM2 process adapter (`src/adapters/pm2.ts`) that invokes
  exactly one fixed command, equivalent to `pm2 jlist`, through
  `node:child_process.execFile` with `shell: false`, a fixed argument
  array, a command timeout, and a strict stdout/stderr buffer limit
  (`core/command-runner.ts`). Never `exec`, never a shell command string,
  never `sudo`; never restarts, reloads, stops, deletes, saves, kills, or
  updates a PM2 process. Inspects only the PM2 daemon the current OS user's
  own environment resolves to. Supports dependency injection of the
  command runner, so its tests never require a real PM2 daemon.
- An opaque `ObservedValue` type (`core/observed-value.ts`) representing
  every PM2 environment value. The raw string lives only in a true
  JavaScript private field — never returned by a getter, `toString`,
  `valueOf`, `toJSON`, or any inspector — and the only operations exposed
  are `equals()`, `equalsPlain()`, and `displayFingerprint()`, all
  delegating to the existing HMAC-based `Fingerprinter`
  (`core/fingerprint.ts`). Construction registers the raw value in the
  run's `SecretRegistry` immediately, so it is scrubbable from output even
  if no other method on it is ever called.
- Immediately after successful JSON parsing, the adapter recursively
  registers every string leaf of the raw `pm2 jlist` payload in the run's
  `SecretRegistry`, before any normalization or reporting — treating the
  entire payload as sensitive, not only the fields the normalized snapshot
  happens to expose.
- A normalized `Pm2Snapshot` (`core/pm2-types.ts`) exposing only a safe
  process identifier, a redacted/validated process name, PM2's numeric id
  (when valid), a validated status enum, environment variable names, and
  opaque `ObservedValue`s — never the raw `pm2_env`, full command lines,
  raw node arguments, raw paths, or raw stdout/stderr.
- Documented, fail-fast hard limits (`PM2_LIMITS` in `src/adapters/pm2.ts`)
  for process count, environment variables per process, key length, value
  length, and JSON payload size, plus a command timeout. Exceeding any of
  them fails the whole run with a stable, non-sensitive error code instead
  of silently truncating a value and comparing the truncated version — a
  truncated secret compared as if it were the whole value could produce a
  false equality result.
- Stable, non-sensitive adapter error codes for: PM2 binary not found, PM2
  daemon unavailable, timeout, output too large, invalid JSON, malformed
  top-level payload, and each hard-limit violation. None of them ever
  carries raw stdout, stderr, or an underlying error's message — see
  `core/command-runner.ts`'s `CommandOutcome`, which classifies failures
  from Node's structured error fields and never hands the adapter raw
  process output at all.
- A real, isolated end-to-end test (`tests/e2e/pm2-live.test.ts`) that
  starts an actual PM2 daemon under a unique temporary `PM2_HOME` (created
  with `mkdtemp`), starts a tiny synthetic Node process with a synthetic
  sentinel environment value, reads it back through the adapter, and
  proves the sentinel never appears in any output or serialization. Torn
  down through a dedicated guard (`tests/e2e/pm2-isolation-guard.ts`) that
  refuses to run any cleanup command — including `pm2 kill` — unless
  `PM2_HOME` is present, non-empty, not the user's real `PM2_HOME`, and
  located inside the test's own temporary directory; the guard's refusal
  behavior has its own unit tests proving the kill command is never
  invoked when a check fails.
- `pm2` added as a pinned, exact-version `devDependency` (`7.0.3`) used
  only by the isolated end-to-end test. It is not a runtime dependency of
  the published package: `npm pack --dry-run` confirms the tarball
  contains no `pm2`, no tests, no fixtures, no temp files, no source maps,
  and no `node_modules`. `pm2` itself adds no `pre`/`post`/`install`
  lifecycle scripts to the dependency tree.
- GitHub Actions CI now runs unit tests, adapter integration tests, and
  the isolated real-PM2 end-to-end test as separate steps (Node.js 20 and
  22), in addition to the existing install, format, lint, typecheck,
  build, and package dry-run steps.

### Security

- Adversarial tests prove `ObservedValue`'s raw value cannot be recovered
  through `JSON.stringify` (direct or nested), `String()`/template-literal
  coercion, implicit `ToString` coercion, `util.inspect` (including with
  `showHidden`), `console.log`, `Object.keys`/`getOwnPropertyNames`/
  `entries`/`Reflect.ownKeys`, `Object.getOwnPropertySymbols`,
  `Object.getOwnPropertyDescriptors`, or a thrown `Error`'s message.
- Unit tests with an injected command-runner fixture cover: a valid
  payload, zero processes, multiple processes, a missing process name, an
  invalid PM2 id, an invalid status, duplicate environment keys in the raw
  JSON text, a missing environment object, invalid JSON, a timeout, a
  missing binary, an unavailable daemon, oversized stdout (both at the
  runner level and via the adapter's own independent payload-size check),
  an excessive process count, an excessive environment-variable count,
  excessive key/value lengths, hostile process names containing newlines
  and ANSI escapes, and a raw secret present in stdout that never appears
  in the returned diagnostic.
- `procseal audit` is unchanged by this milestone: the PM2 adapter is not
  wired into the public CLI yet, so `audit` still always reports
  `not_implemented` and performs no machine inspection. No production data
  is uploaded anywhere — this remains true with the adapter in place,
  since it only ever reads a local PM2 daemon and returns data in-process.

### Fixed

An independent security review of this milestone's branch found four
issues, all fixed here before merge:

- **Incomplete SecretRegistry traversal.** `registerAllStringLeaves()` in
  `src/adapters/pm2.ts` used recursive function calls with a depth cutoff
  (`MAX_WALK_DEPTH = 64`) that silently stopped registering string leaves
  past that depth — contradicting the documented guarantee that every
  string leaf of a successfully parsed payload is registered. Node's
  native `JSON.parse` can successfully build structures far deeper than a
  handful of nested function calls can traverse without throwing "Maximum
  call stack size exceeded" (empirically: a naive recursive walker
  overflows well under 200,000 levels of nesting; `JSON.parse` itself
  succeeds to at least 100,000 levels), so a sufficiently deep payload
  could previously both parse successfully _and_ leave a deeply-nested
  secret unregistered. Replaced with an iterative traversal using an
  explicit array-based stack instead of the call stack: depth is now
  bounded only by available memory (in practice, by `maxJsonPayloadBytes`,
  since expressing depth _D_ requires at least _2D_ bytes of JSON text),
  never by recursion, and every string leaf is registered regardless of
  depth. No new error code was needed. Added adversarial tests with
  payloads nested 500 and 100,000 levels deep, each proving the deepest
  sentinel is registered (via `SecretRegistry.scrub`) and never appears in
  a serialized result.
- **Unsafe E2E daemon cleanup.** `cleanupIsolatedPm2()` in
  `tests/e2e/pm2-isolation-guard.ts` previously deleted the isolated
  `PM2_HOME` temporary directory in an unconditional `finally` block, even
  when `pm2 kill` itself failed — which could erase the isolated daemon's
  control files while leaving its process running, untracked, in the
  background. Redesigned so the temporary directory is deleted only after
  a confirmed-complete teardown:
  - a new `readIsolatedDaemonPid()` reads PM2's own pidfile at the fixed,
    documented location `<PM2_HOME>/pm2.pid` (verified empirically against
    the pinned `pm2@7.0.3` devDependency) with strict parsing — `0`,
    negative numbers, non-numeric text, and the current test process's own
    PID are all rejected, never a source of an unsafe signal;
  - the PID is captured **before** `pm2 kill` runs, since PM2 removes its
    own pidfile on a graceful exit;
  - a new `isProcessAlive()` sends only signal `0` (a non-destructive
    existence probe, delivering no real signal) — there is no code path
    that sends any other signal;
  - if `pm2 kill` throws, cleanup now throws `CleanupIncompleteError` and
    the temporary directory is left untouched;
  - if `pm2 kill` succeeds and a PID was captured, cleanup polls
    `isProcessAlive` until the PID is confirmed dead (or a bounded number
    of attempts is exhausted) before deleting anything; a still-alive PID
    also throws `CleanupIncompleteError` without deleting;
  - the safety guard (`assertSafeToCleanIsolatedPm2Home`) still runs first
    and unchanged, and is now a TypeScript assertion function that narrows
    `pm2Home` to `string` for the rest of the call;
  - no fallback to `pkill`, `killall`, `sudo`, a shell command, or a real
    `PM2_HOME` was introduced — the only command run remains the existing
    guarded `pm2 kill`.

  Updated the existing test that previously asserted the temp directory
  _is_ removed after a simulated kill failure to assert the opposite.
  Added tests for strict PID parsing against malformed/unsafe pidfile
  content (zero, negative, non-numeric, leading zero, a float, trailing
  junk, empty/whitespace, and the test process's own PID), a missing
  pidfile/directory, path-scoping (a pidfile one directory up is never
  read), a still-alive-after-kill failure scenario against a real spawned
  helper process, and a confirmed-dead successful teardown scenario
  against a real spawned-and-exited helper process.

- **Value limit measured in the wrong unit.** `maxValueLength` was
  documented as "8 KiB" but compared against JavaScript's `string.length`,
  which counts UTF-16 code units, not bytes — a multibyte-Unicode value
  could be well under the intended byte budget while still under the
  `.length`-based limit, or vice versa. Renamed the limit to
  `maxValueBytes` and changed the check to
  `Buffer.byteLength(valueString, 'utf8')`. Added boundary tests using
  `'€'.repeat(n)` (1 UTF-16 code unit but 3 UTF-8 bytes per character)
  proving a value under the code-unit count can still fail the byte limit,
  and that a value within the byte limit is accepted. Still fails the
  whole inspection on violation; never truncates and compares a partial
  value.
- **Inaccurate `maxBuffer` documentation.** Code comments and
  `docs/THREAT_MODEL.md` described `execFile`'s `maxBuffer` option as a
  combined stdout/stderr limit. Node applies it to stdout and stderr
  _independently_ ("largest amount of data in bytes allowed on stdout
  **or** stderr", per Node's own docs), not as a combined bound. Corrected
  the documentation in `src/core/command-runner.ts` and
  `docs/THREAT_MODEL.md` to state this accurately, and to make clear that
  the adapter's own independent `Buffer.byteLength` check against the
  received stdout — which runs for every `CommandRunner`, including
  injected test fixtures that bypass `execFile` and `maxBuffer` entirely —
  is the real enforcement of `maxJsonPayloadBytes`, not `maxBuffer` itself.
  No implementation change; no stronger security claim was substituted for
  a real one.
- **Fail-open cleanup on an unreadable/malformed pidfile.**
  `cleanupIsolatedPm2`'s prior pidfile lookup returned a single
  `number | undefined` from `readIsolatedDaemonPid`, so a genuinely absent
  pidfile and an
  _existing but malformed or unreadable_ one were indistinguishable —
  both collapsed to "nothing to verify," letting cleanup proceed to delete
  the temporary directory even when a pidfile that might reflect a real,
  still-running daemon simply couldn't be trusted. `readIsolatedDaemonPid`
  now returns a discriminated `DaemonPidLookup` with one of three `kind`
  values: `'absent'` (no pidfile exists — nothing to verify, safe to
  proceed), `'valid'` (content strictly parsed to a safe PID), or
  `'unverifiable'` (a pidfile exists in some form — malformed content,
  oversized, non-regular, or unreadable — but cannot be trusted). The
  lookup now also uses `lstatSync` before reading, so an oversized pidfile
  is never read
  into memory and a symlinked pidfile is rejected as non-regular rather
  than followed to its target. `cleanupIsolatedPm2` still attempts the
  guarded `pm2 kill` regardless of the lookup's outcome (refusing to
  _delete_ is not refusing to _attempt_ the kill), but only deletes the
  temporary directory for `'absent'` (nothing to verify) or `'valid'` +
  confirmed-dead; `'unverifiable'` now throws `CleanupIncompleteError` and
  preserves the directory, exactly like a failed kill or a still-alive PID.
  Replaced the test that previously asserted a malformed pidfile permits
  deletion with one asserting the opposite. Added tests for each
  `DaemonPidLookup` state — malformed content, oversized, non-regular
  (directory in place of the file), symlinked, unreadable (skipped when
  running as root, where permission bits don't apply), genuinely absent,
  and well-formed — plus `cleanupIsolatedPm2`-level tests proving a
  malformed or non-regular pidfile blocks deletion while still attempting
  the guarded kill.

### Notes

- PS001–PS008 detection logic (comparing declared configuration against
  the live PM2 snapshot) remains fully deferred to the next milestone. This
  milestone is the adapter and its safety proof only.

## [Unreleased] — Rule engine milestone

### Added

- `procseal audit` now performs a real, read-only comparison between one
  explicitly selected PM2 process and one explicitly selected dotenv
  file, via new `--process <name>` and `--env <path>` options (plus
  `--json` and `--check-unexpected`). Both are required; ProcSeal never
  auto-discovers either. The obsolete `not_implemented` result is gone:
  `procseal audit` now reports `status: "completed"` (exit `0` with zero
  findings, exit `3` with one or more) or `status: "failed"` (exit `1`,
  a stable non-sensitive `code` and a fixed static `message`, never raw
  file/process content). Usage errors remain exit `2`.
- Four rules are implemented (`src/rules/engine.ts`, a pure function with
  no I/O): PS001 (declared and live values differ), PS002 (a declared
  variable is missing from the live process), PS003 (an unexpected live
  variable exists — only reported with `--check-unexpected`, otherwise
  never evaluated at all, not merely hidden), and PS005 (the declared and
  live `PORT` values differ, reported instead of PS001 specifically for
  `PORT`). PS004, PS006, PS007, and PS008 remain fully deferred — the
  identifiers are stable and reserved, but no detection logic exists for
  them. Every finding's `details` carries only a validated variable name;
  PS005 never carries either side's actual port number.
- A read-only dotenv-file adapter (`src/adapters/dotenv-file.ts`,
  `src/core/dotenv-file-types.ts`) that reads exactly the file passed to
  `--env`:
  - Opens with `O_NOFOLLOW` and reads via the resulting file descriptor
    only (never a second path-based lookup) — a symlink at the given path
    is rejected race-free at `open()` time (`ELOOP`); every subsequent
    operation targets the exact inode that was opened, immune to the path
    being replaced afterward. This is descriptor-bound reading, not a
    guarantee the content itself is unchanged while being read — see the
    mutation-detection bullet below.
  - Rejects non-regular files. Reads through a bounded loop (`readBounded`)
    that allocates a single `maxFileBytes + 1`-byte buffer once and fills
    it in fixed-size chunks via `readSync`; more than `maxFileBytes + 1`
    bytes can never be buffered, however large the file is or grows to be
    while the loop runs, and the read fails with the existing oversized-file
    error the moment that bound would be exceeded. A pre-read `fstat` size
    check remains as a fast rejection path.
  - A pre/post `fstatSync(fd, { bigint: true })` comparison (`dev`, `ino`,
    `size`, `mtimeNs`, `ctimeNs`) around the read loop detects any
    same-inode mutation — append, truncate, or an in-place rewrite,
    including a same-size rewrite that only nanosecond-resolution
    `mtimeNs`/`ctimeNs` catch — and fails closed with a new stable error
    code, `env_file_changed_during_read`, discarding whatever was read
    without parsing it.
  - Hard limits on variable count (500), key length (120 characters), and
    value size (8 KiB, measured with `Buffer.byteLength(value, 'utf8')`,
    not JavaScript's `.length`). Malformed content and duplicate keys both
    fail the whole read. Every limit fails fast; none truncates and
    continues.
  - Registers every **successfully parsed** value in the run's
    `SecretRegistry` immediately after parsing, before diagnostics,
    duplicates, or limits are checked — including an earlier value a later
    duplicate key overwrites, via a new `ParsedDotenv.assignments` field
    (`src/parsers/dotenv.ts`) that records every successful parse in file
    order, distinct from the deduped `values` map. A malformed fragment
    that never successfully parsed is never registered and never appears
    in its diagnostic. Only values are registered, never keys — dotenv
    keys are already restricted to `[A-Za-z_][A-Za-z0-9_]*` by the
    parser's own key pattern, so they cannot be secrets by construction.
  - Wraps every declared value in the same opaque `ObservedValue` the PM2
    adapter uses, sharing one `Fingerprinter` per audit run (created once
    in `runAuditPipeline`) so declared and live values always compare
    through the same run-scoped HMAC key.
- Conservative process selection (`src/core/process-selection.ts`): the
  requested `--process` value must match a strict identifier pattern
  _before_ the PM2 adapter is ever called (an invalid name never touches
  PM2 at all), and must then match exactly one live process by name,
  compared only against each process's already-safe `safeName`. Zero and
  multiple matches both fail with their own stable error codes
  (`process_not_found`, `process_ambiguous`); a raw/unsafe PM2 process
  name is never compared against or exposed.
- `AuditResult` (`src/core/audit-types.ts`, replacing the old
  `not_implemented`-only shape previously in `core/types.ts`) gains
  `code` (present only when `status: "failed"`), `detail` (optional,
  carried from the failing adapter's own `SafeLabel` detail), and
  `subject.process` (the audited process's safe name — present whenever
  the requested name at least passed syntax validation, independent of
  whether the run succeeded). Both reporters render the new fields through
  the same `sanitizeForDisplay` boundary as everything else.
- Extended the isolated real-PM2 end-to-end suite
  (`tests/e2e/audit-live.test.ts`) to run the real CLI against a real
  isolated daemon and a real temporary dotenv file, proving exit codes `0`
  and `3` and zero sentinel leakage end-to-end — not just through the
  fixture-injected pipeline exercised by
  `tests/integration/audit-command.test.ts`.
- `tests/integration/cli.test.ts` now tests the audit command's usage
  errors and PM2-unreachable failure mode by spawning the real CLI with a
  `PATH` that deliberately excludes `node_modules/.bin` (and any other
  directory that might hold a real `pm2`), so these tests can never find a
  real `pm2` binary and therefore can never reach a real PM2 daemon or
  `PM2_HOME`, however the machine running them happens to be configured.

### Fixed

- **A validated PM2 process name could be redacted by the registry it was
  never supposed to be sensitive to.** Real `pm2 jlist` output duplicates
  a process's name into multiple fields — `name`, `pm2_env.name`, and
  `pm2_env.axm_options.module_name` were all observed against the pinned
  `pm2` devDependency — and the PM2 adapter's existing "treat the entire
  payload as sensitive" registration (correctly) registered all of them.
  Since a process name is exactly the field the adapter already normalizes
  into `Pm2ProcessSnapshot.safeName` specifically so it can be displayed,
  and since `SecretRegistry.scrub` cannot distinguish "this exact string
  is a raw secret" from "this exact string is a name that was
  independently validated as safe to display," the new `subject.process`
  field was being silently redacted to `[REDACTED]` on every completed
  audit. Fixed by excluding a record's own process name from registration
  by exact value — not by field path — wherever it recurs within that
  record, so the fix holds regardless of how many places PM2 puts the name
  in, across versions and configurations, without needing to enumerate
  them. The exclusion is scoped per-record: one process's name is never
  exempted while walking a different process's record. Every other string
  at any depth is still registered exactly as before. Regression tests
  (`tests/integration/pm2-adapter.test.ts`) cover both the multi-location
  duplication and the per-record scoping boundary.

An independent review of this milestone's branch found three further
merge-blocking gaps in the dotenv-file adapter, all fixed here:

- **Unbounded read on a growing file.** `readFileSync(fd)` read the
  complete file into memory before the post-read size check ran, so a
  file that grew after the initial `fstat` could exceed the documented
  1 MiB memory bound. Replaced with `readBounded()`: a single
  `maxFileBytes + 1`-byte buffer allocated once, filled by a chunked
  `readSync` loop that terminates and fails with the existing
  oversized-file error the instant that bound would be exceeded — never
  truncating and continuing, never reading further. Short reads and
  `EINTR`/`EAGAIN` are retried safely without losing or duplicating bytes.
- **In-place mutation of the open file went undetected.** The existing
  symlink/path-replacement protections only proved the read was bound to
  one descriptor; they said nothing about another process truncating,
  rewriting, or appending to that same, already-open inode during the
  read. Added an `fstatSync(fd, { bigint: true })` snapshot (`dev`, `ino`,
  `size`, `mtimeNs`, `ctimeNs`) taken immediately before and after the
  bounded read; any difference now fails closed with a new
  `env_file_changed_during_read` error code, discarding the read content
  before it is ever parsed. Documented accurately as descriptor-bound
  reading with pre/post mutation detection — not as full race-freedom,
  which only the symlink-rejection-at-`open()` property actually has.
- **A duplicate key's earlier value was silently unregistered.** The
  parser's `values` map keeps only the last-written value per key, and
  the adapter registered secrets from that map — so an earlier duplicate
  raw value never reached `SecretRegistry`, even though the file
  genuinely contained it and the adapter's documentation claimed every
  declared value was registered. Added `ParsedDotenv.assignments`
  (`src/parsers/dotenv.ts`), an order-preserving record of every
  successfully parsed occurrence including ones a later duplicate key
  overwrites; the adapter now registers every occurrence in
  `assignments`, before diagnostics or limits are checked. A malformed
  fragment that never successfully parsed still never appears in
  `assignments` and never appears in its diagnostic.

Regression tests added through an injected, deterministic
instrumentation seam (`onChunkReadForTesting`/`readChunkBytesForTesting`
in `ReadDotenvFileOptions`) — no timing-dependent or background-race
tests: a file that keeps growing during the read cannot cause more than
`maxFileBytes + 1` bytes to be buffered; append, truncate, and a
same-size in-place rewrite (caught via `mtimeNs`/`ctimeNs`, not size
alone) all fail closed with `env_file_changed_during_read`; an untouched
read does not false-positive; and a duplicate-key file with two unique
sentinel values proves neither the overwritten nor the final value
reaches terminal, JSON, or error output.

### Notes

- `README.md` was updated with the real, implemented CLI behavior and
  rule documentation for this milestone. The broader visual/product-page
  README redesign remains tracked separately as a release-gate item and is
  not part of this change.
- PS004, PS006, PS007, and PS008 remain fully deferred, as do ecosystem
  files, PM2 dump state comparison, and multi-process/multi-file audits —
  every audit remains exactly one explicit `--process` and one explicit
  `--env`.

## [Unreleased] — Cross-application secret-reuse detection milestone

### Added

- `procseal audit` gains an explicit `--check-reuse` option implementing
  **PS004** (a sensitive live value also occurs in another PM2
  application). Off by default: without `--check-reuse`, behavior and
  output are byte-for-byte identical to before this milestone. No new PM2
  invocation is added — PS004 compares processes already present in the
  one `pm2 jlist` snapshot the existing read-only adapter already fetches
  for the run.
- A centralized, documented candidate-eligibility policy
  (`src/core/reuse-candidate-policy.ts`): a `{key, value}` pair is only
  ever compared for PS004 when the key name, normalized, contains one of
  a short list of explicit credential-terminology substrings (`password`,
  `passwd`, `secret`, `token`, `api key`, `private key`, `client secret`,
  `access key`, `auth key`, `credential`, `passphrase`) **and** the
  value's UTF-8 byte length is at least 12 bytes. Documented explicitly as
  a false-positive-reduction heuristic, not proof a value is or isn't a
  secret — it can produce false negatives (an unrecognized key name, or a
  value under the length floor) and, more rarely, false positives. No
  entropy scoring; no raw length or value ever returned or logged, only
  the boolean eligibility result.
- Eligibility is computed once, at the PM2 adapter boundary
  (`normalizeEnvironment` in `src/adapters/pm2.ts`), from the raw key and
  value, before the value is wrapped in an opaque `ObservedValue`, and
  stored as a new derived field, `Pm2EnvironmentVariable.reuseCandidate`
  (`core/pm2-types.ts`). Nothing downstream of the adapter — the rule
  engine, reporters, or any test fixture — ever sees a raw value or a raw
  length in order to make this decision again.
- A pure PS004 rule module (`src/rules/reuse.ts`, `evaluateReuseRule`):
  compares the selected process's eligible values against every _other_
  process in the run's snapshot (matched by `safeProcessId`, unique
  within a snapshot), using only `ObservedValue.equals()` — the same
  full-HMAC equality primitive every other rule uses, backed by the run's
  shared `Fingerprinter`. Detects reuse even when the value appears under
  a different sensitive variable name on each side (e.g. `API_KEY` in one
  application, `CLIENT_SECRET` in another) — but only when _both_ sides
  independently pass the candidate policy; a long value under a
  non-credential-looking key is never treated as a match.
  - **Deduplication**: the selected process's eligible values are first
    clustered by `ObservedValue.equals()`, so the same value declared
    under two names within the selected process is one cluster, not two
    — repetition confined to a single application never produces a
    finding, only reuse confirmed in at least one genuinely distinct
    other process does.
  - **Ordering**: each qualifying cluster produces exactly one finding —
    `variable` (the alphabetically-first name in the cluster) and
    `reusedInProcessCount` (a plain decimal string counting _other_
    distinct processes holding the value — other processes' names are
    deliberately not enumerated, keeping finding size bounded regardless
    of fleet size). Findings are returned sorted by `variable`, so three
    or more applications sharing one value still produce exactly one
    deterministic finding, never a combinatorial explosion, and the same
    input snapshot always produces the same output order regardless of
    PM2's own array or object-key order.
  - Severity `critical` — the first rule in this project to use it,
    reflecting that a shared credential's blast radius spans every
    application holding it.
- `src/commands/audit.ts`: `--check-reuse` parsed alongside
  `--check-unexpected`; `AUDIT_HELP` documents the flag, moves PS004 from
  "Deferred" to "Implemented," and adds a "Candidate policy" section
  matching the README. `src/cli.ts`'s top-level usage line also mentions
  `--check-reuse`.

### Testing

- `tests/unit/reuse-candidate-policy.test.ts`: key-name recognition
  across casing/separator conventions, the false-positive-prone ordinary
  keys the policy must _not_ match (`PORT`, `NODE_ENV`, `HOST`, `PATH`,
  `USERNAME`, `PUBLIC_KEY`, ...), the UTF-8-byte length floor (including a
  multibyte value where `.length` would undercount), and combined
  eligibility.
- `tests/unit/reuse-rule.test.ts`: two-application reuse, reuse under a
  different sensitive name, no finding for a same-process-only repeat, no
  finding when the matching side isn't independently eligible, short/
  common/non-sensitive values (including `PORT`, `NODE_ENV`, paths, and
  booleans) never triggering, three-or-more-application deduplication,
  multiple distinct reused values reported as separate findings sorted
  deterministically, order-independence of the input snapshot, the
  alphabetically-first-name tie-break, an adversarial no-raw-value
  serialization proof, and exclusion of the selected process from its own
  "other processes" comparison by `safeProcessId`.
- `tests/integration/pm2-adapter.test.ts`: `reuseCandidate` computed
  correctly by the real adapter for a mix of eligible and ineligible
  variables in one payload.
- `tests/integration/audit-command.test.ts`: the same scenarios exercised
  through the full `executeAuditCommand` pipeline, plus explicit proof
  that `--check-reuse` absent produces zero PS004 findings even when a
  value is genuinely shared with another process, and that `--check-reuse`
  parses correctly (on by explicit flag only, off by default).
- A new real, isolated end-to-end test in `tests/e2e/audit-live.test.ts`
  starts two real PM2 processes under one temporary `PM2_HOME`, each
  holding the same sentinel value under a different sensitive variable
  name, and proves: `PS004` is absent without `--check-reuse`; `PS004`
  fires with it, naming only the variable and a count; and the shared
  sentinel value never appears in JSON or terminal output either way. The
  real PM2 daemon and `PM2_HOME` used by this machine are never read or
  touched.
- All prior PS001, PS002, PS003, and PS005 tests, dotenv-file protections,
  PM2 isolation guarantees, and exit-code contracts are unchanged and
  remain green — verified by re-running the full existing suite alongside
  the new tests above.

### Notes

- PS006, PS007, and PS008 remain fully deferred — the identifiers are
  stable and reserved, but no detection logic exists for them yet.
- PS004's candidate policy is explicitly documented as a heuristic: it can
  miss a real secret under an unrecognized key name or below the length
  floor, and can rarely flag an intentionally shared long value under a
  credential-shaped key name. It is not, and is not claimed to be,
  universal secret detection.
- The Issue #3 visual/product-page README redesign is not part of this
  change; documentation updates here are limited to factual CLI behavior,
  rule documentation, and the candidate policy.
