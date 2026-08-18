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
