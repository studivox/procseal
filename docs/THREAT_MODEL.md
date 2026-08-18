# Threat model

ProcSeal is a diagnostic tool, not a secrets manager and not a security
boundary. This document explains what it protects against, what it does
not, and how its fingerprinting and output-redaction designs work.

## What ProcSeal is

A read-only, local-first CLI that compares declared configuration (one
explicitly selected dotenv file) with live process state (one explicitly
selected PM2 process) and reports drift — missing variables, changed
values, port mismatches — without ever printing the underlying secret
values.

## What ProcSeal is not

- Not a secrets manager. It does not store, rotate, or distribute secrets.
- Not a security boundary. Passing an audit does not certify that a
  deployment is secure.
- Not a network service. ProcSeal makes no network calls, performs no
  telemetry, and uploads no configuration or process data anywhere. Every
  operation is local to the machine it runs on. This remains true with the
  PM2 adapter and the dotenv-file adapter both wired into `audit`: the
  former only ever spawns a local `pm2 jlist` process, and the latter only
  ever reads the one local file path it was given — no network calls of
  any kind.
- Not an auto-discovery tool. `procseal audit` never guesses which process
  or file to compare; `--process` and `--env` are both required, and
  exactly one process and one file are compared per run.
- Not (yet) a comparison against anything beyond one process and one file.
  Ecosystem files, PM2 dump state, and multi-process/multi-file audits are
  not implemented — see "Out of scope for this milestone" below.

## Redaction contract

1. Raw secret values must never appear in terminal output, JSON output,
   error messages, logs, or fingerprints.
2. `Finding` has no free-form `message` field. The displayed title for a
   finding always comes from `getRuleTitle(ruleId)` (`core/types.ts`), a
   lookup into the fixed rule catalog — never from caller-supplied text.
   This removes an entire class of "a raw value ended up in a finding
   message" bugs structurally, rather than relying on callers to remember
   not to do that.
3. `Finding.details` may only hold `SafeLabel` values: short strings
   validated against a conservative character set and length limit
   (`core/label.ts`). `createFinding()` (`core/types.ts`) builds a `Finding`
   by normalizing every `details` key and value through
   `toSafeLabelOrRedacted`, which redacts anything that fails validation
   instead of throwing or silently passing it through.
4. Both reporters (`reporters/terminal.ts`, `reporters/json.ts`) apply a
   **final, independent safety net** before writing anything:
   `sanitizeForDisplay()` (`core/output-safety.ts`). This does not trust
   that step 2/3 already happened — TypeScript's `SafeLabel` brand is
   erased at runtime, so a caller that bypasses the type system (an
   untyped adapter, a bad cast) could still hand a reporter a raw value.
   `sanitizeForDisplay()`:
   - serializes non-string input first (so a raw value hidden inside a
     nested object cannot bypass the checks that follow by pretending not
     to be a string);
   - scrubs every value registered in a `SecretRegistry`
     (`core/secret-registry.ts`) via exact substring replacement;
   - replaces every non-printable-ASCII character (control characters,
     newlines, ANSI escape sequences) with `?`, which blocks
     terminal/log-injection using forged lines or cursor/color codes;
   - truncates to a bounded length.

   This is applied to every string-bearing field the reporters emit,
   including the audit-level `message`, `status`, `meta.version`, and every
   finding's `ruleId`, `severity`, derived title, and `details` entries —
   not only the fields that seemed likely to carry user data.

5. `SecretRegistry` only catches values it has been told about. The
   `audit` command creates exactly one run-scoped registry per invocation
   (`executeAuditCommand` in `commands/audit.ts`) and threads it through
   both adapters: the dotenv-file adapter registers every declared value
   it reads, and the PM2 adapter registers every raw string in the
   `pm2 jlist` payload (with one deliberate, narrow exception — see "The
   PM2 adapter" below) — both before any normalization or reporting
   happens. The same registry is then threaded through whichever reporter
   renders the final output.
6. Uncaught errors at the CLI's top level never print the original
   `Error.message` or stack (`core/internal-error.ts`). This is a stronger
   guarantee than substring redaction: redaction can only remove _known_
   values, and the top-level catch has no way to guarantee its registry of
   known values is complete. The safe default is to print a static message
   and a coarse, pattern-validated error code derived only from the
   error's class name — never its message or stack — and nothing else.
   `sanitizeMessage`/`sanitizeError` (`core/redaction.ts`) remain available
   as internal helpers for call sites that _do_ have a reliable, complete
   set of known values to redact, but the top-level catch does not depend
   on them.

## Fingerprint design

Fingerprints let ProcSeal say "this value is the same as that one" (e.g. a
secret reused across two applications) without ever printing either value.

- The fingerprinter (`core/fingerprint.ts`) generates a random 256-bit HMAC
  key with `node:crypto`'s `randomBytes` when a run starts.
- The full-length `HMAC-SHA-256(key, value)` digest never leaves the
  module — it is not returned, logged, persisted, or serialized anywhere.
  Only two operations are exposed on the returned `Fingerprinter`:
  - `displayFingerprint(value)` returns a 16-hex-character (64-bit)
    **truncated** digest, for human-readable terminal/JSON output only.
  - `equals(left, right)` is the **only supported equality primitive**. It
    computes the full-length digest of each argument internally and
    compares them with `node:crypto`'s `timingSafeEqual`, returning a
    boolean and nothing else.
- The key lives only in process memory. It is never written to disk, never
  logged, and is discarded when the process exits.
- Because the key is random and ephemeral, the same input value produces a
  **different** `displayFingerprint` on every run. Fingerprints are only
  meaningful for equality comparisons _within a single run_ — they are not
  a stable identifier across runs, machines, or time.

### Why HMAC instead of a plain hash

A plain hash (e.g. `sha256(value)`) is invertible-by-guessing for
low-entropy secrets: an attacker who sees the hash of a low-entropy value
(a short password, a predictable token) can dictionary- or brute-force it
offline. Keying the hash with a random, run-scoped, in-memory-only secret
removes that offline attack surface — the fingerprint cannot be reproduced
or reversed without the key, and the key never leaves memory or the process
lifetime.

### Why display and equality are separate operations

A 16-hex-character truncated digest is convenient to print but has only 64
bits of collision resistance — far weaker than the underlying 256-bit HMAC.
Exposing only a truncated `fingerprint()` method, and letting a caller (or
a future rule implementation such as PS004) use _that_ for equality
decisions, would silently downgrade every comparison to 64-bit collision
resistance. Separating `displayFingerprint()` (truncated, for humans) from
`equals()` (full digest, `timingSafeEqual`, for logic) makes that mistake
structurally unavailable: there is no API that returns a full digest for a
caller to compare with `===`, and no API that lets a truncated value be
used as an equality input.

### Limitations — read before relying on fingerprints

- **Truncation is for display, not security.** `displayFingerprint()`'s
  output MUST NOT be treated as an authentication token, a capability, or
  any kind of security boundary, and must never be used to decide whether
  two values are equal — use `equals()` for that.
- **Run-scoped only.** Fingerprints are not designed to be compared across
  separate `procseal` invocations. Two runs will produce different
  `displayFingerprint` output for the same value, by design.
- **Not proof of possession.** An `equals()` match shows two observed
  values were equal during one run. It says nothing about who holds the
  underlying secret or whether it is still valid.
- **Timing.** `equals()` uses `timingSafeEqual` specifically so that
  PS004-style secret-reuse comparisons do not leak information about a
  secret's content through comparison timing.

## The PM2 adapter

`src/adapters/pm2.ts` reads the current OS user's PM2 process list. It is
read-only, invokes exactly one fixed command, and is not reachable from the
public CLI yet — see "What ProcSeal is not" above.

### Execution

- Invokes a command equivalent to `pm2 jlist` via `execFile` from
  `node:child_process` (`core/command-runner.ts`), never `exec`, and never
  `execFile`/`spawn` with `shell: true`. `command` and a fixed argument
  array (`['jlist']`) are passed straight to the OS; nothing is ever
  concatenated into a shell command string, so there is no code path for
  shell injection regardless of what a hostile `PM2_HOME` or environment
  might contain.
- Never uses `sudo` and never elevates privilege. By default it inherits
  the current process's environment, which is what limits it to the
  current OS user's own PM2 daemon and `PM2_HOME`; it never reads or
  targets another user's `PM2_HOME`.
- Never runs any PM2 subcommand other than `jlist`. It never restarts,
  reloads, stops, deletes, saves, kills, or updates a PM2 process.
- Enforces a command timeout (`execFile`'s `timeout` option) and passes a
  buffer limit to `execFile`'s `maxBuffer` option — but Node applies
  `maxBuffer` to stdout and stderr **independently**, not as a combined
  bound ("largest amount of data in bytes allowed on stdout **or**
  stderr", per Node's own docs), so this is not a guarantee that combined
  output is bounded by that number. The adapter's actual enforcement of
  its intended payload-size limit is a separate, independent
  `Buffer.byteLength` check against the received stdout string, which runs
  for every `CommandRunner` — including an injected test fixture that
  bypasses `execFile`, and therefore `maxBuffer`, entirely. See
  `PM2_LIMITS` in `src/adapters/pm2.ts` and the comment on
  `createExecFileCommandRunner` in `core/command-runner.ts` for the exact
  numbers and this distinction in more detail.
- The command runner is injected (`CommandRunner` in
  `core/command-runner.ts`), so unit and integration tests exercise every
  failure branch (missing binary, unavailable daemon, timeout, oversized
  output, invalid JSON, malformed payload, each hard limit) without a real
  PM2 daemon. `CommandOutcome`, the type the runner returns, deliberately
  never carries raw stdout/stderr or an underlying error's message — only
  a small classified `kind` — so there is no code path by which the
  adapter could place raw process output into a diagnostic even by
  accident.
- Stable, non-sensitive error codes (`Pm2AdapterErrorCode` in
  `core/pm2-types.ts`): `binary_not_found`, `daemon_unavailable`,
  `timeout`, `output_too_large`, `invalid_json`, `malformed_record`, and
  one per hard limit (`too_many_processes`, `too_many_env_vars`,
  `key_too_long`, `value_too_long`). Hard-limit violations fail the whole
  run rather than silently truncating a value and reporting on the
  truncated version — a truncated secret compared or fingerprinted as if
  it were the whole value could produce a false equality result.

### Sensitive-value handling

- `pm2 jlist` may return complete environment values and other sensitive
  strings (paths, command lines) anywhere in its structure. The adapter
  treats the entire raw payload as sensitive: immediately after successful
  JSON parsing, every string leaf of the parsed payload is recursively
  registered in the run's `SecretRegistry` (`core/secret-registry.ts`) —
  before any normalization or reporting happens, and even on a path that
  is about to fail with an error. This is defense in depth beyond the
  fields the normalized snapshot actually surfaces.
  - One narrow, deliberate exception: each record's own process name is
    excluded from registration, by exact value, wherever it recurs within
    that record. Real `pm2 jlist` output duplicates a process's name into
    multiple fields (`name`, `pm2_env.name`, and
    `pm2_env.axm_options.module_name` have all been observed against the
    pinned `pm2` devDependency) — and a process name is exactly the field
    this adapter normalizes into `Pm2ProcessSnapshot.safeName`
    specifically so it can be displayed (the audit command's
    `subject.process` in particular; see "The rule engine and audit
    orchestration" below). `SecretRegistry.scrub` cannot distinguish "this
    exact string is a raw secret" from "this exact string is a name that
    was independently validated as safe to display," so registering it
    would redact that intentionally-public field everywhere it appears in
    output — including, once observed in practice, corrupting unrelated
    output that merely happened to contain the same digits or substrings
    as some other short registered value, which is why the exclusion is by
    exact value rather than by field path: there is no guarantee PM2's
    internal duplicate-name locations are limited to the three found so
    far, across versions and configurations (cluster mode, modules, ...).
    The exclusion is scoped per-record — process A's name is never
    exempted while walking process B's record — and every other field at
    any depth (`pm2_env.env` values, exec paths, monit data, anything
    else) is still registered exactly as before. Regression tests
    (`tests/integration/pm2-adapter.test.ts`) cover both the multi-location
    duplication and the per-record scoping boundary.
- Every environment value is wrapped in an opaque `ObservedValue`
  (`core/observed-value.ts`) rather than an ordinary string:
  - The raw value lives only in a true JavaScript private field (`#raw`),
    not a TypeScript-only brand — the engine itself, not just the type
    checker, keeps it out of `Object.keys`, `Object.getOwnPropertyNames`,
    `Reflect.ownKeys`, and `Object.getOwnPropertySymbols`.
  - There is no raw-returning getter, `toString`, `valueOf`, `toJSON`, or
    custom inspector. `toString()`, `toJSON()`, and the
    `util.inspect.custom` symbol all return the same fixed opaque marker
    string, so `JSON.stringify`, template-literal/`String()` coercion,
    implicit `ToString` coercion, `util.inspect`, and `console.log` cannot
    reveal it.
  - The only operations exposed are `equals(other)` (full-HMAC equality
    against another `ObservedValue`), `equalsPlain(candidate)` (full-HMAC
    equality against a plain string the caller already holds by some other
    legitimate means — documented as narrow because `candidate` is
    supplied by the caller, never extracted from the `ObservedValue`), and
    `displayFingerprint()` (truncated, display-only). All three delegate
    to the existing `Fingerprinter` (see "Fingerprint design" above);
    `ObservedValue` adds no new comparison primitive.
  - Construction (`ObservedValue.from`) registers the raw value in the
    run's `SecretRegistry` immediately, so a value is scrubbable from
    output even if no other method on it is ever called.
  - Adversarial tests (`tests/unit/observed-value.test.ts`) prove the raw
    value cannot be recovered through any of the above, plus a thrown
    `Error`'s message and `Object.getOwnPropertyDescriptors`.
- The normalized `Pm2Snapshot` (`core/pm2-types.ts`) exposes only a safe
  process identifier, a process name validated as a `SafeLabel` (or
  replaced with the redaction placeholder — this is how hostile names
  containing newlines or ANSI escapes are neutralized), PM2's numeric id
  when it parses as a non-negative safe integer, a validated status enum,
  environment variable names (also validated as `SafeLabel`s), and opaque
  `ObservedValue`s. It never includes the raw `pm2_env`, full command
  lines, raw node arguments, raw paths, raw stdout/stderr, or the original
  PM2 record.

### Isolated testing

- Unit and integration tests (`tests/integration/pm2-adapter.test.ts`)
  inject a fixture `CommandRunner`, so they never touch a real PM2 daemon.
- One real, isolated end-to-end test (`tests/e2e/pm2-live.test.ts`) starts
  an actual PM2 daemon under a unique temporary `PM2_HOME` created with
  `mkdtemp`, starts a tiny synthetic Node process carrying a synthetic
  sentinel environment value, reads it back through the adapter, and
  proves the sentinel never appears in any serialization of the result
  (`JSON.stringify`, `util.inspect`). It never reads or modifies this
  machine's real `PM2_HOME` or PM2 daemon.
- Cleanup (`tests/e2e/pm2-isolation-guard.ts`) refuses — throwing rather
  than warning — to run any cleanup command, including `pm2 kill`, unless
  `PM2_HOME` is present, non-empty, not equal to the real `PM2_HOME`, and
  located inside the test's own temporary directory (itself required to be
  inside the OS temp directory and not the real home directory). The
  guard's refusal behavior has its own unit tests
  (`tests/e2e/pm2-isolation-guard.test.ts`) proving the kill command is
  never invoked, and nothing is deleted, when any check fails.
- The temporary directory is deleted only after a _confirmed-complete_
  teardown, not unconditionally in a `finally` block. Before `pm2 kill`
  runs (PM2 removes its pidfile on a graceful exit, so this must happen
  first), `cleanupIsolatedPm2` looks up the isolated daemon's own PID from
  its pidfile (PM2's documented `<PM2_HOME>/pm2.pid`) via
  `readIsolatedDaemonPid`, which returns one of exactly three states —
  never a single ambiguous "nothing found":
  - `'absent'` — the pidfile genuinely does not exist. Nothing was ever
    captured, so there is nothing to verify.
  - `'valid'` — the pidfile exists and its content strictly parses to a
    safe PID (rejecting `0`, negative numbers, non-numeric text, and —
    specifically — the test process's own PID).
  - `'unverifiable'` — the pidfile _exists in some form_ but cannot be
    trusted: malformed content, an oversized file, a non-regular file
    (checked with `lstatSync`, which does not follow symlinks — a
    symlinked pidfile is rejected as non-regular rather than read through
    to its target), or a file that could not be stat'd or read. This is
    deliberately **not** collapsed into `'absent'`: a pidfile that exists
    but can't be trusted is evidence a daemon _might_ still be running.

  `pm2 kill` is still attempted regardless of which state the lookup
  returned — refusing to _delete_ is not the same as refusing to
  _attempt_ the already-guarded kill. After kill runs: if it threw, cleanup
  throws `CleanupIncompleteError` immediately. Otherwise, an `'absent'`
  lookup proceeds straight to deletion (nothing to verify); a `'valid'`
  lookup polls a safe signal-`0` existence probe (`process.kill(pid, 0)`,
  which delivers no actual signal) until that PID is confirmed dead, and
  throws `CleanupIncompleteError` without deleting if it's still alive; and
  an `'unverifiable'` lookup throws `CleanupIncompleteError` without
  deleting, unconditionally — verification was impossible, so cleanup
  fails closed rather than guessing. In every `CleanupIncompleteError` case
  the temporary directory (and whatever the daemon left on disk) is left
  in place. `pm2-isolation-guard.test.ts` covers all three lookup states
  (including oversized, non-regular, symlinked, and unreadable pidfiles
  classifying as `'unverifiable'`), a kill failure that must not delete
  anything, a still-alive PID that must not delete anything, and a
  confirmed-dead PID that completes teardown.

- `pm2` is a pinned, exact-version `devDependency` used only by this
  end-to-end test; it is never a runtime dependency of the published
  package. `npm pack --dry-run` confirms the published tarball contains no
  `pm2`, no tests, no fixtures, and no `node_modules`.

## The rule engine and audit orchestration

`procseal audit --process <name> --env <path>` is the first command that
actually performs a comparison. This section covers everything specific to
that: the dotenv-file adapter, process selection, the rule engine, and the
shape of the result the reporters render.

### The dotenv-file adapter

`src/adapters/dotenv-file.ts` reads exactly the file passed to `--env` —
never any other path, never an ecosystem file, never auto-discovered.

- Opens with `O_NOFOLLOW` and reads via the resulting file descriptor only
  (never a second path-based lookup), for the same two race-free
  properties documented for the PM2 adapter's command execution: a symlink
  at the given path is rejected by the OS at `open()` time (`ELOOP`), and
  every subsequent operation (`fstat`, read) targets the exact inode that
  was opened, immune to the path being replaced afterward.
- Rejects non-regular files (checked via `fstat().isFile()` after the
  `O_NOFOLLOW` open).
- A 1 MiB file-size limit, checked twice: once against `fstat`'s reported
  size before reading, and again against the actual bytes read afterward —
  the second check is what protects against the file changing size between
  the two calls, not a redundant formality.
- Hard limits on variable count (500), key length (120 characters), and
  value size (8 KiB, measured with `Buffer.byteLength(value, 'utf8')`, not
  JavaScript's `.length` — the same multibyte-Unicode reasoning documented
  for the PM2 adapter's `maxValueBytes`). Every limit fails the whole read
  fast; none of them truncates and continues.
- Malformed content (any `parsers/dotenv.ts` diagnostic — an invalid line,
  an unterminated quote, trailing content after a closed quote) and
  duplicate keys both fail the whole read, with their own stable error
  codes.
- Every declared value is registered in the run's `SecretRegistry`
  immediately after parsing — before diagnostics, duplicates, or limits are
  even checked — the same ordering guarantee the PM2 adapter makes. Only
  values are registered, never keys: dotenv keys are already restricted to
  `[A-Za-z_][A-Za-z0-9_]*` by the parser's own key pattern, so they cannot
  be secrets by construction, unlike the PM2 adapter's payload, whose shape
  is not known ahead of time.
- Each declared value is wrapped in the same opaque `ObservedValue` type
  the PM2 adapter uses, constructed with a `Fingerprinter` shared across
  both adapters for one audit run (created once in
  `runAuditPipeline`) — so a declared value and a live value are always
  compared through the same run-scoped HMAC key, and `ObservedValue.equals()`
  is the only comparison primitive either side ever goes through.

### Process selection

`src/core/process-selection.ts` validates the requested `--process` value
against a conservative pattern (letters, digits, underscore, dot, dash;
120 characters max) _before_ the PM2 adapter is ever called — an invalid
name fails immediately, without touching PM2 at all. A valid name must
then match exactly one process in the live snapshot, compared only against
each process's already-safe `safeName` — zero matches and more than one
match both fail, with their own stable error codes
(`process_not_found`, `process_ambiguous`), and a raw/unsafe PM2 process
name is never compared against or exposed.

### The rule engine

`src/rules/engine.ts` is a pure function: given one declared snapshot, one
live process snapshot, and whether `--check-unexpected` was passed, it
returns findings for exactly the rules implemented in this milestone —
PS001, PS002, PS003, and PS005 (see the project `README.md` for what each
one reports). It makes no I/O calls, mutates neither input, and never
touches a raw value directly — every comparison goes through
`ObservedValue.equals()`, and every finding's `details` carries only a
validated variable name (via the existing `createFinding`/`SafeLabel`
machinery — see the Redaction contract above), never a value. PS005 in
particular carries only the literal string `PORT`, never either side's
actual port number.

PS003 (an unexpected live variable) is gated entirely on the
`--check-unexpected` flag: with it omitted, the rule engine simply never
evaluates that comparison, not merely "runs it and hides the result" — so
there is no code path where an unexpected-variable finding could leak
through some other channel while the flag is off.

### The audit result and orchestration order

`runAuditPipeline` (`commands/audit.ts`) runs the steps in a fixed order,
each of which can stop the whole run with its own stable `AuditErrorCode`:
validate the process name syntax, read the dotenv file, inspect PM2, select
the one matching process, evaluate the rules. This order is deliberate,
not incidental: an invalid process name or a broken dotenv file is caught
_before_ `inspectPm2` is ever called, so those failure modes never touch
PM2 at all (see `tests/integration/cli.test.ts`, which relies on exactly
this to test PM2-unreachable failure modes without a real daemon).

The result (`AuditResult` in `core/audit-types.ts`) has two possible
`status` values:

- `'completed'` — the comparison actually ran. `findings` may be empty (a
  clean audit, exit code `0`) or not (exit code `3`). `subject.process`
  carries the audited process's safe name.
- `'failed'` — an expected, well-defined operational condition stopped the
  run before any comparison happened (exit code `1`). `code` is always
  present (one of `ProcessSelectionErrorCode`, `DotenvFileErrorCode`, or
  `Pm2AdapterErrorCode` — see `core/audit-types.ts`), `findings` is always
  empty, and `message` is one of a fixed set of static strings looked up
  from `code` (`AUDIT_ERROR_MESSAGES` in `commands/audit.ts`) — never
  anything derived from raw file or process content. `subject.process` is
  still included whenever the requested process name at least passed
  syntax validation, independent of whether the run actually found it, so
  a `process_not_found` failure can still say which (validated) name was
  requested.

This is distinct from an _unexpected_ internal error, which never produces
an `AuditResult` at all: an uncaught exception anywhere in the pipeline is
handled entirely by the CLI's top-level catch (`core/internal-error.ts`,
also exit code `1`), which never prints the original `Error.message` or
stack, exactly as documented in the Redaction contract above.

## Out of scope for this milestone

- PS004, PS006, PS007, and PS008. The identifiers are stable and reserved,
  but no detection logic exists for them yet.
- Comparing against ecosystem files, PM2 dump state, or more than one
  process/file per run. Every audit remains exactly one explicit
  `--process` and one explicit `--env`; nothing is auto-discovered.
- Remediation text, configurable severity thresholds, or a policy engine.
- Automatic remediation of any kind. ProcSeal only reports; it never
  changes configuration or process state.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
