# Threat model

ProcSeal is a diagnostic tool, not a secrets manager and not a security
boundary. This document explains what it protects against, what it does
not, and how its fingerprinting and output-redaction designs work.

## What ProcSeal is

A read-only, local-first CLI that compares declared configuration (files on
disk) with live process state (eventually, PM2) and reports drift — missing
variables, changed values, reused secrets, port mismatches, risky deploy
commands — without ever printing the underlying secret values.

## What ProcSeal is not

- Not a secrets manager. It does not store, rotate, or distribute secrets.
- Not a security boundary. Passing an audit does not certify that a
  deployment is secure.
- Not a network service. ProcSeal makes no network calls, performs no
  telemetry, and uploads no configuration or process data anywhere. Every
  operation is local to the machine it runs on. This remains true with the
  PM2 adapter in place: it only ever spawns a local `pm2 jlist` process and
  returns data in-process — no network calls of any kind.
- Not (yet) reachable from `procseal audit`. A read-only PM2 adapter now
  exists (`src/adapters/pm2.ts`, see "The PM2 adapter" below) and has its
  own test suite, but the public CLI does not call it yet. `procseal audit`
  still always reports an explicit `not_implemented` status and performs no
  machine inspection. Comparing the adapter's snapshot against declared
  configuration (PS001–PS008 detection) is the next milestone.

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

5. `SecretRegistry` only catches values it has been told about. In
   `procseal audit` (the public CLI command) nothing is registered in
   production yet, because `audit` is still a placeholder that never
   observes a real configuration value. The PM2 adapter (see "The PM2
   adapter" below) does register every raw value it reads — before any
   normalization or reporting — but it is not called from `audit` yet, so
   this has no production effect until it is wired in. Tests populate a
   registry manually, or via the adapter, to prove the scrub behavior.
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
- Enforces a command timeout and a strict combined stdout/stderr buffer
  limit (`execFile`'s `timeout`/`maxBuffer` options), and independently
  re-checks the raw payload size after receiving it — so an injected test
  runner that bypasses `execFile` entirely is still bound by the same
  limit. See `PM2_LIMITS` in `src/adapters/pm2.ts` for the exact numbers
  and the reasoning behind each one.
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
- Cleanup (`tests/e2e/pm2-isolation-guard.ts`) runs in a `finally` block
  and refuses — throwing rather than warning — to run any cleanup command,
  including `pm2 kill`, unless `PM2_HOME` is present, non-empty, not equal
  to the real `PM2_HOME`, and located inside the test's own temporary
  directory (itself required to be inside the OS temp directory and not
  the real home directory). The guard's refusal behavior has its own unit
  tests (`tests/e2e/pm2-isolation-guard.test.ts`) proving the kill command
  is never invoked, and nothing is deleted, when any check fails.
- `pm2` is a pinned, exact-version `devDependency` used only by this
  end-to-end test; it is never a runtime dependency of the published
  package. `npm pack --dry-run` confirms the published tarball contains no
  `pm2`, no tests, no fixtures, and no `node_modules`.

## Out of scope for this milestone

- Any of the eight rule checks actually running (PS001–PS008 are defined as
  stable identifiers, and the PM2 adapter above can now supply the live
  data they will need, but no rule compares that data against declared
  configuration yet).
- Wiring the PM2 adapter into the public `procseal audit` command. `audit`
  still always reports `not_implemented`, regardless of the adapter's
  existence.
- Automatic remediation of any kind. ProcSeal only reports; it never
  changes configuration or process state.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
