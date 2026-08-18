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
  operation is local to the machine it runs on.
- Not (yet) a live process inspector. Until the PM2 adapter ships,
  `procseal audit` performs no machine inspection at all.

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

5. `SecretRegistry` only catches values it has been told about. In this
   milestone nothing is registered in production, because `procseal audit`
   is a placeholder that never observes a real configuration value. The
   registry exists as infrastructure for the PM2 adapter, which will
   register every raw value it reads before any report is rendered. Tests
   populate a registry manually to prove the scrub behavior.
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

## Out of scope for this milestone

- Live PM2 process inspection (planned; no shell execution will be used to
  read process state — see `docs/ROADMAP.md`).
- Any of the eight rule checks actually running (PS001–PS008 are defined as
  stable identifiers now; their detection logic ships with the PM2
  adapter).
- Automatic remediation of any kind. ProcSeal only reports; it never
  changes configuration or process state.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
