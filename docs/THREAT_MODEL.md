# Threat model

ProcSeal is a diagnostic tool, not a secrets manager and not a security
boundary. This document explains what it protects against, what it does
not, and how its fingerprinting design works.

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
2. Structured findings (`core/types.ts`) may only carry rule metadata, key
   names, severities, and derived data such as fingerprints — never a raw
   value.
3. Error sanitization (`core/redaction.ts`) strips any known raw value from
   a message before it is written to stderr, replacing it with
   `[REDACTED]`.
4. This is enforced primarily by discipline in what gets placed into a
   `Finding.details` object, backed by tests that assert synthetic sentinel
   values never leak into reporter or CLI output.

## Fingerprint design

Fingerprints let ProcSeal say "this value is the same as that one" (e.g. a
secret reused across two applications) without ever printing either value.

- The fingerprinter (`core/fingerprint.ts`) generates a random 256-bit HMAC
  key with `node:crypto`'s `randomBytes` when a run starts.
- Comparisons within that run use `HMAC-SHA-256(key, value)`, truncated to
  16 hex characters for readable output.
- The key lives only in process memory. It is never written to disk, never
  logged, and is discarded when the process exits.
- Because the key is random and ephemeral, the same input value produces a
  **different** fingerprint on every run. Fingerprints are only meaningful
  for equality comparisons _within a single run_ — they are not a stable
  identifier across runs, machines, or time.

### Why HMAC instead of a plain hash

A plain hash (e.g. `sha256(value)`) is invertible-by-guessing for
low-entropy secrets: an attacker who sees the hash of a low-entropy value
(a short password, a predictable token) can dictionary- or brute-force it
offline. Keying the hash with a random, run-scoped, in-memory-only secret
removes that offline attack surface — the fingerprint cannot be reproduced
or reversed without the key, and the key never leaves memory or the process
lifetime.

### Limitations — read before relying on fingerprints

- **Truncation is for display, not security.** A 16-hex-character
  (64-bit) truncated digest is meant to be skimmable in a terminal. It
  MUST NOT be treated as an authentication token, a capability, or any
  kind of security boundary. Use the full-length digest internally for any
  future logic that requires stronger collision resistance.
- **Run-scoped only.** Fingerprints are not designed to be compared across
  separate `procseal` invocations. Two runs will fingerprint the same
  secret differently by design.
- **Not proof of possession.** A fingerprint match shows two observed
  values were equal during one run. It says nothing about who holds the
  underlying secret or whether it is still valid.
- **Timing.** Fingerprint comparisons in this milestone use ordinary string
  equality on truncated hex digests for report generation, not raw secret
  comparison, so secret-length timing side channels are not a concern here.

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
