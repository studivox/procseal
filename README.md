# ProcSeal

> Detect configuration and secret drift in live processes without revealing secret values.

**Status:** pre-alpha. The CLI foundation and a secure, read-only PM2 adapter (`src/adapters/pm2.ts`) are implemented and tested, but `procseal audit` still does not perform a real audit — the public CLI does not yet call the adapter, and `audit` still always reports an explicit `not_implemented` status with zero findings. The PM2 adapter is currently exercised only through its own test suite and internal APIs; it is not wired into the CLI yet, and no production data is uploaded anywhere. Comparing declared configuration against the live process state (PS001–PS008 detection) is deferred to the next milestone. The interface and rule IDs may still change.

## The problem

A deployment can look correct on disk while the running process still uses stale environment variables. This is common with PM2: `.env.production`, an ecosystem file, the PM2 dump, and the live process can each describe a different state. The result is difficult-to-debug outages, reused secrets, wrong ports, and unsafe restart scripts.

ProcSeal is a read-only CLI that will compare declared configuration with runtime state and report drift without printing secret values.

## Try it now

`procseal` is **not published to npm** (the package is private and
pre-release), so `npx procseal` does not work yet. Run it from a local
clone instead:

```bash
git clone https://github.com/studivox/procseal.git
cd procseal
npm ci
npm run build
node dist/cli.js --help
node dist/cli.js audit
node dist/cli.js audit --json
```

Once a first version is published, the intended entry point will be:

```bash
# Future, once published — does not work yet.
npx procseal audit
```

### Exit codes

| Code | Meaning                                                                                                                            |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `0`  | The command completed. For `audit`, inspect the reported `status` field.                                                           |
| `1`  | Internal error. A static message and a non-sensitive error code are printed; the original error message and stack are never shown. |
| `2`  | Usage error — unknown command or invalid option.                                                                                   |

## Implemented in this milestone

- An executable `procseal` CLI: `--help`, `--version`, `audit`, `audit --help`, `audit --json`. `audit` is unchanged from the previous milestone — it still always reports `not_implemented` and performs no machine inspection; the PM2 adapter below is not wired into it yet.
- Shared core types for findings, severities, and the eight stable rule identifiers (PS001–PS008).
- Keyed HMAC-SHA-256 fingerprinting with a random, run-scoped, in-memory-only comparison key, with equality (`equals`) and display (`displayFingerprint`) kept as separate operations — see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- A dotenv-style parser that never mutates `process.env`, returning a structured diagnostic (never a raw value) for malformed input.
- Terminal and JSON reporters that derive finding titles from the fixed rule catalog (never free-form text) and pass every string-bearing output field through a final sanitization boundary (`core/output-safety.ts`) before printing.
- A static, code-only internal-error message at the CLI's top level: the original `Error.message` and stack are never printed, regardless of what a thrown error contains.
- **A read-only PM2 process adapter (`src/adapters/pm2.ts`)**, exercised only through its own test suite and internal APIs so far — not yet reachable from the public CLI:
  - Invokes exactly one fixed command, equivalent to `pm2 jlist`, via `node:child_process.execFile` with `shell: false`, a fixed argument array, a command timeout, and a strict stdout/stderr buffer limit. Never `exec`, never a shell command string, never `sudo`. See `src/core/command-runner.ts`.
  - Inspects only the PM2 daemon belonging to the current OS user (whatever `PM2_HOME`/PM2 daemon the process's own environment resolves to); never reads or targets another user's `PM2_HOME`.
  - Never restarts, reloads, stops, deletes, saves, kills, or updates a PM2 process — the adapter only ever runs `jlist`.
  - Treats the entire raw `pm2 jlist` payload as sensitive: immediately after JSON parsing, every string leaf of the payload is recursively registered in the run's `SecretRegistry`, before any normalization happens.
  - Represents every environment value as an opaque `ObservedValue` (`src/core/observed-value.ts`) — the raw string lives only in a true JavaScript private field, never returned by any getter, `toString`, `valueOf`, `toJSON`, or inspector. The only operations exposed are `equals()`, `equalsPlain()`, and `displayFingerprint()`, all delegating to the existing HMAC-based `Fingerprinter`.
  - Returns a minimal, normalized snapshot (safe process id, redacted/validated process name, PM2 numeric id, a validated status enum, environment variable names, and opaque values) — never the raw `pm2_env`, full command lines, raw paths, or raw stdout/stderr.
  - Enforces documented hard limits (max processes, max env vars per process, max key/value length, max JSON payload size, command timeout) and fails fast with a stable, non-sensitive error code rather than silently truncating a value and comparing the truncated version — see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
  - Supports dependency injection of the command runner, so its unit and integration tests never require a real PM2 daemon.
- A real, isolated end-to-end test (`tests/e2e/pm2-live.test.ts`) that starts an actual PM2 daemon under a unique temporary `PM2_HOME` (via `mkdtemp`), starts a tiny synthetic process with a synthetic sentinel environment value, reads it back through the adapter, and proves the sentinel never appears in any output or serialization — then tears the isolated daemon down through a guard (`tests/e2e/pm2-isolation-guard.ts`) that refuses to run if `PM2_HOME` is absent, empty, the real `PM2_HOME`, or outside the test's own temporary directory. The real PM2 daemon and `PM2_HOME` used by this machine are never read or touched by this test suite.
- No telemetry, no analytics, no network calls, no update checks, no postinstall scripts. PM2 is a pinned `devDependency` used only by the isolated end-to-end test — it is never a runtime dependency of the published package (see `npm pack --dry-run`; PM2, tests, and fixtures are not part of the published tarball).

## Planned (not yet implemented)

- Wiring the PM2 adapter into the public `procseal audit` command (it currently reports `not_implemented` regardless of the adapter's existence)
- Comparing declared configuration with `.env`, `.env.production`, and ecosystem files against live process state
- Detecting missing, unexpected, and stale variables
- Detecting secret reuse across apps using the fingerprinting described above
- Detecting port drift and PM2 dump/live-process drift
- Flagging risky deployment commands such as broad `pm2 restart all`
- Rule detection for PS001–PS008 (the identifiers exist; none of the checks run yet)
- Automatic remediation is a **non-goal**; see [docs/ROADMAP.md](docs/ROADMAP.md)

Example of the _planned_ output once the PM2 adapter ships (not produced yet):

```text
PS001  high    DATABASE_URL differs between file and live process
PS004  high    JWT secret fingerprint is reused by 2 applications
PS005  medium  Declared port 3000, live process port 3100

3 findings · 0 secret values exposed
```

## Security principles

1. Never print or persist raw secret values.
2. Prefer keyed, run-scoped fingerprints over plain hashes.
3. Redact command output and structured reports by default.
4. Make every check read-only unless the user explicitly requests a future remediation feature.
5. Treat ProcSeal as a diagnostic aid, not as a security boundary.
6. No production data is uploaded anywhere. ProcSeal makes no network calls.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the fingerprint design and its limitations, and [SECURITY.md](SECURITY.md) for responsible disclosure guidance.

## Roadmap

The initial scope and release milestones are documented in [docs/ROADMAP.md](docs/ROADMAP.md). The first implementation milestone will focus on a small, testable PM2 adapter rather than broad platform coverage.

## Contributing

The project is intentionally starting in public. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Early contributions are especially welcome around PM2 fixtures, redaction edge cases, rule design, and cross-platform behavior.

## Author

Created by **Volkan Cevik** under **DEDU LTD**.

## License

[MIT](LICENSE)
