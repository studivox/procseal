# ProcSeal

> Detect configuration and secret drift in live processes without revealing secret values.

**Status:** pre-alpha. `procseal audit` now performs a real, read-only comparison between one explicitly selected PM2 process and one explicitly selected dotenv file — see [Try it now](#try-it-now) below. Four rules are implemented (PS001, PS002, PS003, PS005); PS004, PS006, PS007, and PS008 are defined as stable identifiers but not yet implemented. No production data is uploaded anywhere; ProcSeal never auto-discovers a process or a file to compare. The interface and rule IDs may still change.

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
node dist/cli.js audit --help
node dist/cli.js audit --process my-app --env .env.production
node dist/cli.js audit --process my-app --env .env.production --json
node dist/cli.js audit --process my-app --env .env.production --check-unexpected
```

`--process` and `--env` are both required — ProcSeal never auto-discovers a process or a file to compare. `--process` must match exactly one running PM2 process by name; `--check-unexpected` opts into reporting live variables that aren't declared in the dotenv file (PS003), which is otherwise silent.

Once a first version is published, the intended entry point will be:

```bash
# Future, once published — does not work yet.
npx procseal audit --process my-app --env .env.production
```

### Exit codes

| Code | Meaning                                                                                                                                                                                                                                     |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0`  | The audit completed with zero findings.                                                                                                                                                                                                     |
| `1`  | A safe operational or internal failure (e.g. the process or file couldn't be found/read). A static message and a non-sensitive error code are printed; raw file/process content, the original error message, and the stack are never shown. |
| `2`  | Usage error — unknown command, or an invalid/missing option.                                                                                                                                                                                |
| `3`  | The audit completed with one or more findings.                                                                                                                                                                                              |

## Implemented rules

`procseal audit --process <name> --env <path>` compares every variable declared in the dotenv file against that one live PM2 process's environment:

| Rule    | Finding                                                                                          |
| ------- | ------------------------------------------------------------------------------------------------ |
| `PS001` | A declared value differs from the live value (any variable except `PORT` — see `PS005`).         |
| `PS002` | A declared variable is missing from the live process.                                            |
| `PS003` | A live variable isn't declared in the dotenv file. Only reported with `--check-unexpected`.      |
| `PS005` | The declared and live `PORT` values differ. Reported instead of `PS001` for `PORT` specifically. |

`PS004`, `PS006`, `PS007`, and `PS008` are defined as stable rule identifiers but have no detection logic yet — see [Planned](#planned-not-yet-implemented).

No finding — for any rule — ever includes a raw declared or live value. A finding's `details` may only carry a validated variable name; `PS005` in particular never includes either side's actual port number, only the fact that `PORT` differs.

Example output for a process with real drift:

```text
$ procseal audit --process my-app --env .env.production
procseal 0.1.0-alpha.0
status: completed
process: my-app
Audit completed. 3 finding(s).

PS002  high      Declared variable is missing from the live process
    variable: DATABASE_URL
PS001  high      Declared and live values differ
    variable: JWT_SECRET
PS005  medium    Declared and live ports differ
    variable: PORT

3 finding(s)
```

(exit code `3` — see [Exit codes](#exit-codes) above)

## Implemented in this milestone

- An executable `procseal` CLI: `--help`, `--version`, `audit --process <name> --env <path> [--json] [--check-unexpected]`, `audit --help`. Both `--process` and `--env` are required; ProcSeal never auto-discovers either.
- A read-only dotenv-file adapter (`src/adapters/dotenv-file.ts`) that reads exactly the file passed to `--env` — regular files only (symlinks rejected race-free at `open()` via `O_NOFOLLOW`; non-regular files rejected via `fstat`), through a bounded read loop that allocates at most `maxFileBytes + 1` bytes regardless of how large or how fast the file grows, and per-file limits on variable count, key length, and value size (measured in UTF-8 bytes). A pre/post `fstat(fd, { bigint: true })` comparison (`dev`, `ino`, `size`, `mtimeNs`, `ctimeNs`) detects any same-inode mutation during the read and fails closed — descriptor-bound reading detects in-place changes, it does not prevent them. Every successfully parsed value — including one a later duplicate key goes on to overwrite — is registered in the run's `SecretRegistry` and wrapped in the same opaque `ObservedValue` the PM2 adapter uses, sharing one `Fingerprinter` per audit run so declared and live values compare through full-HMAC equality.
- Conservative process-name selection (`src/core/process-selection.ts`): the requested `--process` value must match a strict identifier pattern and must match exactly one live PM2 process by name — zero or multiple matches both fail with their own stable error code, and a raw/unsafe PM2 process name is never compared against or exposed.
- A pure rule engine (`src/rules/engine.ts`) implementing PS001, PS002, PS003, and PS005 (see [Implemented rules](#implemented-rules) above) — every comparison goes through `ObservedValue.equals()`, and every finding detail is a validated variable name, never a value.
- **A read-only PM2 process adapter (`src/adapters/pm2.ts`)**, now wired into `procseal audit`:
  - Invokes exactly one fixed command, equivalent to `pm2 jlist`, via `node:child_process.execFile` with `shell: false` and a fixed argument array, with a command timeout and a buffer limit passed to `execFile`'s `maxBuffer` option (which Node applies to stdout and stderr independently, not as a combined bound) plus the adapter's own independent byte-length check on the received stdout, which is the limit's real enforcement. Never `exec`, never a shell command string, never `sudo`. See `src/core/command-runner.ts`.
  - Inspects only the PM2 daemon belonging to the current OS user; never reads or targets another user's `PM2_HOME`. Never restarts, reloads, stops, deletes, saves, kills, or updates a PM2 process — the adapter only ever runs `jlist`.
  - Treats the entire raw `pm2 jlist` payload as sensitive: every string leaf is registered in the run's `SecretRegistry`, except a process's own name (PM2 duplicates it into multiple fields; a validated process name is meant to be displayable — see `subject.process` in JSON output — so it is excluded from registration by exact value, never by field path, so the exclusion holds regardless of how many places PM2 puts it).
  - Represents every environment value as an opaque `ObservedValue` (`src/core/observed-value.ts`) — the raw string lives only in a true JavaScript private field, never returned by any getter, `toString`, `valueOf`, `toJSON`, or inspector.
  - Returns a minimal, normalized snapshot — never the raw `pm2_env`, full command lines, raw paths, or raw stdout/stderr — enforcing documented hard limits and failing fast with a stable, non-sensitive error code rather than silently truncating a value and comparing the truncated version. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- Terminal and JSON reporters that derive finding titles from the fixed rule catalog (never free-form text), report the audited process identity and finding count, and pass every string-bearing output field through a final sanitization boundary (`core/output-safety.ts`) before printing.
- A static, code-only internal-error message at the CLI's top level for genuinely unexpected failures: the original `Error.message` and stack are never printed. Expected operational failures (process not found, file unreadable, PM2 unavailable, ...) instead produce a structured `status: "failed"` result with a stable error code and a fixed, static message — never raw file or process content.
- Real, isolated end-to-end tests (`tests/e2e/pm2-live.test.ts`, `tests/e2e/audit-live.test.ts`) that start an actual PM2 daemon under a unique temporary `PM2_HOME`, run the real CLI against it and a real temporary dotenv file, and prove exit codes `0`/`3` and zero sentinel leakage — then tear the isolated daemon down through a guard (`tests/e2e/pm2-isolation-guard.ts`) that only deletes the temporary directory after a confirmed-complete teardown (`pm2 kill` succeeded **and** the daemon's PID is confirmed dead, or its pidfile was genuinely absent) — a failed kill, a still-alive daemon, or an unverifiable pidfile all leave the directory in place. The real PM2 daemon and `PM2_HOME` used by this machine are never read or touched by this test suite.
- No telemetry, no analytics, no network calls, no update checks, no postinstall scripts. PM2 is a pinned `devDependency` used only by the isolated end-to-end tests — it is never a runtime dependency of the published package (see `npm pack --dry-run`; PM2, tests, and fixtures are not part of the published tarball).

## Planned (not yet implemented)

- `PS004`: sensitive value reused across applications
- `PS006`: a deployment command is a dangerous, broad PM2 operation
- `PS007`: a configuration file appears to expose a plaintext secret
- `PS008`: saved PM2 dump state differs from the live process set
- Comparing against ecosystem files, `.env.production`-style auto-discovery, or more than one process/file per run — every audit remains exactly one explicit `--process` and one explicit `--env`
- Automatic remediation is a **non-goal**; see [docs/ROADMAP.md](docs/ROADMAP.md)

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
