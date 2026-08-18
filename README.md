# ProcSeal

> Detect configuration and secret drift in live processes without revealing secret values.

**Status:** pre-alpha. The CLI foundation described below is implemented and tested, but `procseal audit` does not yet inspect any real machine — it reports an explicit `not_implemented` status. Live PM2 inspection is planned for a following milestone. The interface and rule IDs may still change.

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

- An executable `procseal` CLI: `--help`, `--version`, `audit`, `audit --help`, `audit --json`.
- Shared core types for findings, severities, and the eight stable rule identifiers (PS001–PS008).
- Keyed HMAC-SHA-256 fingerprinting with a random, run-scoped, in-memory-only comparison key, with equality (`equals`) and display (`displayFingerprint`) kept as separate operations — see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- A dotenv-style parser that never mutates `process.env`, returning a structured diagnostic (never a raw value) for malformed input.
- Terminal and JSON reporters that derive finding titles from the fixed rule catalog (never free-form text) and pass every string-bearing output field through a final sanitization boundary (`core/output-safety.ts`) before printing. Adversarial tests prove that a sentinel value placed in the audit-level message, a finding's metadata key/value, or a nested structure does not appear in terminal or JSON output when it has been registered with the run's `SecretRegistry`; this is defense in depth, not a guarantee for arbitrary unregistered raw values a future adapter might mishandle.
- A static, code-only internal-error message at the CLI's top level: the original `Error.message` and stack are never printed, regardless of what a thrown error contains.
- No telemetry, no analytics, no network calls, no update checks, no postinstall scripts.

## Planned (not yet implemented)

- Live PM2 process inspection through a replaceable adapter (no shell execution)
- Comparing declared configuration with `.env`, `.env.production`, and ecosystem files against live process state
- Detecting missing, unexpected, and stale variables
- Detecting secret reuse across apps using the fingerprinting described above
- Detecting port drift and PM2 dump/live-process drift
- Flagging risky deployment commands such as broad `pm2 restart all`
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
