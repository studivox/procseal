# ProcSeal

> Detect configuration and secret drift in live processes without revealing secret values.

**Status:** pre-alpha / specification phase. ProcSeal is not ready for production use yet, and its interface and rule IDs may change.

## The problem

A deployment can look correct on disk while the running process still uses stale environment variables. This is common with PM2: `.env.production`, an ecosystem file, the PM2 dump, and the live process can each describe a different state. The result is difficult-to-debug outages, reused secrets, wrong ports, and unsafe restart scripts.

ProcSeal is being designed as a read-only CLI that compares declared configuration with runtime state and reports drift without printing secret values.

## Planned first release

- Compare PM2 live environments with `.env`, `.env.production`, and ecosystem files
- Detect missing, unexpected, and stale variables
- Detect secret reuse across apps using keyed one-way fingerprints
- Detect port drift and PM2 dump/live-process drift
- Flag risky deployment commands such as broad `pm2 restart all`
- Produce human-readable terminal output and machine-readable JSON
- Stay read-only by default, with no telemetry and no secret values in reports

## Planned usage

The following is a design target, not a released command yet:

```bash
npx procseal scan --pm2 --config .env.production
```

Example of the planned output:

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

See [SECURITY.md](SECURITY.md) for responsible disclosure guidance.

## Roadmap

The initial scope and release milestones are documented in [docs/ROADMAP.md](docs/ROADMAP.md). The first implementation milestone will focus on a small, testable PM2 adapter rather than broad platform coverage.

## Contributing

The project is intentionally starting in public. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Early contributions are especially welcome around PM2 fixtures, redaction edge cases, rule design, and cross-platform behavior.

## Author

Created by **Volkan Cevik** under **DEDU LTD**.

## License

[MIT](LICENSE)
