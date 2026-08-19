<p align="center">
  <img src="docs/assets/hero-banner.svg" alt="ProcSeal — local-first configuration and secret drift detector for PM2 processes" width="480">
</p>

<p align="center">
  <strong>Detect PM2 configuration and secret drift — without ever printing the secret.</strong>
</p>

<p align="center">
  <a href="https://github.com/studivox/procseal/actions/workflows/ci.yml"><img src="https://github.com/studivox/procseal/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT license"></a>
  <a href="package.json"><img src="https://img.shields.io/badge/node-20%20%7C%2022-339933?logo=node.js&logoColor=white" alt="Node.js 20 or 22"></a>
</p>

<p align="center">
  <sub>Not yet published to npm — see <a href="#installation">Installation</a>. An npm-version badge is added here once it is.</sub>
</p>

ProcSeal is a **read-only** CLI that compares one explicitly named PM2 process against one explicitly named `.env` file and reports drift — missing variables, changed values, wrong ports, and credentials reused across applications — **without printing the underlying secret values**, ever.

## Contents

- [The problem](#the-problem)
- [30-second Quick Start](#30-second-quick-start)
- [Installation](#installation)
- [Live demo](#live-demo)
- [Example output](#example-output)
- [Implemented rules](#implemented-rules)
- [Exit codes](#exit-codes)
- [Security model](#security-model)
- [How it works](#how-it-works)
- [CI/CD usage](#cicd-usage)
- [Supported platforms](#supported-platforms)
- [Limitations and non-goals](#limitations-and-non-goals)
- [FAQ](#faq)
- [Contributing](#contributing)
- [Reporting a security issue](#reporting-a-security-issue)
- [Roadmap](#roadmap)
- [License](#license)

## The problem

A deployment can look correct on disk while the process running it doesn't match. This is a routine failure mode with PM2: `.env.production`, an ecosystem file, `pm2 save`'s dump, and the live process's actual environment can each describe a _different_ state, because PM2 only reads a `.env` file at the moment you run `pm2 start` — it never watches the file afterward. A concrete way this bites:

1. Someone edits `.env.production` to rotate `JWT_SECRET` and fix `PORT`.
2. They forget to run `pm2 restart api --update-env` (or run a bare `pm2 restart api`, which does **not** reload the env file).
3. The live process keeps running with the **old** secret and the **old** port.
4. Nothing on disk looks wrong. The drift is invisible until it causes an outage, a failed rotation, or a credential that should have been retired keeps working.

ProcSeal exists to make that drift visible in one command, before it becomes an incident — and to do it without becoming a second place secrets can leak from.

## 30-second Quick Start

```bash
git clone https://github.com/studivox/procseal.git
cd procseal
npm ci && npm run build

node dist/cli.js audit --process my-app --env .env.production
```

That's it — `--process` and `--env` are both required, ProcSeal never auto-discovers either one, and the run is entirely local and read-only. See [Installation](#installation) for a global-command setup and [Live demo](#live-demo) for a full worked example with real (synthetic) drift.

## Installation

**From npm** (once published — see [Roadmap](#roadmap); this is the intended path for end users and is not live yet):

```bash
npm install -g procseal
procseal audit --process my-app --env .env.production
```

**Local / development install** (works today, verified against this exact revision):

```bash
git clone https://github.com/studivox/procseal.git
cd procseal
npm ci                # clean install from package-lock.json
npm run build          # compiles src/ to dist/
npm test               # optional: unit + integration + isolated E2E suites
node dist/cli.js --version
node dist/cli.js --help
```

To use the `procseal` command name locally without a global install, either run `npm link` after building, or install the packed tarball into another project exactly as an end user would:

```bash
npm pack                                   # produces procseal-<version>.tgz
npm install /path/to/procseal-<version>.tgz --prefix /path/to/some/project
```

Every command in this README was run against a package built and packed this way, not only against the source checkout.

## Live demo

The transcript below is real output from a fresh `npm pack` install, run against an isolated, disposable PM2 daemon under a temporary `PM2_HOME` — not the real PM2 daemon on the machine that generated it, and not a mockup. Every value shown is synthetic. Reproduce it yourself in under a minute:

```bash
# 1. Start a synthetic app with a synthetic secret (use a real PM2 daemon
#    you don't mind touching, or an isolated PM2_HOME of your own).
JWT_SECRET=demo-secret-do-not-use pm2 start app.js --name payments-api

# 2. Write a dotenv file that has drifted from what's actually running.
cat > .env.production <<'EOF'
JWT_SECRET=demo-secret-do-not-use-OLD
DATABASE_URL=postgres://demo:demo@localhost:5432/payments
PORT=3000
STRIPE_API_KEY=demo-stripe-key-not-declared-live
EOF

# 3. Audit it.
procseal audit --process payments-api --env .env.production
```

```text
$ procseal audit --process payments-api --env .env.production
procseal 0.1.0
status: completed
process: payments-api
Audit completed. 3 finding(s).

PS001  high      Declared and live values differ
    variable: JWT_SECRET
PS005  medium    Declared and live ports differ
    variable: PORT
PS002  high      Declared variable is missing from the live process
    variable: STRIPE_API_KEY

3 finding(s)
```

Exit code `3` (findings present — see [Exit codes](#exit-codes)). Notice what's _absent_: the actual value of `JWT_SECRET` on either side, the actual port numbers, and the actual (missing) value of `STRIPE_API_KEY`. Every finding names a variable, never a value.

## Example output

The same audit as `--json`, for scripting or CI:

```json
{
  "status": "completed",
  "message": "Audit completed. 3 finding(s).",
  "findings": [
    {
      "ruleId": "PS001",
      "severity": "high",
      "message": "Declared and live values differ",
      "details": { "variable": "JWT_SECRET" }
    },
    {
      "ruleId": "PS005",
      "severity": "medium",
      "message": "Declared and live ports differ",
      "details": { "variable": "PORT" }
    },
    {
      "ruleId": "PS002",
      "severity": "high",
      "message": "Declared variable is missing from the live process",
      "details": { "variable": "STRIPE_API_KEY" }
    }
  ],
  "meta": { "tool": "procseal", "version": "0.1.0", "generatedAt": "2026-08-19T02:48:40.116Z" },
  "subject": { "process": "payments-api" }
}
```

And a real capture of `--check-reuse` (PS004), with a second app (`billing-worker`) declaring the same secret under a different variable name:

```text
$ procseal audit --process payments-api --env .env.production --check-reuse
procseal 0.1.0
status: completed
process: payments-api
Audit completed. 1 finding(s).

PS004  critical  A sensitive value appears reused across applications
    variable: JWT_SECRET
    reusedInApplicationCount: 1

1 finding(s)
```

## Implemented rules

`procseal audit --process <name> --env <path>` compares every variable declared in the dotenv file against that one live PM2 process's environment.

| Rule    | Finding                                                        | Notes                                    |
| :------ | :------------------------------------------------------------- | :--------------------------------------- |
| `PS001` | A declared value differs from the live value                   | Excludes `PORT` — see `PS005`            |
| `PS002` | A declared variable is missing from the live process           | —                                        |
| `PS003` | A live variable isn't declared in the dotenv file              | Opt-in via `--check-unexpected`          |
| `PS004` | A sensitive live value is also used by another PM2 application | Opt-in via `--check-reuse`               |
| `PS005` | The declared and live `PORT` values differ                     | Replaces `PS001` for `PORT` specifically |

**Planned, not implemented** — these identifiers are reserved and stable, but no detection logic exists for them yet, and this README makes no claim otherwise:

| Rule    | Planned finding                                           |
| :------ | :-------------------------------------------------------- |
| `PS006` | A deployment command is a dangerous, broad PM2 operation  |
| `PS007` | A configuration file appears to expose a plaintext secret |
| `PS008` | Saved PM2 dump state differs from the live process set    |

No finding, for any rule, ever includes a raw declared or live value. A finding's `details` may only carry a validated variable name and, for `PS004`, a count of other applications — never a value, and `PS005` never includes either side's actual port number.

### `--check-unexpected` and `--check-reuse`

Both are **off by default** — omitting them leaves output identical to a run without the flags:

- **`--check-unexpected`** additionally reports `PS003`: a variable the live process has that the dotenv file never declares. Useful for finding stale or forgotten environment variables, but noisy by default (PM2 and the OS both inject their own variables into a process), which is exactly why it's opt-in.
- **`--check-reuse`** additionally reports `PS004`: a sensitive value in the selected process that's also present in another PM2 application. Only variables whose name conservatively looks like a credential (`password`, `secret`, `token`, `api key`, `private key`, `client secret`, `access key`, `auth key`, or similar) **and** whose value is at least 12 UTF-8 bytes long are ever compared — a false-positive-reduction heuristic, not proof a value is or isn't a secret (see [FAQ](#faq)). Reuse is counted per **PM2 application** (process name), not per process record, so a clustered application running several workers under one name is one application, not several.

## Exit codes

| Code | Meaning                                                                                                                                                                                                                      |
| :--- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0`  | The audit completed with zero findings.                                                                                                                                                                                      |
| `1`  | A safe operational or internal failure (process/file not found, PM2 unreachable, ...). A static message and a stable, non-sensitive error code are printed — never raw content, never the original error's message or stack. |
| `2`  | Usage error — unknown command, or an invalid/missing option.                                                                                                                                                                 |
| `3`  | The audit completed with one or more findings.                                                                                                                                                                               |

## Security model

1. **Local-first.** Every operation runs on the machine you invoke it on. No network calls, no telemetry, no update checks, no analytics, no postinstall scripts.
2. **Read-only.** ProcSeal never mutates the dotenv file, PM2 state, `process.env`, or any process. The PM2 adapter invokes exactly one command — the equivalent of `pm2 jlist` — and nothing else; it never restarts, reloads, stops, deletes, saves, or kills anything.
3. **Secrets never printed.** Every declared and live value is wrapped in an opaque type (`ObservedValue`) whose raw string lives only in a true JavaScript private field — there is no getter, `toString`, `toJSON`, or inspector that can recover it. Comparisons use keyed HMAC-SHA-256 equality (`ObservedValue.equals()`), never a plain hash and never `===` on raw strings.
4. **Redaction is a boundary, not a convention.** Every reporter routes every string field through one final sanitization function backed by a run-scoped secret registry, immediately before writing anything — this does not trust that upstream code already redacted correctly.
5. **Diagnostic aid, not a security boundary.** A clean audit does not certify that a deployment is secure. See [Limitations and non-goals](#limitations-and-non-goals).

The full design — HMAC fingerprint construction, the PM2 adapter's hard limits, the dotenv-file adapter's bounded-read and mutation-detection guarantees, and every documented limitation — is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## How it works

```mermaid
flowchart LR
    ENVFILE[".env file<br/>(--env, one explicit path)"]
    PM2D["PM2 daemon<br/>(pm2 jlist, read-only)"]

    subgraph procseal audit
        DOTENV["dotenv-file adapter<br/>bounded read, no traversal"]
        PM2A["PM2 adapter<br/>execFile, jlist only"]
        OV["ObservedValue<br/>opaque, HMAC-comparable"]
        RULES["Rule engine<br/>PS001–PS005, pure function"]
        REG["SecretRegistry<br/>final scrub boundary"]
    end

    ENVFILE --> DOTENV --> OV
    PM2D --> PM2A --> OV
    OV --> RULES --> REG
    REG --> OUT["Terminal / JSON report<br/>exit code 0 / 1 / 2 / 3"]
```

Both adapters register every raw value they touch with the `SecretRegistry` the moment they read it — before any comparison, before any diagnostic, before any error — so even a bug in a later stage cannot leak a value the registry doesn't already know to scrub.

## CI/CD usage

Exit codes make ProcSeal easy to gate a pipeline on: `0` and non-`3` mean no drift, `3` means findings exist.

```yaml
# .github/workflows/config-drift.yml (example — not run by this repository)
- name: Check for PM2 configuration drift
  run: npx procseal audit --process my-app --env .env.production --json
  # exits 3 (fails the step) if drift is found; 0 if clean.
```

Use `--json` in automation for a stable, parseable shape; use the default terminal output for interactive use. Neither ever includes a raw declared or live value, so audit output is safe to attach to a CI log or a PR comment.

## Supported platforms

Validated by this repository's own CI on every change, before every release:

| OS                              | Node.js 20 | Node.js 22 |
| :------------------------------ | :--------: | :--------: |
| Linux (Ubuntu, `ubuntu-latest`) |     ✅     |     ✅     |
| macOS (`macos-latest`)          |     ✅     |     ✅     |

All four combinations run the full suite — unit, integration, and an isolated real-PM2 end-to-end test — against a disposable `PM2_HOME`, never the runner's own. Formatting, linting, and type-checking run once (they're platform-independent). Windows is not currently tested and is not claimed as supported.

## Limitations and non-goals

**Limitations:**

- Exactly one `--process` and one `--env` per run. No ecosystem-file comparison, no `.env.production`-style auto-discovery, no multi-process or multi-file audits, no PM2 dump-state comparison (`PS008`, planned).
- `PS004`'s reuse detection is a heuristic (see [FAQ](#faq)) — it can miss a real secret under an unrecognized key name and, rarely, flag an intentionally shared long value.
- A PM2 application whose process name fails safe-label validation is excluded from `PS004` comparison entirely — a documented false-negative boundary, not a bug.
- No SARIF output, no Docker or systemd adapters, no IDE integration. These may appear in a later release; they are not implemented now.

**Non-goals:**

- ProcSeal is not a secrets manager. It does not store, rotate, generate, or distribute secrets.
- ProcSeal does not remediate anything automatically. It reports; it never changes configuration or process state.
- ProcSeal does not claim universal secret detection. `PS004`'s policy is explicit and documented, not a machine-learning or entropy-based guess.
- A clean (`exit 0`) audit is not a security certification.

## FAQ

**Which `PM2_HOME` does ProcSeal read?**
Whichever one the current OS user's own environment resolves to — respecting a `PM2_HOME` environment variable if you've set one, or PM2's own default (`~/.pm2`) otherwise. ProcSeal never targets another user's `PM2_HOME`, and every test in this repository that touches a real PM2 daemon does so under its own disposable, temporary `PM2_HOME`, never the invoking user's.

**What are the "fingerprints" and why can't I see them?**
Values are compared using HMAC-SHA-256, keyed with a random, in-memory-only key generated fresh for each run and never written to disk. Only two things ever leave that comparison: a boolean (`equals()`) and a truncated, run-scoped **display** fingerprint meant for humans to eyeball, never for equality decisions. Because the key is random per run, the same secret produces a different display fingerprint every time you run ProcSeal — it is not a stable identifier across runs, machines, or time.

**Can `PS004` (reuse detection) produce false positives or false negatives?**
Yes, by design, and this is documented, not hidden. A key name outside its short list of credential-terminology substrings, or a value under 12 UTF-8 bytes, is never compared — a real secret can slip through either check (a false negative). Conversely, an intentionally shared long value that happens to sit under a credential-shaped key name would be flagged (a false positive). See the [Implemented rules](#implemented-rules) table and `src/core/reuse-candidate-policy.ts`.

**Does `PS004` handle PM2 cluster mode correctly?**
Reuse is counted per **application** (PM2's process name), not per process record — a clustered application running several worker processes under one name counts as exactly one application, never one per worker, and never self-triggers a finding against itself. An application whose raw PM2 name fails safe-label validation is excluded from the comparison entirely (a documented false-negative boundary — see [Limitations](#limitations-and-non-goals)).

**What do the exit codes mean, exactly?**
See the [Exit codes](#exit-codes) table. In short: `0` clean, `1` operational failure, `2` usage error, `3` findings present — designed so a CI step can gate directly on the exit code without parsing output.

**Does any data leave my machine?**
No. ProcSeal makes no network calls of any kind — not for telemetry, not for update checks, not for anything. The only two external interactions it ever has are reading the one `.env` file you pass with `--env` and invoking the local `pm2 jlist` command against the local PM2 daemon.

## Contributing

The project is intentionally developed in public. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Contributions are especially welcome around PM2 fixtures, redaction edge cases, rule design, and cross-platform behavior.

## Reporting a security issue

Please do not post secret values, credentials, or exploit details in a public issue. See [SECURITY.md](SECURITY.md) for the private reporting process.

## Roadmap

The full scope and release milestones are in [docs/ROADMAP.md](docs/ROADMAP.md). In short: `v0.1.0` (this release) implements PS001–PS005 against exactly one PM2 process and one dotenv file per run; `PS006`–`PS008`, broader comparison surfaces, and CI/platform integrations are scoped for later and not implemented yet.

## License

[MIT](LICENSE) © 2026 Volkan Cevik, [DEDU LTD](https://github.com/studivox)
