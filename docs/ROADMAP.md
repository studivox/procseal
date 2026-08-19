# ProcSeal Roadmap

This roadmap records intent, not release promises. Scope may change as the threat model and fixtures improve.

## v0.1 — PM2 drift scanner

- [x] Document the threat model and redaction contract
- [x] Parse `.env` files without mutating the process environment
- [x] Read PM2 process metadata through a replaceable adapter
- [x] Compare declared configuration with live process state
- [x] Emit stable findings with severity (PS001, PS002, PS003, PS005 — see below)
- [x] Add terminal and JSON reporters
- [ ] Test Linux and macOS behavior with synthetic fixtures
- [ ] Publish a signed npm provenance build

The CLI foundation (executable `procseal` command, shared types, HMAC
fingerprinting, redaction, dotenv parsing, reporters) landed first as its
own milestone. The read-only PM2 adapter (`src/adapters/pm2.ts`) landed
second, with its own unit, integration, and isolated real-PM2 end-to-end
test suite (see [docs/THREAT_MODEL.md](THREAT_MODEL.md)). The rule engine
milestone landed third: `procseal audit --process <name> --env <path>` now
performs a real, read-only comparison between one explicitly selected PM2
process and one explicitly selected dotenv file, implementing PS001,
PS002, PS003 (opt-in via `--check-unexpected`), and PS005. A fourth
milestone added PS004 (cross-application sensitive-value reuse detection,
opt-in via `--check-reuse`) on top of the same read-only PM2 adapter — no
new command, no second PM2 invocation, just a comparison against
applications already present in the same run's snapshot. An independent
review of that milestone before merge found that reuse was being counted
per PM2 _process record_ rather than per _application_, so a clustered
application's own worker records were miscounted as separate other
applications; fixed by grouping the snapshot by safe application name
before comparing — see [docs/THREAT_MODEL.md](THREAT_MODEL.md) for the
full design. `procseal audit` no longer reports `not_implemented` — see
[docs/THREAT_MODEL.md](THREAT_MODEL.md) and the project `README.md` for
the current status and exit-code contract.

Rules:

| Rule  | Finding                                                         | Status                                     |
| ----- | --------------------------------------------------------------- | ------------------------------------------ |
| PS001 | Declared and live values differ                                 | Implemented                                |
| PS002 | Declared variable is missing from the live process              | Implemented                                |
| PS003 | Unexpected variable exists in the live process                  | Implemented (opt-in, `--check-unexpected`) |
| PS004 | A sensitive value appears reused across applications            | Implemented (opt-in, `--check-reuse`)      |
| PS005 | Declared and live ports differ                                  | Implemented (replaces PS001 for `PORT`)    |
| PS006 | A deployment script contains a risky broad PM2 command          | Deferred                                   |
| PS007 | A configuration file appears likely to expose plaintext secrets | Deferred                                   |
| PS008 | PM2 dump state differs from the live process set                | Deferred                                   |

PS006, PS007, and PS008 remain fully deferred: the identifiers are stable
and reserved, but no detection logic exists for them yet, and this project
does not add remediation text or a configurable severity threshold
either. PS004's eligibility policy (which variables are even compared) is
a conservative, documented heuristic — see
[docs/THREAT_MODEL.md](THREAT_MODEL.md) and the project `README.md` for
its exact rules and limitations; it is not a claim of universal secret
detection.

## v0.2 — CI and platform integration

- [ ] SARIF output for code-scanning workflows
- [ ] Docker and Compose adapters
- [ ] systemd environment inspection
- [ ] Configurable policies and severity thresholds
- [ ] Documented plugin interface

## Later exploration

- Fleet-wide drift snapshots that reveal no raw values
- Optional signed attestations
- IDE and deployment-platform integrations
- Safe remediation plans with explicit human approval

## Non-goals for early releases

- Acting as a secrets manager
- Rotating credentials automatically
- Uploading configuration to a hosted service
- Replacing deployment orchestration or access control
