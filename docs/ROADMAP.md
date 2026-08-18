# ProcSeal Roadmap

This roadmap records intent, not release promises. Scope may change as the threat model and fixtures improve.

## v0.1 — PM2 drift scanner

- [x] Document the threat model and redaction contract
- [x] Parse `.env` files without mutating the process environment
- [x] Read PM2 process metadata through a replaceable adapter
- [ ] Compare declared configuration with live process state
- [ ] Emit stable findings with severity and remediation text
- [x] Add terminal and JSON reporters
- [ ] Test Linux and macOS behavior with synthetic fixtures
- [ ] Publish a signed npm provenance build

The CLI foundation (executable `procseal` command, shared types, HMAC
fingerprinting, redaction, dotenv parsing, reporters) landed first as its
own milestone. The read-only PM2 adapter (`src/adapters/pm2.ts`) landed
second, with its own unit, integration, and isolated real-PM2
end-to-end test suite (see [docs/THREAT_MODEL.md](THREAT_MODEL.md)) — but
it is not wired into the public CLI yet. `procseal audit` still reports an
explicit `not_implemented` status and performs no machine inspection until
PS001–PS008 detection (the next milestone) actually calls the adapter and
compares its snapshot against declared configuration.

Planned initial rules:

| Rule  | Finding                                                         |
| ----- | --------------------------------------------------------------- |
| PS001 | Declared and live values differ                                 |
| PS002 | Declared variable is missing from the live process              |
| PS003 | Unexpected variable exists in the live process                  |
| PS004 | A sensitive value appears reused across applications            |
| PS005 | Declared and live ports differ                                  |
| PS006 | A deployment script contains a risky broad PM2 command          |
| PS007 | A configuration file appears likely to expose plaintext secrets |
| PS008 | PM2 dump state differs from the live process set                |

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
