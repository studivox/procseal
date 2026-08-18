# Contributing to ProcSeal

Thank you for helping build ProcSeal. The project is currently pre-alpha, so small, reviewable changes are preferred.

## Before contributing

1. Check existing issues before opening a new one.
2. Never include real credentials, tokens, private hostnames, or production logs.
3. Use synthetic fixtures for PM2 and environment-file examples.
4. Discuss large architecture changes in an issue before implementation.

## Pull requests

A useful pull request should:

- solve one focused problem;
- include tests or fixtures for behavior changes;
- preserve read-only behavior;
- avoid adding telemetry;
- avoid logging raw configuration values;
- update documentation when the public interface changes.

Use Conventional Commit-style subjects where practical, for example:

```text
feat(pm2): detect live environment drift
fix(redaction): mask multiline secrets
docs: clarify fingerprint threat model
```

## Security-sensitive code

Changes involving redaction, fingerprints, process inspection, file permissions, or command execution require explicit tests for failure cases. A plain unsalted hash is not acceptable for comparing low-entropy secrets.

## Development setup

The executable package has not been published yet. Reproducible setup and test commands will be added with the first implementation milestone. Until then, documentation and specification contributions are welcome.
