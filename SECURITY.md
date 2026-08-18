# Security Policy

## Project status

ProcSeal is currently pre-alpha and has no supported production release. Do not rely on it as a security boundary.

## Reporting a vulnerability

Please do not publish secret values, credentials, exploit details, or sensitive logs in a public issue.

If GitHub's **Report a vulnerability** option is available on the Security tab, use it to open a private security advisory. If it is not available, open a minimal public issue titled `Private security contact requested` without technical details so the maintainer can arrange a private channel.

Include, privately:

- the affected commit or future version;
- the operating system and Node.js version;
- minimal reproduction steps;
- expected and actual behavior;
- the potential impact;
- only redacted logs or fixtures.

## Secret-handling guarantees under design

ProcSeal aims to avoid printing or persisting raw secret values. Reports should contain key names, locations, rule IDs, severity, and keyed fingerprints only when comparison requires them.

A failure of redaction, accidental secret persistence, or recovery of secret values from output should be treated as a high-priority security issue.
