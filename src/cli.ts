#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AUDIT_HELP, executeAuditCommand, parseAuditArgs } from './commands/audit.js';
import { reportInternalError } from './core/internal-error.js';
import { createSecretRegistry, sanitizeForDisplay } from './core/output-safety.js';

/**
 * A command-line argument is attacker-controlled input: it can contain
 * newlines or ANSI escape sequences designed to forge extra terminal lines
 * or manipulate the terminal when reflected back into an error message.
 * Route any reflected argument through the same output-safety boundary the
 * reporters use before it reaches stderr. No known secret values are
 * relevant at this point in the CLI (no configuration has been read yet),
 * so a fresh, empty registry is sufficient here — the character-set
 * stripping is what matters for this boundary.
 */
function sanitizeReflectedArg(value: string): string {
  return sanitizeForDisplay(value, createSecretRegistry());
}

const moduleDir = dirname(fileURLToPath(import.meta.url));

const TOP_LEVEL_HELP = `procseal — local-first configuration and secret drift detector for PM2 processes.

Usage:
  procseal [--help] [--version]
  procseal audit --process <pm2-process-name> --env <path> [--json] [--check-unexpected] [--check-reuse]

Status:
  v0.1.0 — early release, narrow scope by design. "procseal audit"
  performs a real, read-only comparison between one explicitly selected
  PM2 process and one explicitly selected dotenv file. Run "procseal
  audit --help" for the full option and exit-code reference.

Exit codes:
  0  The audit completed with zero findings.
  1  A safe operational or internal failure. A static message and a
     non-sensitive error code are printed; raw file/process content, the
     original error message, and the stack are never shown.
  2  Usage error (unknown command or invalid/missing option).
  3  The audit completed with one or more findings.

Security:
  procseal makes no network calls, performs no telemetry, and never prints
  raw configuration or secret values. See docs/THREAT_MODEL.md for details.
`;

function readVersion(): string {
  const packageJsonPath = join(moduleDir, '..', 'package.json');
  const raw = readFileSync(packageJsonPath, 'utf8');
  const parsed = JSON.parse(raw) as { version?: string };
  return parsed.version ?? '0.0.0';
}

async function runAudit(rest: readonly string[], version: string): Promise<number> {
  const parsed = parseAuditArgs(rest);

  if (parsed.kind === 'help') {
    process.stdout.write(AUDIT_HELP);
    return 0;
  }

  if (parsed.kind === 'usage-error') {
    if (parsed.offendingArg !== undefined) {
      process.stderr.write(
        `Unknown option for "audit": ${sanitizeReflectedArg(parsed.offendingArg)}\n\n`,
      );
    } else {
      process.stderr.write(`${parsed.reason}\n\n`);
    }
    process.stderr.write(AUDIT_HELP);
    return 2;
  }

  const { output, exitCode } = await executeAuditCommand(parsed.options, version);
  process.stdout.write(`${output}\n`);
  return exitCode;
}

async function main(argv: readonly string[]): Promise<number> {
  const version = readVersion();
  const [command, ...rest] = argv;

  if (command === undefined || command === '--help' || command === '-h') {
    process.stdout.write(TOP_LEVEL_HELP);
    return 0;
  }

  if (command === '--version' || command === '-V') {
    process.stdout.write(`${version}\n`);
    return 0;
  }

  if (command === 'audit') {
    return runAudit(rest, version);
  }

  process.stderr.write(`Unknown command: ${sanitizeReflectedArg(command)}\n\n`);
  process.stderr.write(TOP_LEVEL_HELP);
  return 2;
}

main(process.argv.slice(2))
  .then((exitCode) => {
    process.exitCode = exitCode;
  })
  .catch((error: unknown) => {
    const { message, exitCode } = reportInternalError(error);
    process.stderr.write(message);
    process.exitCode = exitCode;
  });
