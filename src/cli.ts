#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AUDIT_HELP, executeAuditCommand } from './commands/audit.js';
import { reportInternalError } from './core/internal-error.js';

const moduleDir = dirname(fileURLToPath(import.meta.url));

const TOP_LEVEL_HELP = `procseal — local-first configuration and secret drift detector for PM2 processes.

Usage:
  procseal [--help] [--version]
  procseal audit [--json] [--help]

Status:
  pre-alpha. The PM2 live-process adapter is not implemented yet.
  "procseal audit" currently reports a "not_implemented" status and performs
  no machine inspection.

Exit codes:
  0  The command completed. For "audit", inspect the reported status field.
  1  Internal error. A static message and a non-sensitive error code are
     printed; the original error message and stack are never shown.
  2  Usage error (unknown command or invalid option).

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

function runAudit(rest: readonly string[], version: string): number {
  if (rest.includes('--help') || rest.includes('-h')) {
    process.stdout.write(AUDIT_HELP);
    return 0;
  }

  const allowedFlags = new Set(['--json']);
  const unknown = rest.find((arg) => !allowedFlags.has(arg));
  if (unknown !== undefined) {
    process.stderr.write(`Unknown option for "audit": ${unknown}\n\n`);
    process.stderr.write(AUDIT_HELP);
    return 2;
  }

  const json = rest.includes('--json');
  const { output, exitCode } = executeAuditCommand({ json }, version);
  process.stdout.write(`${output}\n`);
  return exitCode;
}

function main(argv: readonly string[]): number {
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

  process.stderr.write(`Unknown command: ${command}\n\n`);
  process.stderr.write(TOP_LEVEL_HELP);
  return 2;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  const { message, exitCode } = reportInternalError(error);
  process.stderr.write(message);
  process.exitCode = exitCode;
}
