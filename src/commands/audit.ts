import type { AuditResult } from '../core/types.js';
import { renderJsonReport } from '../reporters/json.js';
import { renderTerminalReport } from '../reporters/terminal.js';

export interface AuditCommandOptions {
  readonly json: boolean;
}

export interface AuditCommandResult {
  readonly output: string;
  readonly exitCode: number;
}

export const AUDIT_HELP = `procseal audit — compare declared configuration with the live process state.

Usage:
  procseal audit [--json] [--help]

Options:
  --json       Emit a machine-readable JSON report instead of terminal text.
  -h, --help   Show this help and exit.

Status:
  pre-alpha. The PM2 live-process adapter has not been implemented yet, so
  this command performs no machine inspection. It always reports a
  "not_implemented" status and produces zero findings.

Exit codes:
  0  The command ran successfully. Inspect the reported "status" field.
  1  Internal error (message is sanitized to avoid leaking configuration values).
  2  Usage error (unknown option).
`;

/**
 * Produces the placeholder audit result for this milestone. Deliberately
 * does not touch the filesystem, environment, or any process table — a real
 * PM2 adapter is a later milestone. This function must never claim that a
 * real audit occurred.
 */
export function runPlaceholderAudit(version: string): AuditResult {
  return {
    status: 'not_implemented',
    message:
      'The PM2 live-process adapter is not implemented yet. procseal audit performed no machine inspection in this run.',
    findings: [],
    meta: {
      tool: 'procseal',
      version,
      generatedAt: new Date().toISOString(),
    },
  };
}

export function executeAuditCommand(
  options: AuditCommandOptions,
  version: string,
): AuditCommandResult {
  const result = runPlaceholderAudit(version);
  const output = options.json ? renderJsonReport(result) : renderTerminalReport(result);
  return { output, exitCode: 0 };
}
