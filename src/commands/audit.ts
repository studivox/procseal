import { createSecretRegistry, type SecretRegistry } from '../core/output-safety.js';
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
  1  Internal error. A static message and a non-sensitive error code are
     printed; the original error message and stack are never shown.
  2  Usage error (unknown option).
`;

/**
 * Produces the placeholder audit result for this milestone. Deliberately
 * does not touch the filesystem, environment, or any process table — a real
 * PM2 adapter is a later milestone. This function must never claim that a
 * real audit occurred.
 *
 * `registry` is the run's single `SecretRegistry`, threaded through here
 * even though nothing is registered into it yet: this milestone parses no
 * real configuration, so there is nothing to register. Once the PM2
 * adapter exists, it registers every raw value it reads into this same
 * registry before a result is built, and this function's message
 * construction already runs through `registry.scrub()` — so wiring a real
 * adapter in only means populating the registry earlier, not restructuring
 * this call chain.
 */
export function runPlaceholderAudit(version: string, registry: SecretRegistry): AuditResult {
  const message = registry.scrub(
    'The PM2 live-process adapter is not implemented yet. procseal audit performed no machine inspection in this run.',
  );

  return {
    status: 'not_implemented',
    message,
    findings: [],
    meta: {
      tool: 'procseal',
      version,
      generatedAt: new Date().toISOString(),
    },
  };
}

/**
 * Creates exactly one run-scoped `SecretRegistry` and threads it through
 * result creation and whichever reporter renders the output, so both share
 * the same registry a future PM2 adapter will populate before this point.
 */
export function executeAuditCommand(
  options: AuditCommandOptions,
  version: string,
): AuditCommandResult {
  const registry = createSecretRegistry();
  const result = runPlaceholderAudit(version, registry);
  const output = options.json
    ? renderJsonReport(result, registry)
    : renderTerminalReport(result, registry);
  return { output, exitCode: 0 };
}
