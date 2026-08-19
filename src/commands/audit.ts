import { inspectPm2 } from '../adapters/pm2.js';
import { readDotenvFile } from '../adapters/dotenv-file.js';
import type { AuditErrorCode, AuditResult } from '../core/audit-types.js';
import { createFingerprinter } from '../core/fingerprint.js';
import { toSafeLabelOrRedacted, type SafeLabel } from '../core/label.js';
import { createSecretRegistry, type SecretRegistry } from '../core/output-safety.js';
import { isValidProcessNameSyntax, selectProcess } from '../core/process-selection.js';
import { renderJsonReport } from '../reporters/json.js';
import { renderTerminalReport } from '../reporters/terminal.js';
import { evaluateRules } from '../rules/engine.js';

export interface AuditCommandOptions {
  readonly processName: string;
  readonly envFilePath: string;
  readonly json: boolean;
  readonly checkUnexpected: boolean;
}

export interface AuditCommandResult {
  readonly output: string;
  readonly exitCode: number;
}

/**
 * The full argument surface `procseal audit` accepts. `--process` and
 * `--env` are both required and must each be given a value — there is no
 * auto-discovery of either. `--check-unexpected` opts into PS003, which is
 * otherwise never reported.
 */
export const AUDIT_HELP = `procseal audit — compare one declared dotenv file with one live PM2 process.

Usage:
  procseal audit --process <pm2-process-name> --env <path> [--json] [--check-unexpected]
  procseal audit --help

Options:
  --process <name>         Required. The exact PM2 process name to audit.
                           Must match exactly one running PM2 process.
  --env <path>             Required. Path to the dotenv file to compare
                           against that process's live environment.
  --json                   Emit a machine-readable JSON report instead of
                           terminal text.
  --check-unexpected       Also report PS003 (a live variable not
                           declared in the dotenv file). Off by default.
  -h, --help               Show this help and exit.

Both --process and --env must be given explicitly; procseal never
auto-discovers a process or a file to compare.

Implemented rules:
  PS001  Declared and live values differ (excluding PORT — see PS005)
  PS002  A declared variable is missing from the live process
  PS003  An unexpected live variable exists (only with --check-unexpected)
  PS005  Declared and live PORT values differ (replaces PS001 for PORT)

Deferred rules (defined as stable identifiers, not implemented here):
  PS004  Sensitive value reused across applications
  PS006  A deployment command is a dangerous, broad PM2 operation
  PS007  A configuration file appears to expose a plaintext secret
  PS008  Saved PM2 dump state differs from the live process set

Exit codes:
  0  The audit completed with zero findings.
  1  A safe operational or internal failure prevented the audit from
     completing (e.g. the process or file could not be found or read).
     A static message and a non-sensitive error code are printed; no raw
     file or process content is ever shown.
  2  Usage error (unknown/missing option).
  3  The audit completed with one or more findings.

Security:
  Read-only. Never mutates the dotenv file, PM2 state, process.env, or any
  process. Raw declared and live values are never printed, logged, or
  included in JSON output — only variable names, counts, and rule IDs.
`;

export type AuditArgsParseResult =
  | { readonly kind: 'help' }
  | { readonly kind: 'options'; readonly options: AuditCommandOptions }
  | { readonly kind: 'usage-error'; readonly reason: string; readonly offendingArg?: string };

/**
 * Parses `procseal audit`'s CLI arguments. Pure and side-effect-free, so it
 * is independently unit-testable without spawning the CLI. `reason`
 * strings here are always fixed, safe text; `offendingArg` (only present
 * for an unrecognized option) carries the raw attacker-controlled token so
 * the caller (`src/cli.ts`) can route it through the same output-safety
 * sanitizer every other reflected CLI argument goes through before it
 * reaches stderr.
 */
export function parseAuditArgs(rest: readonly string[]): AuditArgsParseResult {
  let processName: string | undefined;
  let envFilePath: string | undefined;
  let json = false;
  let checkUnexpected = false;

  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index]!;

    if (arg === '--help' || arg === '-h') {
      return { kind: 'help' };
    }
    if (arg === '--json') {
      json = true;
      continue;
    }
    if (arg === '--check-unexpected') {
      checkUnexpected = true;
      continue;
    }
    if (arg === '--process') {
      const value = rest[index + 1];
      if (value === undefined) {
        return { kind: 'usage-error', reason: 'Missing value for --process.' };
      }
      processName = value;
      index += 1;
      continue;
    }
    if (arg === '--env') {
      const value = rest[index + 1];
      if (value === undefined) {
        return { kind: 'usage-error', reason: 'Missing value for --env.' };
      }
      envFilePath = value;
      index += 1;
      continue;
    }
    return { kind: 'usage-error', reason: 'unknown option', offendingArg: arg };
  }

  if (processName === undefined) {
    return { kind: 'usage-error', reason: 'Missing required option: --process.' };
  }
  if (envFilePath === undefined) {
    return { kind: 'usage-error', reason: 'Missing required option: --env.' };
  }

  return {
    kind: 'options',
    options: { processName, envFilePath, json, checkUnexpected },
  };
}

/**
 * Static, fixed-vocabulary messages for every stable `AuditErrorCode`.
 * Never derived from raw file or process content — this is the same
 * "static message, stable code" contract `core/internal-error.ts` uses for
 * unexpected errors, applied here to the *expected* operational failures
 * an audit run can hit.
 */
const AUDIT_ERROR_MESSAGES: Readonly<Record<AuditErrorCode, string>> = {
  process_name_invalid: 'The requested process name is not a valid identifier.',
  process_not_found: 'No PM2 process matched the requested process name.',
  process_ambiguous: 'More than one PM2 process matched the requested process name.',
  env_file_not_found: 'The requested dotenv file does not exist.',
  env_file_not_regular:
    'The requested dotenv file is not a regular file (symlinks are not permitted).',
  env_file_too_large: 'The requested dotenv file exceeds the maximum allowed size.',
  env_file_changed_during_read: 'The requested dotenv file changed while it was being read.',
  env_file_unreadable: 'The requested dotenv file could not be read.',
  env_file_malformed: 'The requested dotenv file contains malformed content.',
  env_file_duplicate_key: 'The requested dotenv file declares the same variable more than once.',
  env_file_too_many_variables:
    'The requested dotenv file declares more variables than the allowed limit.',
  env_file_key_too_long:
    'The requested dotenv file declares a variable name longer than the allowed limit.',
  env_file_value_too_long:
    'The requested dotenv file declares a value larger than the allowed limit.',
  binary_not_found: 'The pm2 binary could not be found.',
  daemon_unavailable: 'The PM2 daemon is unavailable.',
  timeout: 'The PM2 command timed out.',
  output_too_large: 'The PM2 command produced more output than the allowed limit.',
  invalid_json: 'The PM2 command produced output that could not be parsed as JSON.',
  malformed_record: 'The PM2 command produced an unexpected payload shape.',
  too_many_processes: 'The PM2 daemon reported more processes than the allowed limit.',
  too_many_env_vars:
    'A PM2-managed process declares more environment variables than the allowed limit.',
  key_too_long: 'A PM2-managed process declares a variable name longer than the allowed limit.',
  value_too_long: 'A PM2-managed process declares a value larger than the allowed limit.',
};

function buildMeta(version: string) {
  return {
    tool: 'procseal' as const,
    version,
    generatedAt: new Date().toISOString(),
  };
}

function buildFailedResult(
  code: AuditErrorCode,
  version: string,
  subjectProcess?: SafeLabel,
  detail?: SafeLabel,
): AuditResult {
  return {
    status: 'failed',
    message: AUDIT_ERROR_MESSAGES[code],
    code,
    ...(detail ? { detail } : {}),
    findings: [],
    meta: buildMeta(version),
    ...(subjectProcess ? { subject: { process: subjectProcess } } : {}),
  };
}

function buildCompletedMessage(findingCount: number): string {
  return findingCount === 0
    ? 'Audit completed. No findings.'
    : `Audit completed. ${findingCount} finding(s).`;
}

export interface AuditPipelineDependencies {
  readonly inspectPm2: typeof inspectPm2;
  readonly readDotenvFile: typeof readDotenvFile;
}

/**
 * Runs one audit: validates the requested process name, reads the
 * declared dotenv file, inspects the live PM2 process list, selects
 * exactly one matching process, and compares. Each step can fail with its
 * own stable `AuditErrorCode`; the pipeline stops at the first failure and
 * never proceeds to a later step (in particular, an invalid process name
 * or a broken dotenv file is caught *before* `inspectPm2` is ever called,
 * so those failure modes never touch PM2 at all).
 *
 * `registry` and `fingerprinter` are both shared across the dotenv-file
 * adapter and the PM2 adapter for this one call, so declared and live
 * `ObservedValue`s are always compared through the same run-scoped HMAC
 * key, and so a raw value from either source is scrubbable from any
 * output this run produces.
 */
export async function runAuditPipeline(
  options: AuditCommandOptions,
  version: string,
  registry: SecretRegistry,
  deps: AuditPipelineDependencies,
): Promise<AuditResult> {
  const fingerprinter = createFingerprinter();

  if (!isValidProcessNameSyntax(options.processName)) {
    return buildFailedResult('process_name_invalid', version);
  }

  // The requested name passed strict syntax validation above, so it is
  // already a safe label — every failure branch from here on can safely
  // echo it back as the audit's subject, even though the run didn't
  // complete.
  const requestedProcessLabel = toSafeLabelOrRedacted(options.processName);

  const dotenvResult = deps.readDotenvFile({
    path: options.envFilePath,
    registry,
    fingerprinter,
  });
  if (!dotenvResult.ok) {
    return buildFailedResult(
      dotenvResult.error.code,
      version,
      requestedProcessLabel,
      dotenvResult.error.detail,
    );
  }

  const pm2Result = await deps.inspectPm2({ registry, fingerprinter });
  if (!pm2Result.ok) {
    return buildFailedResult(
      pm2Result.error.code,
      version,
      requestedProcessLabel,
      pm2Result.error.detail,
    );
  }

  const selection = selectProcess(pm2Result.snapshot, options.processName);
  if (!selection.ok) {
    return buildFailedResult(selection.code, version, requestedProcessLabel);
  }

  const findings = evaluateRules({
    declared: dotenvResult.snapshot,
    live: selection.process,
    checkUnexpected: options.checkUnexpected,
  });

  return {
    status: 'completed',
    message: buildCompletedMessage(findings.length),
    findings,
    meta: buildMeta(version),
    subject: { process: selection.process.safeName },
  };
}

function computeExitCode(result: AuditResult): number {
  if (result.status === 'failed') {
    return 1;
  }
  return result.findings.length > 0 ? 3 : 0;
}

/**
 * Creates exactly one run-scoped `SecretRegistry` and threads it, along
 * with one shared `Fingerprinter` (created inside `runAuditPipeline`),
 * through both adapters, rule evaluation, and whichever reporter renders
 * the output.
 */
export async function executeAuditCommand(
  options: AuditCommandOptions,
  version: string,
  deps: Partial<AuditPipelineDependencies> = {},
): Promise<AuditCommandResult> {
  const registry = createSecretRegistry();
  const result = await runAuditPipeline(options, version, registry, {
    inspectPm2: deps.inspectPm2 ?? inspectPm2,
    readDotenvFile: deps.readDotenvFile ?? readDotenvFile,
  });
  const output = options.json
    ? renderJsonReport(result, registry)
    : renderTerminalReport(result, registry);
  return { output, exitCode: computeExitCode(result) };
}
