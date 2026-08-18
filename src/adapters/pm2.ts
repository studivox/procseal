import { createExecFileCommandRunner, type CommandRunner } from '../core/command-runner.js';
import { createFingerprinter, type Fingerprinter } from '../core/fingerprint.js';
import { toSafeLabelOrRedacted, type SafeLabel } from '../core/label.js';
import { ObservedValue } from '../core/observed-value.js';
import {
  PM2_STATUSES,
  type Pm2AdapterError,
  type Pm2AdapterErrorCode,
  type Pm2AdapterResult,
  type Pm2ProcessSnapshot,
  type Pm2Status,
} from '../core/pm2-types.js';
import type { SecretRegistry } from '../core/secret-registry.js';

export type {
  Pm2AdapterError,
  Pm2AdapterErrorCode,
  Pm2AdapterResult,
  Pm2EnvironmentVariable,
  Pm2ProcessSnapshot,
  Pm2Snapshot,
  Pm2SnapshotMeta,
  Pm2Status,
} from '../core/pm2-types.js';

/**
 * Hard limits, chosen to bound resource use and comparison correctness
 * against a hostile or corrupted `pm2 jlist` payload, not to reflect any
 * "typical" fleet size. Every limit is a whole-run, fail-fast boundary
 * (see `Pm2AdapterErrorCode` in core/pm2-types.ts) — none of them silently
 * truncates and continues, because a truncated secret compared or
 * fingerprinted as if it were the whole value can produce a false equality
 * result.
 *
 * - `maxProcesses` (200): far above any realistic single-host PM2 fleet;
 *   guards against a corrupted or hostile payload with an enormous array.
 * - `maxEnvVarsPerProcess` (300): generous for real applications (which
 *   rarely exceed a few dozen declared variables) while bounding per-record
 *   work.
 * - `maxKeyLength` (120): matches `core/label.ts`'s `SafeLabel` length cap
 *   exactly, so once a key passes this hard limit, `SafeLabel` character-set
 *   validation is the only remaining reason it could still be redacted —
 *   there is no separate, confusing "passed the hard limit but still always
 *   gets redacted anyway" gap between the two.
 * - `maxValueBytes` (8 KiB, measured with `Buffer.byteLength(value,
 *   'utf8')` — deliberately not JavaScript's `string.length`, which counts
 *   UTF-16 code units and can meaningfully undercount a multibyte-Unicode
 *   value's real UTF-8 size): comfortably above real secrets (JWTs,
 *   passwords, API keys, even multi-line PEM keys) while bounding memory
 *   and fingerprinting cost per value.
 * - `maxJsonPayloadBytes` (8 MiB): independently re-checked by this
 *   adapter against the raw stdout string (`Buffer.byteLength`), so an
 *   injected test runner that bypasses `execFile` entirely is still bound
 *   by the same limit. This is also passed as `execFile`'s `maxBuffer`
 *   option, but that is a weaker, *per-stream* backstop, not a combined
 *   one — see `core/command-runner.ts` for why this adapter's own check on
 *   stdout is the real enforcement of this limit, not `maxBuffer` itself.
 * - `commandTimeoutMs` (5000): `pm2 jlist` talks to a local Unix-domain
 *   socket and returns near-instantly on a healthy daemon; 5s is generous
 *   slack, not a realistic expected latency.
 */
export interface Pm2Limits {
  readonly maxProcesses: number;
  readonly maxEnvVarsPerProcess: number;
  readonly maxKeyLength: number;
  readonly maxValueBytes: number;
  readonly maxJsonPayloadBytes: number;
  readonly commandTimeoutMs: number;
}

export const PM2_LIMITS: Pm2Limits = {
  maxProcesses: 200,
  maxEnvVarsPerProcess: 300,
  maxKeyLength: 120,
  maxValueBytes: 8192,
  maxJsonPayloadBytes: 8 * 1024 * 1024,
  commandTimeoutMs: 5000,
};

/**
 * POSIX-conventional environment variable name shape. A key that doesn't
 * match this is not a hard-limit failure (see `PM2_LIMITS.maxKeyLength` for
 * the actual hard limit) — it's handled the same way an unsafe process name
 * is: retained as a redacted `SafeLabel`, not dropped and not fatal to the
 * run.
 */
const ENV_KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

export interface Pm2AdapterOptions {
  /** The run's single `SecretRegistry`. Every raw string leaf of the PM2 payload is registered into it before anything else happens. */
  readonly registry: SecretRegistry;
  /** Injectable command runner. Defaults to the real `execFile`-based runner. Tests inject a fixture runner instead of needing a real PM2 daemon. */
  readonly runner?: CommandRunner;
  /** Injectable fingerprinter, shared across every `ObservedValue` this call produces so `equals()` is meaningful between them. Defaults to a fresh one. */
  readonly fingerprinter?: Fingerprinter;
  /** Path or name of the PM2 binary to invoke. Defaults to `'pm2'` (resolved via `PATH`, never a shell). */
  readonly pm2Binary?: string;
  /**
   * Optional explicit environment for the child process. Omit to inherit
   * this process's environment (the current OS user's own PM2 daemon and
   * `PM2_HOME`). The isolated end-to-end test is the only caller that
   * overrides this, pointing it at a unique temporary `PM2_HOME` — never at
   * a real one. This adapter never escalates privileges and never invokes
   * `sudo`.
   */
  readonly env?: NodeJS.ProcessEnv;
  readonly limits?: Partial<Pm2Limits>;
}

function buildError(code: Pm2AdapterErrorCode, detail?: string): Pm2AdapterError {
  return detail ? { code, detail: toSafeLabelOrRedacted(detail) } : { code };
}

function fail(code: Pm2AdapterErrorCode, detail?: string): Pm2AdapterResult {
  return { ok: false, error: buildError(code, detail) };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Registers every string leaf of the parsed PM2 payload into the run's
 * `SecretRegistry`, before any normalization or reporting. `pm2 jlist` may
 * contain complete environment values and other sensitive strings (paths,
 * command lines) anywhere in its structure — this walk makes no assumption
 * about which fields are "the sensitive ones" and treats the entire
 * payload as sensitive, per docs/THREAT_MODEL.md.
 *
 * Iterative by design, using an explicit heap-allocated stack rather than
 * JS function-call recursion: Node's native `JSON.parse` can successfully
 * build structures far deeper than a handful of nested function calls
 * could traverse before throwing "Maximum call stack size exceeded" — a
 * naive recursive walker (or one with a depth cutoff that silently
 * `return`s past some limit) can therefore leave a string leaf
 * unregistered even though it was part of a *successfully parsed*
 * payload. An array used as a stack has no such ceiling; traversal depth
 * here is bounded only by available memory (and in practice by
 * `maxJsonPayloadBytes`, since expressing depth *D* of nesting requires at
 * least *2D* bytes of JSON text), never by the call stack. Every string
 * leaf is registered, at any depth, or the process throws before this
 * function returns — there is no code path that silently skips one.
 */
function registerAllStringLeaves(
  root: unknown,
  registry: SecretRegistry,
  excludeExactValue?: string,
): void {
  const stack: unknown[] = [root];

  while (stack.length > 0) {
    const value = stack.pop();

    if (typeof value === 'string') {
      if (value !== excludeExactValue) {
        registry.register(value);
      }
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        stack.push(item);
      }
      continue;
    }
    if (isPlainObject(value)) {
      for (const item of Object.values(value)) {
        stack.push(item);
      }
    }
  }
}

/**
 * Registers every string leaf of a *known-to-be-an-array* `jlist` payload,
 * the same way `registerAllStringLeaves` does — except for one narrow
 * exception per record: its own process name is never registered,
 * wherever it recurs within that record.
 *
 * This is not a weakening of "treat the entire payload as sensitive" — a
 * process *name* is exactly the field this adapter already normalizes
 * into `Pm2ProcessSnapshot.safeName` specifically so it CAN be displayed
 * (see `buildSafeName`, and the audit command's `subject.process`, and
 * `Finding` details throughout `src/rules/`, all of which are explicitly
 * allowed to carry validated process names). If the raw name string were
 * also registered as sensitive, `SecretRegistry.scrub` — which cannot
 * distinguish "this exact string is a raw secret" from "this exact string
 * is a name that was independently validated as safe to display" — would
 * redact that intentionally-public field everywhere it appears in output,
 * defeating the reason `safeName` exists at all.
 *
 * The exclusion is by *value*, not by field path: empirically, real PM2
 * duplicates a process's name into at least three places
 * (`record.name`, `pm2_env.name`, and `pm2_env.axm_options.module_name`),
 * and there is no guarantee that list is exhaustive across PM2 versions or
 * configurations (cluster mode, modules, ...). Comparing every string leaf
 * against the one known-safe raw name for *this* record — rather than
 * trying to enumerate every field PM2 might put it in — is robust to all
 * of those without needing to track PM2's internal layout. Every other
 * string value at any depth (`pm2_env.env` values, exec paths, monit
 * data, anything else) is still registered exactly as
 * `registerAllStringLeaves` would register it; only exact matches of the
 * record's own name are skipped, and only within that record.
 */
function registerJlistPayloadExceptOwnName(
  records: readonly unknown[],
  registry: SecretRegistry,
): void {
  for (const record of records) {
    if (!isPlainObject(record)) {
      registerAllStringLeaves(record, registry);
      continue;
    }
    const rawName = record['name'];
    const excludeExactValue =
      typeof rawName === 'string' && rawName.length > 0 ? rawName : undefined;
    registerAllStringLeaves(record, registry, excludeExactValue);
  }
}

function buildSafeProcessId(index: number): SafeLabel {
  return toSafeLabelOrRedacted(`proc-${index}`);
}

function buildSafeName(record: Record<string, unknown>, index: number): SafeLabel {
  const raw = record['name'];
  if (typeof raw === 'string' && raw.length > 0) {
    return toSafeLabelOrRedacted(raw);
  }
  return toSafeLabelOrRedacted(`process-${index}`);
}

function buildPm2Id(record: Record<string, unknown>): number | null {
  const raw = record['pm_id'];
  return typeof raw === 'number' && Number.isSafeInteger(raw) && raw >= 0 ? raw : null;
}

function buildStatus(record: Record<string, unknown>): Pm2Status {
  const pm2Env = record['pm2_env'];
  if (!isPlainObject(pm2Env)) {
    return 'unknown';
  }
  const status = pm2Env['status'];
  if (typeof status === 'string' && (PM2_STATUSES as readonly string[]).includes(status)) {
    return status as Pm2Status;
  }
  return 'unknown';
}

type EnvNormalizationResult =
  | {
      readonly ok: true;
      readonly value: readonly { readonly name: SafeLabel; readonly value: ObservedValue }[];
    }
  | { readonly ok: false; readonly error: Pm2AdapterError };

function normalizeEnvironment(
  record: Record<string, unknown>,
  index: number,
  limits: Pm2Limits,
  fingerprinter: Fingerprinter,
  registry: SecretRegistry,
): EnvNormalizationResult {
  const pm2Env = record['pm2_env'];
  const pm2EnvObject = isPlainObject(pm2Env) ? pm2Env : {};
  const envValue = pm2EnvObject['env'];
  const envObject = isPlainObject(envValue) ? envValue : {};
  const entries = Object.entries(envObject);

  if (entries.length > limits.maxEnvVarsPerProcess) {
    return {
      ok: false,
      error: buildError(
        'too_many_env_vars',
        `process ${index} has ${entries.length} vars, limit ${limits.maxEnvVarsPerProcess}`,
      ),
    };
  }

  const variables: { readonly name: SafeLabel; readonly value: ObservedValue }[] = [];

  for (const [key, rawValue] of entries) {
    if (key.length > limits.maxKeyLength) {
      return {
        ok: false,
        error: buildError(
          'key_too_long',
          `process ${index} key length ${key.length}, limit ${limits.maxKeyLength}`,
        ),
      };
    }

    const valueString = typeof rawValue === 'string' ? rawValue : safeStringifyEnvValue(rawValue);
    const valueByteLength = Buffer.byteLength(valueString, 'utf8');

    if (valueByteLength > limits.maxValueBytes) {
      return {
        ok: false,
        error: buildError(
          'value_too_long',
          `process ${index} value length ${valueByteLength} bytes, limit ${limits.maxValueBytes} bytes`,
        ),
      };
    }

    const safeKey = ENV_KEY_PATTERN.test(key)
      ? toSafeLabelOrRedacted(key)
      : toSafeLabelOrRedacted('');
    variables.push({
      name: safeKey,
      value: ObservedValue.from(valueString, fingerprinter, registry),
    });
  }

  return { ok: true, value: variables };
}

function safeStringifyEnvValue(value: unknown): string {
  if (value === null || value === undefined) {
    return '';
  }
  try {
    return JSON.stringify(value) ?? '';
  } catch {
    return '';
  }
}

/**
 * Reads the current OS user's PM2 process list through `pm2 jlist` and
 * returns a normalized, non-sensitive snapshot. Read-only: never restarts,
 * reloads, stops, deletes, saves, kills, or updates a PM2 process, and
 * never runs any PM2 subcommand other than `jlist`. Never uses `sudo`, a
 * shell command string, or `exec`/`spawn` with `shell: true` — see
 * `core/command-runner.ts`.
 */
export async function inspectPm2(options: Pm2AdapterOptions): Promise<Pm2AdapterResult> {
  const limits: Pm2Limits = { ...PM2_LIMITS, ...options.limits };
  const runner = options.runner ?? createExecFileCommandRunner();
  const fingerprinter = options.fingerprinter ?? createFingerprinter();
  const pm2Binary = options.pm2Binary ?? 'pm2';
  const registry = options.registry;

  const outcome = await runner(pm2Binary, ['jlist'], {
    timeoutMs: limits.commandTimeoutMs,
    maxBufferBytes: limits.maxJsonPayloadBytes,
    ...(options.env ? { env: options.env } : {}),
  });

  if (outcome.kind === 'binary-not-found') {
    return fail('binary_not_found');
  }
  if (outcome.kind === 'timeout') {
    return fail('timeout');
  }
  if (outcome.kind === 'output-too-large') {
    return fail('output_too_large');
  }
  if (outcome.kind === 'process-error') {
    return fail('daemon_unavailable');
  }

  const raw = outcome.stdout;

  if (Buffer.byteLength(raw, 'utf8') > limits.maxJsonPayloadBytes) {
    return fail('output_too_large');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return fail('invalid_json');
  }

  if (!Array.isArray(parsed)) {
    // The payload's shape is unknown here — there is no "record" to
    // reason about a name field within, so every string leaf is
    // registered indiscriminately, exactly as `registerAllStringLeaves`
    // always has.
    registerAllStringLeaves(parsed, registry);
    return fail('malformed_record');
  }

  // Every raw string leaf is registered before any normalization or
  // reporting happens, even on a path that is about to fail — so a later
  // diagnostic can never leak one of these values, even indirectly. Each
  // record's own name (wherever PM2 duplicates it) is the one deliberate
  // exception — see `registerJlistPayloadExceptOwnName`.
  registerJlistPayloadExceptOwnName(parsed, registry);

  if (parsed.length > limits.maxProcesses) {
    return fail('too_many_processes', `${parsed.length} processes, limit ${limits.maxProcesses}`);
  }

  const processes: Pm2ProcessSnapshot[] = [];
  let skippedRecordCount = 0;

  for (let index = 0; index < parsed.length; index += 1) {
    const record = parsed[index];
    if (!isPlainObject(record)) {
      skippedRecordCount += 1;
      continue;
    }

    const envResult = normalizeEnvironment(record, index, limits, fingerprinter, registry);
    if (!envResult.ok) {
      return { ok: false, error: envResult.error };
    }

    processes.push({
      safeProcessId: buildSafeProcessId(index),
      safeName: buildSafeName(record, index),
      pm2Id: buildPm2Id(record),
      status: buildStatus(record),
      environmentVariables: envResult.value,
    });
  }

  return {
    ok: true,
    snapshot: {
      processes,
      meta: {
        processCount: processes.length,
        skippedRecordCount,
      },
    },
  };
}
