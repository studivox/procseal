import type { SafeLabel } from './label.js';
import type { ObservedValue } from './observed-value.js';

/**
 * PM2's own process-status vocabulary. Anything outside this set — a typo,
 * a future PM2 version's new status, a forged value — normalizes to
 * `'unknown'` rather than being passed through or rejected. See
 * `normalizeStatus` in `src/adapters/pm2.ts`.
 */
export const PM2_STATUSES = [
  'online',
  'stopping',
  'stopped',
  'launching',
  'errored',
  'one-launch-status',
  'unknown',
] as const;

export type Pm2Status = (typeof PM2_STATUSES)[number];

export interface Pm2EnvironmentVariable {
  /** The variable name. Retained only after validation as a SafeLabel — see core/label.ts. */
  readonly name: SafeLabel;
  /** The variable's value, opaque — see core/observed-value.ts. */
  readonly value: ObservedValue;
  /**
   * Derived, non-sensitive PS004 eligibility flag — never a raw length or
   * the value itself. Computed once, at the adapter boundary, from the raw
   * key and value (`isReuseCandidate` in
   * `core/reuse-candidate-policy.ts`) before the value is wrapped in an
   * opaque `ObservedValue`; nothing downstream of the adapter ever sees
   * the raw value again. A conservative false-positive-reduction
   * heuristic, not proof a value is (or isn't) a secret — see
   * `core/reuse-candidate-policy.ts` for the exact policy and its
   * documented limitations.
   */
  readonly reuseCandidate: boolean;
}

/**
 * The minimum structure later rules need for one PM2-managed process.
 * Deliberately excludes the raw `pm2_env` object, the full command line,
 * raw node arguments, raw paths, and raw stdout/stderr log paths — none of
 * those are needed yet, and each is a potential secret/PII leak (a command
 * line can embed an inline credential; a log path can embed a username).
 * Add a field here only when a specific, later rule needs it, and only in
 * a form that has already been through a safety boundary (SafeLabel,
 * ObservedValue, or a validated enum/number).
 */
export interface Pm2ProcessSnapshot {
  /** Always present, safe, and unique within a snapshot — see buildSafeProcessId. */
  readonly safeProcessId: SafeLabel;
  /** The process's `name`, validated as a SafeLabel or replaced with the redaction placeholder. */
  readonly safeName: SafeLabel;
  /** PM2's own numeric process id, when it parses as a non-negative safe integer; otherwise `null`. */
  readonly pm2Id: number | null;
  readonly status: Pm2Status;
  readonly environmentVariables: readonly Pm2EnvironmentVariable[];
}

export interface Pm2SnapshotMeta {
  readonly processCount: number;
  /**
   * Number of top-level array entries that were not usable process records
   * at all (e.g. `null`, a string, a number) and were skipped rather than
   * failing the whole run. A JSON payload that isn't an array in the first
   * place is a harder failure — see `Pm2AdapterErrorCode` `'malformed_record'`.
   */
  readonly skippedRecordCount: number;
}

export interface Pm2Snapshot {
  readonly processes: readonly Pm2ProcessSnapshot[];
  readonly meta: Pm2SnapshotMeta;
}

/**
 * Stable, non-sensitive error codes. Never renumber or reuse one of these
 * for a different meaning once released, mirroring the stability guarantee
 * already documented for `RuleId` in core/types.ts.
 *
 * `'too_many_processes'`, `'too_many_env_vars'`, `'key_too_long'`, and
 * `'value_too_long'` are the hard-limit codes (see `PM2_LIMITS` in
 * src/adapters/pm2.ts): the whole run fails fast rather than silently
 * truncating and reporting on partial data. A truncated secret compared or
 * fingerprinted as if it were the whole value could produce a false
 * equality result (two different secrets sharing a long-enough common
 * prefix), so refusing is the safe default, not an oversight.
 */
export type Pm2AdapterErrorCode =
  | 'binary_not_found'
  | 'daemon_unavailable'
  | 'timeout'
  | 'output_too_large'
  | 'invalid_json'
  | 'malformed_record'
  | 'too_many_processes'
  | 'too_many_env_vars'
  | 'key_too_long'
  | 'value_too_long';

export interface Pm2AdapterError {
  readonly code: Pm2AdapterErrorCode;
  /**
   * Optional, non-sensitive detail — e.g. a count and a limit, or a
   * validated SafeLabel. Never raw stdout/stderr, never an unvalidated
   * string. See `toSafeLabelOrRedacted` in core/label.ts, which this is
   * always built through.
   */
  readonly detail?: SafeLabel;
}

export type Pm2AdapterResult =
  | { readonly ok: true; readonly snapshot: Pm2Snapshot }
  | { readonly ok: false; readonly error: Pm2AdapterError };
