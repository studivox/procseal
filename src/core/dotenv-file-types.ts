import type { SafeLabel } from './label.js';
import type { ObservedValue } from './observed-value.js';

export interface DotenvVariable {
  /** The variable name, validated as a SafeLabel — see core/label.ts. */
  readonly name: SafeLabel;
  /** The variable's declared value, opaque — see core/observed-value.ts. */
  readonly value: ObservedValue;
}

export interface DotenvSnapshotMeta {
  readonly variableCount: number;
}

/**
 * The minimum structure the rule engine needs from one declared dotenv
 * file. Deliberately excludes the raw file content and any raw value —
 * only variable names (already safe, POSIX-identifier-shaped by
 * `parsers/dotenv.ts`'s own key pattern) and opaque values ever leave the
 * adapter.
 */
export interface DotenvSnapshot {
  readonly variables: readonly DotenvVariable[];
  readonly meta: DotenvSnapshotMeta;
}

/**
 * Stable, non-sensitive error codes. Never renumber or reuse one of these
 * for a different meaning once released — mirrors the same guarantee
 * documented for `Pm2AdapterErrorCode` in core/pm2-types.ts.
 *
 * `'env_file_too_many_variables'`, `'env_file_key_too_long'`, and
 * `'env_file_value_too_long'` are hard-limit codes (see
 * `DOTENV_FILE_LIMITS` in src/adapters/dotenv-file.ts): the whole read
 * fails fast rather than truncating and continuing, for the same reason
 * documented on the PM2 adapter's hard limits — a truncated secret
 * compared as if it were the whole value could produce a false equality
 * result.
 */
export type DotenvFileErrorCode =
  | 'env_file_not_found'
  | 'env_file_not_regular'
  | 'env_file_too_large'
  | 'env_file_unreadable'
  | 'env_file_malformed'
  | 'env_file_duplicate_key'
  | 'env_file_too_many_variables'
  | 'env_file_key_too_long'
  | 'env_file_value_too_long';

export interface DotenvFileError {
  readonly code: DotenvFileErrorCode;
  /**
   * Optional, non-sensitive detail — e.g. a line number and a diagnostic
   * reason, or a count and a limit. Never raw file content, never an
   * unvalidated string. Always built through `toSafeLabelOrRedacted` in
   * core/label.ts.
   */
  readonly detail?: SafeLabel;
}

export type DotenvFileResult =
  | { readonly ok: true; readonly snapshot: DotenvSnapshot }
  | { readonly ok: false; readonly error: DotenvFileError };
