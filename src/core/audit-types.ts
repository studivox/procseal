import type { DotenvFileErrorCode } from './dotenv-file-types.js';
import type { SafeLabel } from './label.js';
import type { Pm2AdapterErrorCode } from './pm2-types.js';
import type { Finding } from './types.js';

/**
 * Stable, non-sensitive error codes for selecting the single target PM2
 * process. Never renumbered or reused for a different meaning once
 * released, mirroring `Pm2AdapterErrorCode` and `DotenvFileErrorCode`.
 */
export type ProcessSelectionErrorCode =
  'process_name_invalid' | 'process_not_found' | 'process_ambiguous';

/**
 * Every stable error code an audit run can fail with: an invalid or
 * unmatched `--process` selection, a dotenv-file adapter failure, or a PM2
 * adapter failure. All three families are disjoint stable-string unions
 * defined in their own module — this type only combines them, so audit
 * orchestration code can handle "some operational failure happened"
 * without needing to know which subsystem it came from.
 */
export type AuditErrorCode = ProcessSelectionErrorCode | DotenvFileErrorCode | Pm2AdapterErrorCode;

export type AuditStatus = 'completed' | 'failed';

/**
 * The audited process's identity, safe to display and to serialize.
 * Present whenever the requested `--process` value at least passed syntax
 * validation, independent of whether the overall run succeeded — so a
 * `'failed'` result (e.g. `process_not_found`) can still say which
 * (validated) name was requested.
 */
export interface AuditSubject {
  readonly process: SafeLabel;
}

export interface AuditMeta {
  readonly tool: 'procseal';
  readonly version: string;
  readonly generatedAt: string;
}

/**
 * The result of one `procseal audit` run.
 *
 * `status: 'completed'` means the comparison actually ran — `findings` may
 * still be empty (a clean audit). `status: 'failed'` means an expected,
 * well-defined operational condition stopped the run before any
 * comparison happened (e.g. the dotenv file couldn't be read, or no PM2
 * process matched); `code` is always present in that case, `findings` is
 * always empty, and `message` is one of a fixed set of static strings
 * (see `commands/audit.ts`) — never anything derived from raw file or
 * process content. This is distinct from an *unexpected* internal error,
 * which never produces an `AuditResult` at all and is handled entirely by
 * `core/internal-error.ts` at the CLI's top level instead.
 */
export interface AuditResult {
  readonly status: AuditStatus;
  readonly message: string;
  /** Present only when `status === 'failed'`. */
  readonly code?: AuditErrorCode;
  /** Optional non-sensitive detail carried from the failing adapter's own error — see `Pm2AdapterError`/`DotenvFileError`. */
  readonly detail?: SafeLabel;
  readonly findings: readonly Finding[];
  readonly meta: AuditMeta;
  readonly subject?: AuditSubject;
}
