const GENERIC_MESSAGE =
  'procseal encountered an internal error and stopped. No error details are shown here, because a caught exception could contain a raw configuration or secret value.';

/**
 * A short, pattern-validated class name is the only thing ever derived from
 * the original error. `error.message` and `error.stack` are never touched,
 * since either could embed a raw value (e.g. a file path with an
 * interpolated secret, or an engine that inlines argument values into a
 * stack trace).
 */
const SAFE_ERROR_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_]{0,39}$/;

export interface InternalErrorReport {
  readonly message: string;
  readonly exitCode: number;
}

function safeErrorCode(error: unknown): string {
  const rawName = error instanceof Error ? error.name : 'Error';
  const safeName = SAFE_ERROR_NAME_PATTERN.test(rawName) ? rawName : 'Error';
  return `E_INTERNAL_${safeName.toUpperCase()}`;
}

/**
 * Produces the safe, static, user-facing report for an unexpected top-level
 * error. This is intentionally not a redaction of the original message —
 * redaction only removes *known* values, and at the top level the set of
 * known values is never guaranteed to be complete. The only safe default is
 * to never print the original message or stack at all.
 */
export function reportInternalError(error: unknown): InternalErrorReport {
  return {
    message: `${GENERIC_MESSAGE} [code: ${safeErrorCode(error)}]\n`,
    exitCode: 1,
  };
}
