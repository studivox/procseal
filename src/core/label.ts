import { redactedPlaceholder } from './redaction.js';

const MAX_LABEL_LENGTH = 120;

/**
 * Conservative allow-list for displayable identifiers such as rule keys,
 * variable names, and short metadata values: letters, digits, space, and a
 * small set of punctuation commonly seen in env var names, paths, and
 * versions. Deliberately excludes everything else, including control
 * characters and most punctuation, so this cannot itself become an
 * injection vector.
 */
const SAFE_LABEL_PATTERN = /^[A-Za-z0-9 _.:/#()+-]{1,120}$/;

/**
 * A string that has been validated against the conservative label
 * character set and length limit. The brand is a compile-time aid only —
 * it cannot be enforced across a JSON boundary or a type-unsafe caller, so
 * reporters must not treat "typed as SafeLabel" as a substitute for their
 * own runtime checks. See core/output-safety.ts.
 */
export type SafeLabel = string & { readonly __safeLabel: unique symbol };

export function isSafeLabel(value: string): value is SafeLabel {
  return (
    typeof value === 'string' && value.length <= MAX_LABEL_LENGTH && SAFE_LABEL_PATTERN.test(value)
  );
}

export class UnsafeLabelError extends Error {
  constructor() {
    super(`value is not a safe displayable label (must match ${SAFE_LABEL_PATTERN.source})`);
    this.name = 'UnsafeLabelError';
  }
}

/** Throws if `value` is not a safe label. Use for construction sites that should fail loudly. */
export function createSafeLabel(value: string): SafeLabel {
  if (!isSafeLabel(value)) {
    throw new UnsafeLabelError();
  }
  return value;
}

/**
 * Non-throwing variant: returns `value` unchanged (as a SafeLabel) when
 * safe, otherwise returns the redaction placeholder. Use in call sites that
 * must never throw on untrusted input, such as normalizing finding
 * metadata before it is stored.
 */
export function toSafeLabelOrRedacted(value: string): SafeLabel {
  return isSafeLabel(value) ? value : (redactedPlaceholder() as SafeLabel);
}
