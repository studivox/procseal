const REDACTED_PLACEHOLDER = '[REDACTED]';

/** The placeholder used everywhere a raw value must not appear. */
export function redactedPlaceholder(): string {
  return REDACTED_PLACEHOLDER;
}

/**
 * Replaces every exact occurrence of each known value in `text` with a
 * redaction placeholder. Used to sanitize free-text messages (e.g. thrown
 * errors) that might otherwise echo a raw configuration value.
 */
export function sanitizeMessage(text: string, knownValues: Iterable<string>): string {
  let sanitized = text;
  for (const value of knownValues) {
    if (value.length === 0) {
      continue;
    }
    sanitized = sanitized.split(value).join(REDACTED_PLACEHOLDER);
  }
  return sanitized;
}

/**
 * Produces a new Error whose message has known values redacted. A fresh
 * stack is generated rather than reusing the original, since some engines
 * embed argument values in stack traces.
 */
export function sanitizeError(error: unknown, knownValues: Iterable<string>): Error {
  const rawMessage = error instanceof Error ? error.message : String(error);
  const sanitized = new Error(sanitizeMessage(rawMessage, knownValues));
  sanitized.name = error instanceof Error ? error.name : 'Error';
  return sanitized;
}
