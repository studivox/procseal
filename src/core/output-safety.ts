import { createSecretRegistry, type SecretRegistry } from './secret-registry.js';

export { createSecretRegistry };
export type { SecretRegistry };

const MAX_DISPLAY_LENGTH = 500;

/**
 * Printable ASCII only. Blocks control characters, newlines, and ANSI
 * escape sequences that could otherwise forge extra terminal lines or
 * manipulate a terminal's cursor/colors ("output injection"). Anything
 * outside this range is replaced with `?`, never dropped silently in a way
 * that could reassemble into something readable.
 */
const DISALLOWED_CHARACTERS = /[^\x20-\x7E]/g;

function safeStringify(value: unknown): string {
  if (typeof value === 'string') {
    return value;
  }
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return '[unserializable value]';
  }
}

/**
 * The final safety net every string-bearing output field must pass through
 * immediately before a reporter writes it. This function does not trust
 * that a value has already been validated upstream — TypeScript types are
 * erased at runtime, and a defensive boundary must assume a caller (e.g. a
 * future PM2 adapter) could hand it anything, including a raw secret or a
 * non-string structure. Non-string input is serialized first so a nested
 * object cannot bypass the registry scrub by hiding a raw value one level
 * down.
 */
export function sanitizeForDisplay(value: unknown, registry: SecretRegistry): string {
  const serialized = safeStringify(value);
  const scrubbed = registry.scrub(serialized);
  const asciiOnly = scrubbed.replace(DISALLOWED_CHARACTERS, '?');
  return asciiOnly.length > MAX_DISPLAY_LENGTH
    ? `${asciiOnly.slice(0, MAX_DISPLAY_LENGTH)}…[truncated]`
    : asciiOnly;
}
