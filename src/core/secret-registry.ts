import { redactedPlaceholder } from './redaction.js';

/**
 * A run-scoped registry of raw values that must never appear in output.
 * This is the mechanism that lets `output-safety.ts` catch a raw value even
 * if it ends up somewhere reporters don't otherwise expect — e.g. smuggled
 * into a finding's metadata by a future adapter bug. It holds values only
 * in memory and is never persisted.
 */
export interface SecretRegistry {
  /** Registers a raw value that must be scrubbed from any future output. */
  register(value: string): void;
  /** Replaces every exact occurrence of a registered value with a redaction placeholder. */
  scrub(text: string): string;
}

export function createSecretRegistry(): SecretRegistry {
  const knownValues = new Set<string>();

  return {
    register(value: string): void {
      if (value.length > 0) {
        knownValues.add(value);
      }
    },
    scrub(text: string): string {
      let scrubbed = text;
      for (const value of knownValues) {
        scrubbed = scrubbed.split(value).join(redactedPlaceholder());
      }
      return scrubbed;
    },
  };
}
