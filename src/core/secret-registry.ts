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
      // Longest-first, independent of registration order: if a shorter
      // registered value happens to be a prefix or suffix of a longer one
      // (e.g. "abc" and "abcdef"), scrubbing the shorter one first would
      // consume only part of the longer secret and leave the remainder
      // ("def") visible in the output. Sorting by length descending before
      // each scrub means the longest match always wins, regardless of the
      // order values were registered in.
      const longestFirst = [...knownValues].sort((a, b) => b.length - a.length);
      let scrubbed = text;
      for (const value of longestFirst) {
        scrubbed = scrubbed.split(value).join(redactedPlaceholder());
      }
      return scrubbed;
    },
  };
}
