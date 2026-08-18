import { createHmac, randomBytes } from 'node:crypto';

const KEY_BYTES = 32;
const KEY_ID_BYTES = 8;

/**
 * Fingerprint output is truncated for readable terminal/JSON output. This
 * truncation is a display convenience only. See docs/THREAT_MODEL.md — a
 * truncated fingerprint MUST NOT be treated as an authentication token or a
 * security boundary, only as a same-run comparison hint.
 */
const TRUNCATED_HEX_LENGTH = 16;

export interface Fingerprinter {
  /** Opaque, random label for this run. Safe to display; not derived from the key. */
  readonly keyId: string;
  /**
   * Returns a keyed HMAC-SHA-256 fingerprint of `value`, truncated for display.
   * The same value fingerprints identically within one Fingerprinter instance
   * (one run) and differently across instances (different runs), because the
   * HMAC key is freshly randomized per instance and never persisted.
   */
  fingerprint(value: string): string;
}

/**
 * Creates a fresh, random, in-memory-only HMAC key and returns a
 * fingerprinter bound to it. Never persist the returned key or any
 * fingerprint it produces; both are only meaningful for the lifetime of the
 * current process.
 */
export function createFingerprinter(): Fingerprinter {
  const key = randomBytes(KEY_BYTES);
  const keyId = randomBytes(KEY_ID_BYTES).toString('hex');

  return {
    keyId,
    fingerprint(value: string): string {
      return createHmac('sha256', key)
        .update(value, 'utf8')
        .digest('hex')
        .slice(0, TRUNCATED_HEX_LENGTH);
    },
  };
}
