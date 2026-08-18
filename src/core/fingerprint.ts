import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const KEY_BYTES = 32;
const KEY_ID_BYTES = 8;

/**
 * Fingerprint output is truncated for readable terminal/JSON output. This
 * truncation is a display convenience only. See docs/THREAT_MODEL.md — a
 * truncated fingerprint MUST NOT be treated as an authentication token, a
 * security boundary, or the equality primitive for rule PS004. Equality
 * comparisons must go through `equals()`, which uses the full digest.
 */
const DISPLAY_HEX_LENGTH = 16;

export interface Fingerprinter {
  /** Opaque, random label for this run. Safe to display; not derived from the key. */
  readonly keyId: string;
  /**
   * Truncated, human-readable HMAC-SHA-256 digest of `value`, for display
   * only. Two different values can — and eventually will — collide in this
   * truncated form; do not use it to decide whether two values are equal.
   */
  displayFingerprint(value: string): string;
  /**
   * The only supported way to compare two values for equality within a
   * run. Computes the full-length HMAC-SHA-256 digest of each value and
   * compares them with `timingSafeEqual`, never returning or exposing
   * either digest.
   */
  equals(left: string, right: string): boolean;
}

/**
 * Creates a fresh, random, in-memory-only HMAC key and returns a
 * fingerprinter bound to it. Never persist the key, nor any full digest it
 * produces; both are only meaningful for the lifetime of the current
 * process. Neither is ever returned by this module — only a truncated
 * display digest (`displayFingerprint`) or a boolean equality result
 * (`equals`) leave this closure.
 */
export function createFingerprinter(): Fingerprinter {
  const key = randomBytes(KEY_BYTES);
  const keyId = randomBytes(KEY_ID_BYTES).toString('hex');

  function fullDigest(value: string): Buffer {
    return createHmac('sha256', key).update(value, 'utf8').digest();
  }

  return {
    keyId,
    displayFingerprint(value: string): string {
      return fullDigest(value).toString('hex').slice(0, DISPLAY_HEX_LENGTH);
    },
    equals(left: string, right: string): boolean {
      const leftDigest = fullDigest(left);
      const rightDigest = fullDigest(right);
      return leftDigest.length === rightDigest.length && timingSafeEqual(leftDigest, rightDigest);
    },
  };
}
