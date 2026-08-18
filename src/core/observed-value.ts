import type { Fingerprinter } from './fingerprint.js';
import type { SecretRegistry } from './secret-registry.js';

/**
 * The only string this type ever exposes. Every serialization, coercion,
 * and inspection path below returns exactly this — never a value derived
 * from the raw string a caller is not otherwise given.
 */
const OPAQUE_MARKER = '[ObservedValue: opaque]';

const INSPECT_SYMBOL = Symbol.for('nodejs.util.inspect.custom');

/**
 * An opaque wrapper around a raw environment/process value that PM2 may
 * hand back complete (JWT secrets, database passwords, API keys — see
 * docs/THREAT_MODEL.md). The raw string lives only in a true JavaScript
 * private field (`#raw`), which — unlike a TypeScript-only brand — is
 * enforced by the engine at runtime: it is not an own enumerable property,
 * so `Object.keys`, `Object.getOwnPropertyNames`, `Reflect.ownKeys`,
 * `JSON.stringify` (absent a leaking `toJSON`), and `util.inspect` (absent
 * a leaking custom inspector) cannot reach it from outside the class body.
 *
 * There is deliberately no getter, no raw-returning `toString`/`valueOf`,
 * and no raw-returning serialization hook. The only operations exposed are
 * the ones a future rule (e.g. PS004 secret-reuse detection) or a reporter
 * legitimately needs: full-HMAC equality and a truncated display
 * fingerprint — both delegated to `core/fingerprint.ts`, which already
 * guarantees `equals()` never leaks a digest and `displayFingerprint()` is
 * truncated and display-only. This class adds no new comparison primitive;
 * it only wraps that existing one.
 */
export class ObservedValue {
  readonly #raw: string;
  readonly #fingerprinter: Fingerprinter;

  private constructor(raw: string, fingerprinter: Fingerprinter) {
    this.#raw = raw;
    this.#fingerprinter = fingerprinter;
  }

  /**
   * The only way to construct an ObservedValue. Registers `raw` in the
   * run's `SecretRegistry` before returning, so even a caller that never
   * calls another method on the result has already made this value
   * scrubbable everywhere `sanitizeForDisplay` runs — construction and
   * registration are not two steps a caller could forget to pair.
   */
  static from(raw: string, fingerprinter: Fingerprinter, registry: SecretRegistry): ObservedValue {
    registry.register(raw);
    return new ObservedValue(raw, fingerprinter);
  }

  /**
   * Full-HMAC equality against another ObservedValue. Meaningful only when
   * both values were produced with the same Fingerprinter (i.e., within the
   * same run) — see core/fingerprint.ts for why display fingerprints must
   * never be used for this instead.
   */
  equals(other: ObservedValue): boolean {
    return this.#fingerprinter.equals(this.#raw, other.#raw);
  }

  /**
   * Full-HMAC equality against a plain candidate string the caller already
   * holds by some other legitimate means (e.g. a value a future rule read
   * from a declared config file, or a test's own known sentinel constant).
   * This is documented, narrow, and intentional: `candidate` is supplied BY
   * the caller, never extracted FROM this ObservedValue, so this method
   * still cannot be used to recover `#raw` — it only ever returns a
   * boolean, exactly like `equals()`. Use `equals()` instead whenever both
   * sides are already ObservedValue instances.
   */
  equalsPlain(candidate: string): boolean {
    return this.#fingerprinter.equals(this.#raw, candidate);
  }

  /** Truncated, human-readable, display-only fingerprint. Never an equality primitive. */
  displayFingerprint(): string {
    return this.#fingerprinter.displayFingerprint(this.#raw);
  }

  /**
   * Intentionally opaque. Note that the default `Object.prototype.valueOf`
   * is left untouched (it returns `this`, not a primitive), so numeric/
   * string coercion (`${value}`, `String(value)`, `` `${value}` ``) falls
   * through to `toString()` below rather than exposing `#raw`.
   */
  toString(): string {
    return OPAQUE_MARKER;
  }

  /** Keeps `JSON.stringify` — directly or nested inside another object — opaque. */
  toJSON(): string {
    return OPAQUE_MARKER;
  }

  /** Keeps `util.inspect` and `console.log` opaque. */
  [INSPECT_SYMBOL](): string {
    return OPAQUE_MARKER;
  }
}
