/**
 * Centralized, conservative eligibility policy for PS004 (cross-application
 * sensitive-value reuse detection — see `src/rules/reuse.ts`).
 *
 * This is a **false-positive reduction heuristic, not proof that a value
 * is or is not a secret**: a variable name that doesn't match this policy
 * can still hold a real credential (a false negative — this policy does
 * not claim universal secret detection), and a variable name that does
 * match can still hold an intentionally shared, non-secret value. PS004
 * only ever compares two values when *both* sides of a potential match
 * pass this policy.
 *
 * Two independent conditions must both hold for a `{key, value}` pair to
 * be an eligible PS004 candidate:
 *
 * 1. `isSensitiveKeyName` — the key name, once uppercased and stripped of
 *    every non-alphanumeric character, contains one of a short,
 *    conservative list of explicit credential-terminology substrings
 *    (`SENSITIVE_KEY_SUBSTRINGS`). This intentionally excludes ordinary
 *    configuration keys (`PORT`, `NODE_ENV`, `LOG_LEVEL`, a plain
 *    `USERNAME`, ...) that would otherwise generate noisy, low-value
 *    findings. Normalizing before matching (rather than requiring an exact
 *    or word-boundary match) means `API_KEY`, `ApiKey`, and `apikey` are
 *    all recognized as the same underlying term without needing to
 *    enumerate every casing/separator convention separately.
 * 2. `meetsMinimumCandidateLength` — the value's UTF-8 byte length is at
 *    least `MIN_REUSE_CANDIDATE_VALUE_BYTES`, a conservative floor chosen
 *    to exclude common short, non-secret values (`true`, `production`,
 *    `8080`, `localhost`, `admin`, short placeholders like `changeme`)
 *    while still comfortably including realistic secrets (JWTs, database
 *    passwords, API keys, private keys — which are almost always longer).
 *
 * No entropy scoring, character-class analysis, or other statistical
 * heuristic is used, and this module never returns or logs a value's
 * actual length or content — only the boolean eligibility result. The
 * policy is deliberately simple and auditable at a glance, at the cost of
 * being unable to distinguish an intentionally-shared long non-secret
 * value (a false positive) from a genuine reused credential — see
 * docs/THREAT_MODEL.md for the full limitations discussion.
 */

/**
 * Conservative, explicit credential-terminology substrings, matched
 * against a key name after normalization (uppercased, non-alphanumeric
 * characters stripped). Deliberately short and explicit rather than broad
 * — e.g. no bare `KEY` or `ID`, which would match far too many ordinary
 * configuration keys (`API_VERSION_KEY... ` no — but `PUBLIC_KEY`,
 * `REQUEST_ID`, etc. would false-positive constantly).
 */
export const SENSITIVE_KEY_SUBSTRINGS = [
  'PASSWORD',
  'PASSWD',
  'SECRET',
  'TOKEN',
  'APIKEY',
  'PRIVATEKEY',
  'CLIENTSECRET',
  'ACCESSKEY',
  'AUTHKEY',
  'CREDENTIAL',
  'PASSPHRASE',
] as const;

/**
 * Conservative minimum UTF-8 byte length (see `Buffer.byteLength`, not
 * `string.length` — consistent with every other byte-based limit in this
 * codebase) a value must meet to be considered a PS004 candidate,
 * independent of key name.
 */
export const MIN_REUSE_CANDIDATE_VALUE_BYTES = 12;

function normalizeKeyForMatching(key: string): string {
  return key.toUpperCase().replace(/[^A-Z0-9]/g, '');
}

/** True when `key`'s name conservatively indicates a credential. */
export function isSensitiveKeyName(key: string): boolean {
  const normalized = normalizeKeyForMatching(key);
  return SENSITIVE_KEY_SUBSTRINGS.some((substring) => normalized.includes(substring));
}

/** True when `value`'s UTF-8 byte length meets the conservative floor. */
export function meetsMinimumCandidateLength(value: string): boolean {
  return Buffer.byteLength(value, 'utf8') >= MIN_REUSE_CANDIDATE_VALUE_BYTES;
}

/**
 * True when a `{key, value}` pair is eligible for PS004 comparison. Must
 * be computed where the raw value is still visible — the PM2 adapter's
 * environment-normalization step, before the value is wrapped in an
 * opaque `ObservedValue` — and the result stored only as a derived
 * boolean, never as a raw length or the value itself. See
 * `Pm2EnvironmentVariable.reuseCandidate` in `src/core/pm2-types.ts` and
 * `normalizeEnvironment` in `src/adapters/pm2.ts`.
 */
export function isReuseCandidate(key: string, value: string): boolean {
  return isSensitiveKeyName(key) && meetsMinimumCandidateLength(value);
}
