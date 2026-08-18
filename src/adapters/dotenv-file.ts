import { closeSync, constants, fstatSync, openSync, readFileSync } from 'node:fs';
import { createFingerprinter, type Fingerprinter } from '../core/fingerprint.js';
import type {
  DotenvFileError,
  DotenvFileErrorCode,
  DotenvFileResult,
  DotenvVariable,
} from '../core/dotenv-file-types.js';
import { toSafeLabelOrRedacted, type SafeLabel } from '../core/label.js';
import { ObservedValue } from '../core/observed-value.js';
import { parseDotenv } from '../parsers/dotenv.js';
import type { SecretRegistry } from '../core/secret-registry.js';

export type {
  DotenvFileError,
  DotenvFileErrorCode,
  DotenvFileResult,
  DotenvSnapshot,
  DotenvSnapshotMeta,
  DotenvVariable,
} from '../core/dotenv-file-types.js';

/**
 * Hard limits, chosen for the same reasons documented on `PM2_LIMITS` in
 * src/adapters/pm2.ts: every limit here is a whole-read, fail-fast
 * boundary, never a silent truncate-and-continue.
 *
 * - `maxFileBytes` (1 MiB): comfortably larger than any real `.env` file
 *   while bounding how much this adapter will ever read into memory.
 *   Checked twice: against `fstat`'s reported size before reading, and
 *   again against the actual bytes read afterward (see `readDotenvFile`)
 *   — the second check is what protects against the file changing size
 *   between the two calls, not just a defensive-programming formality.
 * - `maxVariables` (500): far above any realistic `.env` file's variable
 *   count.
 * - `maxKeyLength` (120): dotenv keys are already restricted to
 *   `[A-Za-z_][A-Za-z0-9_]*` by `parsers/dotenv.ts`'s own key pattern, so
 *   this only bounds their length, matching `PM2_LIMITS.maxKeyLength`.
 * - `maxValueBytes` (8 KiB, measured with `Buffer.byteLength(value,
 *   'utf8')`, not JavaScript's `string.length`): matches
 *   `PM2_LIMITS.maxValueBytes` for the same reason — UTF-16 code-unit
 *   counts can meaningfully undercount a multibyte value's real UTF-8
 *   size.
 */
export interface DotenvFileLimits {
  readonly maxFileBytes: number;
  readonly maxVariables: number;
  readonly maxKeyLength: number;
  readonly maxValueBytes: number;
}

export const DOTENV_FILE_LIMITS: DotenvFileLimits = {
  maxFileBytes: 1024 * 1024,
  maxVariables: 500,
  maxKeyLength: 120,
  maxValueBytes: 8192,
};

export interface ReadDotenvFileOptions {
  /** Path to the dotenv file. Read-only, never written, never watched, never mutated. */
  readonly path: string;
  /** The run's single `SecretRegistry`. Every declared value is registered into it before anything else happens. */
  readonly registry: SecretRegistry;
  /** Shared with the PM2 adapter within one audit run, so `ObservedValue.equals()` compares values from both sides meaningfully. Defaults to a fresh one when used standalone. */
  readonly fingerprinter?: Fingerprinter;
  readonly limits?: Partial<DotenvFileLimits>;
}

function buildError(code: DotenvFileErrorCode, detail?: string): DotenvFileError {
  return detail ? { code, detail: toSafeLabelOrRedacted(detail) } : { code };
}

function fail(code: DotenvFileErrorCode, detail?: string): DotenvFileResult {
  return { ok: false, error: buildError(code, detail) };
}

/**
 * Reads exactly the explicitly supplied dotenv file — never auto-discovers
 * or reads any other path — and returns a normalized, non-sensitive
 * snapshot. Read-only: never writes, truncates, watches, or otherwise
 * mutates the file, and touches no other file, PM2 daemon, or process.
 *
 * Opens with `O_NOFOLLOW` and reads via the resulting file descriptor
 * (never a second path-based lookup), which gives this function two
 * safety properties without any extra bookkeeping:
 * - a symlink at `path` is rejected by the OS at `open()` time (`ELOOP`),
 *   race-free — there is no window between "check if it's a symlink" and
 *   "open it" for a symlink to be swapped in;
 * - once opened, every subsequent operation (`fstat`, `read`) targets the
 *   exact inode that was opened, even if `path` is later unlinked or
 *   replaced by something else on disk — the classic TOCTOU race a
 *   stat-by-path-then-read-by-path implementation would be exposed to
 *   simply cannot happen here, because nothing after `open()` looks the
 *   path up again.
 */
export function readDotenvFile(options: ReadDotenvFileOptions): DotenvFileResult {
  const limits: DotenvFileLimits = { ...DOTENV_FILE_LIMITS, ...options.limits };
  const fingerprinter = options.fingerprinter ?? createFingerprinter();
  const registry = options.registry;

  let fd: number;
  try {
    fd = openSync(options.path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      return fail('env_file_not_found');
    }
    if (code === 'ELOOP') {
      return fail('env_file_not_regular', 'path is a symlink');
    }
    return fail('env_file_unreadable');
  }

  try {
    let stats;
    try {
      stats = fstatSync(fd);
    } catch {
      return fail('env_file_unreadable');
    }

    if (!stats.isFile()) {
      return fail('env_file_not_regular', 'path is not a regular file');
    }

    if (stats.size > limits.maxFileBytes) {
      return fail('env_file_too_large', `${stats.size} bytes, limit ${limits.maxFileBytes} bytes`);
    }

    let raw: string;
    try {
      const buffer = readFileSync(fd);
      // Re-checked against the bytes actually read, not just the earlier
      // fstat size — this is what protects against the file growing
      // between the two calls, not a redundant formality.
      if (buffer.byteLength > limits.maxFileBytes) {
        return fail(
          'env_file_too_large',
          `${buffer.byteLength} bytes, limit ${limits.maxFileBytes} bytes`,
        );
      }
      raw = buffer.toString('utf8');
    } catch {
      return fail('env_file_unreadable');
    }

    const parsed = parseDotenv(raw);

    // Every declared raw value is registered before any diagnostic or
    // normalization is inspected, even on a path that is about to fail —
    // so a later diagnostic can never leak one of these values, even
    // indirectly. Only values are registered here, never keys: dotenv
    // keys are already restricted to `[A-Za-z_][A-Za-z0-9_]*` by the
    // parser's own key pattern, so they can never be secrets by
    // construction — unlike the PM2 adapter's payload, whose shape is not
    // known ahead of time and so is registered leaf-by-leaf regardless of
    // position.
    for (const value of parsed.values.values()) {
      registry.register(value);
    }

    if (parsed.diagnostics.length > 0) {
      const first = parsed.diagnostics[0]!;
      return fail('env_file_malformed', `line ${first.line}: ${first.reason}`);
    }

    if (parsed.duplicateKeys.length > 0) {
      return fail('env_file_duplicate_key', `${parsed.duplicateKeys.length} duplicate key(s)`);
    }

    if (parsed.values.size > limits.maxVariables) {
      return fail(
        'env_file_too_many_variables',
        `${parsed.values.size} variables, limit ${limits.maxVariables}`,
      );
    }

    const variables: DotenvVariable[] = [];
    for (const [key, value] of parsed.values) {
      if (key.length > limits.maxKeyLength) {
        return fail(
          'env_file_key_too_long',
          `key length ${key.length}, limit ${limits.maxKeyLength}`,
        );
      }

      const valueByteLength = Buffer.byteLength(value, 'utf8');
      if (valueByteLength > limits.maxValueBytes) {
        return fail(
          'env_file_value_too_long',
          `value length ${valueByteLength} bytes, limit ${limits.maxValueBytes} bytes`,
        );
      }

      const safeKey: SafeLabel = toSafeLabelOrRedacted(key);
      variables.push({
        name: safeKey,
        value: ObservedValue.from(value, fingerprinter, registry),
      });
    }

    return {
      ok: true,
      snapshot: {
        variables,
        meta: { variableCount: variables.length },
      },
    };
  } finally {
    closeSync(fd);
  }
}
