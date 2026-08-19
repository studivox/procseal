import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
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
 *   while bounding how much this adapter will ever read into memory. The
 *   bound is structural, not just a check: `readDotenvFile` allocates a
 *   single buffer of exactly `maxFileBytes + 1` bytes and never grows it,
 *   so no matter how large the underlying file is — or grows to be while
 *   being read — more than that many bytes can never be buffered. See
 *   `readBounded` below.
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

/** Default per-`readSync` chunk size for the bounded read loop — a small, fixed amount of work per call, not the whole file at once. */
const DEFAULT_READ_CHUNK_BYTES = 64 * 1024;

export interface ReadDotenvFileOptions {
  /** Path to the dotenv file. Read-only, never written, never watched, never mutated. */
  readonly path: string;
  /** The run's single `SecretRegistry`. Every successfully-parsed value — including an earlier, overwritten duplicate — is registered into it before anything else happens. */
  readonly registry: SecretRegistry;
  /** Shared with the PM2 adapter within one audit run, so `ObservedValue.equals()` compares values from both sides meaningfully. Defaults to a fresh one when used standalone. */
  readonly fingerprinter?: Fingerprinter;
  readonly limits?: Partial<DotenvFileLimits>;
  /**
   * Test-only instrumentation seam: invoked synchronously immediately
   * after every successful chunk read (a `readSync` call that returned
   * more than zero bytes), before the loop decides whether to continue.
   * Lets tests deterministically mutate the file underneath the
   * already-open descriptor — append, truncate, or rewrite in place —
   * between reads, with no real timing race and no background process.
   * See `tests/unit/dotenv-file.test.ts`. Production callers should never
   * need this.
   */
  readonly onChunkReadForTesting?: (bytesReadSoFar: number) => void;
  /**
   * Overrides the chunk size the bounded read loop uses per `readSync`
   * call. Defaults to `DEFAULT_READ_CHUNK_BYTES` (64 KiB). Exposed so
   * tests can force many small chunks — and therefore many
   * `onChunkReadForTesting` callbacks — even for a small file, and so a
   * "file keeps growing" test can observe the read loop's own bound
   * terminate the read regardless of how long the file keeps growing.
   */
  readonly readChunkBytesForTesting?: number;
}

function buildError(code: DotenvFileErrorCode, detail?: string): DotenvFileError {
  return detail ? { code, detail: toSafeLabelOrRedacted(detail) } : { code };
}

function fail(code: DotenvFileErrorCode, detail?: string): DotenvFileResult {
  return { ok: false, error: buildError(code, detail) };
}

/**
 * The five fields compared to detect a same-inode change between the
 * pre-read and post-read snapshots. `dev`/`ino` catch the pathological
 * case of comparing stats from two different files entirely (shouldn't
 * happen for two `fstat` calls on the same fd, but costs nothing to
 * assert); `size`, `mtimeNs`, and `ctimeNs` catch an append, a truncate,
 * or an in-place rewrite. `mtimeNs`/`ctimeNs` (not the coarser
 * second-resolution `mtime`/`ctime`) are what catch a same-size in-place
 * content change that an OS with fine-grained timestamps would otherwise
 * let slip past a size-only comparison.
 */
interface FdSnapshot {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly size: bigint;
  readonly mtimeNs: bigint;
  readonly ctimeNs: bigint;
}

interface FdSnapshotWithType extends FdSnapshot {
  readonly isFile: boolean;
}

function snapshotFd(fd: number): FdSnapshotWithType {
  const stats = fstatSync(fd, { bigint: true });
  return {
    dev: stats.dev,
    ino: stats.ino,
    size: stats.size,
    mtimeNs: stats.mtimeNs,
    ctimeNs: stats.ctimeNs,
    isFile: stats.isFile(),
  };
}

function snapshotsMatch(a: FdSnapshot, b: FdSnapshot): boolean {
  return (
    a.dev === b.dev &&
    a.ino === b.ino &&
    a.size === b.size &&
    a.mtimeNs === b.mtimeNs &&
    a.ctimeNs === b.ctimeNs
  );
}

type BoundedReadResult =
  | { readonly ok: true; readonly buffer: Buffer; readonly bytesRead: number }
  | { readonly ok: false; readonly error: DotenvFileError };

/**
 * Reads at most `maxFileBytes` bytes from `fd` — never more — into a
 * single fixed-size buffer, in chunks of `chunkBytes` at a time, via
 * `readSync` on the already-open, already-`O_NOFOLLOW`-validated
 * descriptor (never a second path-based open).
 *
 * The buffer is allocated once, at exactly `maxFileBytes + 1` bytes
 * (`+ 1` so that reading one byte past the limit is observable without
 * ever needing a larger allocation): however large the underlying file
 * is, or grows to be while this loop is running, this function can never
 * buffer more than that many bytes, and returns `env_file_too_large` the
 * moment the read would exceed it rather than continuing to read further.
 *
 * Handles short reads (a `readSync` call returning fewer bytes than
 * requested, without error — normal, expected behavior for `read(2)`, not
 * treated as EOF) by simply continuing the loop for the remainder, and
 * retries on `EINTR`/`EAGAIN` without losing any bytes already read.
 */
function readBounded(
  fd: number,
  maxFileBytes: number,
  chunkBytes: number,
  onChunkRead?: (bytesReadSoFar: number) => void,
): BoundedReadResult {
  const capacity = maxFileBytes + 1;
  const buffer = Buffer.allocUnsafe(capacity);
  let totalRead = 0;

  while (totalRead <= maxFileBytes) {
    const remaining = capacity - totalRead;
    const requestSize = Math.min(chunkBytes, remaining);

    let bytesRead: number;
    try {
      bytesRead = readSync(fd, buffer, totalRead, requestSize, null);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'EAGAIN' || code === 'EINTR') {
        continue;
      }
      return { ok: false, error: buildError('env_file_unreadable') };
    }

    if (bytesRead === 0) {
      break;
    }

    totalRead += bytesRead;
    onChunkRead?.(totalRead);
  }

  if (totalRead > maxFileBytes) {
    return {
      ok: false,
      error: buildError(
        'env_file_too_large',
        `at least ${totalRead} bytes read, limit ${maxFileBytes} bytes`,
      ),
    };
  }

  return { ok: true, buffer, bytesRead: totalRead };
}

/**
 * Reads exactly the explicitly supplied dotenv file — never auto-discovers
 * or reads any other path — and returns a normalized, non-sensitive
 * snapshot. Read-only: never writes, truncates, watches, or otherwise
 * mutates the file, and touches no other file, PM2 daemon, or process.
 *
 * Opens with `O_NOFOLLOW`, then only ever operates on the resulting file
 * descriptor (never a second path-based lookup):
 * - A symlink at `path` is rejected by the OS at `open()` time (`ELOOP`),
 *   race-free — there is no window between "check if it's a symlink" and
 *   "open it" for a symlink to be swapped in.
 * - Every subsequent operation (`fstat`, `read`) targets the exact inode
 *   that was opened, even if `path` is later unlinked or replaced by a
 *   *different* file on disk — a rename-based swap at the same path
 *   cannot affect an already-open descriptor.
 *
 * That second property is **descriptor-bound reading, not a guarantee
 * that the file's content is unchanged while being read** — the
 * underlying inode can still be modified in place (appended to,
 * truncated, or rewritten) by another process for as long as this
 * function holds it open, and nothing about opening via `O_NOFOLLOW`
 * prevents that. This function does not claim otherwise: it captures an
 * `fstat` snapshot before reading and another after, and fails closed
 * with `'env_file_changed_during_read'` if they differ in `dev`, `ino`,
 * `size`, `mtimeNs`, or `ctimeNs` — detecting the mutation and refusing
 * to trust whatever was read, rather than preventing the mutation from
 * happening at all.
 */
export function readDotenvFile(options: ReadDotenvFileOptions): DotenvFileResult {
  const limits: DotenvFileLimits = { ...DOTENV_FILE_LIMITS, ...options.limits };
  const fingerprinter = options.fingerprinter ?? createFingerprinter();
  const registry = options.registry;
  const chunkBytes = options.readChunkBytesForTesting ?? DEFAULT_READ_CHUNK_BYTES;

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
    let preReadStats: FdSnapshotWithType;
    try {
      preReadStats = snapshotFd(fd);
    } catch {
      return fail('env_file_unreadable');
    }

    if (!preReadStats.isFile) {
      return fail('env_file_not_regular', 'path is not a regular file');
    }

    if (preReadStats.size > BigInt(limits.maxFileBytes)) {
      return fail(
        'env_file_too_large',
        `${preReadStats.size} bytes, limit ${limits.maxFileBytes} bytes`,
      );
    }

    const readResult = readBounded(
      fd,
      limits.maxFileBytes,
      chunkBytes,
      options.onChunkReadForTesting,
    );
    if (!readResult.ok) {
      return { ok: false, error: readResult.error };
    }

    let postReadStats: FdSnapshot;
    try {
      postReadStats = snapshotFd(fd);
    } catch {
      return fail('env_file_unreadable');
    }

    if (!snapshotsMatch(preReadStats, postReadStats)) {
      return fail('env_file_changed_during_read');
    }

    const raw = readResult.buffer.subarray(0, readResult.bytesRead).toString('utf8');

    const parsed = parseDotenv(raw);

    // Every successfully-parsed value is registered before any diagnostic
    // or normalization is inspected, even on a path that is about to
    // fail — so a later diagnostic can never leak one of these values,
    // even indirectly. This includes every occurrence of a duplicate key,
    // not only the last one `parsed.values` keeps: an earlier, overwritten
    // value still appeared in the file and must not be assumed safe just
    // because a later line replaced it. Only values are registered here,
    // never keys: dotenv keys are already restricted to
    // `[A-Za-z_][A-Za-z0-9_]*` by the parser's own key pattern, so they
    // can never be secrets by construction — unlike the PM2 adapter's
    // payload, whose shape is not known ahead of time and so is
    // registered leaf-by-leaf regardless of position.
    for (const assignment of parsed.assignments) {
      registry.register(assignment.value);
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
