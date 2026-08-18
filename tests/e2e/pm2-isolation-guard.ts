import { execFile } from 'node:child_process';
import { readFileSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';

/**
 * This module exists only to make one operation — tearing down an isolated
 * test PM2 daemon — as hard as possible to get wrong. It is test-only
 * infrastructure (not part of the published package, not imported by
 * `src/`) but the safety property it enforces is the same one the whole
 * milestone is built around: this project must never touch the current
 * user's real PM2 daemon or real `PM2_HOME`. Every check below fails
 * closed (throws) rather than warns.
 */
export class UnsafeCleanupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsafeCleanupError';
  }
}

/**
 * Thrown when the safety guard passed but cleanup itself could not be
 * confirmed complete — either `pm2 kill` failed, or the isolated daemon's
 * own PID was still observably alive after a kill that reported success.
 * In both cases the temporary directory is deliberately left in place:
 * deleting `PM2_HOME` out from under a daemon process that might still be
 * running could corrupt its state on disk while the process itself keeps
 * running, unsupervised and un-tracked, in the background.
 */
export class CleanupIncompleteError extends Error {
  override readonly cause?: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'CleanupIncompleteError';
    this.cause = cause;
  }
}

/** The conventional real default, or whatever `PM2_HOME` was actually set to for this process. */
export function resolveRealPm2Home(): string {
  const fromEnv = process.env['PM2_HOME'];
  return resolve(fromEnv && fromEnv.trim().length > 0 ? fromEnv : join(homedir(), '.pm2'));
}

export interface CleanupSafetyParams {
  readonly pm2Home: string | undefined;
  readonly tempDir: string;
  readonly realPm2Home: string;
}

/**
 * Refuses (throws `UnsafeCleanupError`) unless `pm2Home` is unambiguously:
 * - present and non-empty,
 * - not equal to the real `PM2_HOME`,
 * - located inside `tempDir`, and
 * `tempDir` itself is unambiguously:
 * - located inside the OS temp directory (never the home directory, never
 *   the filesystem root, never a relative/empty path).
 *
 * On success, narrows `params.pm2Home` to `string` for the rest of the
 * caller's function — there is no code path past this call where
 * `pm2Home` is used without having been validated first.
 */
export function assertSafeToCleanIsolatedPm2Home(
  params: CleanupSafetyParams,
): asserts params is CleanupSafetyParams & { pm2Home: string } {
  const { pm2Home, tempDir, realPm2Home } = params;

  if (!tempDir || tempDir.trim().length === 0) {
    throw new UnsafeCleanupError('refusing cleanup: tempDir is absent or empty');
  }

  const resolvedTempDir = resolve(tempDir);
  const resolvedOsTmpDir = resolve(tmpdir());
  const resolvedHomeDir = resolve(homedir());

  const tempDirIsInsideOsTmp =
    resolvedTempDir === resolvedOsTmpDir || resolvedTempDir.startsWith(resolvedOsTmpDir + sep);
  if (!tempDirIsInsideOsTmp) {
    throw new UnsafeCleanupError(
      'refusing cleanup: tempDir is not inside the OS temporary directory',
    );
  }

  if (resolvedTempDir === resolvedHomeDir || resolvedHomeDir.startsWith(resolvedTempDir + sep)) {
    throw new UnsafeCleanupError(
      'refusing cleanup: tempDir contains or equals the real home directory',
    );
  }

  if (!pm2Home || pm2Home.trim().length === 0) {
    throw new UnsafeCleanupError('refusing cleanup: PM2_HOME is absent or empty');
  }

  const resolvedPm2Home = resolve(pm2Home);
  const resolvedRealPm2Home = resolve(realPm2Home);

  if (resolvedPm2Home === resolvedRealPm2Home) {
    throw new UnsafeCleanupError("refusing cleanup: PM2_HOME matches the user's real PM2_HOME");
  }

  const pm2HomeIsInsideTempDir =
    resolvedPm2Home === resolvedTempDir || resolvedPm2Home.startsWith(resolvedTempDir + sep);
  if (!pm2HomeIsInsideTempDir) {
    throw new UnsafeCleanupError(
      'refusing cleanup: PM2_HOME is not inside the test temporary directory',
    );
  }
}

/**
 * Injectable so the guard's unit tests can prove `pm2 kill` is never
 * invoked when the safety checks fail, without needing a real PM2 binary.
 * The only command this ever runs is `pm2 kill`, via `execFile` with
 * `shell: false` and a fixed argument array — never a broader process
 * search, `pkill`, `killall`, `sudo`, or a shell command string, and only
 * ever with the caller-supplied (already-guarded) `PM2_HOME`.
 */
export type KillRunner = (pm2Binary: string, env: NodeJS.ProcessEnv) => Promise<void>;

export const execFileKillRunner: KillRunner = (pm2Binary, env) =>
  new Promise<void>((resolvePromise, reject) => {
    execFile(pm2Binary, ['kill'], { shell: false, timeout: 10_000, env }, (error) => {
      if (error) {
        reject(error);
        return;
      }
      resolvePromise();
    });
  });

const PID_FILE_NAME = 'pm2.pid';

/**
 * Strict: only a plain, non-negative-looking, no-leading-zero decimal
 * integer with no surrounding junk (after trimming whitespace) is accepted
 * as a candidate PID. Anything else — empty, non-numeric, negative, a
 * leading zero, trailing garbage — is rejected outright.
 */
const STRICT_PID_PATTERN = /^[1-9][0-9]*$/;

/**
 * Reads and strictly parses the isolated daemon's own PID file. PM2 writes
 * its God-daemon PID as plain decimal text to `<PM2_HOME>/pm2.pid`
 * (`PM2_PID_FILE_PATH` in PM2's own `constants.js`, written by
 * `lib/Daemon.js`) and removes that file again on a graceful exit — which
 * is exactly why this must be called *before* `pm2 kill`, not after.
 *
 * Only ever reads this one fixed filename, joined onto the
 * already-validated `pm2Home` — never a wildcard search, never any other
 * path. Returns `undefined` (never throws) for anything that is missing,
 * unreadable, or does not parse as a strict positive integer distinct from
 * this process's own PID — including `"0"`, negative numbers, non-numeric
 * text, and `process.pid` itself, none of which this function will ever
 * hand back as a "safe to check" PID.
 */
export function readIsolatedDaemonPid(pm2Home: string): number | undefined {
  let raw: string;
  try {
    raw = readFileSync(join(pm2Home, PID_FILE_NAME), 'utf8');
  } catch {
    return undefined;
  }

  const trimmed = raw.trim();
  if (!STRICT_PID_PATTERN.test(trimmed)) {
    return undefined;
  }

  const pid = Number(trimmed);
  if (!Number.isSafeInteger(pid) || pid <= 0 || pid === process.pid) {
    return undefined;
  }

  return pid;
}

/**
 * Safe, non-destructive existence probe. Signal `0` performs the OS's
 * permission/existence checks without delivering any actual signal to the
 * target process — the standard way to ask "does this PID exist?" without
 * affecting it. This function accepts no signal parameter and provides no
 * way to send any signal other than `0`; it is not a general-purpose
 * "send a signal to a PID" primitive.
 *
 * `ESRCH` (no such process) is treated as confirmed-dead. Any other
 * outcome — the call succeeds, or fails with `EPERM` (process exists, no
 * permission to signal it) or anything else unexpected — is treated
 * conservatively as still-alive, since this function's only job is to
 * avoid a false "it's dead" answer.
 */
export function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

const DEFAULT_VERIFY_POLL_ATTEMPTS = 30;
const DEFAULT_VERIFY_POLL_INTERVAL_MS = 100;

function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

async function waitUntilProcessDead(
  pid: number,
  attempts: number,
  intervalMs: number,
): Promise<boolean> {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (!isProcessAlive(pid)) {
      return true;
    }
    await sleep(intervalMs);
  }
  return !isProcessAlive(pid);
}

export interface CleanupIsolatedPm2Params extends CleanupSafetyParams {
  readonly pm2Binary: string;
  readonly killRunner?: KillRunner;
  /** Test-only knobs to keep the verification poll fast in unit tests; production callers should leave these at their defaults. */
  readonly verifyPollAttempts?: number;
  readonly verifyPollIntervalMs?: number;
}

/**
 * `pm2 kill` (or any deletion command) is only ever issued here, and only
 * after `assertSafeToCleanIsolatedPm2Home` passes.
 *
 * Unlike an earlier version of this function, the temporary directory is
 * **not** removed unconditionally in a `finally` block. It is removed only
 * after:
 * 1. the safety guard passed,
 * 2. `pm2 kill` completed without throwing, and
 * 3. either there was no isolated daemon PID to check (nothing captured
 *    before step 2, e.g. the daemon had already exited), or that PID is
 *    confirmed no longer alive.
 *
 * If `pm2 kill` throws, or the daemon PID is still observably alive after
 * it returns, this function throws `CleanupIncompleteError` and leaves the
 * temporary directory — and whatever the daemon left on disk — in place,
 * rather than deleting it out from under a process that might still be
 * running.
 */
export async function cleanupIsolatedPm2(params: CleanupIsolatedPm2Params): Promise<void> {
  assertSafeToCleanIsolatedPm2Home(params);
  const killRunner = params.killRunner ?? execFileKillRunner;
  const pm2Home = params.pm2Home;

  // PM2 removes its own pidfile on a graceful exit (see
  // readIsolatedDaemonPid's docs), so this must be captured before kill
  // runs, not after.
  const daemonPid = readIsolatedDaemonPid(pm2Home);

  try {
    await killRunner(params.pm2Binary, { ...process.env, PM2_HOME: pm2Home });
  } catch (error) {
    throw new CleanupIncompleteError(
      'refusing to remove the isolated PM2_HOME: "pm2 kill" failed',
      error,
    );
  }

  if (daemonPid !== undefined) {
    const attempts = params.verifyPollAttempts ?? DEFAULT_VERIFY_POLL_ATTEMPTS;
    const intervalMs = params.verifyPollIntervalMs ?? DEFAULT_VERIFY_POLL_INTERVAL_MS;
    const confirmedDead = await waitUntilProcessDead(daemonPid, attempts, intervalMs);
    if (!confirmedDead) {
      throw new CleanupIncompleteError(
        'refusing to remove the isolated PM2_HOME: the daemon PID is still alive after "pm2 kill" reported success',
      );
    }
  }

  rmSync(params.tempDir, { recursive: true, force: true });
}
