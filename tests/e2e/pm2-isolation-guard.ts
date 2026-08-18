import { execFile } from 'node:child_process';
import { rmSync } from 'node:fs';
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
 */
export function assertSafeToCleanIsolatedPm2Home(params: CleanupSafetyParams): void {
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

export interface CleanupIsolatedPm2Params extends CleanupSafetyParams {
  readonly pm2Binary: string;
  readonly killRunner?: KillRunner;
}

/**
 * `pm2 kill` (or any deletion command) is only ever issued here, and only
 * after `assertSafeToCleanIsolatedPm2Home` passes. The temporary directory
 * is removed afterward regardless of whether `pm2 kill` itself succeeded,
 * so a daemon that already exited cleanly (or never fully started) still
 * gets its temp directory reclaimed.
 */
export async function cleanupIsolatedPm2(params: CleanupIsolatedPm2Params): Promise<void> {
  assertSafeToCleanIsolatedPm2Home(params);
  const killRunner = params.killRunner ?? execFileKillRunner;

  try {
    await killRunner(params.pm2Binary, { ...process.env, PM2_HOME: params.pm2Home! });
  } finally {
    rmSync(params.tempDir, { recursive: true, force: true });
  }
}
