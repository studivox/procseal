import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import {
  assertSafeToCleanIsolatedPm2Home,
  cleanupIsolatedPm2,
  resolveRealPm2Home,
  UnsafeCleanupError,
} from './pm2-isolation-guard.js';

const REAL_PM2_HOME = resolveRealPm2Home();

/**
 * These tests exercise pure guard logic against directories that are never
 * PM2_HOME for a real daemon, so they are safe to force-remove directly
 * here — this is ordinary test-scratch cleanup, not a use of
 * `cleanupIsolatedPm2` (several tests below specifically prove that
 * function refuses to delete anything, and must keep doing so).
 */
const createdDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'procseal-guard-test-'));
  createdDirs.push(dir);
  return dir;
}

after(() => {
  for (const dir of createdDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveRealPm2Home() falls back to the conventional ~/.pm2 default when PM2_HOME is unset', () => {
  assert.equal(REAL_PM2_HOME, join(homedir(), '.pm2'));
});

test('refuses when PM2_HOME is undefined', () => {
  const tempDir = makeTempDir();
  assert.throws(
    () =>
      assertSafeToCleanIsolatedPm2Home({ pm2Home: undefined, tempDir, realPm2Home: REAL_PM2_HOME }),
    UnsafeCleanupError,
  );
});

test('refuses when PM2_HOME is an empty string', () => {
  const tempDir = makeTempDir();
  assert.throws(
    () => assertSafeToCleanIsolatedPm2Home({ pm2Home: '', tempDir, realPm2Home: REAL_PM2_HOME }),
    UnsafeCleanupError,
  );
  assert.throws(
    () => assertSafeToCleanIsolatedPm2Home({ pm2Home: '   ', tempDir, realPm2Home: REAL_PM2_HOME }),
    UnsafeCleanupError,
  );
});

test('refuses when PM2_HOME equals the real PM2_HOME', () => {
  const tempDir = makeTempDir();
  assert.throws(
    () =>
      assertSafeToCleanIsolatedPm2Home({
        pm2Home: REAL_PM2_HOME,
        tempDir,
        realPm2Home: REAL_PM2_HOME,
      }),
    UnsafeCleanupError,
  );
});

test('refuses when PM2_HOME is not inside the test temporary directory', () => {
  const tempDir = makeTempDir();
  const otherDir = makeTempDir();
  assert.throws(
    () =>
      assertSafeToCleanIsolatedPm2Home({ pm2Home: otherDir, tempDir, realPm2Home: REAL_PM2_HOME }),
    UnsafeCleanupError,
  );
});

test('refuses when PM2_HOME is a sibling directory that merely shares a prefix with tempDir', () => {
  const tempDir = makeTempDir();
  const prefixSibling = `${tempDir}-evil-sibling`;
  assert.throws(
    () =>
      assertSafeToCleanIsolatedPm2Home({
        pm2Home: prefixSibling,
        tempDir,
        realPm2Home: REAL_PM2_HOME,
      }),
    UnsafeCleanupError,
  );
});

test('refuses when tempDir is not inside the OS temporary directory', () => {
  assert.throws(
    () =>
      assertSafeToCleanIsolatedPm2Home({
        pm2Home: join(homedir(), 'not-a-temp-dir', 'pm2home'),
        tempDir: join(homedir(), 'not-a-temp-dir'),
        realPm2Home: REAL_PM2_HOME,
      }),
    UnsafeCleanupError,
  );
});

test('refuses when tempDir is the real home directory', () => {
  assert.throws(
    () =>
      assertSafeToCleanIsolatedPm2Home({
        pm2Home: join(homedir(), '.pm2'),
        tempDir: homedir(),
        realPm2Home: REAL_PM2_HOME,
      }),
    UnsafeCleanupError,
  );
});

test('refuses when tempDir is empty', () => {
  assert.throws(
    () =>
      assertSafeToCleanIsolatedPm2Home({
        pm2Home: '/tmp/x/y',
        tempDir: '',
        realPm2Home: REAL_PM2_HOME,
      }),
    UnsafeCleanupError,
  );
});

test('accepts a PM2_HOME that is genuinely inside a genuine OS-temp tempDir', () => {
  const tempDir = makeTempDir();
  const pm2Home = join(tempDir, 'pm2home');
  assert.doesNotThrow(() =>
    assertSafeToCleanIsolatedPm2Home({ pm2Home, tempDir, realPm2Home: REAL_PM2_HOME }),
  );
});

test('cleanupIsolatedPm2() never invokes the kill runner when the safety check fails, and does not remove an unrelated directory', async () => {
  const tempDir = makeTempDir();
  const otherDir = makeTempDir();
  let killInvoked = false;

  await assert.rejects(
    cleanupIsolatedPm2({
      pm2Home: otherDir,
      tempDir,
      realPm2Home: REAL_PM2_HOME,
      pm2Binary: 'pm2',
      killRunner: async () => {
        killInvoked = true;
      },
    }),
    UnsafeCleanupError,
  );

  assert.equal(killInvoked, false);
  assert.equal(existsSync(tempDir), true);
  assert.equal(existsSync(otherDir), true);
});

test('cleanupIsolatedPm2() invokes the kill runner with the isolated PM2_HOME and removes the tempDir on success', async () => {
  const tempDir = makeTempDir();
  const pm2Home = join(tempDir, 'pm2home');
  let receivedEnv: NodeJS.ProcessEnv | undefined;

  await cleanupIsolatedPm2({
    pm2Home,
    tempDir,
    realPm2Home: REAL_PM2_HOME,
    pm2Binary: 'pm2',
    killRunner: async (_binary, env) => {
      receivedEnv = env;
    },
  });

  assert.equal(receivedEnv?.['PM2_HOME'], pm2Home);
  assert.equal(existsSync(tempDir), false);
});

test('cleanupIsolatedPm2() still removes the tempDir even if the kill runner throws', async () => {
  const tempDir = makeTempDir();
  const pm2Home = join(tempDir, 'pm2home');

  await assert.rejects(
    cleanupIsolatedPm2({
      pm2Home,
      tempDir,
      realPm2Home: REAL_PM2_HOME,
      pm2Binary: 'pm2',
      killRunner: async () => {
        throw new Error('simulated kill failure');
      },
    }),
  );

  assert.equal(existsSync(tempDir), false);
});
