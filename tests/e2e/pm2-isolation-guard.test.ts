import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import {
  assertSafeToCleanIsolatedPm2Home,
  cleanupIsolatedPm2,
  CleanupIncompleteError,
  isProcessAlive,
  readIsolatedDaemonPid,
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

/** Writes a pidfile at the location `readIsolatedDaemonPid` reads from. */
function writePidFile(pm2Home: string, content: string): void {
  mkdirSync(pm2Home, { recursive: true });
  writeFileSync(join(pm2Home, 'pm2.pid'), content, 'utf8');
}

/** Spawns a short-lived Node child process and resolves once it has fully exited. */
function spawnAndWaitForExit(): Promise<number> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, ['-e', 'process.exit(0)']);
    const pid = child.pid;
    if (pid === undefined) {
      reject(new Error('failed to spawn helper process'));
      return;
    }
    child.on('exit', () => resolvePromise(pid));
    child.on('error', reject);
  });
}

/** Spawns a long-lived Node child process that stays alive until killed. */
function spawnLongLived(): { readonly pid: number; kill: () => void } {
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 60_000);']);
  const pid = child.pid;
  if (pid === undefined) {
    throw new Error('failed to spawn helper process');
  }
  return { pid, kill: () => child.kill('SIGKILL') };
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

test('cleanupIsolatedPm2() invokes the kill runner with the isolated PM2_HOME and removes the tempDir on success (no pidfile to verify)', async () => {
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

test('cleanupIsolatedPm2() does NOT remove the tempDir when the kill runner fails, and reports a CleanupIncompleteError', async () => {
  const tempDir = makeTempDir();
  const pm2Home = join(tempDir, 'pm2home');
  // A marker file standing in for the daemon's real control files
  // (dump.pm2, pm2.pid, ...), to prove cleanup leaves them untouched.
  writePidFile(pm2Home, '424242');

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
    CleanupIncompleteError,
  );

  // The core regression this test guards against: a failed kill must never
  // be treated as though cleanup succeeded.
  assert.equal(existsSync(tempDir), true);
  assert.equal(existsSync(pm2Home), true);
  assert.equal(existsSync(join(pm2Home, 'pm2.pid')), true);
});

test('readIsolatedDaemonPid: strict parsing — malformed and unsafe pidfile contents', () => {
  const tempDir = makeTempDir();

  const cases: Record<string, string> = {
    zero: '0',
    negative: '-42',
    nonNumeric: 'not-a-pid',
    leadingZero: '007',
    floatingPoint: '123.45',
    withTrailingJunk: '123abc',
    empty: '',
    whitespaceOnly: '   ',
    ownProcessPid: String(process.pid),
  };

  for (const [label, content] of Object.entries(cases)) {
    const pm2Home = join(tempDir, `case-${label}`);
    writePidFile(pm2Home, content);
    const pid = readIsolatedDaemonPid(pm2Home);
    assert.equal(
      pid,
      undefined,
      `expected case "${label}" (content=${JSON.stringify(content)}) to be rejected`,
    );
  }
});

test('readIsolatedDaemonPid: missing pidfile and missing directory both return undefined without throwing', () => {
  const tempDir = makeTempDir();
  const missingDirPm2Home = join(tempDir, 'never-created');
  assert.doesNotThrow(() => readIsolatedDaemonPid(missingDirPm2Home));
  assert.equal(readIsolatedDaemonPid(missingDirPm2Home), undefined);

  const missingFilePm2Home = join(tempDir, 'dir-exists-no-pidfile');
  mkdirSync(missingFilePm2Home, { recursive: true });
  assert.equal(readIsolatedDaemonPid(missingFilePm2Home), undefined);
});

test('readIsolatedDaemonPid: accepts a well-formed positive integer, trimming surrounding whitespace', () => {
  const tempDir = makeTempDir();
  const pm2Home = join(tempDir, 'well-formed');
  writePidFile(pm2Home, '  424242  \n');
  assert.equal(readIsolatedDaemonPid(pm2Home), 424242);
});

test('readIsolatedDaemonPid only ever reads the fixed pm2.pid filename inside the given directory, never elsewhere', () => {
  const tempDir = makeTempDir();
  const pm2Home = join(tempDir, 'scoped');
  mkdirSync(pm2Home, { recursive: true });
  // A pidfile placed one level up (outside pm2Home) must never be read.
  writeFileSync(join(tempDir, 'pm2.pid'), '999', 'utf8');
  assert.equal(readIsolatedDaemonPid(pm2Home), undefined);
});

test('isProcessAlive() reports the current process as alive', () => {
  assert.equal(isProcessAlive(process.pid), true);
});

test('isProcessAlive() reports an implausible, definitely-unused PID as not alive', () => {
  // A PID this large will not exist on any real system.
  assert.equal(isProcessAlive(2 ** 30), false);
});

test('cleanupIsolatedPm2() proceeds and removes the tempDir when the pidfile is malformed (nothing unsafe was ever checked)', async () => {
  const tempDir = makeTempDir();
  const pm2Home = join(tempDir, 'pm2home');
  writePidFile(pm2Home, '0'); // rejected by readIsolatedDaemonPid -> no PID to verify

  await cleanupIsolatedPm2({
    pm2Home,
    tempDir,
    realPm2Home: REAL_PM2_HOME,
    pm2Binary: 'pm2',
    killRunner: async () => {
      /* simulate a successful "pm2 kill" */
    },
  });

  assert.equal(existsSync(tempDir), false);
});

test('cleanupIsolatedPm2() refuses to delete when the daemon PID is still alive after kill reports success', async (t) => {
  const tempDir = makeTempDir();
  const pm2Home = join(tempDir, 'pm2home');
  const helper = spawnLongLived();
  t.after(() => helper.kill());

  writePidFile(pm2Home, String(helper.pid));

  await assert.rejects(
    cleanupIsolatedPm2({
      pm2Home,
      tempDir,
      realPm2Home: REAL_PM2_HOME,
      pm2Binary: 'pm2',
      killRunner: async () => {
        /* simulates "pm2 kill" reporting success without actually killing the helper */
      },
      verifyPollAttempts: 3,
      verifyPollIntervalMs: 20,
    }),
    CleanupIncompleteError,
  );

  assert.equal(existsSync(tempDir), true);
  assert.equal(isProcessAlive(helper.pid), true);
});

test('cleanupIsolatedPm2() confirms a dead daemon PID and removes the tempDir (successful confirmed teardown)', async () => {
  const tempDir = makeTempDir();
  const pm2Home = join(tempDir, 'pm2home');
  const deadPid = await spawnAndWaitForExit();

  writePidFile(pm2Home, String(deadPid));

  await cleanupIsolatedPm2({
    pm2Home,
    tempDir,
    realPm2Home: REAL_PM2_HOME,
    pm2Binary: 'pm2',
    killRunner: async () => {
      /* the helper process is already dead; simulate "pm2 kill" success */
    },
    verifyPollAttempts: 3,
    verifyPollIntervalMs: 20,
  });

  assert.equal(existsSync(tempDir), false);
});
