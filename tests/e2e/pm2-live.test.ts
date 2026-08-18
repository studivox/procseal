import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { inspect } from 'node:util';
import { inspectPm2, type Pm2AdapterResult } from '../../src/adapters/pm2.js';
import { createSecretRegistry } from '../../src/core/secret-registry.js';
import { cleanupIsolatedPm2, resolveRealPm2Home } from './pm2-isolation-guard.js';

/**
 * A real, isolated PM2 daemon test. This is the only test in the suite
 * that talks to an actual PM2 process manager — everything else injects a
 * fixture `CommandRunner` (see tests/integration/pm2-adapter.test.ts).
 *
 * Isolation: `PM2_HOME` is always a path inside a fresh `mkdtemp()`
 * directory, passed explicitly per-invocation (never written to the real
 * `process.env` of this test process). The devDependency-pinned PM2 binary
 * at `node_modules/.bin/pm2` is used, never a system-installed one. See
 * `pm2-isolation-guard.ts` for the guard that fails closed before any
 * cleanup command runs.
 */

const PM2_BINARY = join(process.cwd(), 'node_modules', '.bin', 'pm2');
const SENTINEL_ENV_VALUE = 'procseal-e2e-sentinel-3f9c2b71a0';
const APP_NAME = 'procseal-e2e-app';
const POLL_ATTEMPTS = 40;
const POLL_INTERVAL_MS = 250;

function runPm2Command(
  args: readonly string[],
  env: NodeJS.ProcessEnv,
): Promise<{ readonly stdout: string; readonly stderr: string }> {
  return new Promise((resolvePromise, reject) => {
    execFile(
      PM2_BINARY,
      args,
      { shell: false, timeout: 45_000, maxBuffer: 8 * 1024 * 1024, env },
      (error, stdout, stderr) => {
        if (error) {
          reject(error);
          return;
        }
        resolvePromise({ stdout, stderr });
      },
    );
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

test(
  'isolated real PM2 daemon: the adapter observes a started process and its env key, and the sentinel value never reaches any output',
  { timeout: 120_000 },
  async () => {
    assert.ok(
      existsSync(PM2_BINARY),
      `expected the devDependency-pinned pm2 binary at ${PM2_BINARY} — run "npm ci" first`,
    );

    const tempDir = mkdtempSync(join(tmpdir(), 'procseal-pm2-e2e-'));
    const pm2Home = join(tempDir, 'pm2home');
    const realPm2Home = resolveRealPm2Home();
    const appPath = join(tempDir, 'sentinel-app.js');
    writeFileSync(appPath, 'setInterval(() => {}, 60_000);\n', 'utf8');

    const queryEnv: NodeJS.ProcessEnv = { ...process.env, PM2_HOME: pm2Home };
    const startEnv: NodeJS.ProcessEnv = {
      ...process.env,
      PM2_HOME: pm2Home,
      PROCSEAL_E2E_SENTINEL: SENTINEL_ENV_VALUE,
    };

    try {
      await runPm2Command(['start', appPath, '--name', APP_NAME], startEnv);

      const registry = createSecretRegistry();
      let onlineProcess: Pm2AdapterResult | undefined;

      for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt += 1) {
        const result = await inspectPm2({ registry, pm2Binary: PM2_BINARY, env: queryEnv });
        assert.equal(
          result.ok,
          true,
          `adapter call against the isolated daemon failed: ${result.ok ? '' : result.error.code}`,
        );
        if (
          result.ok &&
          result.snapshot.processes.some((p) => p.safeName === APP_NAME && p.status === 'online')
        ) {
          onlineProcess = result;
          break;
        }
        await sleep(POLL_INTERVAL_MS);
      }

      assert.ok(
        onlineProcess && onlineProcess.ok,
        'expected the started process to appear online within the retry window',
      );
      const found = (
        onlineProcess as Extract<Pm2AdapterResult, { ok: true }>
      ).snapshot.processes.find((p) => p.safeName === APP_NAME);
      assert.ok(found, 'expected to find the started process by name in the snapshot');
      assert.equal(found!.status, 'online');

      const sentinelVar = found!.environmentVariables.find(
        (v) => v.name === 'PROCSEAL_E2E_SENTINEL',
      );
      assert.ok(
        sentinelVar,
        'expected PROCSEAL_E2E_SENTINEL to be observed as an environment variable name',
      );
      assert.equal(sentinelVar!.value.equalsPlain(SENTINEL_ENV_VALUE), true);
      assert.equal(sentinelVar!.value.equalsPlain('not-the-sentinel'), false);

      // The core claim of this test: the sentinel value never reaches any
      // serialization of the adapter's result, however it's inspected.
      const reFetched = await inspectPm2({ registry, pm2Binary: PM2_BINARY, env: queryEnv });
      const asJson = JSON.stringify(reFetched);
      const asInspected = inspect(reFetched, { depth: 10, showHidden: true });
      assert.equal(asJson.includes(SENTINEL_ENV_VALUE), false);
      assert.equal(asInspected.includes(SENTINEL_ENV_VALUE), false);

      // And the registry — populated by the adapter's recursive registration
      // of every raw string leaf in the live jlist payload — can scrub the
      // sentinel out of arbitrary text, proving it really was captured.
      assert.equal(
        registry.scrub(`leaked=${SENTINEL_ENV_VALUE}`).includes(SENTINEL_ENV_VALUE),
        false,
      );
    } finally {
      await cleanupIsolatedPm2({ pm2Home, tempDir, realPm2Home, pm2Binary: PM2_BINARY });
    }
  },
);
