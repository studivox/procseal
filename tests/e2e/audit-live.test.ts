import assert from 'node:assert/strict';
import { execFile, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { cleanupIsolatedPm2, resolveRealPm2Home } from './pm2-isolation-guard.js';

/**
 * The real, end-to-end `procseal audit` flow: a real (isolated) PM2 daemon,
 * a real temporary dotenv file, and the real CLI entry point spawned as a
 * subprocess — proving exit 0 (a clean audit) and exit 3 (findings) work
 * against an actual running process, not just the fixture-injected
 * pipeline exercised in tests/integration/audit-command.test.ts.
 *
 * Isolation is identical to tests/e2e/pm2-live.test.ts: `PM2_HOME` is
 * always a path inside a fresh `mkdtemp()` directory, and the
 * devDependency-pinned PM2 binary at `node_modules/.bin/pm2` is used —
 * never a system-installed one, never the real user's `PM2_HOME`. See
 * `pm2-isolation-guard.ts` for the guard that fails closed before any
 * cleanup command runs.
 */

const PM2_BINARY = join(process.cwd(), 'node_modules', '.bin', 'pm2');
const TSX_BINARY = join(process.cwd(), 'node_modules', '.bin', 'tsx');
const CLI_ENTRY = join(process.cwd(), 'src', 'cli.ts');
const PROJECT_BIN_DIR = join(process.cwd(), 'node_modules', '.bin');

const SENTINEL_API_KEY = 'procseal-audit-e2e-sentinel-api-key-8b2c';
const SENTINEL_JWT_SECRET = 'procseal-audit-e2e-sentinel-jwt-04f1';
const APP_NAME = 'procseal-audit-e2e-app';
const POLL_ATTEMPTS = 40;
const POLL_INTERVAL_MS = 250;

interface ExecResult {
  readonly stdout: string;
  readonly stderr: string;
  readonly status: number;
}

function run(
  command: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv,
): Promise<{ readonly stdout: string; readonly stderr: string }> {
  return new Promise((resolvePromise, reject) => {
    execFile(
      command,
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

function runCli(args: readonly string[], env: NodeJS.ProcessEnv): ExecResult {
  const result = spawnSync(TSX_BINARY, [CLI_ENTRY, ...args], {
    encoding: 'utf8',
    timeout: 45_000,
    maxBuffer: 8 * 1024 * 1024,
    env,
  });
  return {
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    status: result.status ?? -1,
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

test(
  'isolated real PM2 daemon + real dotenv file: procseal audit exits 0 on a clean match and exits 3 with findings on drift',
  { timeout: 120_000 },
  async () => {
    assert.ok(
      existsSync(PM2_BINARY),
      `expected the devDependency-pinned pm2 binary at ${PM2_BINARY} — run "npm ci" first`,
    );

    const tempDir = mkdtempSync(join(tmpdir(), 'procseal-audit-e2e-'));
    const pm2Home = join(tempDir, 'pm2home');
    const realPm2Home = resolveRealPm2Home();
    const appPath = join(tempDir, 'sentinel-app.js');
    writeFileSync(appPath, 'setInterval(() => {}, 60_000);\n', 'utf8');

    const pm2QueryEnv: NodeJS.ProcessEnv = { ...process.env, PM2_HOME: pm2Home };
    // Deliberately minimal, not `...process.env`: PM2 records whatever
    // environment is present at `pm2 start` time as the started process's
    // own live environment, and the adapter treats every one of those
    // values as sensitive (registering it for scrubbing). Inheriting the
    // full host environment would pull in unrelated short, common values
    // (shell state, tool flags, ...) that could coincidentally collide
    // with unrelated short substrings elsewhere in this test's own
    // assertions — a minimal, explicit environment keeps this test
    // deterministic and scoped to exactly the values it cares about.
    const pm2StartEnv: NodeJS.ProcessEnv = {
      PATH: process.env['PATH'],
      HOME: process.env['HOME'],
      PM2_HOME: pm2Home,
      API_KEY: SENTINEL_API_KEY,
      JWT_SECRET: SENTINEL_JWT_SECRET,
      PORT: '4000',
    };
    // The CLI subprocess must find *this project's* pm2 first, and must
    // only ever see the isolated PM2_HOME — never a real one.
    const cliEnv: NodeJS.ProcessEnv = {
      ...process.env,
      PATH: [PROJECT_BIN_DIR, process.env['PATH'] ?? ''].join(':'),
      PM2_HOME: pm2Home,
    };

    try {
      await run(PM2_BINARY, ['start', appPath, '--name', APP_NAME], pm2StartEnv);

      // Wait until the adapter's own view (via a throwaway jlist call)
      // shows the process online, so the audit itself isn't racing daemon
      // startup.
      let online = false;
      for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt += 1) {
        const { stdout } = await run(PM2_BINARY, ['jlist'], pm2QueryEnv);
        const parsed = JSON.parse(stdout) as ReadonlyArray<{
          name?: string;
          pm2_env?: { status?: string };
        }>;
        if (parsed.some((p) => p.name === APP_NAME && p.pm2_env?.status === 'online')) {
          online = true;
          break;
        }
        await sleep(POLL_INTERVAL_MS);
      }
      assert.ok(online, 'expected the started process to appear online within the retry window');

      // --- Scenario 1: a matching dotenv file -> exit 0, zero findings. ---
      const matchingEnvPath = join(tempDir, 'matching.env');
      writeFileSync(
        matchingEnvPath,
        `API_KEY=${SENTINEL_API_KEY}\nJWT_SECRET=${SENTINEL_JWT_SECRET}\nPORT=4000\n`,
        'utf8',
      );

      const cleanResult = runCli(
        ['audit', '--process', APP_NAME, '--env', matchingEnvPath, '--json'],
        cliEnv,
      );
      assert.equal(
        cleanResult.status,
        0,
        `expected exit 0, got ${cleanResult.status}: ${cleanResult.stdout}`,
      );
      const cleanParsed = JSON.parse(cleanResult.stdout) as {
        status: string;
        findings: readonly unknown[];
        subject: { process: string };
      };
      assert.equal(cleanParsed.status, 'completed');
      assert.deepEqual(cleanParsed.findings, []);
      assert.equal(cleanParsed.subject.process, APP_NAME);
      assert.equal(cleanResult.stdout.includes(SENTINEL_API_KEY), false);
      assert.equal(cleanResult.stdout.includes(SENTINEL_JWT_SECRET), false);

      // --- Scenario 2: drift -> exit 3, findings present, no secret leak. ---
      const driftedEnvPath = join(tempDir, 'drifted.env');
      writeFileSync(
        driftedEnvPath,
        `API_KEY=${SENTINEL_API_KEY}-DIFFERENT\nMISSING_ONLY_DECLARED=some-value\nPORT=5000\n`,
        'utf8',
      );

      const driftResult = runCli(
        ['audit', '--process', APP_NAME, '--env', driftedEnvPath, '--json', '--check-unexpected'],
        cliEnv,
      );
      assert.equal(
        driftResult.status,
        3,
        `expected exit 3, got ${driftResult.status}: ${driftResult.stdout}`,
      );
      const driftParsed = JSON.parse(driftResult.stdout) as {
        status: string;
        findings: ReadonlyArray<{ ruleId: string; details?: Readonly<Record<string, string>> }>;
      };
      assert.equal(driftParsed.status, 'completed');
      const ruleIds = driftParsed.findings.map((f) => f.ruleId);
      // API_KEY differs -> PS001; MISSING_ONLY_DECLARED absent live -> PS002;
      // PORT differs -> PS005; JWT_SECRET declared nowhere but live has it,
      // and --check-unexpected is set -> at least one PS003 (the live
      // process also inherited the test runner's own environment when
      // `pm2 start` ran, so other PS003 findings for unrelated inherited
      // variables are expected too — only presence of these four rule IDs
      // is asserted, not an exhaustive/exact finding set).
      assert.ok(ruleIds.includes('PS001'), `expected PS001 in ${JSON.stringify(ruleIds)}`);
      assert.ok(ruleIds.includes('PS002'), `expected PS002 in ${JSON.stringify(ruleIds)}`);
      assert.ok(ruleIds.includes('PS003'), `expected PS003 in ${JSON.stringify(ruleIds)}`);
      assert.ok(ruleIds.includes('PS005'), `expected PS005 in ${JSON.stringify(ruleIds)}`);
      assert.equal(driftResult.stdout.includes(SENTINEL_API_KEY), false);
      assert.equal(driftResult.stdout.includes(SENTINEL_JWT_SECRET), false);
      assert.equal(driftResult.stdout.includes('4000'), false);
      assert.equal(driftResult.stdout.includes('5000'), false);

      // Terminal (non-JSON) output for the same drifted scenario, checked
      // for the same absence of raw values.
      const driftTerminal = runCli(
        ['audit', '--process', APP_NAME, '--env', driftedEnvPath, '--check-unexpected'],
        cliEnv,
      );
      assert.equal(driftTerminal.status, 3);
      assert.equal(driftTerminal.stdout.includes(SENTINEL_API_KEY), false);
      assert.equal(driftTerminal.stdout.includes(SENTINEL_JWT_SECRET), false);
    } finally {
      await cleanupIsolatedPm2({ pm2Home, tempDir, realPm2Home, pm2Binary: PM2_BINARY });
    }
  },
);
