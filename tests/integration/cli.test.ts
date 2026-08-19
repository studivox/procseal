import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { ALL_SENTINEL_VALUES } from '../fixtures/sentinel-values.js';

const tsxBin = join(process.cwd(), 'node_modules', '.bin', 'tsx');
const cliEntry = join(process.cwd(), 'src', 'cli.ts');
const basicEnvFixture = join(process.cwd(), 'tests', 'fixtures', 'basic.env');

interface CliResult {
  readonly stdout: string;
  readonly stderr: string;
  readonly status: number;
}

function runCli(args: readonly string[], env?: NodeJS.ProcessEnv): CliResult {
  const result = spawnSync(tsxBin, [cliEntry, ...args], {
    encoding: 'utf8',
    env: env ?? process.env,
  });
  return {
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    status: result.status ?? -1,
  };
}

/**
 * A PATH that includes the currently-running Node's own directory (so
 * `tsx`'s `#!/usr/bin/env node` shebang keeps resolving) plus standard
 * system directories, but deliberately excludes `node_modules/.bin` —
 * where this project's devDependency-pinned `pm2` lives — and any other
 * project- or user-specific directory that might hold a real `pm2`
 * install. Every test below that could reach the PM2 adapter uses this,
 * so a spawned CLI subprocess can never find a real `pm2` binary and
 * therefore can never reach a real PM2 daemon or `PM2_HOME`, however that
 * daemon happens to be configured on the machine running these tests. See
 * docs/THREAT_MODEL.md.
 */
const PM2_UNREACHABLE_ENV: NodeJS.ProcessEnv = {
  ...process.env,
  PATH: [dirname(process.execPath), '/usr/bin', '/bin'].join(':'),
};

test('--help prints usage and exits 0', () => {
  const { stdout, status } = runCli(['--help']);
  assert.equal(status, 0);
  assert.match(stdout, /Usage:/);
  assert.match(stdout, /procseal audit/);
});

test('no arguments prints help and exits 0', () => {
  const { stdout, status } = runCli([]);
  assert.equal(status, 0);
  assert.match(stdout, /Usage:/);
});

test('--version prints a semver-like pre-release string and exits 0', () => {
  const { stdout, status } = runCli(['--version']);
  assert.equal(status, 0);
  assert.match(stdout.trim(), /^\d+\.\d+\.\d+/);
});

test('audit --help prints audit-specific usage, required options, implemented and deferred rules, and exit codes, exits 0', () => {
  const { stdout, status } = runCli(['audit', '--help']);
  assert.equal(status, 0);
  assert.match(stdout, /procseal audit/);
  assert.match(stdout, /--process/);
  assert.match(stdout, /--env/);
  assert.match(stdout, /--json/);
  assert.match(stdout, /--check-unexpected/);
  assert.match(stdout, /PS001/);
  assert.match(stdout, /PS002/);
  assert.match(stdout, /PS003/);
  assert.match(stdout, /PS005/);
  assert.match(stdout, /PS004/);
  assert.match(stdout, /PS006/);
  assert.match(stdout, /PS007/);
  assert.match(stdout, /PS008/);
  assert.match(stdout, /Exit codes:/);
});

test('audit with no options at all exits with usage error code 2 (both --process and --env are required)', () => {
  const { status, stderr } = runCli(['audit']);
  assert.equal(status, 2);
  assert.match(stderr, /--process/);
});

test('audit with only --process (missing --env) exits with usage error code 2', () => {
  const { status, stderr } = runCli(['audit', '--process', 'my-app']);
  assert.equal(status, 2);
  assert.match(stderr, /--env/);
});

test('audit with only --env (missing --process) exits with usage error code 2', () => {
  const { status, stderr } = runCli(['audit', '--env', basicEnvFixture]);
  assert.equal(status, 2);
  assert.match(stderr, /--process/);
});

test('audit --process with no value exits with usage error code 2', () => {
  const { status, stderr } = runCli(['audit', '--process']);
  assert.equal(status, 2);
  assert.match(stderr, /--process/);
});

test('audit --env with no value exits with usage error code 2', () => {
  const { status, stderr } = runCli(['audit', '--env']);
  assert.equal(status, 2);
  assert.match(stderr, /--env/);
});

test('audit with an invalid --process name exits 1 with a stable process_name_invalid code, never reaching PM2', () => {
  const { status, stdout } = runCli(
    ['audit', '--process', 'not a valid name!!', '--env', basicEnvFixture, '--json'],
    PM2_UNREACHABLE_ENV,
  );
  assert.equal(status, 1);
  const parsed = JSON.parse(stdout) as { status: string; code: string };
  assert.equal(parsed.status, 'failed');
  assert.equal(parsed.code, 'process_name_invalid');
});

test('audit with a nonexistent --env file exits 1 with a stable env_file_not_found code, never reaching PM2', () => {
  const { status, stdout } = runCli(
    ['audit', '--process', 'my-app', '--env', '/nonexistent/path/does-not-exist.env', '--json'],
    PM2_UNREACHABLE_ENV,
  );
  assert.equal(status, 1);
  const parsed = JSON.parse(stdout) as { status: string; code: string };
  assert.equal(parsed.status, 'failed');
  assert.equal(parsed.code, 'env_file_not_found');
});

test('audit exits 1 with a stable binary_not_found code when pm2 cannot be found on PATH', () => {
  const { status, stdout } = runCli(
    ['audit', '--process', 'my-app', '--env', basicEnvFixture, '--json'],
    PM2_UNREACHABLE_ENV,
  );
  assert.equal(status, 1);
  const parsed = JSON.parse(stdout) as { status: string; code: string; findings: unknown[] };
  assert.equal(parsed.status, 'failed');
  assert.equal(parsed.code, 'binary_not_found');
  assert.deepEqual(parsed.findings, []);
});

test('audit terminal output for a PM2-unreachable failure includes the status, code, and static message but no stack trace', () => {
  const { status, stdout } = runCli(
    ['audit', '--process', 'my-app', '--env', basicEnvFixture],
    PM2_UNREACHABLE_ENV,
  );
  assert.equal(status, 1);
  assert.match(stdout, /status: failed/);
  assert.match(stdout, /code: binary_not_found/);
  assert.equal(stdout.includes('    at '), false);
});

test('an unknown command exits with usage error code 2', () => {
  const { status, stderr } = runCli(['bogus-command']);
  assert.equal(status, 2);
  assert.match(stderr, /Unknown command/);
});

test('an unknown flag on audit exits with usage error code 2', () => {
  const { status, stderr } = runCli(['audit', '--not-a-real-flag']);
  assert.equal(status, 2);
  assert.match(stderr, /Unknown option/);
});

test('adversarial: a hostile unknown command with an embedded newline cannot forge a line in stderr', () => {
  const hostile = 'evil\nFAKE-LOG: fabricated line';
  const { status, stderr } = runCli([hostile]);
  assert.equal(status, 2);
  assert.equal(stderr.includes(hostile), false);
  assert.equal(stderr.includes('\nFAKE-LOG: fabricated line'), false);
  assert.match(stderr, /Unknown command:/);
});

test('adversarial: a hostile unknown command with ANSI escape sequences is neutralized in stderr', () => {
  const hostile = '\x1b[31mFAKE-RED\x1b[0m\x07';
  const { status, stderr } = runCli([hostile]);
  assert.equal(status, 2);
  assert.equal(stderr.includes('\x1b'), false);
  assert.equal(stderr.includes('\x07'), false);
});

test('adversarial: a hostile unknown audit option with an embedded newline cannot forge a line in stderr', () => {
  const hostile = '--evil\nFAKE-LOG: fabricated line';
  const { status, stderr } = runCli(['audit', hostile]);
  assert.equal(status, 2);
  assert.equal(stderr.includes(hostile), false);
  assert.equal(stderr.includes('\nFAKE-LOG: fabricated line'), false);
  assert.match(stderr, /Unknown option for "audit":/);
});

test('adversarial: a hostile unknown audit option with ANSI escape sequences is neutralized in stderr', () => {
  const hostile = '--\x1b[31mevil\x1b[0m';
  const { status, stderr } = runCli(['audit', hostile]);
  assert.equal(status, 2);
  assert.equal(stderr.includes('\x1b'), false);
});

test('adversarial: a hostile argument crafted to look like a stack trace cannot forge real newline-separated lines', () => {
  // sanitizeForDisplay neutralizes control characters (replacing them, not
  // deleting surrounding text), so the reflected text may still contain
  // this substring — the property under test is that it can never do so as
  // a genuine separate terminal line, because no real newline reaches
  // stderr. Confirmed here, and no Error object is ever constructed from
  // (and no .message/.stack read from) a CLI argument in the first place.
  const hostile = 'evil\nError: fake stack trace\n    at fabricated (file.js:1:1)';
  const { status, stderr } = runCli([hostile]);
  assert.equal(status, 2);
  assert.equal(stderr.includes('\n    at fabricated (file.js:1:1)'), false);
  const lines = stderr.split('\n');
  assert.equal(
    lines.some((line) => line.trim() === 'at fabricated (file.js:1:1)'),
    false,
  );
});

test('adversarial: a hostile --process value cannot forge output — rejected by strict syntax validation before it reaches anything else', () => {
  const hostile = 'evil\nFAKE-LOG: fabricated line\x1b[31m';
  const { status, stdout } = runCli(
    ['audit', '--process', hostile, '--env', basicEnvFixture, '--json'],
    PM2_UNREACHABLE_ENV,
  );
  assert.equal(status, 1);
  assert.equal(stdout.includes(hostile), false);
  assert.equal(stdout.includes('\n'), true); // JSON.stringify with indentation still has newlines — just never the raw hostile string
  const parsed = JSON.parse(stdout) as { code: string };
  assert.equal(parsed.code, 'process_name_invalid');
});

test('no CLI output ever contains a synthetic sentinel value', () => {
  const invocations: readonly (readonly string[])[] = [
    [],
    ['--help'],
    ['--version'],
    ['audit'],
    ['audit', '--help'],
    ['audit', '--process', 'my-app', '--env', basicEnvFixture, '--json'],
    ['bogus-command'],
  ];

  for (const args of invocations) {
    const { stdout, stderr } = runCli(args, PM2_UNREACHABLE_ENV);
    for (const sentinel of ALL_SENTINEL_VALUES) {
      assert.equal(
        stdout.includes(sentinel),
        false,
        `stdout for ${JSON.stringify(args)} leaked a sentinel value`,
      );
      assert.equal(
        stderr.includes(sentinel),
        false,
        `stderr for ${JSON.stringify(args)} leaked a sentinel value`,
      );
    }
  }
});
