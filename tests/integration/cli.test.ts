import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { test } from 'node:test';
import { ALL_SENTINEL_VALUES } from '../fixtures/sentinel-values.js';

const tsxBin = join(process.cwd(), 'node_modules', '.bin', 'tsx');
const cliEntry = join(process.cwd(), 'src', 'cli.ts');

interface CliResult {
  readonly stdout: string;
  readonly stderr: string;
  readonly status: number;
}

function runCli(args: readonly string[]): CliResult {
  const result = spawnSync(tsxBin, [cliEntry, ...args], { encoding: 'utf8' });
  return {
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    status: result.status ?? -1,
  };
}

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

test('audit --help prints audit-specific usage and exits 0', () => {
  const { stdout, status } = runCli(['audit', '--help']);
  assert.equal(status, 0);
  assert.match(stdout, /procseal audit/);
  assert.match(stdout, /--json/);
});

test('audit reports a not_implemented status without inspecting the machine, exit 0', () => {
  const { stdout, status } = runCli(['audit']);
  assert.equal(status, 0);
  assert.match(stdout, /not_implemented/);
});

test('audit --json produces parseable JSON with a not_implemented status and no findings', () => {
  const { stdout, status } = runCli(['audit', '--json']);
  assert.equal(status, 0);
  const parsed = JSON.parse(stdout) as { status: string; findings: unknown[] };
  assert.equal(parsed.status, 'not_implemented');
  assert.deepEqual(parsed.findings, []);
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

test('no CLI output ever contains a synthetic sentinel value', () => {
  const invocations: readonly (readonly string[])[] = [
    [],
    ['--help'],
    ['--version'],
    ['audit'],
    ['audit', '--json'],
    ['audit', '--help'],
    ['bogus-command'],
  ];

  for (const args of invocations) {
    const { stdout, stderr } = runCli(args);
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
