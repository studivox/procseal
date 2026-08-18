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
