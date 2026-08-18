import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createExecFileCommandRunner } from '../../src/core/command-runner.js';

const DEFAULT_OPTIONS = { timeoutMs: 5000, maxBufferBytes: 1024 * 1024 };

test('classifies a successful invocation and returns its stdout', async () => {
  const runner = createExecFileCommandRunner();
  const outcome = await runner(
    process.execPath,
    ['-e', "process.stdout.write('hello-from-child')"],
    DEFAULT_OPTIONS,
  );
  assert.deepEqual(outcome, { kind: 'success', stdout: 'hello-from-child' });
});

test('classifies a nonexistent binary as binary-not-found', async () => {
  const runner = createExecFileCommandRunner();
  const outcome = await runner(
    'procseal-definitely-not-a-real-binary-xyz',
    ['jlist'],
    DEFAULT_OPTIONS,
  );
  assert.deepEqual(outcome, { kind: 'binary-not-found' });
});

test('classifies a nonzero exit as process-error', async () => {
  const runner = createExecFileCommandRunner();
  const outcome = await runner(process.execPath, ['-e', 'process.exit(7)'], DEFAULT_OPTIONS);
  assert.deepEqual(outcome, { kind: 'process-error' });
});

test('classifies a timed-out command as timeout', async () => {
  const runner = createExecFileCommandRunner();
  const outcome = await runner(process.execPath, ['-e', 'setTimeout(() => {}, 5000)'], {
    timeoutMs: 200,
    maxBufferBytes: 1024 * 1024,
  });
  assert.deepEqual(outcome, { kind: 'timeout' });
});

test('classifies output exceeding maxBufferBytes as output-too-large', async () => {
  const runner = createExecFileCommandRunner();
  const outcome = await runner(
    process.execPath,
    ['-e', "process.stdout.write('x'.repeat(1_000_000))"],
    { timeoutMs: 5000, maxBufferBytes: 1024 },
  );
  assert.deepEqual(outcome, { kind: 'output-too-large' });
});

test('arguments are passed as a literal argv array, never interpreted by a shell', async () => {
  const runner = createExecFileCommandRunner();
  const hostileArg = '$(echo pwned); `echo also-pwned`; & | ; > /tmp/procseal-should-not-exist';
  const outcome = await runner(
    process.execPath,
    ['-e', 'process.stdout.write(process.argv[1])', hostileArg],
    DEFAULT_OPTIONS,
  );
  assert.equal(outcome.kind, 'success');
  assert.equal(outcome.kind === 'success' ? outcome.stdout : '', hostileArg);
});

test('an explicit env option is passed through to the child instead of silently ignored', async () => {
  const runner = createExecFileCommandRunner();
  const outcome = await runner(
    process.execPath,
    ['-e', 'process.stdout.write(process.env.PROCSEAL_TEST_MARKER ?? "")'],
    { ...DEFAULT_OPTIONS, env: { ...process.env, PROCSEAL_TEST_MARKER: 'marker-value' } },
  );
  assert.deepEqual(outcome, { kind: 'success', stdout: 'marker-value' });
});
