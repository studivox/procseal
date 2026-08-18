import assert from 'node:assert/strict';
import { test } from 'node:test';
import { inspectPm2 } from '../../src/adapters/pm2.js';
import { createFingerprinter } from '../../src/core/fingerprint.js';
import { createSecretRegistry } from '../../src/core/secret-registry.js';
import {
  fixtureRunner,
  pm2JlistEntry,
  rawStdoutRunner,
  stdoutRunner,
} from '../fixtures/pm2-jlist.js';
import {
  SENTINEL_API_KEY,
  SENTINEL_DB_PASSWORD,
  SENTINEL_JWT_SECRET,
} from '../fixtures/sentinel-values.js';

function assertOk<T extends { ok: boolean }>(result: T): asserts result is T & { ok: true } {
  assert.equal(result.ok, true);
}

function assertErr<T extends { ok: boolean }>(result: T): asserts result is T & { ok: false } {
  assert.equal(result.ok, false);
}

test('a valid pm2 jlist payload is normalized into a snapshot with an opaque, comparable env value', async () => {
  const registry = createSecretRegistry();
  const payload = [
    pm2JlistEntry({
      name: 'billing-api',
      pm_id: 3,
      status: 'online',
      env: { JWT_SECRET: SENTINEL_JWT_SECRET, PORT: '3000' },
    }),
  ];

  const result = await inspectPm2({ registry, runner: stdoutRunner(payload) });

  assertOk(result);
  assert.equal(result.snapshot.processes.length, 1);
  const proc = result.snapshot.processes[0]!;
  assert.equal(proc.safeName, 'billing-api');
  assert.equal(proc.pm2Id, 3);
  assert.equal(proc.status, 'online');
  assert.equal(proc.environmentVariables.length, 2);

  const jwtVar = proc.environmentVariables.find((entry) => entry.name === 'JWT_SECRET');
  assert.ok(jwtVar);
  assert.equal(jwtVar.value.equalsPlain(SENTINEL_JWT_SECRET), true);
  assert.equal(jwtVar.value.equalsPlain(SENTINEL_API_KEY), false);

  // The raw value must never appear anywhere in a serialized form of the result.
  assert.equal(JSON.stringify(result).includes(SENTINEL_JWT_SECRET), false);
});

test('no processes: an empty jlist array normalizes to an empty snapshot', async () => {
  const registry = createSecretRegistry();
  const result = await inspectPm2({ registry, runner: stdoutRunner([]) });
  assertOk(result);
  assert.deepEqual(result.snapshot.processes, []);
  assert.equal(result.snapshot.meta.processCount, 0);
});

test('multiple processes are all normalized with distinct safe process identifiers', async () => {
  const registry = createSecretRegistry();
  const payload = [
    pm2JlistEntry({ name: 'app-one', pm_id: 0 }),
    pm2JlistEntry({ name: 'app-two', pm_id: 1 }),
    pm2JlistEntry({ name: 'app-three', pm_id: 2 }),
  ];
  const result = await inspectPm2({ registry, runner: stdoutRunner(payload) });
  assertOk(result);
  assert.equal(result.snapshot.processes.length, 3);
  const ids = result.snapshot.processes.map((process) => process.safeProcessId);
  assert.equal(new Set(ids).size, 3);
});

test('missing process name: falls back to a stable, safe identifier instead of failing', async () => {
  const registry = createSecretRegistry();
  const record = pm2JlistEntry({ pm_id: 0 });
  delete record['name'];
  const result = await inspectPm2({ registry, runner: stdoutRunner([record]) });
  assertOk(result);
  assert.equal(result.snapshot.processes[0]!.safeName, 'process-0');
});

test('invalid PM2 id: a non-numeric or negative pm_id normalizes to null, not a thrown error', async () => {
  const registry = createSecretRegistry();
  const negative = pm2JlistEntry({ pm_id: -5 });
  const stringy = { ...pm2JlistEntry({}), pm_id: 'not-a-number' };

  const resultNegative = await inspectPm2({ registry, runner: stdoutRunner([negative]) });
  assertOk(resultNegative);
  assert.equal(resultNegative.snapshot.processes[0]!.pm2Id, null);

  const resultStringy = await inspectPm2({ registry, runner: stdoutRunner([stringy]) });
  assertOk(resultStringy);
  assert.equal(resultStringy.snapshot.processes[0]!.pm2Id, null);
});

test('invalid status: an unrecognized status string normalizes to "unknown"', async () => {
  const registry = createSecretRegistry();
  const record = pm2JlistEntry({ status: 'not-a-real-pm2-status' });
  const result = await inspectPm2({ registry, runner: stdoutRunner([record]) });
  assertOk(result);
  assert.equal(result.snapshot.processes[0]!.status, 'unknown');
});

test('duplicate environment keys in the raw JSON text collapse to the last value, matching JSON.parse semantics', async () => {
  const registry = createSecretRegistry();
  const raw = JSON.stringify([
    { name: 'dup-app', pm_id: 0, pm2_env: { status: 'online' } },
  ]).replace(
    '"pm2_env":{"status":"online"}',
    '"pm2_env":{"status":"online","env":{"FOO":"first","FOO":"second"}}',
  );

  const result = await inspectPm2({ registry, runner: rawStdoutRunner(raw) });
  assertOk(result);
  const vars = result.snapshot.processes[0]!.environmentVariables;
  assert.equal(vars.length, 1);
  assert.equal(vars[0]!.name, 'FOO');
  assert.equal(vars[0]!.value.equalsPlain('second'), true);
  assert.equal(vars[0]!.value.equalsPlain('first'), false);
});

test('missing environment object: pm2_env.env absent normalizes to zero environment variables', async () => {
  const registry = createSecretRegistry();
  const record = pm2JlistEntry({ omitEnv: true });
  const result = await inspectPm2({ registry, runner: stdoutRunner([record]) });
  assertOk(result);
  assert.deepEqual(result.snapshot.processes[0]!.environmentVariables, []);
});

test('missing pm2_env entirely: still normalizes with status "unknown" and no env vars', async () => {
  const registry = createSecretRegistry();
  const record = pm2JlistEntry({ omitPm2Env: true });
  const result = await inspectPm2({ registry, runner: stdoutRunner([record]) });
  assertOk(result);
  const proc = result.snapshot.processes[0]!;
  assert.equal(proc.status, 'unknown');
  assert.deepEqual(proc.environmentVariables, []);
});

test('invalid JSON: unparsable stdout produces a stable invalid_json error, not a thrown exception', async () => {
  const registry = createSecretRegistry();
  const result = await inspectPm2({ registry, runner: rawStdoutRunner('{not valid json') });
  assertErr(result);
  assert.equal(result.error.code, 'invalid_json');
});

test('timeout: a timed-out command produces a stable timeout error', async () => {
  const registry = createSecretRegistry();
  const result = await inspectPm2({ registry, runner: fixtureRunner({ kind: 'timeout' }) });
  assertErr(result);
  assert.equal(result.error.code, 'timeout');
});

test('binary missing: an absent pm2 binary produces a stable binary_not_found error', async () => {
  const registry = createSecretRegistry();
  const result = await inspectPm2({
    registry,
    runner: fixtureRunner({ kind: 'binary-not-found' }),
  });
  assertErr(result);
  assert.equal(result.error.code, 'binary_not_found');
});

test('daemon unavailable: a nonzero-exit invocation produces a stable daemon_unavailable error', async () => {
  const registry = createSecretRegistry();
  const result = await inspectPm2({ registry, runner: fixtureRunner({ kind: 'process-error' }) });
  assertErr(result);
  assert.equal(result.error.code, 'daemon_unavailable');
});

test('oversized stdout at the runner level produces a stable output_too_large error', async () => {
  const registry = createSecretRegistry();
  const result = await inspectPm2({
    registry,
    runner: fixtureRunner({ kind: 'output-too-large' }),
  });
  assertErr(result);
  assert.equal(result.error.code, 'output_too_large');
});

test("oversized stdout that slips past the runner is still caught by the adapter's own payload-size check", async () => {
  const registry = createSecretRegistry();
  const hugePayload = stdoutRunner([pm2JlistEntry({ env: { PAYLOAD: 'x'.repeat(2000) } })]);
  const result = await inspectPm2({
    registry,
    runner: hugePayload,
    limits: { maxJsonPayloadBytes: 100 },
  });
  assertErr(result);
  assert.equal(result.error.code, 'output_too_large');
});

test('excessive process count: exceeding maxProcesses fails fast with too_many_processes', async () => {
  const registry = createSecretRegistry();
  const payload = Array.from({ length: 5 }, (_unused, index) => pm2JlistEntry({ pm_id: index }));
  const result = await inspectPm2({
    registry,
    runner: stdoutRunner(payload),
    limits: { maxProcesses: 3 },
  });
  assertErr(result);
  assert.equal(result.error.code, 'too_many_processes');
});

test('excessive environment-variable count: exceeding maxEnvVarsPerProcess fails fast with too_many_env_vars', async () => {
  const registry = createSecretRegistry();
  const env: Record<string, string> = {};
  for (let index = 0; index < 10; index += 1) {
    env[`VAR_${index}`] = `value-${index}`;
  }
  const payload = [pm2JlistEntry({ env })];
  const result = await inspectPm2({
    registry,
    runner: stdoutRunner(payload),
    limits: { maxEnvVarsPerProcess: 5 },
  });
  assertErr(result);
  assert.equal(result.error.code, 'too_many_env_vars');
});

test('excessive key length fails fast with key_too_long', async () => {
  const registry = createSecretRegistry();
  const longKey = 'A'.repeat(50);
  const payload = [pm2JlistEntry({ env: { [longKey]: 'v' } })];
  const result = await inspectPm2({
    registry,
    runner: stdoutRunner(payload),
    limits: { maxKeyLength: 10 },
  });
  assertErr(result);
  assert.equal(result.error.code, 'key_too_long');
});

test('excessive value length fails fast with value_too_long, never truncating and comparing a partial value', async () => {
  const registry = createSecretRegistry();
  const payload = [pm2JlistEntry({ env: { SECRET: 'x'.repeat(50) } })];
  const result = await inspectPm2({
    registry,
    runner: stdoutRunner(payload),
    limits: { maxValueLength: 10 },
  });
  assertErr(result);
  assert.equal(result.error.code, 'value_too_long');
});

test('hostile process names containing newlines and ANSI escapes never reach the safe name field raw', async () => {
  const registry = createSecretRegistry();
  const hostileName = 'evil\nFAKE-LOG: fabricated line\x1b[31m';
  const payload = [pm2JlistEntry({ name: hostileName })];
  const result = await inspectPm2({ registry, runner: stdoutRunner(payload) });
  assertOk(result);
  const safeName = result.snapshot.processes[0]!.safeName;
  assert.equal(safeName.includes('\n'), false);
  assert.equal(safeName.includes('\x1b'), false);
  assert.equal(safeName, '[REDACTED]');
});

test('a raw secret present in stdout but not forming valid JSON never appears in the returned diagnostic', async () => {
  const registry = createSecretRegistry();
  const hostileStdout = `not json but leaks ${SENTINEL_DB_PASSWORD}`;
  const result = await inspectPm2({ registry, runner: rawStdoutRunner(hostileStdout) });
  assertErr(result);
  assert.equal(JSON.stringify(result).includes(SENTINEL_DB_PASSWORD), false);
});

test('a raw secret anywhere in the payload — even fields the snapshot never surfaces — is registered for scrubbing', async () => {
  const registry = createSecretRegistry();
  const record = pm2JlistEntry({ env: {} });
  // Simulate a raw field the normalized snapshot deliberately never exposes
  // (e.g. an execution path that happens to embed a credential-like value)
  // to prove the recursive registration walk covers the whole payload, not
  // just the fields the adapter's own normalization step reads. The
  // registry scrubs exact registered values, so the field is set to the
  // bare sentinel here — a value embedded inside a longer composite string
  // is registered as that whole string, not auto-decomposed into
  // substrings (see core/secret-registry.ts).
  record['pm_exec_path'] = SENTINEL_API_KEY;

  const result = await inspectPm2({ registry, runner: stdoutRunner([record]) });
  assertOk(result);
  assert.equal(JSON.stringify(result).includes(SENTINEL_API_KEY), false);

  const scrubbed = registry.scrub(`leaked path token=${SENTINEL_API_KEY}`);
  assert.equal(scrubbed.includes(SENTINEL_API_KEY), false);
});

test('malformed top-level payload (not an array) fails fast with malformed_record', async () => {
  const registry = createSecretRegistry();
  const result = await inspectPm2({ registry, runner: stdoutRunner({ not: 'an array' }) });
  assertErr(result);
  assert.equal(result.error.code, 'malformed_record');
});

test('non-object entries inside an otherwise-valid array are skipped, not fatal', async () => {
  const registry = createSecretRegistry();
  const payload = [null, 42, 'not-an-object', pm2JlistEntry({ name: 'survivor' })];
  const result = await inspectPm2({ registry, runner: stdoutRunner(payload) });
  assertOk(result);
  assert.equal(result.snapshot.processes.length, 1);
  assert.equal(result.snapshot.meta.skippedRecordCount, 3);
});

test('a shared fingerprinter lets equals() compare an env value observed on one process against another', async () => {
  const registry = createSecretRegistry();
  const fingerprinter = createFingerprinter();
  const payload = [
    pm2JlistEntry({ name: 'app-a', pm_id: 0, env: { SHARED_SECRET: SENTINEL_JWT_SECRET } }),
    pm2JlistEntry({ name: 'app-b', pm_id: 1, env: { SHARED_SECRET: SENTINEL_JWT_SECRET } }),
  ];
  const result = await inspectPm2({ registry, runner: stdoutRunner(payload), fingerprinter });
  assertOk(result);
  const [first, second] = result.snapshot.processes;
  const firstValue = first!.environmentVariables[0]!.value;
  const secondValue = second!.environmentVariables[0]!.value;
  assert.equal(firstValue.equals(secondValue), true);
});
