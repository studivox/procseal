import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createFingerprinter, type Fingerprinter } from '../../src/core/fingerprint.js';
import { toSafeLabelOrRedacted } from '../../src/core/label.js';
import { ObservedValue } from '../../src/core/observed-value.js';
import type { Pm2ProcessSnapshot } from '../../src/core/pm2-types.js';
import { isReuseCandidate } from '../../src/core/reuse-candidate-policy.js';
import { createSecretRegistry, type SecretRegistry } from '../../src/core/secret-registry.js';
import { evaluateReuseRule } from '../../src/rules/reuse.js';

function makeProcess(
  safeProcessId: string,
  safeName: string,
  entries: Readonly<Record<string, string>>,
  fingerprinter: Fingerprinter,
  registry: SecretRegistry,
): Pm2ProcessSnapshot {
  const environmentVariables = Object.entries(entries).map(([name, value]) => ({
    name: toSafeLabelOrRedacted(name),
    value: ObservedValue.from(value, fingerprinter, registry),
    reuseCandidate: isReuseCandidate(name, value),
  }));
  return {
    safeProcessId: toSafeLabelOrRedacted(safeProcessId),
    safeName: toSafeLabelOrRedacted(safeName),
    pm2Id: 0,
    status: 'online',
    environmentVariables,
  };
}

function setup() {
  return { fingerprinter: createFingerprinter(), registry: createSecretRegistry() };
}

test('no findings when the selected process has no reuse-candidate variables at all', () => {
  const { fingerprinter, registry } = setup();
  const selected = makeProcess('proc-0', 'my-app', { PORT: '3000' }, fingerprinter, registry);
  const other = makeProcess('proc-1', 'other-app', { PORT: '3000' }, fingerprinter, registry);

  assert.deepEqual(evaluateReuseRule(selected, [selected, other]), []);
});

test('fires when the same eligible value occurs in two different applications', () => {
  const { fingerprinter, registry } = setup();
  const shared = 'a-genuinely-long-shared-secret-value';
  const selected = makeProcess('proc-0', 'my-app', { API_KEY: shared }, fingerprinter, registry);
  const other = makeProcess('proc-1', 'other-app', { API_KEY: shared }, fingerprinter, registry);

  const findings = evaluateReuseRule(selected, [selected, other]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.ruleId, 'PS004');
  assert.deepEqual(findings[0]!.details, { variable: 'API_KEY', reusedInProcessCount: '1' });
});

test('still fires when the reused value appears under a different sensitive variable name', () => {
  const { fingerprinter, registry } = setup();
  const shared = 'a-genuinely-long-shared-secret-value';
  const selected = makeProcess('proc-0', 'my-app', { JWT_SECRET: shared }, fingerprinter, registry);
  const other = makeProcess('proc-1', 'other-app', { AUTH_TOKEN: shared }, fingerprinter, registry);

  const findings = evaluateReuseRule(selected, [selected, other]);
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0]!.details, { variable: 'JWT_SECRET', reusedInProcessCount: '1' });
});

test('does not fire when the value is repeated only inside the selected process', () => {
  const { fingerprinter, registry } = setup();
  const shared = 'a-genuinely-long-shared-secret-value';
  const selected = makeProcess(
    'proc-0',
    'my-app',
    { API_KEY: shared, CLIENT_SECRET: shared },
    fingerprinter,
    registry,
  );
  const other = makeProcess('proc-1', 'other-app', { PORT: '3000' }, fingerprinter, registry);

  assert.deepEqual(evaluateReuseRule(selected, [selected, other]), []);
});

test('does not fire when the matching other-process value is not itself an eligible candidate', () => {
  const { fingerprinter, registry } = setup();
  const shared = 'a-genuinely-long-shared-secret-value';
  const selected = makeProcess('proc-0', 'my-app', { API_KEY: shared }, fingerprinter, registry);
  // Same raw value, but under a non-sensitive key name on the other side —
  // only eligible-vs-eligible pairs are ever compared.
  const other = makeProcess('proc-1', 'other-app', { BUILD_ID: shared }, fingerprinter, registry);

  assert.deepEqual(evaluateReuseRule(selected, [selected, other]), []);
});

test('short, common, non-sensitive values never trigger, including PORT, NODE_ENV, paths, and booleans', () => {
  const { fingerprinter, registry } = setup();
  const entries = {
    PORT: '3000',
    NODE_ENV: 'production',
    DEBUG: 'true',
    HOST_PATH: '/var/www/app',
    API_KEY: 'short',
  };
  const selected = makeProcess('proc-0', 'my-app', entries, fingerprinter, registry);
  const other = makeProcess('proc-1', 'other-app', entries, fingerprinter, registry);

  assert.deepEqual(evaluateReuseRule(selected, [selected, other]), []);
});

test('three or more applications sharing one value produce exactly one deduplicated finding, not one per pair', () => {
  const { fingerprinter, registry } = setup();
  const shared = 'a-genuinely-long-shared-secret-value';
  const selected = makeProcess('proc-0', 'my-app', { JWT_SECRET: shared }, fingerprinter, registry);
  const b = makeProcess('proc-1', 'app-b', { AUTH_TOKEN: shared }, fingerprinter, registry);
  const c = makeProcess('proc-2', 'app-c', { PASSWORD: shared }, fingerprinter, registry);

  const findings = evaluateReuseRule(selected, [selected, b, c]);
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0]!.details, { variable: 'JWT_SECRET', reusedInProcessCount: '2' });
});

test('multiple distinct reused values are reported as separate findings, sorted deterministically by variable name', () => {
  const { fingerprinter, registry } = setup();
  const sharedA = 'a-genuinely-long-shared-secret-value-a';
  const sharedB = 'a-genuinely-long-shared-secret-value-b';
  const selected = makeProcess(
    'proc-0',
    'my-app',
    { JWT_SECRET: sharedA, DB_PASSWORD: sharedB },
    fingerprinter,
    registry,
  );
  const other = makeProcess(
    'proc-1',
    'other-app',
    { AUTH_TOKEN: sharedA, DB_PASSWORD: sharedB },
    fingerprinter,
    registry,
  );

  const findings = evaluateReuseRule(selected, [selected, other]);
  assert.equal(findings.length, 2);
  assert.deepEqual(
    findings.map((f) => f.details),
    [
      { variable: 'DB_PASSWORD', reusedInProcessCount: '1' },
      { variable: 'JWT_SECRET', reusedInProcessCount: '1' },
    ],
  );
});

test('ordering is deterministic regardless of the input fleet array order', () => {
  const { fingerprinter, registry } = setup();
  const sharedA = 'a-genuinely-long-shared-secret-value-a';
  const sharedB = 'a-genuinely-long-shared-secret-value-b';
  const selected = makeProcess(
    'proc-0',
    'my-app',
    { JWT_SECRET: sharedA, DB_PASSWORD: sharedB },
    fingerprinter,
    registry,
  );
  const other = makeProcess(
    'proc-1',
    'other-app',
    { AUTH_TOKEN: sharedA, DB_PASSWORD: sharedB },
    fingerprinter,
    registry,
  );

  const forward = evaluateReuseRule(selected, [selected, other]);
  const reversed = evaluateReuseRule(selected, [other, selected]);
  assert.deepEqual(
    forward.map((f) => f.details),
    reversed.map((f) => f.details),
  );
});

test('a value declared under two names in the selected process, and reused elsewhere, produces one finding using the alphabetically-first name', () => {
  const { fingerprinter, registry } = setup();
  const shared = 'a-genuinely-long-shared-secret-value';
  const selected = makeProcess(
    'proc-0',
    'my-app',
    { CLIENT_SECRET: shared, API_KEY: shared },
    fingerprinter,
    registry,
  );
  const other = makeProcess('proc-1', 'other-app', { AUTH_TOKEN: shared }, fingerprinter, registry);

  const findings = evaluateReuseRule(selected, [selected, other]);
  assert.equal(findings.length, 1);
  // "API_KEY" < "CLIENT_SECRET" ordinally.
  assert.deepEqual(findings[0]!.details, { variable: 'API_KEY', reusedInProcessCount: '1' });
});

test('adversarial: no finding, when serialized, ever contains either raw reused value', () => {
  const { fingerprinter, registry } = setup();
  const shared = 'sentinel-reuse-value-should-never-leak-9f13';
  const selected = makeProcess('proc-0', 'my-app', { API_KEY: shared }, fingerprinter, registry);
  const other = makeProcess('proc-1', 'other-app', { API_KEY: shared }, fingerprinter, registry);

  const findings = evaluateReuseRule(selected, [selected, other]);
  const serialized = JSON.stringify(findings);
  assert.equal(serialized.includes(shared), false);
});

test('excludes the selected process itself from the "other processes" comparison, by safeProcessId', () => {
  const { fingerprinter, registry } = setup();
  const shared = 'a-genuinely-long-shared-secret-value';
  // Two distinct process objects that happen to carry the same
  // safeProcessId as `selected` must never be treated as a second,
  // distinct application.
  const selected = makeProcess('proc-0', 'my-app', { API_KEY: shared }, fingerprinter, registry);
  const decoy = makeProcess('proc-0', 'my-app', { API_KEY: shared }, fingerprinter, registry);

  assert.deepEqual(evaluateReuseRule(selected, [selected, decoy]), []);
});
