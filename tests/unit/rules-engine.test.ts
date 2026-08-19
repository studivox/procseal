import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { DotenvSnapshot } from '../../src/core/dotenv-file-types.js';
import { createFingerprinter, type Fingerprinter } from '../../src/core/fingerprint.js';
import { toSafeLabelOrRedacted } from '../../src/core/label.js';
import { ObservedValue } from '../../src/core/observed-value.js';
import type { Pm2ProcessSnapshot } from '../../src/core/pm2-types.js';
import { isReuseCandidate } from '../../src/core/reuse-candidate-policy.js';
import { createSecretRegistry, type SecretRegistry } from '../../src/core/secret-registry.js';
import { evaluateRules } from '../../src/rules/engine.js';

function makeDeclared(
  entries: Record<string, string>,
  fingerprinter: Fingerprinter,
  registry: SecretRegistry,
): DotenvSnapshot {
  const variables = Object.entries(entries).map(([name, value]) => ({
    name: toSafeLabelOrRedacted(name),
    value: ObservedValue.from(value, fingerprinter, registry),
  }));
  return { variables, meta: { variableCount: variables.length } };
}

function makeLive(
  entries: Record<string, string>,
  fingerprinter: Fingerprinter,
  registry: SecretRegistry,
  options: { readonly safeProcessId?: string; readonly safeName?: string } = {},
): Pm2ProcessSnapshot {
  const environmentVariables = Object.entries(entries).map(([name, value]) => ({
    name: toSafeLabelOrRedacted(name),
    value: ObservedValue.from(value, fingerprinter, registry),
    reuseCandidate: isReuseCandidate(name, value),
  }));
  return {
    safeProcessId: toSafeLabelOrRedacted(options.safeProcessId ?? 'proc-0'),
    safeName: toSafeLabelOrRedacted(options.safeName ?? 'test-app'),
    pm2Id: 0,
    status: 'online',
    environmentVariables,
  };
}

function setup() {
  const fingerprinter = createFingerprinter();
  const registry = createSecretRegistry();
  return { fingerprinter, registry };
}

test('no findings when every declared value matches the live value exactly', () => {
  const { fingerprinter, registry } = setup();
  const declared = makeDeclared({ API_KEY: 'abc123' }, fingerprinter, registry);
  const live = makeLive({ API_KEY: 'abc123' }, fingerprinter, registry);

  const findings = evaluateRules({
    declared,
    live,
    checkUnexpected: false,
    checkReuse: false,
    allProcesses: [live],
  });
  assert.deepEqual(findings, []);
});

test('PS001 fires when a declared value differs from the live value (non-PORT key)', () => {
  const { fingerprinter, registry } = setup();
  const declared = makeDeclared({ API_KEY: 'declared-value' }, fingerprinter, registry);
  const live = makeLive({ API_KEY: 'different-live-value' }, fingerprinter, registry);

  const findings = evaluateRules({
    declared,
    live,
    checkUnexpected: false,
    checkReuse: false,
    allProcesses: [live],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.ruleId, 'PS001');
  assert.deepEqual(findings[0]!.details, { variable: 'API_KEY' });
});

test('PS002 fires when a declared variable is missing from the live process', () => {
  const { fingerprinter, registry } = setup();
  const declared = makeDeclared({ MISSING_VAR: 'value' }, fingerprinter, registry);
  const live = makeLive({}, fingerprinter, registry);

  const findings = evaluateRules({
    declared,
    live,
    checkUnexpected: false,
    checkReuse: false,
    allProcesses: [live],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.ruleId, 'PS002');
  assert.deepEqual(findings[0]!.details, { variable: 'MISSING_VAR' });
});

test('PS003 does not fire by default even when the live process has an undeclared variable', () => {
  const { fingerprinter, registry } = setup();
  const declared = makeDeclared({}, fingerprinter, registry);
  const live = makeLive({ UNEXPECTED_VAR: 'value' }, fingerprinter, registry);

  const findings = evaluateRules({
    declared,
    live,
    checkUnexpected: false,
    checkReuse: false,
    allProcesses: [live],
  });
  assert.deepEqual(findings, []);
});

test('PS003 fires only when checkUnexpected is explicitly true', () => {
  const { fingerprinter, registry } = setup();
  const declared = makeDeclared({}, fingerprinter, registry);
  const live = makeLive({ UNEXPECTED_VAR: 'value' }, fingerprinter, registry);

  const findings = evaluateRules({
    declared,
    live,
    checkUnexpected: true,
    checkReuse: false,
    allProcesses: [live],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.ruleId, 'PS003');
  assert.deepEqual(findings[0]!.details, { variable: 'UNEXPECTED_VAR' });
});

test('PS005 fires instead of PS001 when the PORT value differs, and never carries a port number', () => {
  const { fingerprinter, registry } = setup();
  const declared = makeDeclared({ PORT: '3000' }, fingerprinter, registry);
  const live = makeLive({ PORT: '4000' }, fingerprinter, registry);

  const findings = evaluateRules({
    declared,
    live,
    checkUnexpected: false,
    checkReuse: false,
    allProcesses: [live],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.ruleId, 'PS005');
  assert.deepEqual(findings[0]!.details, { variable: 'PORT' });
  assert.equal(JSON.stringify(findings).includes('3000'), false);
  assert.equal(JSON.stringify(findings).includes('4000'), false);
});

test('no duplicate PS001 is ever emitted for PORT alongside PS005', () => {
  const { fingerprinter, registry } = setup();
  const declared = makeDeclared({ PORT: '3000' }, fingerprinter, registry);
  const live = makeLive({ PORT: '4000' }, fingerprinter, registry);

  const findings = evaluateRules({
    declared,
    live,
    checkUnexpected: false,
    checkReuse: false,
    allProcesses: [live],
  });
  const ps001 = findings.filter((f) => f.ruleId === 'PS001');
  const ps005 = findings.filter((f) => f.ruleId === 'PS005');
  assert.equal(ps001.length, 0);
  assert.equal(ps005.length, 1);
});

test('PORT missing from the live process still fires PS002, not PS005', () => {
  const { fingerprinter, registry } = setup();
  const declared = makeDeclared({ PORT: '3000' }, fingerprinter, registry);
  const live = makeLive({}, fingerprinter, registry);

  const findings = evaluateRules({
    declared,
    live,
    checkUnexpected: false,
    checkReuse: false,
    allProcesses: [live],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.ruleId, 'PS002');
});

test('PORT matching exactly produces no finding at all', () => {
  const { fingerprinter, registry } = setup();
  const declared = makeDeclared({ PORT: '3000' }, fingerprinter, registry);
  const live = makeLive({ PORT: '3000' }, fingerprinter, registry);

  const findings = evaluateRules({
    declared,
    live,
    checkUnexpected: false,
    checkReuse: false,
    allProcesses: [live],
  });
  assert.deepEqual(findings, []);
});

test('a full mixed scenario: matching, differing, missing, PORT, and unexpected variables all classify correctly', () => {
  const { fingerprinter, registry } = setup();
  const declared = makeDeclared(
    {
      MATCHING: 'same',
      DIFFERENT: 'declared-value',
      MISSING: 'declared-only',
      PORT: '3000',
    },
    fingerprinter,
    registry,
  );
  const live = makeLive(
    {
      MATCHING: 'same',
      DIFFERENT: 'live-value',
      PORT: '4000',
      LIVE_ONLY: 'unexpected',
    },
    fingerprinter,
    registry,
  );

  const findings = evaluateRules({
    declared,
    live,
    checkUnexpected: true,
    checkReuse: false,
    allProcesses: [live],
  });
  const byRule = new Map<string, string>(
    findings.map((f) => [String(f.details?.['variable'] ?? ''), f.ruleId]),
  );

  assert.equal(byRule.get('DIFFERENT'), 'PS001');
  assert.equal(byRule.get('MISSING'), 'PS002');
  assert.equal(byRule.get('PORT'), 'PS005');
  assert.equal(byRule.get('LIVE_ONLY'), 'PS003');
  assert.equal(byRule.has('MATCHING'), false);
  assert.equal(findings.length, 4);
});

test('adversarial: no finding, when serialized, ever contains a declared or live raw value', () => {
  const { fingerprinter, registry } = setup();
  const declared = makeDeclared({ SECRET: 'declared-raw-secret-value' }, fingerprinter, registry);
  const live = makeLive({ SECRET: 'live-raw-secret-value' }, fingerprinter, registry);

  const findings = evaluateRules({
    declared,
    live,
    checkUnexpected: false,
    checkReuse: false,
    allProcesses: [live],
  });
  const serialized = JSON.stringify(findings);
  assert.equal(serialized.includes('declared-raw-secret-value'), false);
  assert.equal(serialized.includes('live-raw-secret-value'), false);
});

test('PS004 never fires when checkReuse is false, even when a value is genuinely reused across processes', () => {
  const { fingerprinter, registry } = setup();
  const declared = makeDeclared({}, fingerprinter, registry);
  const shared = 'a-genuinely-long-shared-secret-value';
  const live = makeLive({ API_KEY: shared }, fingerprinter, registry, { safeProcessId: 'proc-0' });
  const other = makeLive({ API_KEY: shared }, fingerprinter, registry, {
    safeProcessId: 'proc-1',
    safeName: 'other-app',
  });

  const findings = evaluateRules({
    declared,
    live,
    checkUnexpected: false,
    checkReuse: false,
    allProcesses: [live, other],
  });
  assert.deepEqual(findings, []);
});

test('PS004 fires through the full evaluateRules pipeline when checkReuse is true', () => {
  const { fingerprinter, registry } = setup();
  const declared = makeDeclared({}, fingerprinter, registry);
  const shared = 'a-genuinely-long-shared-secret-value';
  const live = makeLive({ API_KEY: shared }, fingerprinter, registry, { safeProcessId: 'proc-0' });
  const other = makeLive({ API_KEY: shared }, fingerprinter, registry, {
    safeProcessId: 'proc-1',
    safeName: 'other-app',
  });

  const findings = evaluateRules({
    declared,
    live,
    checkUnexpected: false,
    checkReuse: true,
    allProcesses: [live, other],
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.ruleId, 'PS004');
  assert.deepEqual(findings[0]!.details, { variable: 'API_KEY', reusedInApplicationCount: '1' });
});
