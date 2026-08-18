import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createFinding, getRuleTitle, RULE_DEFINITIONS, RULE_IDS } from '../../src/core/types.js';
import { SENTINEL_JWT_SECRET } from '../fixtures/sentinel-values.js';

test('defines exactly the eight stable rule identifiers, in order', () => {
  assert.deepEqual(RULE_IDS, [
    'PS001',
    'PS002',
    'PS003',
    'PS004',
    'PS005',
    'PS006',
    'PS007',
    'PS008',
  ]);
  assert.equal(new Set(RULE_IDS).size, 8);
});

test('every rule ID has exactly one definition', () => {
  assert.equal(RULE_DEFINITIONS.length, RULE_IDS.length);
  const ids = RULE_DEFINITIONS.map((rule) => rule.id);
  assert.deepEqual([...ids].sort(), [...RULE_IDS].sort());
});

test('getRuleTitle returns the catalog title for every known rule ID', () => {
  for (const rule of RULE_DEFINITIONS) {
    assert.equal(getRuleTitle(rule.id), rule.title);
  }
});

test('getRuleTitle falls back to a generic label instead of throwing on a forged rule ID', () => {
  const forged = 'PS999' as (typeof RULE_IDS)[number];
  assert.equal(getRuleTitle(forged), 'Unrecognized rule');
});

test('createFinding passes safe details through unchanged', () => {
  const finding = createFinding({
    ruleId: 'PS004',
    severity: 'high',
    details: { variable: 'JWT_SECRET', fingerprint: 'abc123' },
  });
  assert.deepEqual(finding.details, { variable: 'JWT_SECRET', fingerprint: 'abc123' });
});

test('createFinding redacts a details key or value that is not a safe label', () => {
  const finding = createFinding({
    ruleId: 'PS004',
    severity: 'high',
    details: { note: `raw secret: ${SENTINEL_JWT_SECRET}\nwith a newline` },
  });
  const value = finding.details?.['note'];
  assert.equal(value, '[REDACTED]');
});

test('createFinding omits details entirely when none are given', () => {
  const finding = createFinding({ ruleId: 'PS001', severity: 'low' });
  assert.equal(finding.details, undefined);
});
