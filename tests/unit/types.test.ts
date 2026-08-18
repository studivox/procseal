import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RULE_DEFINITIONS, RULE_IDS } from '../../src/core/types.js';

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
