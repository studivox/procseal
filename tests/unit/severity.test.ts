import assert from 'node:assert/strict';
import { test } from 'node:test';
import { compareSeverity, isSeverity } from '../../src/core/severity.js';

test('orders severities from info (lowest) to critical (highest)', () => {
  assert.ok(compareSeverity('info', 'critical') < 0);
  assert.ok(compareSeverity('high', 'low') > 0);
  assert.equal(compareSeverity('medium', 'medium'), 0);
});

test('isSeverity accepts only known severity strings', () => {
  assert.equal(isSeverity('high'), true);
  assert.equal(isSeverity('critical'), true);
  assert.equal(isSeverity('nonsense'), false);
});
