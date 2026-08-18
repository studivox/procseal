import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createSecretRegistry, sanitizeForDisplay } from '../../src/core/output-safety.js';
import { SENTINEL_JWT_SECRET } from '../fixtures/sentinel-values.js';

test('scrubs a registered raw value out of a plain string', () => {
  const registry = createSecretRegistry();
  registry.register(SENTINEL_JWT_SECRET);
  const output = sanitizeForDisplay(`secret is ${SENTINEL_JWT_SECRET}`, registry);
  assert.equal(output.includes(SENTINEL_JWT_SECRET), false);
});

test('replaces control characters and newlines, blocking output/log injection', () => {
  const registry = createSecretRegistry();
  const output = sanitizeForDisplay('line-one\nFAKE: injected line\x1b[31m', registry);
  assert.equal(output.includes('\n'), false);
  assert.equal(output.includes('\x1b'), false);
});

test('truncates excessively long values', () => {
  const registry = createSecretRegistry();
  const huge = 'a'.repeat(10_000);
  const output = sanitizeForDisplay(huge, registry);
  assert.ok(output.length < huge.length);
  assert.match(output, /\[truncated]$/);
});

test('serializes and scrubs non-string values, so a nested object cannot hide a raw value', () => {
  const registry = createSecretRegistry();
  registry.register(SENTINEL_JWT_SECRET);
  const nested = { inner: { deeper: SENTINEL_JWT_SECRET } };
  const output = sanitizeForDisplay(nested, registry);
  assert.equal(output.includes(SENTINEL_JWT_SECRET), false);
});

test('handles values that cannot be JSON-serialized without throwing', () => {
  const registry = createSecretRegistry();
  const circular: Record<string, unknown> = {};
  circular['self'] = circular;
  assert.doesNotThrow(() => sanitizeForDisplay(circular, registry));
});
