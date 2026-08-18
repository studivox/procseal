import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createSecretRegistry } from '../../src/core/secret-registry.js';
import { SENTINEL_DB_PASSWORD, SENTINEL_JWT_SECRET } from '../fixtures/sentinel-values.js';

test('scrub() replaces every occurrence of a registered value', () => {
  const registry = createSecretRegistry();
  registry.register(SENTINEL_JWT_SECRET);

  const scrubbed = registry.scrub(`a=${SENTINEL_JWT_SECRET} b=${SENTINEL_JWT_SECRET}`);

  assert.equal(scrubbed.includes(SENTINEL_JWT_SECRET), false);
  assert.equal(scrubbed, 'a=[REDACTED] b=[REDACTED]');
});

test('scrub() leaves text unchanged when nothing is registered', () => {
  const registry = createSecretRegistry();
  const text = 'nothing sensitive here';
  assert.equal(registry.scrub(text), text);
});

test('scrub() only redacts registered values, not unregistered ones', () => {
  const registry = createSecretRegistry();
  registry.register(SENTINEL_JWT_SECRET);

  const scrubbed = registry.scrub(`${SENTINEL_JWT_SECRET} and ${SENTINEL_DB_PASSWORD}`);

  assert.equal(scrubbed.includes(SENTINEL_JWT_SECRET), false);
  assert.equal(scrubbed.includes(SENTINEL_DB_PASSWORD), true);
});

test('register() ignores empty strings', () => {
  const registry = createSecretRegistry();
  registry.register('');
  assert.equal(registry.scrub(''), '');
});
