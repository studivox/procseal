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

test('duplicate registrations of the same value do not create inconsistent behavior', () => {
  const registry = createSecretRegistry();
  registry.register(SENTINEL_JWT_SECRET);
  registry.register(SENTINEL_JWT_SECRET);
  registry.register(SENTINEL_JWT_SECRET);

  const scrubbed = registry.scrub(`value=${SENTINEL_JWT_SECRET}`);

  assert.equal(scrubbed, 'value=[REDACTED]');
});

test('adversarial: registering a prefix ("abc") before the longer secret ("abcdef") cannot leave the suffix "def" visible', () => {
  const registry = createSecretRegistry();
  registry.register('abc');
  registry.register('abcdef');

  const scrubbed = registry.scrub('token=abcdef');

  assert.equal(scrubbed.includes('def'), false);
  assert.equal(scrubbed.includes('abcdef'), false);
  assert.equal(scrubbed, 'token=[REDACTED]');
});

test('adversarial: registering the longer secret ("abcdef") before the prefix ("abc") gives the same safe result', () => {
  const registry = createSecretRegistry();
  registry.register('abcdef');
  registry.register('abc');

  const scrubbed = registry.scrub('token=abcdef');

  assert.equal(scrubbed.includes('def'), false);
  assert.equal(scrubbed.includes('abcdef'), false);
  assert.equal(scrubbed, 'token=[REDACTED]');
});

test('adversarial: a registered suffix ("cret") does not leave a prefix fragment of a longer secret ("mysecret") visible', () => {
  const registry = createSecretRegistry();
  registry.register('cret');
  registry.register('mysecret');

  const scrubbed = registry.scrub('password=mysecret');

  assert.equal(scrubbed.includes('myse'), false);
  assert.equal(scrubbed.includes('mysecret'), false);
  assert.equal(scrubbed, 'password=[REDACTED]');
});

test('adversarial: repeated and overlapping secrets in the same text are all fully scrubbed regardless of registration order', () => {
  const registryShortFirst = createSecretRegistry();
  registryShortFirst.register('abc');
  registryShortFirst.register('abcdef');

  const registryLongFirst = createSecretRegistry();
  registryLongFirst.register('abcdef');
  registryLongFirst.register('abc');

  const text = 'first=abcdef second=abc third=abcdef fourth=abc';

  const scrubbedShortFirst = registryShortFirst.scrub(text);
  const scrubbedLongFirst = registryLongFirst.scrub(text);

  for (const scrubbed of [scrubbedShortFirst, scrubbedLongFirst]) {
    assert.equal(scrubbed.includes('def'), false);
    assert.equal(scrubbed.includes('abc'), false);
    assert.equal(scrubbed, 'first=[REDACTED] second=[REDACTED] third=[REDACTED] fourth=[REDACTED]');
  }
  assert.equal(scrubbedShortFirst, scrubbedLongFirst);
});

test('the registry does not expose its contents through enumeration or serialization', () => {
  const registry = createSecretRegistry();
  registry.register(SENTINEL_JWT_SECRET);

  assert.deepEqual(Object.keys(registry).sort(), ['register', 'scrub']);
  assert.equal(JSON.stringify(registry).includes(SENTINEL_JWT_SECRET), false);
});
