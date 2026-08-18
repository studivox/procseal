import assert from 'node:assert/strict';
import { test } from 'node:test';
import { inspect } from 'node:util';
import { createFingerprinter } from '../../src/core/fingerprint.js';
import { ObservedValue } from '../../src/core/observed-value.js';
import { createSecretRegistry } from '../../src/core/secret-registry.js';
import { SENTINEL_API_KEY, SENTINEL_JWT_SECRET } from '../fixtures/sentinel-values.js';

function makeObservedValue(raw: string) {
  const fingerprinter = createFingerprinter();
  const registry = createSecretRegistry();
  const value = ObservedValue.from(raw, fingerprinter, registry);
  return { value, fingerprinter, registry };
}

test('construction registers the raw value in the run SecretRegistry', () => {
  const { registry } = makeObservedValue(SENTINEL_JWT_SECRET);
  const scrubbed = registry.scrub(`token=${SENTINEL_JWT_SECRET}`);
  assert.equal(scrubbed.includes(SENTINEL_JWT_SECRET), false);
  assert.equal(scrubbed, 'token=[REDACTED]');
});

test('equals() is true for the same raw value produced with the same fingerprinter', () => {
  const fingerprinter = createFingerprinter();
  const registry = createSecretRegistry();
  const a = ObservedValue.from(SENTINEL_JWT_SECRET, fingerprinter, registry);
  const b = ObservedValue.from(SENTINEL_JWT_SECRET, fingerprinter, registry);
  assert.equal(a.equals(b), true);
});

test('equals() is false for two different raw values', () => {
  const fingerprinter = createFingerprinter();
  const registry = createSecretRegistry();
  const a = ObservedValue.from(SENTINEL_JWT_SECRET, fingerprinter, registry);
  const b = ObservedValue.from(SENTINEL_API_KEY, fingerprinter, registry);
  assert.equal(a.equals(b), false);
});

test('equalsPlain() compares against a plain candidate without exposing the raw value', () => {
  const { value } = makeObservedValue(SENTINEL_JWT_SECRET);
  assert.equal(value.equalsPlain(SENTINEL_JWT_SECRET), true);
  assert.equal(value.equalsPlain(SENTINEL_API_KEY), false);
});

test('displayFingerprint() never contains the raw value and is truncated', () => {
  const { value } = makeObservedValue(SENTINEL_JWT_SECRET);
  const fp = value.displayFingerprint();
  assert.equal(fp.includes(SENTINEL_JWT_SECRET), false);
  assert.match(fp, /^[0-9a-f]+$/);
  assert.equal(fp.length, 16);
});

test('adversarial: JSON.stringify() of the value directly never leaks the raw value', () => {
  const { value } = makeObservedValue(SENTINEL_JWT_SECRET);
  const serialized = JSON.stringify(value);
  assert.equal(serialized.includes(SENTINEL_JWT_SECRET), false);
});

test('adversarial: JSON.stringify() of a structure nesting the value never leaks the raw value', () => {
  const { value } = makeObservedValue(SENTINEL_JWT_SECRET);
  const serialized = JSON.stringify({ env: { JWT_SECRET: value }, list: [value, value] });
  assert.equal(serialized.includes(SENTINEL_JWT_SECRET), false);
});

test('adversarial: String(value) never leaks the raw value', () => {
  const { value } = makeObservedValue(SENTINEL_JWT_SECRET);
  assert.equal(String(value).includes(SENTINEL_JWT_SECRET), false);
});

test('adversarial: template-literal string coercion never leaks the raw value', () => {
  const { value } = makeObservedValue(SENTINEL_JWT_SECRET);
  const text = `observed=${value}`;
  assert.equal(text.includes(SENTINEL_JWT_SECRET), false);
});

test('adversarial: implicit ToString coercion via Array.prototype.join never leaks the raw value', () => {
  const { value } = makeObservedValue(SENTINEL_JWT_SECRET);
  const text = [value].join('');
  assert.equal(text.includes(SENTINEL_JWT_SECRET), false);
});

test('adversarial: util.inspect() never leaks the raw value', () => {
  const { value } = makeObservedValue(SENTINEL_JWT_SECRET);
  const inspected = inspect(value, { depth: 10, showHidden: true });
  assert.equal(inspected.includes(SENTINEL_JWT_SECRET), false);
});

test('adversarial: util.inspect() with showHidden still cannot reach the private field', () => {
  const { value } = makeObservedValue(SENTINEL_JWT_SECRET);
  const inspected = inspect(value, { showHidden: true, depth: null, getters: true });
  assert.equal(inspected.includes(SENTINEL_JWT_SECRET), false);
});

test('adversarial: console.log() output never leaks the raw value', () => {
  const { value } = makeObservedValue(SENTINEL_JWT_SECRET);
  const originalLog = console.log;
  const captured: string[] = [];
  console.log = (...args: unknown[]) => {
    captured.push(args.map((arg) => (typeof arg === 'string' ? arg : inspect(arg))).join(' '));
  };
  try {
    console.log('observed value:', value);
  } finally {
    console.log = originalLog;
  }
  assert.equal(captured.join('\n').includes(SENTINEL_JWT_SECRET), false);
});

test('adversarial: Object.keys / getOwnPropertyNames / entries never enumerate the raw value', () => {
  const { value } = makeObservedValue(SENTINEL_JWT_SECRET);
  assert.deepEqual(Object.keys(value), []);
  assert.deepEqual(Object.getOwnPropertyNames(value), []);
  assert.deepEqual(Object.entries(value), []);
  assert.deepEqual(Reflect.ownKeys(value), []);
});

test('adversarial: Object.getOwnPropertySymbols never exposes a symbol carrying the raw value', () => {
  const { value } = makeObservedValue(SENTINEL_JWT_SECRET);
  const symbols = Object.getOwnPropertySymbols(value);
  for (const symbol of symbols) {
    const described = symbol.toString();
    assert.equal(described.includes(SENTINEL_JWT_SECRET), false);
  }
});

test('adversarial: JSON.stringify(Object.getOwnPropertyDescriptors(value)) never leaks the raw value', () => {
  const { value } = makeObservedValue(SENTINEL_JWT_SECRET);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  assert.equal(JSON.stringify(descriptors).includes(SENTINEL_JWT_SECRET), false);
});

test('adversarial: an Error thrown while formatting the value never leaks the raw value in its message', () => {
  const { value } = makeObservedValue(SENTINEL_JWT_SECRET);
  let caughtMessage: string;
  try {
    throw new Error(`unexpected observed value: ${value}`);
  } catch (error) {
    caughtMessage = error instanceof Error ? error.message : String(error);
  }
  assert.equal(caughtMessage.includes(SENTINEL_JWT_SECRET), false);
});

test('adversarial: a reporter-style JSON.stringify(null, 2) pretty-print never leaks the raw value', () => {
  const { value } = makeObservedValue(SENTINEL_JWT_SECRET);
  const pretty = JSON.stringify({ finding: { value } }, null, 2);
  assert.equal(pretty.includes(SENTINEL_JWT_SECRET), false);
});

test("equals() compares raw values through the receiver's fingerprinter, regardless of which fingerprinter the other side was built with", () => {
  const registryA = createSecretRegistry();
  const registryB = createSecretRegistry();
  const a = ObservedValue.from(SENTINEL_JWT_SECRET, createFingerprinter(), registryA);
  const b = ObservedValue.from(SENTINEL_JWT_SECRET, createFingerprinter(), registryB);
  assert.equal(a.equals(b), true);
});
