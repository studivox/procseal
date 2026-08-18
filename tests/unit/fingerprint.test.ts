import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createFingerprinter } from '../../src/core/fingerprint.js';
import { SENTINEL_DB_PASSWORD, SENTINEL_JWT_SECRET } from '../fixtures/sentinel-values.js';

test('equals() reports the same value as equal to itself within one run', () => {
  const fingerprinter = createFingerprinter();
  assert.equal(fingerprinter.equals(SENTINEL_JWT_SECRET, SENTINEL_JWT_SECRET), true);
});

test('equals() reports two different values as not equal within one run', () => {
  const fingerprinter = createFingerprinter();
  assert.equal(fingerprinter.equals(SENTINEL_JWT_SECRET, SENTINEL_DB_PASSWORD), false);
});

test('displayFingerprint() is deterministic for the same value within one run', () => {
  const fingerprinter = createFingerprinter();
  const first = fingerprinter.displayFingerprint(SENTINEL_JWT_SECRET);
  const second = fingerprinter.displayFingerprint(SENTINEL_JWT_SECRET);
  assert.equal(first, second);
});

test('displayFingerprint() differs across two independently created runs', () => {
  const runA = createFingerprinter();
  const runB = createFingerprinter();
  const fingerprintA = runA.displayFingerprint(SENTINEL_JWT_SECRET);
  const fingerprintB = runB.displayFingerprint(SENTINEL_JWT_SECRET);
  assert.notEqual(fingerprintA, fingerprintB);
  assert.notEqual(runA.keyId, runB.keyId);
});

test('displayFingerprint() never contains the raw value it was derived from', () => {
  const fingerprinter = createFingerprinter();
  const digest = fingerprinter.displayFingerprint(SENTINEL_JWT_SECRET);
  assert.equal(digest.includes(SENTINEL_JWT_SECRET), false);
  assert.match(digest, /^[0-9a-f]+$/);
  assert.equal(digest.length, 16);
});

test('the Fingerprinter object exposes no way to read the underlying key or full digest', () => {
  const fingerprinter = createFingerprinter();
  const exposedKeys = Object.keys(fingerprinter).sort();
  assert.deepEqual(exposedKeys, ['displayFingerprint', 'equals', 'keyId']);
});
