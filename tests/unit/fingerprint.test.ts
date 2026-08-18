import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createFingerprinter } from '../../src/core/fingerprint.js';
import { SENTINEL_JWT_SECRET } from '../fixtures/sentinel-values.js';

test('the same value fingerprints identically within one run', () => {
  const fingerprinter = createFingerprinter();
  const first = fingerprinter.fingerprint(SENTINEL_JWT_SECRET);
  const second = fingerprinter.fingerprint(SENTINEL_JWT_SECRET);
  assert.equal(first, second);
});

test('the same value fingerprints differently across two run keys', () => {
  const runA = createFingerprinter();
  const runB = createFingerprinter();
  const fingerprintA = runA.fingerprint(SENTINEL_JWT_SECRET);
  const fingerprintB = runB.fingerprint(SENTINEL_JWT_SECRET);
  assert.notEqual(fingerprintA, fingerprintB);
  assert.notEqual(runA.keyId, runB.keyId);
});

test('a fingerprint never contains the raw value it was derived from', () => {
  const fingerprinter = createFingerprinter();
  const digest = fingerprinter.fingerprint(SENTINEL_JWT_SECRET);
  assert.equal(digest.includes(SENTINEL_JWT_SECRET), false);
  assert.match(digest, /^[0-9a-f]+$/);
});
