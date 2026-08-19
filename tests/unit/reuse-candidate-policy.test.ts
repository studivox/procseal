import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  isReuseCandidate,
  isSensitiveKeyName,
  meetsMinimumCandidateLength,
  MIN_REUSE_CANDIDATE_VALUE_BYTES,
} from '../../src/core/reuse-candidate-policy.js';

const LONG_VALUE = 'x'.repeat(MIN_REUSE_CANDIDATE_VALUE_BYTES);
const SHORT_VALUE = 'x'.repeat(MIN_REUSE_CANDIDATE_VALUE_BYTES - 1);

test('isSensitiveKeyName recognizes conventional credential key names', () => {
  const positives = [
    'PASSWORD',
    'DB_PASSWORD',
    'PASSWD',
    'JWT_SECRET',
    'CLIENT_SECRET',
    'API_TOKEN',
    'AUTH_TOKEN',
    'API_KEY',
    'STRIPE_API_KEY',
    'PRIVATE_KEY',
    'ACCESS_KEY',
    'AWS_ACCESS_KEY',
    'AUTH_KEY',
    'DB_CREDENTIAL',
    'SSH_PASSPHRASE',
  ];
  for (const key of positives) {
    assert.equal(isSensitiveKeyName(key), true, `expected ${key} to be recognized as sensitive`);
  }
});

test('isSensitiveKeyName recognizes different casing and separator conventions as the same term', () => {
  assert.equal(isSensitiveKeyName('apiKey'), true);
  assert.equal(isSensitiveKeyName('ApiKey'), true);
  assert.equal(isSensitiveKeyName('api_key'), true);
  assert.equal(isSensitiveKeyName('API_KEY'), true);
});

test('isSensitiveKeyName does not flag ordinary configuration keys', () => {
  const negatives = [
    'PORT',
    'NODE_ENV',
    'LOG_LEVEL',
    'HOST',
    'HOME',
    'PATH',
    'DEBUG',
    'USERNAME',
    'DATABASE_URL',
    'PUBLIC_KEY',
    'REQUEST_ID',
    'TIMEOUT_MS',
    'APP_NAME',
  ];
  for (const key of negatives) {
    assert.equal(
      isSensitiveKeyName(key),
      false,
      `expected ${key} not to be recognized as sensitive`,
    );
  }
});

test('meetsMinimumCandidateLength rejects short common values and accepts realistic secret lengths', () => {
  assert.equal(meetsMinimumCandidateLength('true'), false);
  assert.equal(meetsMinimumCandidateLength('production'), false);
  assert.equal(meetsMinimumCandidateLength('8080'), false);
  assert.equal(meetsMinimumCandidateLength('admin'), false);
  assert.equal(meetsMinimumCandidateLength(SHORT_VALUE), false);
  assert.equal(meetsMinimumCandidateLength(LONG_VALUE), true);
  assert.equal(meetsMinimumCandidateLength('sentinel-jwt-9f13c2b7e4a1'), true);
});

test('meetsMinimumCandidateLength measures UTF-8 bytes, not UTF-16 code units', () => {
  // '€' is 1 UTF-16 code unit but 3 UTF-8 bytes; 4 of them is 4 code units
  // but 12 bytes, meeting the floor even though `.length` would say 4.
  const value = '€'.repeat(4);
  assert.equal(value.length, 4);
  assert.equal(Buffer.byteLength(value, 'utf8'), 12);
  assert.equal(meetsMinimumCandidateLength(value), true);
});

test('isReuseCandidate requires both a sensitive key name and the minimum length', () => {
  assert.equal(isReuseCandidate('API_KEY', LONG_VALUE), true);
  assert.equal(isReuseCandidate('API_KEY', SHORT_VALUE), false, 'sensitive name, value too short');
  assert.equal(isReuseCandidate('PORT', LONG_VALUE), false, 'long value, non-sensitive name');
  assert.equal(isReuseCandidate('PORT', '3000'), false, 'neither condition holds');
});

test('common non-sensitive values never qualify, even under an adversarially chosen key', () => {
  assert.equal(isReuseCandidate('SOME_PASSWORD', 'true'), false);
  assert.equal(isReuseCandidate('SOME_PASSWORD', 'production'), false);
  assert.equal(isReuseCandidate('SOME_PASSWORD', '/var/www'), false);
  assert.equal(isReuseCandidate('SOME_PASSWORD', 'changeme'), false);
});
