import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createSafeLabel,
  isSafeLabel,
  toSafeLabelOrRedacted,
  UnsafeLabelError,
} from '../../src/core/label.js';

test('accepts typical key names, paths, and version-like strings', () => {
  for (const value of [
    'JWT_SECRET',
    'DATABASE_URL',
    '/etc/procseal/config',
    '0.1.0-alpha.0',
    'PS004',
  ]) {
    assert.equal(isSafeLabel(value), true, `expected "${value}" to be a safe label`);
    assert.equal(createSafeLabel(value), value);
  }
});

test('rejects control characters, including newlines', () => {
  assert.equal(isSafeLabel('line-one\nline-two'), false);
  assert.equal(isSafeLabel('bell\x07char'), false);
});

test('rejects values longer than the length limit', () => {
  const tooLong = 'a'.repeat(121);
  assert.equal(isSafeLabel(tooLong), false);
});

test('accepts values right at the length limit', () => {
  const exactlyMax = 'a'.repeat(120);
  assert.equal(isSafeLabel(exactlyMax), true);
});

test('createSafeLabel throws UnsafeLabelError for unsafe input', () => {
  assert.throws(() => createSafeLabel('unsafe;`rm -rf /`'), UnsafeLabelError);
});

test('toSafeLabelOrRedacted never throws and redacts unsafe input', () => {
  const result = toSafeLabelOrRedacted('unsafe\ncontrol\rchars');
  assert.equal(result, '[REDACTED]');
});

test('toSafeLabelOrRedacted passes safe input through unchanged', () => {
  assert.equal(toSafeLabelOrRedacted('JWT_SECRET'), 'JWT_SECRET');
});
