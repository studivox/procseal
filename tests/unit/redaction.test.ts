import assert from 'node:assert/strict';
import { test } from 'node:test';
import { sanitizeError, sanitizeMessage } from '../../src/core/redaction.js';
import { SENTINEL_DB_PASSWORD, SENTINEL_JWT_SECRET } from '../fixtures/sentinel-values.js';

test('sanitizeMessage removes every known sentinel value from free text', () => {
  const message = `Connection failed using secret ${SENTINEL_JWT_SECRET} and password ${SENTINEL_DB_PASSWORD}`;

  const sanitized = sanitizeMessage(message, [SENTINEL_JWT_SECRET, SENTINEL_DB_PASSWORD]);

  assert.equal(sanitized.includes(SENTINEL_JWT_SECRET), false);
  assert.equal(sanitized.includes(SENTINEL_DB_PASSWORD), false);
  assert.match(sanitized, /\[REDACTED\]/);
});

test('sanitizeError strips known sentinel values from a thrown error message', () => {
  const error = new Error(`unexpected token near ${SENTINEL_JWT_SECRET}`);

  const sanitized = sanitizeError(error, [SENTINEL_JWT_SECRET]);

  assert.equal(sanitized.message.includes(SENTINEL_JWT_SECRET), false);
});

test('sanitizeMessage leaves text unchanged when no known values are present', () => {
  const message = 'a generic error with no secret content';
  assert.equal(sanitizeMessage(message, [SENTINEL_JWT_SECRET]), message);
});
