import assert from 'node:assert/strict';
import { test } from 'node:test';
import { reportInternalError } from '../../src/core/internal-error.js';
import { SENTINEL_DB_PASSWORD, SENTINEL_JWT_SECRET } from '../fixtures/sentinel-values.js';

test('never includes the original Error.message, even when it contains a sentinel', () => {
  const error = new Error(`failed to connect using secret ${SENTINEL_JWT_SECRET}`);
  const report = reportInternalError(error);
  assert.equal(report.message.includes(SENTINEL_JWT_SECRET), false);
  assert.equal(report.exitCode, 1);
});

test('never includes the original stack trace', () => {
  const error = new Error(`connection string was ${SENTINEL_DB_PASSWORD}`);
  const report = reportInternalError(error);
  assert.equal(error.stack !== undefined, true);
  for (const line of (error.stack ?? '').split('\n')) {
    if (line.trim().length > 0) {
      assert.equal(report.message.includes(line), false);
    }
  }
});

test('is safe for a non-Error thrown value that happens to be a sentinel string', () => {
  const report = reportInternalError(SENTINEL_JWT_SECRET);
  assert.equal(report.message.includes(SENTINEL_JWT_SECRET), false);
});

test('derives a bounded, pattern-safe error code even from a hostile error name', () => {
  const error = new Error('boom');
  error.name = `Evil${SENTINEL_JWT_SECRET}Name\n\x1b[31m`;
  const report = reportInternalError(error);
  assert.equal(report.message.includes(SENTINEL_JWT_SECRET), false);
  assert.match(report.message, /\[code: E_INTERNAL_ERROR]/);
});

test('produces a static message regardless of the error thrown', () => {
  const reportA = reportInternalError(new Error('one'));
  const reportB = reportInternalError(new Error('two'));
  assert.equal(
    reportA.message.replace(/E_INTERNAL_\w+/, ''),
    reportB.message.replace(/E_INTERNAL_\w+/, ''),
  );
});
