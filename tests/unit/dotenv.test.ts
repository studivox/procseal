import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { parseDotenv } from '../../src/parsers/dotenv.js';

const fixturesDir = join(process.cwd(), 'tests', 'fixtures');

test('parses basic key=value pairs without mutating process.env', () => {
  const before = { ...process.env };
  const content = readFileSync(join(fixturesDir, 'basic.env'), 'utf8');

  const parsed = parseDotenv(content);

  assert.equal(parsed.values.get('PORT'), '4000');
  assert.equal(parsed.values.get('JWT_SECRET'), 'sentinel-jwt-9f13c2b7e4a1');
  assert.equal(parsed.values.get('API_KEY'), 'sentinel-api-key-77f0d3');
  assert.deepEqual({ ...process.env }, before);
});

test('handles quoted values, empty values, whitespace, comments, and duplicate keys', () => {
  const content = readFileSync(join(fixturesDir, 'quoting-and-whitespace.env'), 'utf8');

  const parsed = parseDotenv(content);

  assert.equal(parsed.values.get('SINGLE_QUOTED'), 'sentinel-single-quoted-9a1b');
  assert.equal(parsed.values.get('DOUBLE_QUOTED'), 'sentinel double quoted value with spaces');
  assert.equal(parsed.values.get('EMPTY_VALUE'), '');
  assert.equal(parsed.values.get('SPACED_KEY'), 'sentinel-spaced-value');
  assert.equal(parsed.values.get('INLINE_COMMENT'), 'sentinel-inline-value');
  assert.equal(parsed.values.get('ESCAPED_DOUBLE'), 'line-one\nline-two');

  assert.equal(parsed.values.get('DUPLICATE_KEY'), 'sentinel-duplicate-second');
  assert.deepEqual(parsed.duplicateKeys, ['DUPLICATE_KEY']);
});

test('does not mutate process.env while parsing', () => {
  const before = { ...process.env };
  parseDotenv('SOME_TEST_KEY=some-test-value\n');
  assert.deepEqual({ ...process.env }, before);
  assert.equal(process.env['SOME_TEST_KEY'], undefined);
});
