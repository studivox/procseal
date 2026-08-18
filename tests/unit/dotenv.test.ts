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
  assert.deepEqual(parsed.diagnostics, []);
});

test('does not mutate process.env while parsing', () => {
  const before = { ...process.env };
  parseDotenv('SOME_TEST_KEY=some-test-value\n');
  assert.deepEqual({ ...process.env }, before);
  assert.equal(process.env['SOME_TEST_KEY'], undefined);
});

test('strips a trailing comment after a double-quoted value', () => {
  const parsed = parseDotenv('KEY="synthetic-value" # trailing comment\n');
  assert.equal(parsed.values.get('KEY'), 'synthetic-value');
  assert.deepEqual(parsed.diagnostics, []);
});

test('strips a trailing comment after a single-quoted value', () => {
  const parsed = parseDotenv("KEY='synthetic-value' # trailing comment\n");
  assert.equal(parsed.values.get('KEY'), 'synthetic-value');
  assert.deepEqual(parsed.diagnostics, []);
});

test('treats a hash inside double quotes as a literal character, not a comment', () => {
  const parsed = parseDotenv('KEY="synthetic # value not a comment"\n');
  assert.equal(parsed.values.get('KEY'), 'synthetic # value not a comment');
  assert.deepEqual(parsed.diagnostics, []);
});

test('treats a hash inside single quotes as a literal character, not a comment', () => {
  const parsed = parseDotenv("KEY='synthetic # value not a comment'\n");
  assert.equal(parsed.values.get('KEY'), 'synthetic # value not a comment');
  assert.deepEqual(parsed.diagnostics, []);
});

test('unescapes an escaped double quote inside a double-quoted value', () => {
  const parsed = parseDotenv('KEY="a \\"quoted\\" word"\n');
  assert.equal(parsed.values.get('KEY'), 'a "quoted" word');
});

test('keeps a backslash literal inside a single-quoted value (no escape processing)', () => {
  const parsed = parseDotenv("KEY='a \\backslash word'\n");
  assert.equal(parsed.values.get('KEY'), 'a \\backslash word');
});

test('parses an empty double-quoted value', () => {
  const parsed = parseDotenv('KEY=""\n');
  assert.equal(parsed.values.get('KEY'), '');
  assert.deepEqual(parsed.diagnostics, []);
});

test('parses an empty single-quoted value', () => {
  const parsed = parseDotenv("KEY=''\n");
  assert.equal(parsed.values.get('KEY'), '');
  assert.deepEqual(parsed.diagnostics, []);
});

test('handles CRLF line endings', () => {
  const parsed = parseDotenv('FIRST=synthetic-one\r\nSECOND=synthetic-two\r\n');
  assert.equal(parsed.values.get('FIRST'), 'synthetic-one');
  assert.equal(parsed.values.get('SECOND'), 'synthetic-two');
});

test('supports the export keyword before a key', () => {
  const parsed = parseDotenv('export KEY=synthetic-value\n');
  assert.equal(parsed.values.get('KEY'), 'synthetic-value');
});

test('records duplicate keys, keeping the last value', () => {
  const parsed = parseDotenv('KEY=first\nKEY=second\nKEY=third\n');
  assert.equal(parsed.values.get('KEY'), 'third');
  assert.deepEqual(parsed.duplicateKeys, ['KEY']);
});

test('reports an unterminated double-quoted value as a diagnostic without a value', () => {
  const parsed = parseDotenv('KEY="unterminated\n');
  assert.equal(parsed.values.has('KEY'), false);
  assert.deepEqual(parsed.diagnostics, [{ line: 1, key: 'KEY', reason: 'unterminated-quote' }]);
});

test('reports an unterminated single-quoted value as a diagnostic without a value', () => {
  const parsed = parseDotenv("KEY='unterminated\n");
  assert.equal(parsed.values.has('KEY'), false);
  assert.deepEqual(parsed.diagnostics, [{ line: 1, key: 'KEY', reason: 'unterminated-quote' }]);
});

test('reports trailing content after a closed quote as a diagnostic without a misleading value', () => {
  const parsed = parseDotenv('KEY="value"garbage\n');
  assert.equal(parsed.values.has('KEY'), false);
  assert.deepEqual(parsed.diagnostics, [
    { line: 1, key: 'KEY', reason: 'trailing-content-after-quote' },
  ]);
});

test('reports a malformed line with no "=" as an invalid-line diagnostic', () => {
  const parsed = parseDotenv('THIS_IS_NOT_KEY_VALUE\n');
  assert.equal(parsed.values.size, 0);
  assert.deepEqual(parsed.diagnostics, [{ line: 1, reason: 'invalid-line' }]);
});

// Unquoted-hash convention (documented in parsers/dotenv.ts): outside
// quotes the first unescaped "#" always begins a comment, whether or not
// it is preceded by whitespace. Inside either quote style "#" is always
// literal.
test('KEY=value#comment strips the comment even with no preceding whitespace', () => {
  const parsed = parseDotenv('KEY=value#comment\n');
  assert.equal(parsed.values.get('KEY'), 'value');
});

test('KEY=value # comment strips a whitespace-separated comment', () => {
  const parsed = parseDotenv('KEY=value # comment\n');
  assert.equal(parsed.values.get('KEY'), 'value');
});

test('KEY=#comment parses to an empty value', () => {
  const parsed = parseDotenv('KEY=#comment\n');
  assert.equal(parsed.values.get('KEY'), '');
});

test('KEY="value#literal" keeps the hash literal inside double quotes', () => {
  const parsed = parseDotenv('KEY="value#literal"\n');
  assert.equal(parsed.values.get('KEY'), 'value#literal');
});

test("KEY='value#literal' keeps the hash literal inside single quotes", () => {
  const parsed = parseDotenv("KEY='value#literal'\n");
  assert.equal(parsed.values.get('KEY'), 'value#literal');
});

test('a diagnostic never carries the raw attempted value', () => {
  const parsed = parseDotenv('SECRET="unterminated-sentinel-value-should-not-appear\n');
  for (const diagnostic of parsed.diagnostics) {
    const serialized = JSON.stringify(diagnostic);
    assert.equal(serialized.includes('unterminated-sentinel-value-should-not-appear'), false);
  }
});
