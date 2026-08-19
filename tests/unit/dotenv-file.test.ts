import assert from 'node:assert/strict';
import {
  appendFileSync,
  chmodSync,
  closeSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readSync,
  renameSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { readDotenvFile } from '../../src/adapters/dotenv-file.js';
import { createFingerprinter } from '../../src/core/fingerprint.js';
import { createSecretRegistry } from '../../src/core/secret-registry.js';
import {
  SENTINEL_API_KEY,
  SENTINEL_DB_PASSWORD,
  SENTINEL_JWT_SECRET,
} from '../fixtures/sentinel-values.js';

function assertOk<T extends { ok: boolean }>(result: T): asserts result is T & { ok: true } {
  assert.equal(result.ok, true);
}

function assertErr<T extends { ok: boolean }>(result: T): asserts result is T & { ok: false } {
  assert.equal(result.ok, false);
}

const createdDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'procseal-dotenv-file-test-'));
  createdDirs.push(dir);
  return dir;
}

function writeEnvFile(content: string): string {
  const dir = makeTempDir();
  const filePath = join(dir, 'test.env');
  writeFileSync(filePath, content, 'utf8');
  return filePath;
}

after(() => {
  for (const dir of createdDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('reads a valid dotenv file into an opaque, comparable snapshot', () => {
  const registry = createSecretRegistry();
  const path = writeEnvFile(`JWT_SECRET=${SENTINEL_JWT_SECRET}\nPORT=4000\n`);

  const result = readDotenvFile({ path, registry });

  assertOk(result);
  assert.equal(result.snapshot.variables.length, 2);
  assert.equal(result.snapshot.meta.variableCount, 2);
  const jwt = result.snapshot.variables.find((v) => v.name === 'JWT_SECRET');
  assert.ok(jwt);
  assert.equal(jwt.value.equalsPlain(SENTINEL_JWT_SECRET), true);
  assert.equal(jwt.value.equalsPlain('something-else'), false);
  assert.equal(JSON.stringify(result).includes(SENTINEL_JWT_SECRET), false);
});

test('a nonexistent file produces a stable env_file_not_found error', () => {
  const registry = createSecretRegistry();
  const result = readDotenvFile({ path: '/nonexistent/path/does-not-exist.env', registry });
  assertErr(result);
  assert.equal(result.error.code, 'env_file_not_found');
});

test('a symlinked file is rejected as env_file_not_regular, never followed', () => {
  const registry = createSecretRegistry();
  const dir = makeTempDir();
  const targetPath = join(dir, 'real.env');
  writeFileSync(targetPath, `SECRET=${SENTINEL_API_KEY}\n`, 'utf8');
  const linkPath = join(dir, 'link.env');
  symlinkSync(targetPath, linkPath);

  const result = readDotenvFile({ path: linkPath, registry });
  assertErr(result);
  assert.equal(result.error.code, 'env_file_not_regular');
  // Never registered, since the symlink was never opened/read.
  assert.equal(registry.scrub(SENTINEL_API_KEY), SENTINEL_API_KEY);
});

test('a directory in place of a file is rejected as env_file_not_regular', () => {
  const registry = createSecretRegistry();
  const dir = makeTempDir();
  const dirAsPath = join(dir, 'not-a-file.env');
  mkdirSync(dirAsPath);

  const result = readDotenvFile({ path: dirAsPath, registry });
  assertErr(result);
  assert.equal(result.error.code, 'env_file_not_regular');
});

test('a file larger than the configured limit produces env_file_too_large, checked before reading the full content', () => {
  const registry = createSecretRegistry();
  const path = writeEnvFile(`BIG=${'x'.repeat(2000)}\n`);

  const result = readDotenvFile({ path, registry, limits: { maxFileBytes: 100 } });
  assertErr(result);
  assert.equal(result.error.code, 'env_file_too_large');
});

test('the default 1 MiB file-size limit rejects an oversized real file', () => {
  const registry = createSecretRegistry();
  // Just over 1 MiB.
  const path = writeEnvFile(`BIG=${'x'.repeat(1024 * 1024 + 10)}\n`);

  const result = readDotenvFile({ path, registry });
  assertErr(result);
  assert.equal(result.error.code, 'env_file_too_large');
});

test('malformed content (an unterminated quote) fails the whole read with env_file_malformed', () => {
  const registry = createSecretRegistry();
  const path = writeEnvFile('BROKEN="unterminated\n');

  const result = readDotenvFile({ path, registry });
  assertErr(result);
  assert.equal(result.error.code, 'env_file_malformed');
});

test('a value declared on a valid line before a malformed line is still registered before the failure is reported', () => {
  const registry = createSecretRegistry();
  const path = writeEnvFile(`GOOD_SECRET=${SENTINEL_DB_PASSWORD}\nBROKEN="unterminated\n`);

  const result = readDotenvFile({ path, registry });
  assertErr(result);
  assert.equal(result.error.code, 'env_file_malformed');
  assert.equal(
    registry.scrub(`leaked=${SENTINEL_DB_PASSWORD}`).includes(SENTINEL_DB_PASSWORD),
    false,
  );
});

test('duplicate keys fail the whole read with env_file_duplicate_key', () => {
  const registry = createSecretRegistry();
  const path = writeEnvFile('DUP=first\nDUP=second\n');

  const result = readDotenvFile({ path, registry });
  assertErr(result);
  assert.equal(result.error.code, 'env_file_duplicate_key');
});

test('exceeding the maximum variable count fails fast with env_file_too_many_variables', () => {
  const registry = createSecretRegistry();
  const path = writeEnvFile('A=1\nB=2\nC=3\n');

  const result = readDotenvFile({ path, registry, limits: { maxVariables: 2 } });
  assertErr(result);
  assert.equal(result.error.code, 'env_file_too_many_variables');
});

test('exceeding the maximum key length fails fast with env_file_key_too_long', () => {
  const registry = createSecretRegistry();
  const longKey = 'A'.repeat(50);
  const path = writeEnvFile(`${longKey}=value\n`);

  const result = readDotenvFile({ path, registry, limits: { maxKeyLength: 10 } });
  assertErr(result);
  assert.equal(result.error.code, 'env_file_key_too_long');
});

test('exceeding the maximum value size fails fast with env_file_value_too_long, never truncating and comparing a partial value', () => {
  const registry = createSecretRegistry();
  const path = writeEnvFile(`SECRET=${'x'.repeat(50)}\n`);

  const result = readDotenvFile({ path, registry, limits: { maxValueBytes: 10 } });
  assertErr(result);
  assert.equal(result.error.code, 'env_file_value_too_long');
});

test('the value limit is enforced in UTF-8 bytes, not JavaScript string length', () => {
  const registry = createSecretRegistry();
  // '€' is 1 UTF-16 code unit but 3 UTF-8 bytes.
  const multibyteValue = '€'.repeat(400);
  assert.equal(multibyteValue.length, 400);
  assert.equal(Buffer.byteLength(multibyteValue, 'utf8'), 1200);
  const path = writeEnvFile(`SECRET=${multibyteValue}\n`);

  const result = readDotenvFile({ path, registry, limits: { maxValueBytes: 500 } });
  assertErr(result);
  assert.equal(result.error.code, 'env_file_value_too_long');
});

test('a multibyte value within the byte limit is accepted and compares correctly', () => {
  const registry = createSecretRegistry();
  const multibyteValue = '€'.repeat(100); // 300 UTF-8 bytes
  const path = writeEnvFile(`SECRET=${multibyteValue}\n`);

  const result = readDotenvFile({ path, registry, limits: { maxValueBytes: 300 } });
  assertOk(result);
  const variable = result.snapshot.variables[0]!;
  assert.equal(variable.value.equalsPlain(multibyteValue), true);
});

test('an unreadable file (no read permission) produces a stable env_file_unreadable error', (t) => {
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    t.skip('running as root bypasses file permission checks');
    return;
  }
  const registry = createSecretRegistry();
  const path = writeEnvFile('SECRET=value\n');
  chmodSync(path, 0o000);

  const result = readDotenvFile({ path, registry });
  assertErr(result);
  assert.equal(result.error.code, 'env_file_unreadable');
});

test('a shared fingerprinter lets a declared value compare correctly against an independently-constructed ObservedValue', () => {
  const registry = createSecretRegistry();
  const fingerprinter = createFingerprinter();
  const path = writeEnvFile(`SECRET=${SENTINEL_JWT_SECRET}\n`);

  const result = readDotenvFile({ path, registry, fingerprinter });
  assertOk(result);
  assert.equal(result.snapshot.variables[0]!.value.equalsPlain(SENTINEL_JWT_SECRET), true);
});

test('race-safety mechanism: reading via an already-open file descriptor is immune to the file at that path being atomically replaced afterward', () => {
  // This proves the same underlying property readDotenvFile relies on
  // (open once via O_NOFOLLOW, then fstat and read via that fd only,
  // never looking the path up again) rather than reaching into the
  // adapter's internals directly. An in-place truncate-and-rewrite of the
  // *same* inode (e.g. a second writeFileSync to the same path) would
  // still be visible through an already-open fd, since both descriptors
  // share the same underlying file data — the property that matters is
  // specifically about an atomic rename-based swap, which points the path
  // at a *different* inode while an already-open fd keeps referencing the
  // original one.
  const dir = makeTempDir();
  const path = join(dir, 'race.env');
  writeFileSync(path, 'ORIGINAL=true\n', 'utf8');

  const fd = openSync(path, 'r');
  try {
    const replacement = join(dir, 'replacement.env');
    writeFileSync(replacement, 'REPLACED=true\n', 'utf8');
    renameSync(replacement, path);

    const buffer = Buffer.alloc(64);
    const bytesRead = readSync(fd, buffer, 0, buffer.length, 0);
    const content = buffer.subarray(0, bytesRead).toString('utf8');

    assert.match(content, /ORIGINAL=true/);
    assert.equal(content.includes('REPLACED'), false);
  } finally {
    closeSync(fd);
  }
});

test('adversarial: every duplicate value is registered — including the earlier, overwritten one — and neither reaches output', () => {
  const registry = createSecretRegistry();
  // Two distinct sentinels for the same key: parsed.values only keeps the
  // second (last-write-wins), but both must still be registered.
  const path = writeEnvFile(`DUP=${SENTINEL_JWT_SECRET}\nDUP=${SENTINEL_DB_PASSWORD}\n`);

  const result = readDotenvFile({ path, registry });
  assertErr(result);
  assert.equal(result.error.code, 'env_file_duplicate_key');

  assert.equal(
    registry.scrub(`first=${SENTINEL_JWT_SECRET}`).includes(SENTINEL_JWT_SECRET),
    false,
    'the earlier, overwritten duplicate value must still be registered',
  );
  assert.equal(
    registry.scrub(`final=${SENTINEL_DB_PASSWORD}`).includes(SENTINEL_DB_PASSWORD),
    false,
    'the final duplicate value must be registered',
  );

  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes(SENTINEL_JWT_SECRET), false);
  assert.equal(serialized.includes(SENTINEL_DB_PASSWORD), false);
});

test('a malformed line never leaks its content: the diagnostic detail carries no raw text, and the unparsed fragment is never registered', () => {
  const registry = createSecretRegistry();
  const path = writeEnvFile(`BROKEN="unterminated ${SENTINEL_API_KEY}\n`);

  const result = readDotenvFile({ path, registry });
  assertErr(result);
  assert.equal(result.error.code, 'env_file_malformed');
  assert.equal(
    result.error.detail !== undefined && result.error.detail.includes(SENTINEL_API_KEY),
    false,
  );
  assert.equal(JSON.stringify(result).includes(SENTINEL_API_KEY), false);
  // Never successfully parsed, so — unlike a duplicate value — it was
  // never registered either. This is the documented boundary: only
  // *successfully parsed* assignments are ever registered.
  assert.equal(
    registry.scrub(`x=${SENTINEL_API_KEY}`).includes(SENTINEL_API_KEY),
    true,
    'a fragment that never successfully parsed must not be registered',
  );
});

test('bounded read: a file that keeps growing during the read cannot cause more than maxFileBytes + 1 bytes to be buffered, and fails with env_file_too_large', () => {
  const registry = createSecretRegistry();
  const dir = makeTempDir();
  const path = join(dir, 'growing.env');
  writeFileSync(path, 'A=1\n', 'utf8');

  let hookCalls = 0;
  const result = readDotenvFile({
    path,
    registry,
    limits: { maxFileBytes: 200 },
    readChunkBytesForTesting: 20,
    onChunkReadForTesting: () => {
      hookCalls += 1;
      // Keeps the file growing faster than it can ever be fully consumed
      // — if the read loop weren't structurally bounded by its fixed
      // buffer allocation, this would never terminate.
      appendFileSync(path, `B${'x'.repeat(49)}\n`, 'utf8');
    },
  });

  assertErr(result);
  assert.equal(result.error.code, 'env_file_too_large');
  // Bounded by roughly (maxFileBytes / chunkBytes): proves the loop
  // stopped rather than reading indefinitely as the file kept growing.
  assert.ok(
    hookCalls > 0 && hookCalls < 50,
    `expected a small, bounded chunk count, got ${hookCalls}`,
  );
});

test('mutation detection: appending to the file mid-read fails closed with env_file_changed_during_read', () => {
  const registry = createSecretRegistry();
  const dir = makeTempDir();
  const path = join(dir, 'append.env');
  writeFileSync(path, `KEY=${SENTINEL_JWT_SECRET}\n`, 'utf8');

  let mutated = false;
  const result = readDotenvFile({
    path,
    registry,
    onChunkReadForTesting: () => {
      if (!mutated) {
        mutated = true;
        appendFileSync(path, 'EXTRA=appended-after-open\n', 'utf8');
      }
    },
  });

  assertErr(result);
  assert.equal(result.error.code, 'env_file_changed_during_read');
  assert.equal(mutated, true);
});

test('mutation detection: truncating the file mid-read fails closed with env_file_changed_during_read', () => {
  const registry = createSecretRegistry();
  const dir = makeTempDir();
  const path = join(dir, 'truncate.env');
  writeFileSync(path, `KEY=${SENTINEL_JWT_SECRET}\nOTHER=some-other-value\n`, 'utf8');

  let mutated = false;
  const result = readDotenvFile({
    path,
    registry,
    onChunkReadForTesting: () => {
      if (!mutated) {
        mutated = true;
        truncateSync(path, 4);
      }
    },
  });

  assertErr(result);
  assert.equal(result.error.code, 'env_file_changed_during_read');
  assert.equal(mutated, true);
});

test('mutation detection: an in-place, same-size content rewrite mid-read is caught via mtime/ctime, not size alone', () => {
  const registry = createSecretRegistry();
  const dir = makeTempDir();
  const path = join(dir, 'rewrite.env');
  const original = `KEY=${SENTINEL_JWT_SECRET}\n`;
  writeFileSync(path, original, 'utf8');
  const replacement = `${'X'.repeat(original.length - 1)}\n`;
  assert.equal(Buffer.byteLength(replacement, 'utf8'), Buffer.byteLength(original, 'utf8'));

  let mutated = false;
  const result = readDotenvFile({
    path,
    registry,
    onChunkReadForTesting: () => {
      if (!mutated) {
        mutated = true;
        writeFileSync(path, replacement, 'utf8');
      }
    },
  });

  assertErr(result);
  assert.equal(result.error.code, 'env_file_changed_during_read');
  assert.equal(mutated, true);
});

test('mutation detection does not false-positive when the file is left untouched during the read', () => {
  const registry = createSecretRegistry();
  const path = writeEnvFile(`KEY=${SENTINEL_JWT_SECRET}\n`);

  let hookCalls = 0;
  const result = readDotenvFile({
    path,
    registry,
    onChunkReadForTesting: () => {
      hookCalls += 1;
    },
  });

  assertOk(result);
  assert.ok(hookCalls > 0);
});
