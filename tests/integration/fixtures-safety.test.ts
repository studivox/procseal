import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const SUSPICIOUS_PATTERNS: readonly RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /AKIA[0-9A-Z]{16}/,
  /ghp_[0-9A-Za-z]{36}/,
  /sk-[A-Za-z0-9]{20,}/,
  /xox[baprs]-[0-9A-Za-z-]{10,}/,
];

function trackedFiles(pathspec?: string): string[] {
  const args = pathspec ? ['ls-files', pathspec] : ['ls-files'];
  return execFileSync('git', args, { encoding: 'utf8' })
    .split('\n')
    .filter((line: string) => line.length > 0);
}

test('tracked files contain no known real-credential patterns', () => {
  for (const file of trackedFiles()) {
    const content = readFileSync(file, 'utf8');
    for (const pattern of SUSPICIOUS_PATTERNS) {
      assert.equal(
        pattern.test(content),
        false,
        `${file} matched suspicious credential pattern ${pattern}`,
      );
    }
  }
});

test('tracked env fixtures declare themselves synthetic', () => {
  const envFixtures = trackedFiles('tests/fixtures').filter((file) => file.endsWith('.env'));
  assert.ok(envFixtures.length > 0, 'expected at least one tracked .env fixture');

  for (const file of envFixtures) {
    const content = readFileSync(file, 'utf8');
    assert.match(content, /SYNTHETIC/i, `${file} does not declare itself synthetic`);
  }
});
