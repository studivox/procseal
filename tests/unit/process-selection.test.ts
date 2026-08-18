import assert from 'node:assert/strict';
import { test } from 'node:test';
import { toSafeLabelOrRedacted } from '../../src/core/label.js';
import type { Pm2ProcessSnapshot, Pm2Snapshot } from '../../src/core/pm2-types.js';
import { isValidProcessNameSyntax, selectProcess } from '../../src/core/process-selection.js';

function makeProcess(name: string, id: number): Pm2ProcessSnapshot {
  return {
    safeProcessId: toSafeLabelOrRedacted(`proc-${id}`),
    safeName: toSafeLabelOrRedacted(name),
    pm2Id: id,
    status: 'online',
    environmentVariables: [],
  };
}

function makeSnapshot(processes: readonly Pm2ProcessSnapshot[]): Pm2Snapshot {
  return { processes, meta: { processCount: processes.length, skippedRecordCount: 0 } };
}

test('isValidProcessNameSyntax accepts conservative identifier-like names', () => {
  assert.equal(isValidProcessNameSyntax('my-app'), true);
  assert.equal(isValidProcessNameSyntax('my_app_2'), true);
  assert.equal(isValidProcessNameSyntax('app.production'), true);
  assert.equal(isValidProcessNameSyntax('A'), true);
});

test('isValidProcessNameSyntax rejects hostile or unusual input', () => {
  assert.equal(isValidProcessNameSyntax(''), false);
  assert.equal(isValidProcessNameSyntax(' leading-space'), false);
  assert.equal(isValidProcessNameSyntax('trailing-space '), false);
  assert.equal(isValidProcessNameSyntax('has space'), false);
  assert.equal(isValidProcessNameSyntax('newline\ninjected'), false);
  assert.equal(isValidProcessNameSyntax('\x1b[31mred\x1b[0m'), false);
  assert.equal(isValidProcessNameSyntax('a'.repeat(121)), false);
  assert.equal(isValidProcessNameSyntax('-starts-with-dash'), false);
});

test('selectProcess returns process_name_invalid for a syntactically invalid name, without inspecting the snapshot', () => {
  const snapshot = makeSnapshot([makeProcess('valid-app', 0)]);
  const result = selectProcess(snapshot, 'not a valid name!!');
  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.code, 'process_name_invalid');
});

test('selectProcess returns process_not_found for zero matches', () => {
  const snapshot = makeSnapshot([makeProcess('app-a', 0), makeProcess('app-b', 1)]);
  const result = selectProcess(snapshot, 'app-c');
  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.code, 'process_not_found');
});

test('selectProcess returns process_not_found for an empty snapshot', () => {
  const snapshot = makeSnapshot([]);
  const result = selectProcess(snapshot, 'anything');
  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.code, 'process_not_found');
});

test('selectProcess returns process_ambiguous for more than one match', () => {
  const snapshot = makeSnapshot([makeProcess('dup-app', 0), makeProcess('dup-app', 1)]);
  const result = selectProcess(snapshot, 'dup-app');
  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.code, 'process_ambiguous');
});

test('selectProcess returns exactly the one matching process', () => {
  const target = makeProcess('the-target', 5);
  const snapshot = makeSnapshot([makeProcess('other-app', 0), target]);
  const result = selectProcess(snapshot, 'the-target');
  assert.equal(result.ok, true);
  assert.equal(result.ok === true && result.process.pm2Id, 5);
});

test('selectProcess never matches a hostile/redacted safeName by supplying the literal placeholder', () => {
  // A process whose raw PM2 name was unsafe and got redacted has
  // safeName === "[REDACTED]" in the snapshot. The literal string
  // "[REDACTED]" cannot itself pass isValidProcessNameSyntax (it contains
  // "[" and "]"), so it can never be requested as a --process value and
  // therefore can never accidentally match a redacted entry.
  assert.equal(isValidProcessNameSyntax('[REDACTED]'), false);
});
