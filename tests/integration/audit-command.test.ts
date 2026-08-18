import assert from 'node:assert/strict';
import { test } from 'node:test';
import { executeAuditCommand, parseAuditArgs } from '../../src/commands/audit.js';
import type { DotenvFileResult } from '../../src/core/dotenv-file-types.js';
import { createFingerprinter } from '../../src/core/fingerprint.js';
import { toSafeLabelOrRedacted } from '../../src/core/label.js';
import { ObservedValue } from '../../src/core/observed-value.js';
import type { Pm2AdapterResult } from '../../src/core/pm2-types.js';
import {
  SENTINEL_API_KEY,
  SENTINEL_DB_PASSWORD,
  SENTINEL_JWT_SECRET,
} from '../fixtures/sentinel-values.js';

const VERSION = '0.0.0-test';

/**
 * Builds a `readDotenvFile`-shaped fake that, when called, constructs its
 * declared variables using the *caller-supplied* registry and
 * fingerprinter (exactly like the real adapter would) rather than a
 * pre-built, disconnected one — so these tests exercise the same
 * shared-registry/shared-fingerprinter wiring `runAuditPipeline` sets up
 * in production, not a shortcut around it.
 */
function fakeDeclared(entries: Readonly<Record<string, string>>) {
  return ((options: {
    readonly registry: { register(v: string): void };
    readonly fingerprinter?: unknown;
  }) => {
    const fingerprinter = (options.fingerprinter ?? createFingerprinter()) as ReturnType<
      typeof createFingerprinter
    >;
    const variables = Object.entries(entries).map(([name, value]) => ({
      name: toSafeLabelOrRedacted(name),
      value: ObservedValue.from(value, fingerprinter, options.registry as never),
    }));
    return { ok: true, snapshot: { variables, meta: { variableCount: variables.length } } };
  }) as unknown as typeof import('../../src/adapters/dotenv-file.js').readDotenvFile;
}

function fixedDotenvResult(
  result: DotenvFileResult,
): typeof import('../../src/adapters/dotenv-file.js').readDotenvFile {
  return () => result;
}

function fakeLive(
  processName: string,
  entries: Readonly<Record<string, string>>,
): typeof import('../../src/adapters/pm2.js').inspectPm2 {
  return (async (options: {
    readonly registry: { register(v: string): void };
    readonly fingerprinter?: unknown;
  }) => {
    const fingerprinter = (options.fingerprinter ?? createFingerprinter()) as ReturnType<
      typeof createFingerprinter
    >;
    const environmentVariables = Object.entries(entries).map(([name, value]) => ({
      name: toSafeLabelOrRedacted(name),
      value: ObservedValue.from(value, fingerprinter, options.registry as never),
    }));
    const process = {
      safeProcessId: toSafeLabelOrRedacted('proc-0'),
      safeName: toSafeLabelOrRedacted(processName),
      pm2Id: 0,
      status: 'online' as const,
      environmentVariables,
    };
    return {
      ok: true,
      snapshot: { processes: [process], meta: { processCount: 1, skippedRecordCount: 0 } },
    };
  }) as unknown as typeof import('../../src/adapters/pm2.js').inspectPm2;
}

function fixedPm2Result(
  result: Pm2AdapterResult,
): typeof import('../../src/adapters/pm2.js').inspectPm2 {
  return (async () => result) as unknown as typeof import('../../src/adapters/pm2.js').inspectPm2;
}

test('exit 0: audit completes with zero findings when declared and live values match exactly', async () => {
  const { output, exitCode } = await executeAuditCommand(
    { processName: 'my-app', envFilePath: '/unused', json: true, checkUnexpected: false },
    VERSION,
    {
      readDotenvFile: fakeDeclared({ API_KEY: 'same-value', PORT: '3000' }),
      inspectPm2: fakeLive('my-app', { API_KEY: 'same-value', PORT: '3000' }),
    },
  );

  assert.equal(exitCode, 0);
  const parsed = JSON.parse(output) as {
    status: string;
    findings: unknown[];
    subject: { process: string };
  };
  assert.equal(parsed.status, 'completed');
  assert.deepEqual(parsed.findings, []);
  assert.equal(parsed.subject.process, 'my-app');
});

test('exit 3: audit completes with findings when values differ', async () => {
  const { output, exitCode } = await executeAuditCommand(
    { processName: 'my-app', envFilePath: '/unused', json: true, checkUnexpected: false },
    VERSION,
    {
      readDotenvFile: fakeDeclared({ API_KEY: 'declared-value' }),
      inspectPm2: fakeLive('my-app', { API_KEY: 'live-value' }),
    },
  );

  assert.equal(exitCode, 3);
  const parsed = JSON.parse(output) as { status: string; findings: readonly { ruleId: string }[] };
  assert.equal(parsed.status, 'completed');
  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.findings[0]!.ruleId, 'PS001');
});

test('exit 1: an invalid --process value fails before either adapter is ever called', async () => {
  let dotenvCalled = false;
  let pm2Called = false;

  const { output, exitCode } = await executeAuditCommand(
    {
      processName: 'not a valid name!',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
    },
    VERSION,
    {
      readDotenvFile: (() => {
        dotenvCalled = true;
        return { ok: true, snapshot: { variables: [], meta: { variableCount: 0 } } };
      }) as unknown as typeof import('../../src/adapters/dotenv-file.js').readDotenvFile,
      inspectPm2: (async () => {
        pm2Called = true;
        return {
          ok: true,
          snapshot: { processes: [], meta: { processCount: 0, skippedRecordCount: 0 } },
        };
      }) as unknown as typeof import('../../src/adapters/pm2.js').inspectPm2,
    },
  );

  assert.equal(exitCode, 1);
  assert.equal(dotenvCalled, false);
  assert.equal(pm2Called, false);
  const parsed = JSON.parse(output) as { status: string; code: string };
  assert.equal(parsed.status, 'failed');
  assert.equal(parsed.code, 'process_name_invalid');
});

test('exit 1: a dotenv-file failure fails before PM2 is ever called, and carries the requested process as subject', async () => {
  let pm2Called = false;

  const { output, exitCode } = await executeAuditCommand(
    { processName: 'my-app', envFilePath: '/unused', json: true, checkUnexpected: false },
    VERSION,
    {
      readDotenvFile: fixedDotenvResult({ ok: false, error: { code: 'env_file_not_found' } }),
      inspectPm2: (async () => {
        pm2Called = true;
        return {
          ok: true,
          snapshot: { processes: [], meta: { processCount: 0, skippedRecordCount: 0 } },
        };
      }) as unknown as typeof import('../../src/adapters/pm2.js').inspectPm2,
    },
  );

  assert.equal(exitCode, 1);
  assert.equal(pm2Called, false);
  const parsed = JSON.parse(output) as {
    status: string;
    code: string;
    subject: { process: string };
  };
  assert.equal(parsed.status, 'failed');
  assert.equal(parsed.code, 'env_file_not_found');
  assert.equal(parsed.subject.process, 'my-app');
});

test('exit 1: a PM2 adapter failure is surfaced with its own stable code', async () => {
  const { output, exitCode } = await executeAuditCommand(
    { processName: 'my-app', envFilePath: '/unused', json: true, checkUnexpected: false },
    VERSION,
    {
      readDotenvFile: fixedDotenvResult({
        ok: true,
        snapshot: { variables: [], meta: { variableCount: 0 } },
      }),
      inspectPm2: fixedPm2Result({ ok: false, error: { code: 'daemon_unavailable' } }),
    },
  );

  assert.equal(exitCode, 1);
  const parsed = JSON.parse(output) as { status: string; code: string };
  assert.equal(parsed.status, 'failed');
  assert.equal(parsed.code, 'daemon_unavailable');
});

test('exit 1: zero matching processes produces process_not_found', async () => {
  const { output, exitCode } = await executeAuditCommand(
    { processName: 'ghost-app', envFilePath: '/unused', json: true, checkUnexpected: false },
    VERSION,
    {
      readDotenvFile: fixedDotenvResult({
        ok: true,
        snapshot: { variables: [], meta: { variableCount: 0 } },
      }),
      inspectPm2: fixedPm2Result({
        ok: true,
        snapshot: { processes: [], meta: { processCount: 0, skippedRecordCount: 0 } },
      }),
    },
  );

  assert.equal(exitCode, 1);
  const parsed = JSON.parse(output) as { status: string; code: string };
  assert.equal(parsed.code, 'process_not_found');
});

test('exit 1: more than one matching process produces process_ambiguous', async () => {
  const dup = {
    safeProcessId: toSafeLabelOrRedacted('proc-0'),
    safeName: toSafeLabelOrRedacted('dup-app'),
    pm2Id: 0,
    status: 'online' as const,
    environmentVariables: [],
  };

  const { output, exitCode } = await executeAuditCommand(
    { processName: 'dup-app', envFilePath: '/unused', json: true, checkUnexpected: false },
    VERSION,
    {
      readDotenvFile: fixedDotenvResult({
        ok: true,
        snapshot: { variables: [], meta: { variableCount: 0 } },
      }),
      inspectPm2: fixedPm2Result({
        ok: true,
        snapshot: {
          processes: [dup, { ...dup, pm2Id: 1 }],
          meta: { processCount: 2, skippedRecordCount: 0 },
        },
      }),
    },
  );

  assert.equal(exitCode, 1);
  const parsed = JSON.parse(output) as { status: string; code: string };
  assert.equal(parsed.code, 'process_ambiguous');
});

test('PS003 is absent by default and present only with checkUnexpected: true, through the full pipeline', async () => {
  const deps = {
    readDotenvFile: fakeDeclared({}),
    inspectPm2: fakeLive('my-app', { UNEXPECTED: 'value' }),
  };

  const withoutFlag = await executeAuditCommand(
    { processName: 'my-app', envFilePath: '/unused', json: true, checkUnexpected: false },
    VERSION,
    deps,
  );
  assert.equal(withoutFlag.exitCode, 0);

  const withFlag = await executeAuditCommand(
    { processName: 'my-app', envFilePath: '/unused', json: true, checkUnexpected: true },
    VERSION,
    deps,
  );
  assert.equal(withFlag.exitCode, 3);
  const parsed = JSON.parse(withFlag.output) as { findings: readonly { ruleId: string }[] };
  assert.equal(parsed.findings[0]!.ruleId, 'PS003');
});

test('terminal output for a completed audit includes status, process, and finding count but no raw values', async () => {
  const { output } = await executeAuditCommand(
    { processName: 'my-app', envFilePath: '/unused', json: false, checkUnexpected: false },
    VERSION,
    {
      readDotenvFile: fakeDeclared({ SECRET: SENTINEL_JWT_SECRET }),
      inspectPm2: fakeLive('my-app', { SECRET: 'a-completely-different-live-value' }),
    },
  );

  assert.match(output, /status: completed/);
  assert.match(output, /process: my-app/);
  assert.match(output, /PS001/);
  assert.equal(output.includes(SENTINEL_JWT_SECRET), false);
});

test('adversarial: sentinel declared and live values never reach JSON output, terminal output, or the failure path, regardless of outcome', async () => {
  const scenarios: ReadonlyArray<{
    readonly json: boolean;
    readonly checkUnexpected: boolean;
  }> = [
    { json: true, checkUnexpected: false },
    { json: false, checkUnexpected: false },
    { json: true, checkUnexpected: true },
    { json: false, checkUnexpected: true },
  ];

  for (const scenario of scenarios) {
    const { output } = await executeAuditCommand(
      { processName: 'my-app', envFilePath: '/unused', ...scenario },
      VERSION,
      {
        readDotenvFile: fakeDeclared({
          JWT_SECRET: SENTINEL_JWT_SECRET,
          DB_PASSWORD: SENTINEL_DB_PASSWORD,
        }),
        inspectPm2: fakeLive('my-app', {
          JWT_SECRET: `${SENTINEL_JWT_SECRET}-different`,
          API_KEY: SENTINEL_API_KEY,
        }),
      },
    );

    assert.equal(output.includes(SENTINEL_JWT_SECRET), false);
    assert.equal(output.includes(SENTINEL_DB_PASSWORD), false);
    assert.equal(output.includes(SENTINEL_API_KEY), false);
  }
});

test('parseAuditArgs: --process and --env are both required; a bare "audit" invocation is a usage error', () => {
  const result = parseAuditArgs([]);
  assert.equal(result.kind, 'usage-error');
});

test('parseAuditArgs: accepts --process, --env, --json, and --check-unexpected together in any combination', () => {
  const result = parseAuditArgs([
    '--json',
    '--process',
    'my-app',
    '--check-unexpected',
    '--env',
    '/some/path.env',
  ]);
  assert.equal(result.kind, 'options');
  assert.deepEqual(result.kind === 'options' ? result.options : null, {
    processName: 'my-app',
    envFilePath: '/some/path.env',
    json: true,
    checkUnexpected: true,
  });
});

test('parseAuditArgs: --help short-circuits regardless of other flags present', () => {
  const result = parseAuditArgs(['--json', '--help']);
  assert.equal(result.kind, 'help');
});
