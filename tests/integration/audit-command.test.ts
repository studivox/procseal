import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ENV_KEY_PATTERN } from '../../src/adapters/pm2.js';
import { executeAuditCommand, parseAuditArgs } from '../../src/commands/audit.js';
import type { DotenvFileResult } from '../../src/core/dotenv-file-types.js';
import { createFingerprinter } from '../../src/core/fingerprint.js';
import { toSafeLabelOrRedacted } from '../../src/core/label.js';
import { ObservedValue } from '../../src/core/observed-value.js';
import type { Pm2AdapterResult } from '../../src/core/pm2-types.js';
import { isReuseCandidate } from '../../src/core/reuse-candidate-policy.js';
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
  return fakeLiveFleet([{ name: processName, entries }]);
}

/**
 * Like `fakeLive`, but builds every process in `processes` (sharing one
 * registry/fingerprinter across all of them, exactly like the real
 * `inspectPm2` adapter would within one run) into a single `Pm2Snapshot`
 * — needed for `--check-reuse` (PS004) tests, which compare the selected
 * process against every *other* process in the same snapshot.
 * `reuseCandidate` (and the safe/redacted variable name) is computed with
 * the same `ENV_KEY_PATTERN` gate and `isReuseCandidate` policy function
 * `normalizeEnvironment` in `src/adapters/pm2.ts` uses, not hand-picked,
 * so these tests exercise the same eligibility decision production would
 * make — including for a key name that fails `ENV_KEY_PATTERN`.
 */
function fakeLiveFleet(
  processes: ReadonlyArray<{
    readonly name: string;
    readonly entries: Readonly<Record<string, string>>;
  }>,
): typeof import('../../src/adapters/pm2.js').inspectPm2 {
  return (async (options: {
    readonly registry: { register(v: string): void };
    readonly fingerprinter?: unknown;
  }) => {
    const fingerprinter = (options.fingerprinter ?? createFingerprinter()) as ReturnType<
      typeof createFingerprinter
    >;
    const builtProcesses = processes.map((proc, index) => {
      const environmentVariables = Object.entries(proc.entries).map(([name, value]) => {
        const isValidKeyName = ENV_KEY_PATTERN.test(name);
        return {
          name: isValidKeyName ? toSafeLabelOrRedacted(name) : toSafeLabelOrRedacted(''),
          value: ObservedValue.from(value, fingerprinter, options.registry as never),
          reuseCandidate: isValidKeyName && isReuseCandidate(name, value),
        };
      });
      return {
        safeProcessId: toSafeLabelOrRedacted(`proc-${index}`),
        safeName: toSafeLabelOrRedacted(proc.name),
        pm2Id: index,
        status: 'online' as const,
        environmentVariables,
      };
    });
    return {
      ok: true,
      snapshot: {
        processes: builtProcesses,
        meta: { processCount: builtProcesses.length, skippedRecordCount: 0 },
      },
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
    {
      processName: 'my-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
      checkReuse: false,
    },
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
    {
      processName: 'my-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
      checkReuse: false,
    },
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
      checkReuse: false,
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
    {
      processName: 'my-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
      checkReuse: false,
    },
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
    {
      processName: 'my-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
      checkReuse: false,
    },
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
    {
      processName: 'ghost-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
      checkReuse: false,
    },
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
    {
      processName: 'dup-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
      checkReuse: false,
    },
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
    {
      processName: 'my-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
      checkReuse: false,
    },
    VERSION,
    deps,
  );
  assert.equal(withoutFlag.exitCode, 0);

  const withFlag = await executeAuditCommand(
    {
      processName: 'my-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: true,
      checkReuse: false,
    },
    VERSION,
    deps,
  );
  assert.equal(withFlag.exitCode, 3);
  const parsed = JSON.parse(withFlag.output) as { findings: readonly { ruleId: string }[] };
  assert.equal(parsed.findings[0]!.ruleId, 'PS003');
});

test('terminal output for a completed audit includes status, process, and finding count but no raw values', async () => {
  const { output } = await executeAuditCommand(
    {
      processName: 'my-app',
      envFilePath: '/unused',
      json: false,
      checkUnexpected: false,
      checkReuse: false,
    },
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
      { processName: 'my-app', envFilePath: '/unused', checkReuse: false, ...scenario },
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

test('PS004 is absent without --check-reuse, even when the selected process shares a sensitive value with another process', async () => {
  const shared = SENTINEL_API_KEY;
  const deps = {
    readDotenvFile: fakeDeclared({}),
    inspectPm2: fakeLiveFleet([
      { name: 'my-app', entries: { API_KEY: shared } },
      { name: 'other-app', entries: { CLIENT_SECRET: shared } },
    ]),
  };

  const { output, exitCode } = await executeAuditCommand(
    {
      processName: 'my-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
      checkReuse: false,
    },
    VERSION,
    deps,
  );
  assert.equal(exitCode, 0);
  const parsed = JSON.parse(output) as { findings: readonly { ruleId: string }[] };
  assert.deepEqual(
    parsed.findings.filter((f) => f.ruleId === 'PS004'),
    [],
  );
  assert.equal(output.includes(shared), false);
});

test('PS004 fires with --check-reuse when the selected process shares a sensitive value with another process, under a different variable name, and reveals neither value', async () => {
  const shared = SENTINEL_API_KEY;
  const deps = {
    readDotenvFile: fakeDeclared({}),
    inspectPm2: fakeLiveFleet([
      { name: 'my-app', entries: { API_KEY: shared } },
      { name: 'other-app', entries: { CLIENT_SECRET: shared } },
    ]),
  };

  const { output, exitCode } = await executeAuditCommand(
    {
      processName: 'my-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
      checkReuse: true,
    },
    VERSION,
    deps,
  );
  assert.equal(exitCode, 3);
  const parsed = JSON.parse(output) as {
    findings: ReadonlyArray<{ ruleId: string; details?: Readonly<Record<string, string>> }>;
  };
  const ps004 = parsed.findings.filter((f) => f.ruleId === 'PS004');
  assert.equal(ps004.length, 1);
  assert.deepEqual(ps004[0]!.details, { variable: 'API_KEY', reusedInApplicationCount: '1' });
  assert.equal(output.includes(shared), false);
});

test('PS004 does not fire when a sensitive value is repeated only within the selected process itself', async () => {
  const shared = SENTINEL_API_KEY;
  const deps = {
    readDotenvFile: fakeDeclared({}),
    inspectPm2: fakeLiveFleet([
      { name: 'my-app', entries: { API_KEY: shared, CLIENT_SECRET: shared } },
      { name: 'other-app', entries: { PORT: '3000' } },
    ]),
  };

  const { output, exitCode } = await executeAuditCommand(
    {
      processName: 'my-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
      checkReuse: true,
    },
    VERSION,
    deps,
  );
  assert.equal(exitCode, 0);
  const parsed = JSON.parse(output) as { findings: readonly { ruleId: string }[] };
  assert.deepEqual(parsed.findings, []);
  assert.equal(output.includes(shared), false);
});

test('PS004 does not fire for short, common, or non-sensitive values, even with matching names across processes', async () => {
  const deps = {
    readDotenvFile: fakeDeclared({}),
    inspectPm2: fakeLiveFleet([
      {
        name: 'my-app',
        entries: {
          NODE_ENV: 'production',
          PORT: '3000',
          DEBUG: 'true',
          HOST_PATH: '/var/www/app',
          API_KEY: 'short', // sensitive name, but under the minimum length
        },
      },
      {
        name: 'other-app',
        entries: {
          NODE_ENV: 'production',
          PORT: '3000',
          DEBUG: 'true',
          HOST_PATH: '/var/www/app',
          API_KEY: 'short',
        },
      },
    ]),
  };

  const { output, exitCode } = await executeAuditCommand(
    {
      processName: 'my-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
      checkReuse: true,
    },
    VERSION,
    deps,
  );
  assert.equal(exitCode, 0);
  const parsed = JSON.parse(output) as { findings: readonly { ruleId: string }[] };
  assert.deepEqual(parsed.findings, []);
});

test('PS004 with three applications sharing one value produces exactly one deterministic, deduplicated finding', async () => {
  const shared = SENTINEL_JWT_SECRET;
  const deps = {
    readDotenvFile: fakeDeclared({}),
    inspectPm2: fakeLiveFleet([
      { name: 'my-app', entries: { JWT_SECRET: shared } },
      { name: 'app-b', entries: { AUTH_TOKEN: shared } },
      { name: 'app-c', entries: { PASSWORD: shared } },
    ]),
  };

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const { output, exitCode } = await executeAuditCommand(
      {
        processName: 'my-app',
        envFilePath: '/unused',
        json: true,
        checkUnexpected: false,
        checkReuse: true,
      },
      VERSION,
      deps,
    );
    assert.equal(exitCode, 3);
    const parsed = JSON.parse(output) as {
      findings: ReadonlyArray<{ ruleId: string; details?: Readonly<Record<string, string>> }>;
    };
    const ps004 = parsed.findings.filter((f) => f.ruleId === 'PS004');
    assert.equal(ps004.length, 1);
    assert.deepEqual(ps004[0]!.details, { variable: 'JWT_SECRET', reusedInApplicationCount: '2' });
    assert.equal(output.includes(shared), false);
  }
});

test('PS004 reports multiple distinct reused values separately, without revealing either value', async () => {
  const sharedA = SENTINEL_JWT_SECRET;
  const sharedB = SENTINEL_DB_PASSWORD;
  const deps = {
    readDotenvFile: fakeDeclared({}),
    inspectPm2: fakeLiveFleet([
      { name: 'my-app', entries: { JWT_SECRET: sharedA, DB_PASSWORD: sharedB } },
      { name: 'other-app', entries: { AUTH_TOKEN: sharedA, DB_PASSWORD: sharedB } },
    ]),
  };

  const { output, exitCode } = await executeAuditCommand(
    {
      processName: 'my-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
      checkReuse: true,
    },
    VERSION,
    deps,
  );
  assert.equal(exitCode, 3);
  const parsed = JSON.parse(output) as {
    findings: ReadonlyArray<{ ruleId: string; details?: Readonly<Record<string, string>> }>;
  };
  const ps004 = parsed.findings.filter((f) => f.ruleId === 'PS004');
  assert.equal(ps004.length, 2);
  assert.deepEqual(
    ps004.map((f) => f.details),
    [
      { variable: 'DB_PASSWORD', reusedInApplicationCount: '1' },
      { variable: 'JWT_SECRET', reusedInApplicationCount: '1' },
    ],
  );
  assert.equal(output.includes(sharedA), false);
  assert.equal(output.includes(sharedB), false);
});

test('PS004 counts a cluster-mode application with four worker records as exactly one distinct application', async () => {
  const shared = SENTINEL_API_KEY;
  const deps = {
    readDotenvFile: fakeDeclared({}),
    inspectPm2: fakeLiveFleet([
      { name: 'my-app', entries: { API_KEY: shared } },
      // Four PM2 cluster-mode worker records for one OTHER application:
      // same safeName, four separate process records.
      { name: 'clustered-app', entries: { API_KEY: shared } },
      { name: 'clustered-app', entries: { API_KEY: shared } },
      { name: 'clustered-app', entries: { API_KEY: shared } },
      { name: 'clustered-app', entries: { API_KEY: shared } },
    ]),
  };

  const { output, exitCode } = await executeAuditCommand(
    {
      processName: 'my-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
      checkReuse: true,
    },
    VERSION,
    deps,
  );
  assert.equal(exitCode, 3);
  const parsed = JSON.parse(output) as {
    findings: ReadonlyArray<{ ruleId: string; details?: Readonly<Record<string, string>> }>;
  };
  const ps004 = parsed.findings.filter((f) => f.ruleId === 'PS004');
  assert.equal(ps004.length, 1);
  assert.deepEqual(ps004[0]!.details, { variable: 'API_KEY', reusedInApplicationCount: '1' });
  assert.equal(output.includes(shared), false);
});

test('--process selection rejects a name matched by multiple cluster-worker records before PS004 (or any rule) ever runs, so "the selected application has duplicate instances of itself" cannot reach evaluateReuseRule through the CLI', async () => {
  // `selectProcess` already requires exactly one process record to match
  // the requested `--process` name (see core/process-selection.ts); three
  // worker records sharing the requested name are `process_ambiguous`,
  // not a valid single selection. This means the specific "selected
  // application's own duplicate cluster-worker records" self-trigger
  // scenario can never actually reach `evaluateReuseRule` through the
  // real command pipeline — that guarantee is instead proven directly
  // against the pure rule in tests/unit/reuse-rule.test.ts, which can
  // call it with data no `--process` selection could ever produce.
  const shared = SENTINEL_API_KEY;
  const deps = {
    readDotenvFile: fakeDeclared({}),
    inspectPm2: fakeLiveFleet([
      { name: 'my-app', entries: { API_KEY: shared } },
      { name: 'my-app', entries: { API_KEY: shared } },
      { name: 'my-app', entries: { API_KEY: shared } },
    ]),
  };

  const { output, exitCode } = await executeAuditCommand(
    {
      processName: 'my-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
      checkReuse: true,
    },
    VERSION,
    deps,
  );
  assert.equal(exitCode, 1);
  const parsed = JSON.parse(output) as { status: string; code: string };
  assert.equal(parsed.status, 'failed');
  assert.equal(parsed.code, 'process_ambiguous');
  assert.equal(output.includes(shared), false);
});

test('PS004 excludes another process with an unsafe/redacted application name from the comparison', async () => {
  const shared = SENTINEL_API_KEY;
  const deps = {
    readDotenvFile: fakeDeclared({}),
    inspectPm2: fakeLiveFleet([
      { name: 'my-app', entries: { API_KEY: shared } },
      // A hostile raw PM2 name that fails SafeLabel validation and
      // therefore collapses to the redaction placeholder — must never be
      // treated as a countable application identity.
      { name: 'evil\napp-name', entries: { API_KEY: shared } },
    ]),
  };

  const { output, exitCode } = await executeAuditCommand(
    {
      processName: 'my-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
      checkReuse: true,
    },
    VERSION,
    deps,
  );
  assert.equal(exitCode, 0);
  const parsed = JSON.parse(output) as { findings: readonly { ruleId: string }[] };
  assert.deepEqual(parsed.findings, []);
  assert.equal(output.includes(shared), false);
});

test('PS004 excludes a variable whose key name fails validation from candidate eligibility, even under a sensitive-looking name', async () => {
  const shared = SENTINEL_API_KEY;
  const deps = {
    readDotenvFile: fakeDeclared({}),
    inspectPm2: fakeLiveFleet([
      // "API-SECRET" contains a dash, which fails the adapter's
      // ENV_KEY_PATTERN even though it reads as sensitive and the value
      // is long enough — it must never become a PS004 candidate.
      { name: 'my-app', entries: { 'API-SECRET': shared } },
      { name: 'other-app', entries: { 'API-SECRET': shared } },
    ]),
  };

  const { output, exitCode } = await executeAuditCommand(
    {
      processName: 'my-app',
      envFilePath: '/unused',
      json: true,
      checkUnexpected: false,
      checkReuse: true,
    },
    VERSION,
    deps,
  );
  assert.equal(exitCode, 0);
  const parsed = JSON.parse(output) as { findings: readonly { ruleId: string }[] };
  assert.deepEqual(parsed.findings, []);
  assert.equal(output.includes(shared), false);
});

test('PS004 output is unchanged by the input fleet process ordering', async () => {
  const shared = SENTINEL_JWT_SECRET;
  const forward = fakeLiveFleet([
    { name: 'my-app', entries: { JWT_SECRET: shared } },
    { name: 'app-b', entries: { AUTH_TOKEN: shared } },
    { name: 'app-c', entries: { PASSWORD: shared } },
  ]);
  const reversed = fakeLiveFleet([
    { name: 'app-c', entries: { PASSWORD: shared } },
    { name: 'app-b', entries: { AUTH_TOKEN: shared } },
    { name: 'my-app', entries: { JWT_SECRET: shared } },
  ]);

  const options = {
    processName: 'my-app',
    envFilePath: '/unused',
    json: true,
    checkUnexpected: false,
    checkReuse: true,
  };

  const forwardResult = await executeAuditCommand(options, VERSION, {
    readDotenvFile: fakeDeclared({}),
    inspectPm2: forward,
  });
  const reversedResult = await executeAuditCommand(options, VERSION, {
    readDotenvFile: fakeDeclared({}),
    inspectPm2: reversed,
  });

  const forwardParsed = JSON.parse(forwardResult.output) as { findings: unknown };
  const reversedParsed = JSON.parse(reversedResult.output) as { findings: unknown };
  assert.deepEqual(forwardParsed.findings, reversedParsed.findings);
  assert.equal(forwardResult.output.includes(shared), false);
  assert.equal(reversedResult.output.includes(shared), false);
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
    checkReuse: false,
  });
});

test('parseAuditArgs: --check-reuse is off by default and true only when explicitly passed', () => {
  const without = parseAuditArgs(['--process', 'my-app', '--env', '/some/path.env']);
  assert.equal(without.kind === 'options' && without.options.checkReuse, false);

  const withFlag = parseAuditArgs([
    '--process',
    'my-app',
    '--env',
    '/some/path.env',
    '--check-reuse',
  ]);
  assert.equal(withFlag.kind, 'options');
  assert.deepEqual(withFlag.kind === 'options' ? withFlag.options : null, {
    processName: 'my-app',
    envFilePath: '/some/path.env',
    json: false,
    checkUnexpected: false,
    checkReuse: true,
  });
});

test('parseAuditArgs: --help short-circuits regardless of other flags present', () => {
  const result = parseAuditArgs(['--json', '--help']);
  assert.equal(result.kind, 'help');
});
