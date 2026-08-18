import type { CommandOutcome, CommandRunner } from '../../src/core/command-runner.js';

/**
 * Synthetic stand-ins for a `pm2 jlist` process record. Only the fields the
 * adapter actually reads are modeled; real `pm2 jlist` output has many more
 * (raw command lines, paths, monit stats, ...) which the adapter never
 * reads into its normalized snapshot — see src/core/pm2-types.ts.
 */
export interface Pm2JlistEntryOptions {
  readonly name?: string;
  readonly pm_id?: number;
  readonly status?: string;
  readonly env?: Record<string, unknown>;
  readonly omitPm2Env?: boolean;
  readonly omitEnv?: boolean;
}

export function pm2JlistEntry(options: Pm2JlistEntryOptions = {}): Record<string, unknown> {
  if (options.omitPm2Env) {
    return {
      name: options.name ?? 'sample-app',
      pm_id: options.pm_id ?? 0,
      pid: 12345,
    };
  }

  return {
    name: options.name ?? 'sample-app',
    pm_id: options.pm_id ?? 0,
    pid: 12345,
    pm2_env: {
      status: options.status ?? 'online',
      ...(options.omitEnv ? {} : { env: options.env ?? {} }),
    },
  };
}

/** A command runner that always returns the given fixed outcome, ignoring its arguments. */
export function fixtureRunner(outcome: CommandOutcome): CommandRunner {
  return () => Promise.resolve(outcome);
}

/** A successful-run fixture whose stdout is `JSON.stringify(payload)`. */
export function stdoutRunner(payload: unknown): CommandRunner {
  return fixtureRunner({ kind: 'success', stdout: JSON.stringify(payload) });
}

/** A successful-run fixture with literal, pre-serialized stdout text. */
export function rawStdoutRunner(raw: string): CommandRunner {
  return fixtureRunner({ kind: 'success', stdout: raw });
}
