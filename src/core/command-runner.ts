import { execFile } from 'node:child_process';

/**
 * The only outcomes a command execution can produce, as seen by callers.
 * Deliberately does not carry `stderr` or the underlying error's message:
 * the adapter that consumes this must never place raw process output or
 * error text into a diagnostic (see docs/THREAT_MODEL.md and
 * src/adapters/pm2.ts), and the cheapest way to guarantee that is to not
 * hand it the text in the first place. Classification happens once, here,
 * from Node's structured error fields (`error.code`, `error.killed`,
 * `error.signal`) — never from string content.
 */
export type CommandOutcome =
  | { readonly kind: 'success'; readonly stdout: string }
  | { readonly kind: 'binary-not-found' }
  | { readonly kind: 'timeout' }
  | { readonly kind: 'output-too-large' }
  | { readonly kind: 'process-error' };

export interface CommandRunOptions {
  /** Hard wall-clock limit for the child process. */
  readonly timeoutMs: number;
  /** Hard limit on combined stdout/stderr buffering, in bytes. */
  readonly maxBufferBytes: number;
  /**
   * Optional environment for the child process. `undefined` means "inherit
   * this process's environment," which is what lets the adapter see only
   * the current OS user's own PM2 daemon by default. Tests pass an explicit
   * isolated `PM2_HOME` here instead of mutating global `process.env`.
   */
  readonly env?: NodeJS.ProcessEnv;
}

/**
 * A command runner executes exactly one fixed binary with a fixed argument
 * array and returns a classified outcome. This is the seam the PM2 adapter
 * is injected through, so unit tests can exercise every branch (missing
 * binary, daemon unavailable, timeout, oversized output, ...) without a
 * real PM2 daemon.
 */
export type CommandRunner = (
  command: string,
  args: readonly string[],
  options: CommandRunOptions,
) => Promise<CommandOutcome>;

/**
 * The production `CommandRunner`. Uses `child_process.execFile` — never
 * `exec`, and never `spawn`/`execFile` with `shell: true` — so `command`
 * and `args` are passed as a fixed argv array to the OS, not concatenated
 * into a shell command string. There is no code path here that builds a
 * command string from untrusted input.
 */
export function createExecFileCommandRunner(): CommandRunner {
  return (command, args, { timeoutMs, maxBufferBytes, env }) =>
    new Promise<CommandOutcome>((resolve) => {
      execFile(
        command,
        args,
        {
          shell: false,
          timeout: timeoutMs,
          maxBuffer: maxBufferBytes,
          windowsHide: true,
          env,
        },
        (error, stdout) => {
          if (!error) {
            resolve({ kind: 'success', stdout });
            return;
          }

          if (error.code === 'ENOENT') {
            resolve({ kind: 'binary-not-found' });
            return;
          }

          if (error.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') {
            resolve({ kind: 'output-too-large' });
            return;
          }

          if (error.killed === true && error.signal) {
            resolve({ kind: 'timeout' });
            return;
          }

          resolve({ kind: 'process-error' });
        },
      );
    });
}
