import { toSafeLabelOrRedacted } from './label.js';
import type { Pm2ProcessSnapshot, Pm2Snapshot } from './pm2-types.js';
import type { ProcessSelectionErrorCode } from './audit-types.js';

/**
 * Conservative allow-list for a requested `--process` value: letters,
 * digits, underscore, dot, and dash, starting with a letter/digit/
 * underscore, up to 120 characters — deliberately narrower than what PM2
 * itself permits in a process name, so a value that doesn't look like a
 * normal process identifier is rejected before it ever reaches
 * `inspectPm2`. Every character this pattern allows is also allowed by
 * `core/label.ts`'s broader `SAFE_LABEL_PATTERN`, so a name that passes
 * this check is guaranteed to equal its own `safeName` in the PM2
 * adapter's snapshot (see `buildSafeName` in src/adapters/pm2.ts) rather
 * than being redacted — which is exactly what `selectProcess` below
 * compares against. This function never touches a raw PM2 process name.
 */
const PROCESS_NAME_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,119}$/;

export function isValidProcessNameSyntax(name: string): boolean {
  return PROCESS_NAME_PATTERN.test(name);
}

export type ProcessSelectionResult =
  | { readonly ok: true; readonly process: Pm2ProcessSnapshot }
  | { readonly ok: false; readonly code: ProcessSelectionErrorCode };

/**
 * Selects exactly one PM2 process by name from an already-normalized
 * snapshot. Callers should check `isValidProcessNameSyntax` before ever
 * calling `inspectPm2` in the first place (see `commands/audit.ts`), so an
 * invalid name never triggers a PM2 invocation at all; this function
 * re-validates regardless; so it is safe to call standalone. Compares only
 * against each process's already-safe `safeName` — never a raw PM2
 * process name — and requires exactly one match: zero and more than one
 * both fail, with distinct stable codes.
 */
export function selectProcess(
  snapshot: Pm2Snapshot,
  requestedName: string,
): ProcessSelectionResult {
  if (!isValidProcessNameSyntax(requestedName)) {
    return { ok: false, code: 'process_name_invalid' };
  }

  const target = toSafeLabelOrRedacted(requestedName);
  const matches = snapshot.processes.filter((process) => process.safeName === target);

  if (matches.length === 0) {
    return { ok: false, code: 'process_not_found' };
  }
  if (matches.length > 1) {
    return { ok: false, code: 'process_ambiguous' };
  }

  return { ok: true, process: matches[0]! };
}
