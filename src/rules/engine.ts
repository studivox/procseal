import type { DotenvSnapshot } from '../core/dotenv-file-types.js';
import type { Pm2ProcessSnapshot } from '../core/pm2-types.js';
import { createFinding, type Finding } from '../core/types.js';
import { evaluateReuseRule } from './reuse.js';

/**
 * The exact declared key this milestone treats specially. Case-sensitive,
 * matching conventional `process.env.PORT` usage — deliberately not
 * case-insensitive, to keep matching simple and predictable rather than
 * guessing at declaration style.
 */
const PORT_VARIABLE_NAME = 'PORT';

export interface EvaluateRulesInput {
  readonly declared: DotenvSnapshot;
  readonly live: Pm2ProcessSnapshot;
  /** PS003 (unexpected live variable) only ever fires when this is true — see `--check-unexpected` in commands/audit.ts. */
  readonly checkUnexpected: boolean;
  /** PS004 (cross-application sensitive-value reuse) only ever fires when this is true — see `--check-reuse` in commands/audit.ts. Without it, `allProcesses` is accepted but never read. */
  readonly checkReuse: boolean;
  /**
   * Every PM2 process in the current run's snapshot, including `live`
   * itself. Required (not optional) so a caller can never accidentally
   * omit it and get a silently-incomplete PS004 comparison; only read
   * when `checkReuse` is true. See `src/rules/reuse.ts`.
   */
  readonly allProcesses: readonly Pm2ProcessSnapshot[];
}

/**
 * Compares one declared dotenv snapshot against one live PM2 process
 * snapshot and returns the findings for the rules implemented so far:
 * PS001 (value differs), PS002 (declared variable missing live), PS003
 * (unexpected live variable, opt-in only), PS004 (cross-application
 * sensitive-value reuse, opt-in only — see `src/rules/reuse.ts`), and
 * PS005 (PORT differs — takes the place of PS001 specifically for the
 * `PORT` key, per docs/THREAT_MODEL.md). PS006, PS007, and PS008 are not
 * implemented by this function or anywhere else in this milestone.
 *
 * Pure and side-effect-free: makes no I/O, mutates neither input, and
 * never touches a raw value directly — every comparison goes through
 * `ObservedValue.equals()` (full-HMAC equality; see core/observed-value.ts
 * and core/fingerprint.ts), and every finding detail is a validated
 * `SafeLabel` variable name (or, for PS004, an additional safe numeric
 * count), never a value. PS005's finding deliberately carries only the
 * variable name (`PORT`), never either side's actual port number.
 *
 * Findings are returned in a fixed order: PS001/PS002/PS005 in declared-
 * variable iteration order, then PS003 (when enabled) in live-variable
 * iteration order, then PS004 (when enabled) last, internally sorted by
 * variable name — see `evaluateReuseRule`'s own ordering guarantee.
 */
export function evaluateRules(input: EvaluateRulesInput): readonly Finding[] {
  const findings: Finding[] = [];
  const liveByName = new Map(input.live.environmentVariables.map((v) => [v.name, v.value]));

  for (const declaredVar of input.declared.variables) {
    const liveValue = liveByName.get(declaredVar.name);

    if (liveValue === undefined) {
      findings.push(
        createFinding({
          ruleId: 'PS002',
          severity: 'high',
          details: { variable: declaredVar.name },
        }),
      );
      continue;
    }

    if (declaredVar.value.equals(liveValue)) {
      continue;
    }

    if (declaredVar.name === PORT_VARIABLE_NAME) {
      findings.push(
        createFinding({
          ruleId: 'PS005',
          severity: 'medium',
          details: { variable: declaredVar.name },
        }),
      );
    } else {
      findings.push(
        createFinding({
          ruleId: 'PS001',
          severity: 'high',
          details: { variable: declaredVar.name },
        }),
      );
    }
  }

  if (input.checkUnexpected) {
    const declaredNames = new Set(input.declared.variables.map((v) => v.name));
    for (const liveVar of input.live.environmentVariables) {
      if (!declaredNames.has(liveVar.name)) {
        findings.push(
          createFinding({
            ruleId: 'PS003',
            severity: 'low',
            details: { variable: liveVar.name },
          }),
        );
      }
    }
  }

  if (input.checkReuse) {
    findings.push(...evaluateReuseRule(input.live, input.allProcesses));
  }

  return findings;
}
