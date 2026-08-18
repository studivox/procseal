import type { DotenvSnapshot } from '../core/dotenv-file-types.js';
import type { Pm2ProcessSnapshot } from '../core/pm2-types.js';
import { createFinding, type Finding } from '../core/types.js';

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
}

/**
 * Compares one declared dotenv snapshot against one live PM2 process
 * snapshot and returns the findings for the rules implemented in this
 * milestone: PS001 (value differs), PS002 (declared variable missing live),
 * PS003 (unexpected live variable, opt-in only), and PS005 (PORT differs —
 * takes the place of PS001 specifically for the `PORT` key, per
 * docs/THREAT_MODEL.md). PS004, PS006, PS007, and PS008 are not
 * implemented by this function or anywhere else in this milestone.
 *
 * Pure and side-effect-free: makes no I/O, mutates neither input, and
 * never touches a raw value directly — every comparison goes through
 * `ObservedValue.equals()` (full-HMAC equality; see core/observed-value.ts
 * and core/fingerprint.ts), and every finding detail is a validated
 * `SafeLabel` variable name, never a value. PS005's finding deliberately
 * carries only the variable name (`PORT`), never either side's actual
 * port number.
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

  return findings;
}
