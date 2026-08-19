import { toSafeLabelOrRedacted, type SafeLabel } from './label.js';
import type { Severity } from './severity.js';

/**
 * Stable rule identifiers. These IDs must never be renumbered or reused for a
 * different meaning once released, since downstream tooling and CI policies
 * may key off them.
 */
export const RULE_IDS = [
  'PS001',
  'PS002',
  'PS003',
  'PS004',
  'PS005',
  'PS006',
  'PS007',
  'PS008',
] as const;

export type RuleId = (typeof RULE_IDS)[number];

export interface RuleDefinition {
  readonly id: RuleId;
  readonly title: string;
}

export const RULE_DEFINITIONS: readonly RuleDefinition[] = [
  { id: 'PS001', title: 'Declared and live values differ' },
  { id: 'PS002', title: 'Declared variable is missing from the live process' },
  { id: 'PS003', title: 'Unexpected variable exists in the live process' },
  { id: 'PS004', title: 'A sensitive value appears reused across applications' },
  { id: 'PS005', title: 'Declared and live ports differ' },
  { id: 'PS006', title: 'A deployment command is a dangerous, broad PM2 operation' },
  { id: 'PS007', title: 'A configuration file appears to expose a plaintext secret' },
  { id: 'PS008', title: 'Saved PM2 dump state differs from the live process set' },
];

/**
 * Looks up the stable, catalog-defined title for a rule. Findings never
 * carry their own free-form message — the displayed title always comes
 * from here, not from caller-supplied text — which removes an entire class
 * of "a raw value ended up in a finding message" leaks. Falls back to a
 * generic label instead of throwing, so a reporter can never crash on a
 * malformed or forged `ruleId`.
 */
export function getRuleTitle(ruleId: RuleId): string {
  return RULE_DEFINITIONS.find((rule) => rule.id === ruleId)?.title ?? 'Unrecognized rule';
}

/**
 * A finding must never carry a raw configuration or secret value. There is
 * no free-form `message` field: the displayed title is always derived from
 * `getRuleTitle(ruleId)`. `details` may only hold short, validated
 * `SafeLabel` values (see core/label.ts) — key names, variable names, port
 * numbers, or derived data such as display fingerprints, never prose and
 * never a raw secret. This is enforced at construction time by
 * `createFinding`, and independently re-checked at the reporter boundary
 * (core/output-safety.ts) as defense in depth, since TypeScript's brand on
 * `SafeLabel` is erased at runtime and cannot be relied on alone.
 */
export interface Finding {
  readonly ruleId: RuleId;
  readonly severity: Severity;
  readonly details?: Readonly<Record<string, SafeLabel>>;
}

/**
 * Builds a `Finding`, normalizing every `details` key and value through
 * `toSafeLabelOrRedacted`. A caller that accidentally passes a raw
 * configuration value gets a redaction placeholder in the finding, not a
 * thrown error and not a silent pass-through of the raw value.
 */
export function createFinding(input: {
  readonly ruleId: RuleId;
  readonly severity: Severity;
  readonly details?: Readonly<Record<string, string>>;
}): Finding {
  if (!input.details) {
    return { ruleId: input.ruleId, severity: input.severity };
  }

  const details: Record<string, SafeLabel> = {};
  for (const [key, value] of Object.entries(input.details)) {
    details[toSafeLabelOrRedacted(key)] = toSafeLabelOrRedacted(value);
  }

  return { ruleId: input.ruleId, severity: input.severity, details };
}
