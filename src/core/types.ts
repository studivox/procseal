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
 * A finding must never carry a raw configuration or secret value. Only
 * key/variable names, rule metadata, and derived data such as keyed
 * fingerprints are safe to place in `details`.
 */
export interface Finding {
  readonly ruleId: RuleId;
  readonly severity: Severity;
  readonly message: string;
  readonly details?: Readonly<Record<string, string | number | boolean>>;
}

/**
 * This milestone only ever produces `not_implemented`: the PM2 adapter does
 * not exist yet, so `audit` must not claim to have inspected anything real.
 */
export type AuditStatus = 'not_implemented';

export interface AuditMeta {
  readonly tool: 'procseal';
  readonly version: string;
  readonly generatedAt: string;
}

export interface AuditResult {
  readonly status: AuditStatus;
  readonly message: string;
  readonly findings: readonly Finding[];
  readonly meta: AuditMeta;
}
