import type { AuditResult } from '../core/types.js';

/**
 * Renders a stable, machine-readable JSON report. Only structured findings
 * are emitted — never raw configuration or secret values.
 */
export function renderJsonReport(result: AuditResult): string {
  const payload = {
    status: result.status,
    message: result.message,
    findings: result.findings.map((finding) => ({
      ruleId: finding.ruleId,
      severity: finding.severity,
      message: finding.message,
      details: finding.details ?? {},
    })),
    meta: result.meta,
  };

  return JSON.stringify(payload, null, 2);
}
