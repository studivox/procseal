import type { AuditResult } from '../core/audit-types.js';
import { sanitizeForDisplay, type SecretRegistry } from '../core/output-safety.js';
import { getRuleTitle } from '../core/types.js';

/**
 * Renders a human-readable report. Every string-bearing field — including
 * ones that are structurally "safe" by type, such as `finding.severity` —
 * is passed through `sanitizeForDisplay` immediately before being written.
 * This is a deliberate final safety net: it does not assume upstream
 * validation happened, so a malformed or adversarial `AuditResult` cannot
 * leak a registered raw value through this reporter.
 *
 * `registry` is intentionally required, not optional or defaulted. A
 * default would make the secret-scrubbing boundary something a caller can
 * silently skip by omission; requiring it means a caller (e.g. a future
 * PM2 adapter) must consciously supply the run's populated registry, and
 * forgetting to do so is a compile-time error, not a silent, unprotected
 * report.
 */
export function renderTerminalReport(result: AuditResult, registry: SecretRegistry): string {
  const lines: string[] = [];

  lines.push(`procseal ${sanitizeForDisplay(result.meta.version, registry)}`);
  lines.push(`status: ${sanitizeForDisplay(result.status, registry)}`);
  if (result.code !== undefined) {
    lines.push(`code: ${sanitizeForDisplay(result.code, registry)}`);
  }
  if (result.subject !== undefined) {
    lines.push(`process: ${sanitizeForDisplay(result.subject.process, registry)}`);
  }
  lines.push(sanitizeForDisplay(result.message, registry));
  lines.push('');

  if (result.findings.length === 0) {
    lines.push('No findings.');
    return lines.join('\n');
  }

  for (const finding of result.findings) {
    const ruleId = sanitizeForDisplay(finding.ruleId, registry);
    const severity = sanitizeForDisplay(finding.severity, registry).padEnd(8);
    const title = sanitizeForDisplay(getRuleTitle(finding.ruleId), registry);
    lines.push(`${ruleId}  ${severity}  ${title}`);

    if (finding.details) {
      for (const [key, value] of Object.entries(finding.details)) {
        lines.push(
          `    ${sanitizeForDisplay(key, registry)}: ${sanitizeForDisplay(value, registry)}`,
        );
      }
    }
  }
  lines.push('');
  lines.push(`${result.findings.length} finding(s)`);

  return lines.join('\n');
}
