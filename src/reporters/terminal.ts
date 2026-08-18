import type { AuditResult } from '../core/types.js';

/**
 * Renders a human-readable report. Only rule metadata, severities, messages,
 * and finding `details` (which must never contain raw configuration values —
 * see core/types.ts) are ever written here.
 */
export function renderTerminalReport(result: AuditResult): string {
  const lines: string[] = [];

  lines.push(`procseal ${result.meta.version}`);
  lines.push(`status: ${result.status}`);
  lines.push(result.message);
  lines.push('');

  if (result.findings.length === 0) {
    lines.push('No findings.');
    return lines.join('\n');
  }

  for (const finding of result.findings) {
    lines.push(`${finding.ruleId}  ${finding.severity.padEnd(8)}  ${finding.message}`);
    if (finding.details) {
      for (const [key, value] of Object.entries(finding.details)) {
        lines.push(`    ${key}: ${String(value)}`);
      }
    }
  }
  lines.push('');
  lines.push(`${result.findings.length} finding(s)`);

  return lines.join('\n');
}
