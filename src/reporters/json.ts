import { getRuleTitle, type AuditResult, type Finding } from '../core/types.js';
import {
  createSecretRegistry,
  sanitizeForDisplay,
  type SecretRegistry,
} from '../core/output-safety.js';

/**
 * Renders a stable, machine-readable JSON report. Every string-bearing
 * field is passed through `sanitizeForDisplay` immediately before being
 * placed in the payload — the same final safety net the terminal reporter
 * uses — so this reporter provides equivalent protection, not weaker
 * protection just because the output happens to be JSON.
 */
export function renderJsonReport(
  result: AuditResult,
  registry: SecretRegistry = createSecretRegistry(),
): string {
  const payload = {
    status: sanitizeForDisplay(result.status, registry),
    message: sanitizeForDisplay(result.message, registry),
    findings: result.findings.map((finding) => sanitizeFinding(finding, registry)),
    meta: {
      tool: result.meta.tool,
      version: sanitizeForDisplay(result.meta.version, registry),
      generatedAt: result.meta.generatedAt,
    },
  };

  return JSON.stringify(payload, null, 2);
}

function sanitizeFinding(finding: Finding, registry: SecretRegistry) {
  return {
    ruleId: sanitizeForDisplay(finding.ruleId, registry),
    severity: sanitizeForDisplay(finding.severity, registry),
    message: sanitizeForDisplay(getRuleTitle(finding.ruleId), registry),
    details: sanitizeDetails(finding.details, registry),
  };
}

function sanitizeDetails(
  details: Finding['details'],
  registry: SecretRegistry,
): Readonly<Record<string, string>> {
  if (!details) {
    return {};
  }
  const safe: Record<string, string> = {};
  for (const [key, value] of Object.entries(details)) {
    safe[sanitizeForDisplay(key, registry)] = sanitizeForDisplay(value, registry);
  }
  return safe;
}
