import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createFingerprinter } from '../../src/core/fingerprint.js';
import type { AuditResult, Finding } from '../../src/core/types.js';
import { renderJsonReport } from '../../src/reporters/json.js';
import { renderTerminalReport } from '../../src/reporters/terminal.js';
import { SENTINEL_JWT_SECRET } from '../fixtures/sentinel-values.js';

function buildResultWithFinding(): AuditResult {
  const fingerprinter = createFingerprinter();
  const finding: Finding = {
    ruleId: 'PS004',
    severity: 'high',
    message: 'Sensitive value reused across applications',
    details: {
      variable: 'JWT_SECRET',
      fingerprint: fingerprinter.fingerprint(SENTINEL_JWT_SECRET),
    },
  };
  return {
    status: 'not_implemented',
    message: 'placeholder result for reporter testing',
    findings: [finding],
    meta: { tool: 'procseal', version: '0.0.0-test', generatedAt: new Date().toISOString() },
  };
}

test('terminal reporter never includes a raw sentinel value', () => {
  const output = renderTerminalReport(buildResultWithFinding());
  assert.equal(output.includes(SENTINEL_JWT_SECRET), false);
  assert.match(output, /PS004/);
  assert.match(output, /JWT_SECRET/);
});

test('terminal reporter reports "No findings." for the placeholder audit result', () => {
  const empty: AuditResult = {
    status: 'not_implemented',
    message: 'placeholder',
    findings: [],
    meta: { tool: 'procseal', version: '0.0.0-test', generatedAt: new Date().toISOString() },
  };
  assert.match(renderTerminalReport(empty), /No findings\./);
});

test('json reporter never includes a raw sentinel value and produces valid JSON', () => {
  const output = renderJsonReport(buildResultWithFinding());
  assert.equal(output.includes(SENTINEL_JWT_SECRET), false);

  const parsed = JSON.parse(output) as { findings: Array<{ ruleId: string }> };
  assert.equal(parsed.findings[0]?.ruleId, 'PS004');
});
