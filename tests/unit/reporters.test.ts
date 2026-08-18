import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createSecretRegistry } from '../../src/core/output-safety.js';
import { createFinding, type AuditResult, type Finding } from '../../src/core/types.js';
import { renderJsonReport } from '../../src/reporters/json.js';
import { renderTerminalReport } from '../../src/reporters/terminal.js';
import { SENTINEL_DB_PASSWORD, SENTINEL_JWT_SECRET } from '../fixtures/sentinel-values.js';

function baseResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    status: 'not_implemented',
    message: 'placeholder result for reporter testing',
    findings: [],
    meta: { tool: 'procseal', version: '0.0.0-test', generatedAt: new Date().toISOString() },
    ...overrides,
  };
}

test('renders a legitimate finding using the rule-catalog title and validated details', () => {
  const finding = createFinding({
    ruleId: 'PS004',
    severity: 'high',
    details: { variable: 'JWT_SECRET', fingerprint: 'abc123' },
  });
  const result = baseResult({ findings: [finding] });

  const terminal = renderTerminalReport(result);
  assert.match(terminal, /PS004/);
  assert.match(terminal, /reused across applications/);
  assert.match(terminal, /JWT_SECRET/);

  const json = JSON.parse(renderJsonReport(result)) as { findings: Array<{ message: string }> };
  assert.match(json.findings[0]?.message ?? '', /reused across applications/);
});

test('reports "No findings." for the placeholder audit result', () => {
  const terminal = renderTerminalReport(baseResult());
  assert.match(terminal, /No findings\./);
});

test('adversarial: a sentinel in the audit-level message is scrubbed from both reporters', () => {
  const registry = createSecretRegistry();
  registry.register(SENTINEL_JWT_SECRET);
  const malicious = baseResult({ message: `leaked secret: ${SENTINEL_JWT_SECRET}` });

  const terminal = renderTerminalReport(malicious, registry);
  const json = renderJsonReport(malicious, registry);

  assert.equal(terminal.includes(SENTINEL_JWT_SECRET), false);
  assert.equal(json.includes(SENTINEL_JWT_SECRET), false);
  assert.doesNotThrow(() => JSON.parse(json));
});

test('adversarial: a sentinel smuggled into an extra "message" property is never read or emitted', () => {
  const registry = createSecretRegistry();
  registry.register(SENTINEL_JWT_SECRET);
  // Findings have no `message` field in the type; simulate a caller bypassing
  // the type system (e.g. via an untyped adapter) to smuggle one in anyway.
  const malicious = {
    ruleId: 'PS004',
    severity: 'high',
    message: `raw secret: ${SENTINEL_JWT_SECRET}`,
  } as unknown as Finding;
  const result = baseResult({ findings: [malicious] });

  const terminal = renderTerminalReport(result, registry);
  const json = renderJsonReport(result, registry);

  assert.equal(terminal.includes(SENTINEL_JWT_SECRET), false);
  assert.equal(json.includes(SENTINEL_JWT_SECRET), false);
});

test('adversarial: a sentinel in a details metadata key is scrubbed from both reporters', () => {
  const registry = createSecretRegistry();
  registry.register(SENTINEL_JWT_SECRET);
  const malicious = {
    ruleId: 'PS004',
    severity: 'high',
    details: { [SENTINEL_JWT_SECRET]: 'some-label' },
  } as unknown as Finding;
  const result = baseResult({ findings: [malicious] });

  const terminal = renderTerminalReport(result, registry);
  const json = renderJsonReport(result, registry);

  assert.equal(terminal.includes(SENTINEL_JWT_SECRET), false);
  assert.equal(json.includes(SENTINEL_JWT_SECRET), false);
});

test('adversarial: a sentinel in a details metadata value is scrubbed from both reporters', () => {
  const registry = createSecretRegistry();
  registry.register(SENTINEL_DB_PASSWORD);
  const malicious = {
    ruleId: 'PS004',
    severity: 'high',
    details: { password: SENTINEL_DB_PASSWORD },
  } as unknown as Finding;
  const result = baseResult({ findings: [malicious] });

  const terminal = renderTerminalReport(result, registry);
  const json = renderJsonReport(result, registry);

  assert.equal(terminal.includes(SENTINEL_DB_PASSWORD), false);
  assert.equal(json.includes(SENTINEL_DB_PASSWORD), false);
});

test('adversarial: a sentinel nested inside a details value object is scrubbed from both reporters', () => {
  const registry = createSecretRegistry();
  registry.register(SENTINEL_JWT_SECRET);
  const malicious = {
    ruleId: 'PS004',
    severity: 'high',
    details: { config: { nested: { deeper: SENTINEL_JWT_SECRET } } },
  } as unknown as Finding;
  const result = baseResult({ findings: [malicious] });

  const terminal = renderTerminalReport(result, registry);
  const json = renderJsonReport(result, registry);

  assert.equal(terminal.includes(SENTINEL_JWT_SECRET), false);
  assert.equal(json.includes(SENTINEL_JWT_SECRET), false);
});

test('adversarial: an unregistered but unsafe (control-character) value never reaches raw output', () => {
  const registry = createSecretRegistry();
  const malicious = {
    ruleId: 'PS004',
    severity: 'high',
    details: { note: 'line-one\nFAKE-LOG-LINE: fabricated' },
  } as unknown as Finding;
  const result = baseResult({ findings: [malicious] });

  const terminal = renderTerminalReport(result, registry);
  assert.equal(terminal.includes('\nFAKE-LOG-LINE'), false);
});

test('JSON reporter output always parses as valid JSON, even for adversarial findings', () => {
  const registry = createSecretRegistry();
  const malicious = {
    ruleId: 'PS004',
    severity: 'high',
    details: { note: `"};malicious":"${SENTINEL_JWT_SECRET}` },
  } as unknown as Finding;
  const result = baseResult({ findings: [malicious] });

  const json = renderJsonReport(result, registry);
  assert.doesNotThrow(() => JSON.parse(json));
});
