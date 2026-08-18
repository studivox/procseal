export type DotenvDiagnosticReason =
  'invalid-line' | 'unterminated-quote' | 'trailing-content-after-quote';

/**
 * A structured note about a line that could not be parsed cleanly. Never
 * carries the raw attempted value — only the line number, reason, and (when
 * known) the variable name — so a diagnostic can be logged or displayed
 * without risking a secret leak.
 */
export interface DotenvDiagnostic {
  readonly line: number;
  readonly key?: string;
  readonly reason: DotenvDiagnosticReason;
}

export interface ParsedDotenv {
  readonly values: ReadonlyMap<string, string>;
  readonly duplicateKeys: readonly string[];
  readonly diagnostics: readonly DotenvDiagnostic[];
}

const KEY_PATTERN = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/;
const INLINE_COMMENT_AFTER_QUOTE_PATTERN = /^[ \t]+#/;
const UNQUOTED_INLINE_COMMENT_PATTERN = /\s#/;

/**
 * Parses dotenv-style text into a plain map using a small hand-written
 * scanner (no regex backtracking over quoted content, no dependency).
 * Never reads or writes `process.env` — callers decide what, if anything,
 * to do with the parsed values. Malformed lines produce a structured
 * diagnostic instead of a silently-wrong value.
 */
export function parseDotenv(content: string): ParsedDotenv {
  const values = new Map<string, string>();
  const duplicateKeys = new Set<string>();
  const diagnostics: DotenvDiagnostic[] = [];

  const lines = content.split(/\r\n|\n|\r/);

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] as string;
    const lineNumber = index + 1;
    const trimmed = line.trim();

    if (trimmed.length === 0 || trimmed.startsWith('#')) {
      continue;
    }

    const keyMatch = KEY_PATTERN.exec(line);
    if (!keyMatch) {
      diagnostics.push({ line: lineNumber, reason: 'invalid-line' });
      continue;
    }

    const key = keyMatch[1] as string;
    const afterEquals = line.slice((keyMatch[0] as string).length);
    const result = parseValue(afterEquals);

    if (result.kind !== 'ok') {
      diagnostics.push({ line: lineNumber, key, reason: result.kind });
      continue;
    }

    if (values.has(key)) {
      duplicateKeys.add(key);
    }
    values.set(key, result.value);
  }

  return { values, duplicateKeys: [...duplicateKeys], diagnostics };
}

type ParseValueResult =
  | { kind: 'ok'; value: string }
  | { kind: 'unterminated-quote' }
  | { kind: 'trailing-content-after-quote' };

function parseValue(raw: string): ParseValueResult {
  const leadingTrimmed = raw.replace(/^[ \t]+/, '');

  if (leadingTrimmed.startsWith('"')) {
    return finishQuoted(leadingTrimmed, scanDoubleQuoted(leadingTrimmed));
  }

  if (leadingTrimmed.startsWith("'")) {
    return finishQuoted(leadingTrimmed, scanSingleQuoted(leadingTrimmed));
  }

  const trimmed = leadingTrimmed.trim();
  const commentMatch = UNQUOTED_INLINE_COMMENT_PATTERN.exec(trimmed);
  const withoutComment = commentMatch ? trimmed.slice(0, commentMatch.index) : trimmed;
  return { kind: 'ok', value: withoutComment.trim() };
}

function finishQuoted(text: string, scanned: QuoteScanResult | null): ParseValueResult {
  if (!scanned) {
    return { kind: 'unterminated-quote' };
  }
  const trailing = text.slice(scanned.endIndex + 1);
  if (trailing.trim().length > 0 && !INLINE_COMMENT_AFTER_QUOTE_PATTERN.test(trailing)) {
    return { kind: 'trailing-content-after-quote' };
  }
  return { kind: 'ok', value: scanned.value };
}

interface QuoteScanResult {
  readonly value: string;
  readonly endIndex: number;
}

/**
 * Scans a double-quoted value starting at index 0 of `text` (which must
 * begin with `"`). Supports `\"`, `\\`, `\n`, `\r`, and `\t` escapes; any
 * other backslash sequence is kept literally. A `#` inside the quotes is
 * just a character, never a comment marker. Returns `null` if the quote is
 * never closed on this line.
 */
function scanDoubleQuoted(text: string): QuoteScanResult | null {
  let i = 1;
  let value = '';

  while (i < text.length) {
    const ch = text[i] as string;

    if (ch === '\\' && i + 1 < text.length) {
      const next = text[i + 1] as string;
      const escaped = ESCAPE_SEQUENCES[next];
      if (escaped !== undefined) {
        value += escaped;
        i += 2;
        continue;
      }
      value += ch;
      i += 1;
      continue;
    }

    if (ch === '"') {
      return { value, endIndex: i };
    }

    value += ch;
    i += 1;
  }

  return null;
}

const ESCAPE_SEQUENCES: Readonly<Record<string, string>> = {
  '"': '"',
  '\\': '\\',
  n: '\n',
  r: '\r',
  t: '\t',
};

/**
 * Scans a single-quoted value starting at index 0 of `text` (which must
 * begin with `'`). Single-quoted values are fully literal — no escape
 * processing, matching common dotenv convention — so `#` and `\` inside
 * the quotes are just characters. Returns `null` if the quote is never
 * closed on this line.
 */
function scanSingleQuoted(text: string): QuoteScanResult | null {
  const closeIndex = text.indexOf("'", 1);
  if (closeIndex === -1) {
    return null;
  }
  return { value: text.slice(1, closeIndex), endIndex: closeIndex };
}
