export interface ParsedDotenv {
  readonly values: ReadonlyMap<string, string>;
  readonly duplicateKeys: readonly string[];
}

const LINE_PATTERN = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/;
const INLINE_COMMENT_PATTERN = /\s#/;

/**
 * Parses dotenv-style text into a plain map. This function never reads or
 * writes `process.env` — callers decide what, if anything, to do with the
 * parsed values.
 */
export function parseDotenv(content: string): ParsedDotenv {
  const values = new Map<string, string>();
  const duplicateKeys = new Set<string>();

  for (const line of content.split(/\r\n|\n|\r/)) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#')) {
      continue;
    }

    const match = LINE_PATTERN.exec(line);
    if (!match) {
      continue;
    }

    const key = match[1] as string;
    const value = parseValue(match[2] as string);

    if (values.has(key)) {
      duplicateKeys.add(key);
    }
    values.set(key, value);
  }

  return { values, duplicateKeys: [...duplicateKeys] };
}

function parseValue(raw: string): string {
  const trimmed = raw.trim();

  if (trimmed.length >= 2) {
    const first = trimmed[0];
    const last = trimmed[trimmed.length - 1];

    if (first === '"' && last === '"') {
      return unescapeDoubleQuoted(trimmed.slice(1, -1));
    }
    if (first === "'" && last === "'") {
      return trimmed.slice(1, -1);
    }
  }

  const commentMatch = INLINE_COMMENT_PATTERN.exec(trimmed);
  const withoutComment = commentMatch ? trimmed.slice(0, commentMatch.index) : trimmed;
  return withoutComment.trim();
}

function unescapeDoubleQuoted(value: string): string {
  return value
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t')
    .replace(/\\"/g, '"')
    .replace(/\\\\/g, '\\');
}
