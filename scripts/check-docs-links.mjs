#!/usr/bin/env node
/**
 * Deterministic validation for README.md's repository-relative links and
 * assets — no network access, no external service. Checks:
 *
 * 1. Every relative markdown link/image target (`[text](path)`,
 *    `![alt](path)`) resolves to a file that actually exists in the
 *    repository. Absolute URLs (http(s)://, mailto:) are skipped.
 * 2. Every in-page anchor link (`[text](#some-heading)`) resolves to a
 *    heading actually present in the document, using GitHub's own
 *    heading-to-anchor slug algorithm (lowercase, spaces to `-`, strip
 *    characters outside `[a-z0-9_-]`, de-duplicate repeats with `-1`,
 *    `-2`, ...).
 * 3. Every referenced file under docs/assets/ that looks like an SVG is
 *    well-formed XML (a simple stack-based tag-balance check — this is
 *    not a full XML validator, but it catches unclosed/mismatched tags,
 *    which is the class of error a hand-written SVG is prone to).
 *
 * Run: node scripts/check-docs-links.mjs [file...]
 * Defaults to README.md. Exits non-zero on any failure.
 */
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const targets = process.argv.slice(2);
const files = targets.length > 0 ? targets : ['README.md'];

let failures = 0;

function slugify(heading, seen) {
  let slug = heading
    .toLowerCase()
    .trim()
    // Strip inline markdown formatting markers and code backticks before slugifying.
    .replace(/`/g, '')
    .replace(/[*_]/g, '')
    .replace(/[^\w\- ]/g, '')
    .replace(/\s+/g, '-');
  const count = seen.get(slug) ?? 0;
  seen.set(slug, count + 1);
  return count === 0 ? slug : `${slug}-${count}`;
}

function collectHeadingSlugs(content) {
  const seen = new Map();
  const slugs = new Set();
  for (const line of content.split('\n')) {
    const match = /^(#{1,6})\s+(.+)$/.exec(line);
    if (match) {
      slugs.add(slugify(match[2], seen));
    }
  }
  return slugs;
}

function checkSvgBalance(path) {
  const content = readFileSync(path, 'utf8');
  const tagPattern = /<\/?([a-zA-Z][\w:-]*)[^>]*?(\/)?>/g;
  const stack = [];
  let match;
  while ((match = tagPattern.exec(content)) !== null) {
    const [full, name, selfClose] = match;
    if (full.startsWith('<?') || full.startsWith('<!--')) continue;
    if (selfClose) continue;
    if (full.startsWith('</')) {
      const top = stack.pop();
      if (top !== name) {
        return `mismatched closing tag </${name}> (expected </${top ?? 'nothing open'}>)`;
      }
    } else {
      stack.push(name);
    }
  }
  if (stack.length > 0) {
    return `unclosed tag(s): ${stack.join(', ')}`;
  }
  return null;
}

function checkFile(file) {
  const absFile = resolve(file);
  if (!existsSync(absFile)) {
    console.error(`✗ ${file}: file does not exist`);
    failures += 1;
    return;
  }
  const content = readFileSync(absFile, 'utf8');
  const baseDir = dirname(absFile);
  const headingSlugs = collectHeadingSlugs(content);

  // Two target sources: markdown links/images `[..](target)`/`![..](target)`,
  // and raw HTML `src="target"` / `href="target"` attributes (this README
  // uses HTML for the centered hero image and badge row, which plain
  // markdown-link syntax would never catch).
  const markdownLinkPattern = /!?\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
  const htmlAttrPattern = /\b(?:src|href)="([^"]+)"/g;
  const targets = [];
  let match;
  while ((match = markdownLinkPattern.exec(content)) !== null) {
    targets.push(match[1]);
  }
  while ((match = htmlAttrPattern.exec(content)) !== null) {
    targets.push(match[1]);
  }

  let checkedLinks = 0;
  let checkedAnchors = 0;
  let checkedAssets = 0;

  for (const target of targets) {
    if (/^[a-z][a-z0-9+.-]*:/i.test(target)) {
      // Absolute URL (http://, https://, mailto:, ...) — not checked here.
      continue;
    }

    if (target.startsWith('#')) {
      checkedAnchors += 1;
      const slug = target.slice(1);
      if (!headingSlugs.has(slug)) {
        console.error(`✗ ${file}: anchor link "${target}" has no matching heading`);
        failures += 1;
      }
      continue;
    }

    const [pathPart] = target.split('#');
    if (pathPart.length === 0) continue; // pure same-file anchor already handled above
    checkedLinks += 1;
    const resolved = join(baseDir, pathPart);
    if (!existsSync(resolved)) {
      console.error(`✗ ${file}: linked path "${pathPart}" does not exist (resolved: ${resolved})`);
      failures += 1;
      continue;
    }
    if (resolved.toLowerCase().endsWith('.svg')) {
      checkedAssets += 1;
      const problem = checkSvgBalance(resolved);
      if (problem) {
        console.error(`✗ ${file}: asset "${pathPart}" is not well-formed SVG (${problem})`);
        failures += 1;
      }
    }
  }

  console.log(
    `${file}: checked ${checkedLinks} relative link(s), ${checkedAnchors} anchor(s), ${checkedAssets} SVG asset(s)`,
  );
}

for (const file of files) {
  checkFile(file);
}

if (failures > 0) {
  console.error(`\n${failures} documentation link/asset problem(s) found.`);
  process.exit(1);
}
console.log('\nAll documentation links and assets are valid.');
