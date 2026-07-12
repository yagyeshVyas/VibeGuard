'use strict';

/*
 * Context-aware false positive suppression + inline suppression comments.
 *
 * Inline suppression syntax (two forms):
 *   // vibeguard-ignore-line [rule1, rule2]            -> suppress on this line
 *   // vibeguard-ignore-next-line [rule1, ...]         -> suppress on the next line
 *   // vibeguard-ignore[ruleId]: reason                 -> suppress ruleId on this line
 *   // vibeguard-ignore-next[ruleId]: reason            -> suppress ruleId on the next line
 * No rule list = suppress everything on the target line. Works with //, #, /* *.
 *
 * Suppressed findings are dropped from output but counted as `suppressedCount`
 * on the scan result (see scanner.js). --show-suppressed re-adds them.
 *
 * This runs AFTER rule matching, BEFORE findings are returned.
 */

const PLACEHOLDER_PATTERNS = [
  /(?:your[_-]?(?:api[_-]?key|token|secret)|placeholder|changeme|todo|fixme|xxx+|replace[_-]?me|insert[_-]?key|redacted|redact)/i,
  /^(?:test|spec|mock|fixture|__test__|__fixtures__)\//i,
];

const SAFE_CONTEXT_LINES = 3;

const FILE_CONTEXT = {
  test: /(?:^|\/)(?:test|spec|__tests__|\.test\.|\.spec\.|tests\/|_test\.)/i,
  docs: /(?:\.md$|\.txt$|README|CHANGELOG|CONTRIBUTING|LICENSE)/i,
  config: /(?:\.config\.|\.rc\.|config\.js$|config\.ts$)/i,
  example: /(?:example|demo|sample|tutorial)/i,
};

function isPlaceholder(line) {
  for (const p of PLACEHOLDER_PATTERNS) {
    if (p.test(line)) return true;
  }
  return false;
}

function isTestFile(relPath) {
  return FILE_CONTEXT.test.test(relPath) || FILE_CONTEXT.example.test(relPath);
}

function isDocsFile(relPath) {
  return FILE_CONTEXT.docs.test(relPath);
}

function hasSafeContext(lines, idx, ruleId) {
  const start = Math.max(0, idx - SAFE_CONTEXT_LINES);
  const end = Math.min(lines.length, idx + SAFE_CONTEXT_LINES + 1);
  const context = lines.slice(start, end).join('\n').toLowerCase();

  // If the surrounding code has try/catch or validation, some rules can be suppressed
  if (ruleId === 'injection.eval' || ruleId === 'code.eval') {
    if (/\b(?:json\.parse|function\s+\w+\s*\(|safe|sanitiz|escape|validate)\b/i.test(context)) return true;
  }

  // If there's a comment indicating intentional use
  if (/(?:eslint-disable|@vibeguard-ignore|@ts-ignore|istanbul ignore|coverage ignore)/i.test(context)) return true;

  // If it's inside a typeof check
  if (typeof lines[idx] === 'string' && /typeof\s+\w+\s*===?\s*['"]/.test(context)) return true;

  return false;
}

function suppressFindings(findings, content, relPath) {
  if (!findings || findings.length === 0) return findings;
  const lines = content ? content.split(/\r?\n/) : [];
  const isTest = isTestFile(relPath);
  const isDocs = isDocsFile(relPath);

  return findings.filter((f) => {
    // Only suppress in docs files — never suppress findings in actual code
    if (isDocs && !f.ruleId.startsWith('secret.')) return false;

    // Only suppress placeholder secrets — check the actual line content
    if (f.ruleId.startsWith('secret.')) {
      const lineIdx = f.line ? f.line - 1 : -1;
      const line = lineIdx >= 0 && lineIdx < lines.length ? lines[lineIdx] : '';
      if (isPlaceholder(line)) return false;
    }

    // Do NOT suppress findings in test files — tests expect specific findings
    // Do NOT suppress based on "safe context" — too many false negatives
    // Do NOT suppress low confidence — let the scanner's own confidence handle it

    return true;
  });
}

// Parse inline suppression comments from file lines.
// Returns a Map: targetLine(1-based) -> Set(ruleIds) | '*'
// Also returns the raw suppressed entries for --show-suppressed.
//
// Supports both forms:
//   // vibeguard-ignore-line [rule1, rule2]
//   // vibeguard-ignore-next-line [rule1, ...]
//   // vibeguard-ignore[ruleId]: reason
//   // vibeguard-ignore-next[ruleId]: reason
function buildIgnoreMap(lines) {
  const map = new Map(); // targetLine(1-based) -> Set(ruleIds) | '*'
  // Old syntax: vibeguard-ignore(-next)?-line [rules]
  const reOld = /(?:\/\/|#|\/\*|\*)\s*vibeguard-ignore(-next)?-line\b([^*\n]*)/i;
  // New syntax: vibeguard-ignore[ruleId]: reason  (or vibeguard-ignore-next[ruleId]: reason)
  // Must NOT match vibeguard-ignore-line or vibeguard-ignore-next-line (old syntax).
  const reNew = /(?:\/\/|#|\/\*|\*)\s*vibeguard-ignore(?:-(next))?(?!\s*-line)\[([^\]]+)\]\s*:?\s*(.*)/i;

  for (let i = 0; i < lines.length; i++) {
    // Check new syntax first (more specific).
    const mNew = reNew.exec(lines[i]);
    if (mNew) {
      const target = mNew[1] === 'next' ? i + 2 : i + 1;
      const ruleId = mNew[2].trim();
      const existing = map.get(target);
      if (existing === '*') continue;
      if (ruleId === '*') { map.set(target, '*'); continue; }
      map.set(target, new Set([...(existing || []), ruleId]));
      continue;
    }
    // Check old syntax.
    const mOld = reOld.exec(lines[i]);
    if (mOld) {
      const target = mOld[1] ? i + 2 : i + 1;
      const rulesPart = (mOld[2] || '').replace(/\*\/.*/, '').trim();
      // Strip surrounding brackets if present: [rule1, rule2] -> rule1, rule2
      const cleaned = rulesPart.replace(/^\[|\]$/g, '').trim();
      const rules = cleaned ? cleaned.split(/[\s,]+/).filter(Boolean) : '*';
      const existing = map.get(target);
      if (existing === '*' || rules === '*') { map.set(target, '*'); continue; }
      map.set(target, new Set([...(existing || []), ...rules]));
    }
  }
  return map;
}

// Apply inline suppressions to findings. Returns { kept, suppressed }.
// `suppressed` findings are annotated with `suppressed: true` and `suppressionReason`.
function applyInlineSuppressionsWithCount(findings, contents) {
  const byFile = new Map();
  for (const c of contents) byFile.set(c.rel, buildIgnoreMap(c.lines));
  const kept = [];
  const suppressed = [];
  for (const f of findings) {
    const map = byFile.get(f.file);
    if (!map) { kept.push(f); continue; }
    const entry = map.get(f.line);
    if (!entry) { kept.push(f); continue; }
    const isSuppressed = entry === '*' || entry.has(f.ruleId);
    if (isSuppressed) {
      suppressed.push({ ...f, suppressed: true });
    } else {
      kept.push(f);
    }
  }
  return { kept, suppressed };
}

module.exports = { suppressFindings, isPlaceholder, isTestFile, isDocsFile, hasSafeContext, buildIgnoreMap, applyInlineSuppressionsWithCount };
