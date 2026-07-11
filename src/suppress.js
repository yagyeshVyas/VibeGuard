'use strict';

/*
 * Context-aware false positive suppression.
 *
 * Scans nearby lines for "safe context" patterns that indicate a finding
 * is a false positive. For example:
 * - eval() inside a test file (test.js) → suppress
 * - secret that looks like a placeholder/example → suppress
 * - HTTP URL in a comment → suppress
 * - Variable named "testKey" or "mockToken" → suppress
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

module.exports = { suppressFindings, isPlaceholder, isTestFile, isDocsFile, hasSafeContext };
