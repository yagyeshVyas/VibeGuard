'use strict';

/*
 * The fix -> verify loop.
 *
 * `scan` can drop a baseline file. `verify` re-scans and reports, per baseline
 * finding, whether it is RESOLVED or STILL PRESENT, plus any NEW issues.
 *
 * Matching is intentionally forgiving on line numbers: after an edit, lines
 * shift. We key primarily on (ruleId + file + snippet), then fall back to
 * (ruleId + file).
 */

const fs = require('fs');
const path = require('path');
const { scan } = require('./scanner');

const BASELINE_NAME = '.vibeguard-baseline.json';

function baselinePath(root) {
  return path.join(path.resolve(root), BASELINE_NAME);
}

function writeBaseline(root, result) {
  const data = {
    generatedAt: result.generatedAt,
    grade: result.grade,
    counts: result.counts,
    findings: result.findings,
  };
  fs.writeFileSync(baselinePath(root), JSON.stringify(data, null, 2));
  return baselinePath(root);
}

function readBaseline(root) {
  try {
    return JSON.parse(fs.readFileSync(baselinePath(root), 'utf8'));
  } catch {
    return null;
  }
}

// Stable identity for a finding across edits.
function fingerprint(f) {
  return `${f.ruleId}::${f.file}::${(f.snippet || '').trim()}`;
}
function looseKey(f) {
  return `${f.ruleId}::${f.file}`;
}

/**
 * Re-scan and diff against baseline (if present).
 * If no baseline exists, we treat the *current* scan as the reference and just
 * report current state (still useful in CI right after a fix).
 */
function verify(root, opts = {}) {
  const baseline = readBaseline(root);
  const current = scan(root, opts);

  const currentFP = new Set(current.findings.map(fingerprint));
  const currentLoose = new Set(current.findings.map(looseKey));

  if (!baseline) {
    return {
      hasBaseline: false,
      current,
      resolved: [],
      remaining: current.findings,
      introduced: [],
    };
  }

  const resolved = [];
  const remaining = [];
  for (const f of baseline.findings) {
    const stillExact = currentFP.has(fingerprint(f));
    const stillLoose = currentLoose.has(looseKey(f));
    if (stillExact || stillLoose) remaining.push(f);
    else resolved.push(f);
  }

  // New issues introduced since baseline (e.g. a bad "fix").
  const baseLoose = new Set(baseline.findings.map(looseKey));
  const baseFP = new Set(baseline.findings.map(fingerprint));
  const introduced = current.findings.filter(
    (f) => !baseFP.has(fingerprint(f)) && !baseLoose.has(looseKey(f))
  );

  return { hasBaseline: true, baseline, current, resolved, remaining, introduced };
}

module.exports = {
  verify,
  writeBaseline,
  readBaseline,
  baselinePath,
  BASELINE_NAME,
};
