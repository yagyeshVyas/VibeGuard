'use strict';

/*
 * Orchestrate best-in-class external scanners when they are installed.
 *
 * VibeGuard's own rules are fast and quiet; deep dataflow/secret engines are a
 * solved problem elsewhere. Rather than reinvent them, `--deep` folds in whatever
 * is available on the machine:
 *   - semgrep  (deep dataflow / large rule packs)
 *   - gitleaks (dedicated secret detection with entropy + rulesets)
 *
 * All runs are opt-in (network/slow) and non-fatal: a missing tool is skipped
 * with a note, never an error.
 */

const { execFileSync, execSync } = require('child_process');

const isWin = process.platform === 'win32';
const TIMEOUT_MS = 180000;

function run(cmd, args, cwd) {
  const opts = { cwd, timeout: TIMEOUT_MS, maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true };
  // cmd/args are fixed literals here — no user input reaches the shell path.
  return (isWin ? execSync([cmd, ...args].join(' '), opts) : execFileSync(cmd, args, opts)).toString('utf8');
}

// -------- Semgrep ----------------------------------------------------------

const SEMGREP_SEV = { ERROR: 'high', WARNING: 'medium', INFO: 'low' };

function parseSemgrep(json) {
  const out = [];
  const results = (json && json.results) || [];
  for (const r of results) {
    const sev = SEMGREP_SEV[(r.extra && r.extra.severity) || 'WARNING'] || 'medium';
    out.push({
      ruleId: `semgrep.${r.check_id || 'finding'}`.slice(0, 80),
      severity: sev,
      confidence: 'high',
      title: 'Semgrep finding',
      message: (r.extra && r.extra.message) || r.check_id || 'Semgrep finding',
      fix: (r.extra && r.extra.fix) || 'See the Semgrep rule for remediation guidance.',
      file: r.path,
      line: (r.start && r.start.line) || 1,
      column: (r.start && r.start.col) || 1,
      snippet: (r.extra && r.extra.lines ? String(r.extra.lines) : '').slice(0, 120),
    });
  }
  return out;
}

function runSemgrep(root) {
  try {
    const out = run('semgrep', ['--config', 'auto', '--json', '--quiet', '--timeout', '60', '.'], root);
    return { findings: parseSemgrep(JSON.parse(out || '{}')), ran: true, note: null };
  } catch (err) {
    if (err && err.stdout) {
      try {
        return { findings: parseSemgrep(JSON.parse(err.stdout.toString('utf8'))), ran: true, note: null };
      } catch { /* fallthrough */ }
    }
    return { findings: [], ran: false, note: `semgrep unavailable (${err.code || err.message})` };
  }
}

// -------- gitleaks ---------------------------------------------------------

function parseGitleaks(json) {
  const out = [];
  const arr = Array.isArray(json) ? json : [];
  for (const g of arr) {
    out.push({
      ruleId: `gitleaks.${g.RuleID || 'secret'}`.slice(0, 80),
      severity: 'critical',
      confidence: 'high',
      title: 'gitleaks secret',
      message: `${g.Description || 'Secret detected'} (${g.RuleID || 'rule'}).`,
      fix: 'Remove the secret, load it from a secrets manager, and rotate it — treat it as compromised.',
      file: g.File,
      line: g.StartLine || 1,
      column: 1,
      snippet: g.Match ? String(g.Match).slice(0, 8) + '****' : 'secret',
    });
  }
  return out;
}

function runGitleaks(root) {
  try {
    // gitleaks v8: scan a directory, no git history, JSON to stdout.
    const out = run('gitleaks', ['dir', '.', '--no-banner', '--report-format', 'json', '--report-path', '-'], root);
    return { findings: parseGitleaks(JSON.parse(out || '[]')), ran: true, note: null };
  } catch (err) {
    if (err && err.stdout) {
      try {
        return { findings: parseGitleaks(JSON.parse(err.stdout.toString('utf8') || '[]')), ran: true, note: null };
      } catch { /* fallthrough */ }
    }
    return { findings: [], ran: false, note: `gitleaks unavailable (${err.code || err.message})` };
  }
}

// -------- bandit (Python) --------------------------------------------------

const BANDIT_SEV = { HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

function parseBandit(json) {
  const out = [];
  const results = (json && json.results) || [];
  for (const r of results) {
    out.push({
      ruleId: `bandit.${r.test_id || 'finding'}`,
      severity: BANDIT_SEV[r.issue_severity] || 'medium',
      confidence: (r.issue_confidence === 'LOW' ? 'low' : 'high'),
      title: 'Bandit (Python) finding',
      message: `${r.issue_text || 'Python security issue'} [${r.test_id || ''}].`,
      fix: 'See the Bandit test docs for remediation.',
      file: r.filename,
      line: r.line_number || 1,
      column: 1,
      snippet: (r.code || '').split('\n')[0].slice(0, 120),
    });
  }
  return out;
}

function runBandit(root) {
  const fs = require('fs');
  const path = require('path');
  const hasPy =
    fs.existsSync(path.join(root, 'requirements.txt')) ||
    fs.existsSync(path.join(root, 'pyproject.toml')) ||
    fs.existsSync(path.join(root, 'setup.py'));
  if (!hasPy) return { findings: [], ran: false, note: 'no python project' };
  try {
    let data;
    try {
      data = JSON.parse(run('bandit', ['-r', '.', '-f', 'json', '-q'], root) || '{}');
    } catch (err) {
      if (err && err.stdout) data = JSON.parse(err.stdout.toString('utf8') || '{}');
      else throw err;
    }
    return { findings: parseBandit(data), ran: true, note: null };
  } catch (err) {
    return { findings: [], ran: false, note: `bandit unavailable (${err.code || err.message})` };
  }
}

function runExternal(root) {
  const sg = runSemgrep(root);
  const gl = runGitleaks(root);
  const bd = runBandit(root);
  return {
    findings: [...sg.findings, ...gl.findings, ...bd.findings],
    ran: { semgrep: sg.ran, gitleaks: gl.ran, bandit: bd.ran },
    notes: [sg.note, gl.note, bd.note].filter(Boolean),
  };
}

module.exports = { runExternal, parseSemgrep, parseGitleaks, parseBandit };
