'use strict';

/*
 * Dependency vulnerability scanning.
 *
 * We do NOT reinvent an advisory database. We shell out to the tools that already
 * do this well — `npm audit --json` and `pip-audit --format json` — and fold
 * their results into VibeGuard's findings. Failures are non-fatal: if a tool is
 * missing or offline, we skip and say so rather than blocking a scan.
 */

const fs = require('fs');
const path = require('path');
const { execFileSync, execSync } = require('child_process');

const AUDIT_TIMEOUT_MS = 60000;

// npm severity -> VibeGuard severity. npm uses low/moderate/high/critical.
const NPM_SEV = { critical: 'critical', high: 'high', moderate: 'medium', low: 'low', info: 'low' };
const PIP_SEV = { critical: 'critical', high: 'high', medium: 'medium', moderate: 'medium', low: 'low' };

function fileExists(p) {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
  }
}

const isWin = process.platform === 'win32';

// Run a fixed command and parse its JSON stdout.
// SECURITY NOTE: `cmd` and `args` here are always hardcoded literals in this
// module — never user input — so the Windows shell path cannot be injected.
// POSIX uses execFileSync (no shell at all); Windows uses execSync with a
// constant string because npm/pip-audit ship as shim scripts that need a shell
// to resolve, and passing an args array with shell:true triggers DEP0190.
function runJson(cmd, args, cwd) {
  const opts = {
    cwd,
    timeout: AUDIT_TIMEOUT_MS,
    maxBuffer: 20 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'ignore'],
    windowsHide: true,
  };
  const out = isWin
    ? execSync([cmd, ...args].join(' '), opts)
    : execFileSync(cmd, args, opts);
  return JSON.parse(out.toString('utf8') || '{}');
}

function npmAudit(root) {
  const findings = [];
  const hasNode = fileExists(path.join(root, 'package.json'));
  if (!hasNode) return { findings, ran: false, note: 'no package.json' };

  let data;
  try {
    // npm audit exits non-zero when vulns exist; execFileSync throws but still
    // gives us stdout on err.stdout.
    try {
      data = runJson('npm', ['audit', '--json'], root);
    } catch (err) {
      if (err && err.stdout) data = JSON.parse(err.stdout.toString('utf8') || '{}');
      else throw err;
    }
  } catch (err) {
    return { findings, ran: false, note: `npm audit unavailable (${err.code || err.message})` };
  }

  return { findings: parseNpmAudit(data), ran: true, note: null };
}

// Pure parser (testable without running npm).
function parseNpmAudit(data) {
  const findings = [];
  const vulns = (data && data.vulnerabilities) || {};
  for (const name of Object.keys(vulns)) {
    const v = vulns[name];
    const sev = NPM_SEV[v.severity] || 'medium';
    const viaTitles = Array.isArray(v.via)
      ? v.via.filter((x) => typeof x === 'object').map((x) => x.title).filter(Boolean)
      : [];
    const detail = viaTitles.length ? `: ${viaTitles.slice(0, 2).join('; ')}` : '';
    findings.push({
      ruleId: 'dep.npm-vulnerability',
      severity: sev,
      confidence: 'high',
      title: 'Vulnerable npm dependency',
      message: `${name} (${v.range || 'installed version'}) has a known ${v.severity} vulnerability${detail}.`,
      fix: v.fixAvailable
        ? `Run 'npm audit fix'${v.fixAvailable === true ? '' : ' --force (may include a breaking major bump)'} or update ${name}.`
        : `No automatic fix yet — review the advisory for ${name} and pin/replace if needed.`,
      file: 'package.json',
      line: 1,
      column: 1,
      snippet: `dependency: ${name}`,
    });
  }
  return findings;
}

function pipAudit(root) {
  const findings = [];
  const hasPy =
    fileExists(path.join(root, 'requirements.txt')) ||
    fileExists(path.join(root, 'pyproject.toml')) ||
    fileExists(path.join(root, 'Pipfile.lock'));
  if (!hasPy) return { findings, ran: false, note: 'no python manifest' };

  let data;
  try {
    try {
      data = runJson('pip-audit', ['--format', 'json'], root);
    } catch (err) {
      if (err && err.stdout) data = JSON.parse(err.stdout.toString('utf8') || '{}');
      else throw err;
    }
  } catch (err) {
    return { findings, ran: false, note: `pip-audit unavailable (${err.code || err.message})` };
  }

  // pip-audit json: { dependencies: [ { name, version, vulns: [ { id, fix_versions, ... } ] } ] }
  const deps = data.dependencies || data || [];
  for (const dep of deps) {
    const vulns = dep.vulns || [];
    for (const vuln of vulns) {
      const sev = PIP_SEV[(vuln.severity || '').toLowerCase()] || 'high';
      findings.push({
        ruleId: 'dep.pip-vulnerability',
        severity: sev,
        confidence: 'high',
        title: 'Vulnerable Python dependency',
        message: `${dep.name} ${dep.version} is affected by ${vuln.id}${vuln.description ? ': ' + String(vuln.description).slice(0, 120) : ''}.`,
        fix:
          vuln.fix_versions && vuln.fix_versions.length
            ? `Upgrade ${dep.name} to ${vuln.fix_versions.join(' / ')}.`
            : `No fixed version listed for ${vuln.id} — review the advisory.`,
        file: 'requirements.txt',
        line: 1,
        column: 1,
        snippet: `dependency: ${dep.name} ${dep.version}`,
      });
    }
  }
  return { findings, ran: true, note: null };
}

function scanDependencies(root) {
  const npm = npmAudit(root);
  const pip = pipAudit(root);
  return {
    findings: [...npm.findings, ...pip.findings],
    ran: { npm: npm.ran, pip: pip.ran },
    notes: [npm.note, pip.note].filter(Boolean),
  };
}

module.exports = { scanDependencies, npmAudit, pipAudit, parseNpmAudit };
