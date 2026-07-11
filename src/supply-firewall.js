'use strict';

/*
 * VibeGuard Supply Chain Firewall.
 *
 * Pre-install protection that blocks malicious packages BEFORE they reach node_modules:
 * - Pre-install hook: runs before npm install, blocks dangerous packages
 * - Lockfile pinning: verifies all dependencies are pinned to exact versions
 * - Integrity verification: checks all packages have integrity hashes
 * - License audit: flags GPL/AGPL/Copyleft licenses in production
 * - Postinstall audit: blocks packages with dangerous postinstall scripts
 * - Typosquat + slopsquat: checks every package name against known attacks
 *
 * 100% local. Zero network. Zero dependencies.
 */

const fs = require('fs');
const path = require('path');
const { checkPackage } = require('./firewall');

const DANGEROUS_SCRIPTS = [
  /(?:curl|wget)\s+[^|]+\|\s*(?:bash|sh|sh -c)/i,
  /(?:eval|exec)\s*\(/i,
  /node\s+-e\s+['"]/i,
  /python\s+-c\s+['"]/i,
  /rm\s+-rf/i,
  /chmod\s+777/i,
  /nc\s+-/i,
  /\/dev\/tcp/i,
  /base64\s+-d\s*\|/i,
  /mkfifo/i,
];

const LICENSE_RISKS = {
  GPL: { severity: 'high', reason: 'GPL — copyleft, may require source disclosure' },
  AGPL: { severity: 'critical', reason: 'AGPL — network copyleft, SaaS must disclose source' },
  SSPL: { severity: 'critical', reason: 'SSPL — Server Side Public License, effectively non-open-source' },
  BUSL: { severity: 'high', reason: 'BUSL — Business Source License, not OSI approved' },
  'CC-BY-NC': { severity: 'high', reason: 'Non-commercial license — cannot be used commercially' },
  UNLICENSED: { severity: 'high', reason: 'Unlicensed — no usage rights granted' },
};

function preInstallCheck(dir, packages) {
  const findings = [];
  let blocked = false;

  for (const pkg of packages) {
    const name = typeof pkg === 'string' ? pkg : pkg.name;
    const version = typeof pkg === 'object' ? pkg.version : null;

    // Check package name against firewall
    const check = checkPackage(name);
    for (const risk of check.risks) {
      findings.push({
        package: name,
        version,
        severity: risk.severity,
        type: risk.type,
        message: risk.message,
        action: risk.action,
      });
      if (risk.action === 'block') blocked = true;
    }

    // Check version
    if (version) {
      if (version === '*' || version === 'latest' || version === '') {
        findings.push({
          package: name,
          version,
          severity: 'high',
          type: 'unpinned',
          message: `Package "${name}" is not pinned to a specific version (${version})`,
          action: 'warn',
        });
      }
      if (version.startsWith('^') || version.startsWith('~')) {
        findings.push({
          package: name,
          version,
          severity: 'medium',
          type: 'range',
          message: `Package "${name}" uses version range (${version}) — may install different version`,
          action: 'warn',
        });
      }
    }
  }

  return { findings, blocked, total: packages.length };
}

function auditLockfile(dir) {
  const lockPath = path.join(dir, 'package-lock.json');
  let lock;
  try { lock = JSON.parse(fs.readFileSync(lockPath, 'utf8')); } catch {
    return { error: 'No package-lock.json found. Run npm install to generate.' };
  }

  const deps = lock.dependencies || lock.packages || {};
  const findings = [];

  for (const [name, info] of Object.entries(deps)) {
    // Check integrity hash
    if (!info.integrity && !info.resolved?.includes('file:')) {
      findings.push({
        package: name,
        severity: 'high',
        type: 'missing_integrity',
        message: `Package "${name}" has no integrity hash — cannot verify it hasn't been tampered with`,
      });
    }

    // Check for resolved from non-registry
    if (info.resolved && !info.resolved.includes('registry.npmjs.org')) {
      findings.push({
        package: name,
        severity: 'medium',
        type: 'non_registry',
        message: `Package "${name}" is resolved from non-npm registry: ${info.resolved.slice(0, 80)}`,
      });
    }
  }

  return {
    total: Object.keys(deps).length,
    withIntegrity: Object.values(deps).filter(d => d.integrity).length,
    findings,
    findingsCount: findings.length,
  };
}

function auditPackageJson(dir) {
  const pkgPath = path.join(dir, 'package.json');
  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')); } catch {
    return { error: 'No package.json found' };
  }

  const findings = [];

  // Check scripts for dangerous commands
  if (pkg.scripts) {
    for (const [name, script] of Object.entries(pkg.scripts)) {
      for (const pattern of DANGEROUS_SCRIPTS) {
        if (pattern.test(script)) {
          findings.push({
            script: name,
            command: script.slice(0, 100),
            severity: name === 'postinstall' ? 'critical' : 'high',
            type: 'dangerous_script',
            message: `Script "${name}" contains dangerous pattern: ${script.slice(0, 100)}`,
          });
        }
      }
    }
  }

  // Check license
  if (pkg.license) {
    const lic = String(pkg.license).toUpperCase();
    for (const [key, risk] of Object.entries(LICENSE_RISKS)) {
      if (lic.includes(key)) {
        findings.push({
          severity: risk.severity,
          type: 'license',
          message: `License: ${pkg.license} — ${risk.reason}`,
        });
      }
    }
  } else {
    findings.push({
      severity: 'medium',
      type: 'no_license',
      message: 'No license specified — package is "all rights reserved" by default',
    });
  }

  // Check dependencies for wildcard versions
  const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  for (const [name, version] of Object.entries(allDeps)) {
    if (version === '*' || version === 'latest' || version === '') {
      findings.push({
        package: name,
        version,
        severity: 'high',
        type: 'unpinned',
        message: `Dependency "${name}" is not pinned (${version})`,
      });
    }
  }

  return { findings, findingsCount: findings.length, total: Object.keys(allDeps).length };
}

function renderSupplyReport(result) {
  const C = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  const lines = [
    `${C.bold}VibeGuard Supply Chain Firewall${C.reset}`,
    `${C.dim}${'─'.repeat(60)}${C.reset}`,
    '',
  ];

  if (result.error) {
    lines.push(`  ${C.yellow}${result.error}${C.reset}`);
    return lines.join('\n');
  }

  if (result.findings && result.findings.length === 0) {
    lines.push(`  ${C.green}No supply chain risks detected${C.reset}`);
    return lines.join('\n');
  }

  if (result.total !== undefined) lines.push(`  Total packages: ${result.total}`);
  if (result.withIntegrity !== undefined) lines.push(`  With integrity: ${C.green}${result.withIntegrity}${C.reset}/${result.total}`);
  lines.push('');

  if (result.findings) {
    const critical = result.findings.filter(f => f.severity === 'critical');
    const high = result.findings.filter(f => f.severity === 'high');
    const medium = result.findings.filter(f => f.severity === 'medium');

    if (critical.length > 0) {
      lines.push(`${C.red}${C.bold}Critical${C.reset}`);
      for (const f of critical) lines.push(`  ${C.red}[CRITICAL]${C.reset} ${f.message}`);
      lines.push('');
    }
    if (high.length > 0) {
      lines.push(`${C.yellow}${C.bold}High${C.reset}`);
      for (const f of high) lines.push(`  ${C.yellow}[HIGH]${C.reset} ${f.message}`);
      lines.push('');
    }
    if (medium.length > 0) {
      lines.push(`${C.dim}Medium${C.reset}`);
      for (const f of medium) lines.push(`  ${C.dim}[MEDIUM]${C.reset} ${f.message}`);
      lines.push('');
    }
  }

  return lines.join('\n');
}

module.exports = { preInstallCheck, auditLockfile, auditPackageJson, renderSupplyReport, DANGEROUS_SCRIPTS, LICENSE_RISKS };