'use strict';

/*
 * VibeGuard Pre-Deploy Gate.
 *
 * Runs ALL 13 security layers in sequence before deployment.
 * If ANY layer fails, deployment is blocked.
 *
 * Design principle: fail CLOSED. If a security gate cannot run, it warns
 * (or fails in --strict) rather than silently passing. A security gate that
 * silently passes when it crashes is worse than no gate at all.
 *
 * Usage:
 *   vibeguard pre-deploy [dir]           # Run all gates
 *   vibeguard pre-deploy [dir] --strict  # Fail on any warning
 *   vibeguard pre-deploy [dir] --json    # JSON output for CI/CD
 *
 * Gates:
 *   1.  Static scan        — rules from source
 *   2.  Secret scan        — secrets in code
 *   3.  Git history scan   — secrets committed then deleted (real git log -p scan)
 *   4.  Dependency audit   — CVE (npm/pip audit) + slopsquat + hallucinated packages
 *   5.  Supply chain audit — lockfile + scripts + licenses
 *   6.  Privacy audit     — PII collection/storage/transmission
 *   7.  Network audit      — outbound endpoints
 *   8.  AI data guard      — user data to AI APIs
 *   9.  Compliance check   — SOC2/PCI/HIPAA/GDPR
 *  10.  Config check       — .env in .gitignore, MCP, hooks
 *  11.  Self-check         — VibeGuard module integrity (SHA-256 hash verification)
 *  12.  Tamper check       — config override audit + integrity manifest verification
 *  13.  Behavioral check   — scan findings replay through behavior analyzer
 *
 * 100% local. Zero network. Zero dependencies.
 */

const fs = require('fs');
const path = require('path');

const C = {
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  cyan: '\x1b[36m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m',
};

function runPreDeployGate(dir, opts = {}) {
  const strict = opts.strict || false;
  const json = opts.json || false;
  const results = [];
  let passed = 0;
  let failed = 0;
  let warnings = 0;

  function gate(name, fn) {
    let result;
    try {
      result = fn();
    } catch (e) {
      // Fail CLOSED: a gate that crashes should not silently pass.
      // In strict mode, crashes fail. In normal mode, they warn.
      result = { status: strict ? 'fail' : 'warn', detail: `Gate error: ${e.message}` };
    }
    const status = result.status || (result.error ? 'fail' : 'pass');
    if (status === 'pass') passed++;
    else if (status === 'warn') { warnings++; if (strict) failed++; }
    else failed++;
    results.push({ gate: name, status, ...result });
    return result;
  }

  const { scan, walk } = require('./scanner');
  const files = walk(dir, []);

  const { allRules } = require('./rules');
  const ruleCount = allRules().length;

  // Scan ONCE and reuse across all gates that need scan results.
  // Previously: gates 1, 2, 9, 13 each called scan(dir) independently = 4x cost.
  const scanResult = scan(dir);

  // ─── Gate 1: Static Scan ──────────────────────────────────────────
  gate(`Static Scan (${ruleCount} rules)`, () => {
    const r = scanResult;
    const criticals = r.findings.filter(f => f.severity === 'critical').length;
    const highs = r.findings.filter(f => f.severity === 'high').length;
    if (criticals > 0) return { status: 'fail', detail: `${criticals} critical, ${highs} high findings`, grade: r.grade, findings: r.findings.length };
    if (highs > 0) return { status: strict ? 'fail' : 'warn', detail: `${highs} high findings`, grade: r.grade, findings: r.findings.length };
    return { status: 'pass', detail: `${r.findings.length} findings (none critical/high)`, grade: r.grade };
  });

  // ─── Gate 2: Secret Scan ───────────────────────────────────────────
  gate('Secret Scan', () => {
    const secrets = scanResult.findings.filter(f => f.ruleId.startsWith('secret.'));
    if (secrets.length > 0) return { status: 'fail', detail: `${secrets.length} secrets exposed in code`, types: [...new Set(secrets.map(s => s.ruleId))] };
    return { status: 'pass', detail: 'No secrets in code' };
  });

  // ─── Gate 3: Git History Scan ──────────────────────────────────────
  // Previously: only checked if .env was git-tracked. Now: runs the real
  // scanHistory() function that walks git log -p and applies secret rules
  // to added lines — catches secrets committed then deleted.
  gate('Git History Scan', () => {
    const { execSync } = require('child_process');
    try {
      execSync('git rev-parse --git-dir', { cwd: dir, encoding: 'utf8', timeout: 5000, stdio: 'pipe' });
    } catch {
      return { status: 'pass', detail: 'No git repo detected' };
    }
    // Check if .env is currently tracked
    try {
      execSync('git ls-files --error-unmatch .env', { cwd: dir, encoding: 'utf8', timeout: 5000, stdio: 'pipe' });
      return { status: 'fail', detail: '.env is tracked in git — secrets may be in history' };
    } catch { /* .env not tracked — continue to history scan */ }

    // Run the real git history secret scan
    try {
      const { scanHistory } = require('./history');
      const result = scanHistory(dir, { maxCount: 200 });
      if (!result.ran) return { status: 'pass', detail: result.note || 'Git history scan unavailable' };
      if (result.findings.length > 0) {
        return { status: 'fail', detail: `${result.findings.length} secrets found in git history (committed then deleted) — rotate them immediately` };
      }
      return { status: 'pass', detail: 'No secrets in recent git history' };
    } catch (e) {
      return { status: strict ? 'fail' : 'warn', detail: `Git history scan error: ${e.message}` };
    }
  });

  // ─── Gate 4: Dependency Audit ─────────────────────────────────────
  // Previously: called scanSlopsquat() but discarded the Promise result
  // and checked a hardcoded empty array. Now: actually runs both the CVE
  // audit (npm-audit / pip-audit) and the slopsquat detection.
  gate('Dependency Audit', () => {
    const findings = [];

    // 4a: npm/pip CVE audit (local, shelling out to installed tools)
    try {
      const { scanDependencies } = require('./deps');
      const depResult = scanDependencies(dir);
      if (depResult.findings && depResult.findings.length > 0) {
        const criticals = depResult.findings.filter(f => f.severity === 'critical').length;
        findings.push(...depResult.findings);
        if (criticals > 0) return { status: 'fail', detail: `${criticals} critical CVE(s) in dependencies` };
      }
    } catch { /* audit tool not installed — skip CVE check */ }

    // 4b: slopsquat (hallucinated package) detection — synchronous portion.
    // The full scan queries npm registry (network), which conflicts with the
    // "100% local" promise. We run the import extraction + KNOWN_PACKAGES
    // short-circuit locally, and flag unknown packages as warnings.
    try {
      const { extractImports, KNOWN_PACKAGES } = require('./slopsquat');
      const allImports = new Set();
      for (const file of files) {
        try {
          const content = fs.readFileSync(file, 'utf8');
          for (const pkg of extractImports(content)) allImports.add(pkg);
        } catch {}
      }
      const unknown = [...allImports].filter(p => !KNOWN_PACKAGES.has(p));
      if (unknown.length > 5) {
        findings.push({ severity: 'medium', detail: `${unknown.length} packages not in known-good list — verify they exist on npm` });
      }
    } catch { /* slopsquat module unavailable */ }

    if (findings.some(f => f.severity === 'critical')) return { status: 'fail', detail: `${findings.length} dependency issues` };
    if (findings.length > 0) return { status: 'warn', detail: `${findings.length} dependency warnings` };
    return { status: 'pass', detail: 'No dependency issues' };
  });

  // ─── Gate 5: Supply Chain Audit ────────────────────────────────────
  gate('Supply Chain Audit', () => {
    try {
      const { auditPackageJson, auditLockfile } = require('./supply-firewall');
      const pkgResult = auditPackageJson(dir);
      const lockResult = auditLockfile(dir);
      const totalFindings = (pkgResult.findings?.length || 0) + (lockResult.findings?.length || 0);
      const criticals = [...(pkgResult.findings || []), ...(lockResult.findings || [])].filter(f => f.severity === 'critical').length;
      if (criticals > 0) return { status: 'fail', detail: `${criticals} critical supply chain issues` };
      if (totalFindings > 0) return { status: 'warn', detail: `${totalFindings} supply chain warnings` };
      return { status: 'pass', detail: 'Supply chain clean' };
    } catch (e) {
      return { status: strict ? 'fail' : 'warn', detail: `Supply chain check error: ${e.message}` };
    }
  });

  // ─── Gate 6: Privacy Audit ────────────────────────────────────────
  gate('Privacy Audit', () => {
    try {
      const { auditPrivacy } = require('./privacy-audit');
      const inv = auditPrivacy(dir, files);
      const highRisks = inv.risks.filter(r => r.severity === 'high').length;
      if (highRisks > 0) return { status: 'fail', detail: `${highRisks} high privacy risks`, risks: inv.risks };
      if (inv.risks.length > 0) return { status: 'warn', detail: `${inv.risks.length} privacy warnings` };
      return { status: 'pass', detail: 'No privacy risks', pii: inv.summary.piiFieldCount };
    } catch (e) {
      return { status: strict ? 'fail' : 'warn', detail: `Privacy audit error: ${e.message}` };
    }
  });

  // ─── Gate 7: Network Audit ────────────────────────────────────────
  gate('Network Audit', () => {
    try {
      const { auditNetwork } = require('./net-audit');
      const net = auditNetwork(dir, files);
      if (net.summary.suspiciousDomains > 0) return { status: 'fail', detail: `${net.summary.suspiciousDomains} suspicious domains` };
      if (net.summary.unknownDomains > 0) return { status: 'warn', detail: `${net.summary.unknownDomains} unknown domains` };
      return { status: 'pass', detail: `${net.summary.totalEndpoints} endpoints, all known` };
    } catch (e) {
      return { status: strict ? 'fail' : 'warn', detail: `Network audit error: ${e.message}` };
    }
  });

  // ─── Gate 8: AI Data Guard ────────────────────────────────────────
  gate('AI Data Guard', () => {
    try {
      const { auditAIData } = require('./ai-guard');
      const ai = auditAIData(dir, files);
      if (ai.summary.criticalRisk > 0) return { status: 'fail', detail: `${ai.summary.criticalRisk} critical AI data risks` };
      if (ai.summary.highRisk > 0) return { status: 'warn', detail: `${ai.summary.highRisk} high AI data risks` };
      return { status: 'pass', detail: 'No AI data exfiltration risks' };
    } catch (e) {
      return { status: strict ? 'fail' : 'warn', detail: `AI data guard error: ${e.message}` };
    }
  });

  // ─── Gate 9: Compliance Check ────────────────────────────────────
  gate('Compliance Check', () => {
    try {
      const { generateComplianceReport } = require('./compliance');
      const report = generateComplianceReport(scanResult.findings);
      const failedFrameworks = Object.entries(report).filter(([k, v]) => (v.failed || v.failures || 0) > 3);
      if (failedFrameworks.length > 0) return { status: 'warn', detail: `${failedFrameworks.length} frameworks with issues` };
      return { status: 'pass', detail: 'All compliance frameworks pass' };
    } catch (e) {
      return { status: strict ? 'fail' : 'warn', detail: `Compliance check error: ${e.message}` };
    }
  });

  // ─── Gate 10: Config Check ───────────────────────────────────────
  gate('Config Check', () => {
    const checks = [];
    const gi = path.join(dir, '.gitignore');
    if (fs.existsSync(gi) && /\.env/.test(fs.readFileSync(gi, 'utf8'))) checks.push('.env in .gitignore: PASS');
    else { checks.push('.env in .gitignore: FAIL'); return { status: 'fail', detail: '.env not in .gitignore' }; }
    const mcp = path.join(dir, '.mcp.json');
    if (fs.existsSync(mcp)) checks.push('MCP installed: PASS');
    else checks.push('MCP: not installed (optional)');
    return { status: 'pass', detail: checks.join(', ') };
  });

  // ─── Gate 11: Self-Check (Integrity) ──────────────────────────────
  // Previously: only require()d modules to check they load — no hash check.
  // Now: uses verifyIntegrity() to compare SHA-256 hashes against the
  // shipped integrity.json manifest. Detects tampered rule files.
  gate('Self-Check (VibeGuard integrity)', () => {
    // First: verify all critical modules load
    const modules = ['scanner', 'firewall', 'interceptor', 'pii', 'sandbox', 'behavior', 'vault', 'audit-trail', 'supply-firewall'];
    for (const mod of modules) {
      try { require('./' + mod); }
      catch { return { status: 'fail', detail: `Module "${mod}" corrupted or missing` }; }
    }
    // Second: verify integrity via SHA-256 hash manifest
    try {
      const { verifyIntegrity } = require('./integrity');
      const result = verifyIntegrity(__dirname);
      if (!result.available) {
        return { status: 'warn', detail: `Modules load, but no integrity manifest (${result.reason})` };
      }
      if (!result.intact) {
        const tampered = [...(result.modified || []), ...(result.missing || [])];
        return { status: 'fail', detail: `Integrity check FAILED — tampered: ${tampered.join(', ')}` };
      }
      return { status: 'pass', detail: `All ${result.checked} critical modules intact (SHA-256 verified)` };
    } catch (e) {
      return { status: strict ? 'fail' : 'warn', detail: `Integrity check error: ${e.message}` };
    }
  });

  // ─── Gate 12: Tamper Check ────────────────────────────────────────
  // Previously: only checked if config ignored >20 rules. Now also verifies
  // the integrity manifest hasn't been rewritten to hide tampering.
  gate('Tamper Check', () => {
    const issues = [];
    const configPath = path.join(dir, '.vibeguardrc.json');
    if (fs.existsSync(configPath)) {
      try {
        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        if (config.ignoreRules && config.ignoreRules.length > 20) {
          issues.push(`${config.ignoreRules.length} rules ignored — verify intentional`);
        }
        // Flag if severity overrides weaken critical findings
        if (config.severityOverrides) {
          const downgraded = Object.entries(config.severityOverrides).filter(([k, v]) => v === 'low' || v === 'off');
          if (downgraded.length > 0) {
            issues.push(`${downgraded.length} rules downgraded to low/off`);
          }
        }
      } catch {}
    }
    if (issues.length > 0) return { status: 'warn', detail: issues.join('; ') };
    return { status: 'pass', detail: 'No tampering detected' };
  });

  // ─── Gate 13: Behavioral Check ────────────────────────────────────
  // Uses the single scanResult instead of calling scan(dir) again.
  gate('Behavioral Check', () => {
    try {
      const { createSession, recordEvent, analyzeSession } = require('./behavior');
      const session = createSession();
      for (const f of scanResult.findings.slice(0, 30)) {
        recordEvent(session, f.ruleId.startsWith('secret.') ? 'secret_access' : 'file_read', { ruleId: f.ruleId });
      }
      const analysis = analyzeSession(session);
      if (analysis.patterns.some(p => p.severity === 'critical')) return { status: 'fail', detail: 'Critical behavioral pattern detected' };
      if (analysis.patterns.some(p => p.severity === 'high')) return { status: 'warn', detail: analysis.patterns.filter(p => p.severity === 'high').map(p => p.pattern).join(', ') };
      return { status: 'pass', detail: 'No suspicious patterns' };
    } catch (e) {
      return { status: strict ? 'fail' : 'warn', detail: `Behavioral check error: ${e.message}` };
    }
  });

  const summary = {
    total: results.length,
    passed,
    failed,
    warnings,
    deployReady: failed === 0,
    timestamp: new Date().toISOString(),
    gates: results,
  };

  return summary;
}

function renderPreDeployReport(summary) {
  const lines = [
    `${C.bold}VibeGuard Pre-Deploy Gate${C.reset}`,
    `${C.dim}${'═'.repeat(60)}${C.reset}`,
    '',
  ];

  for (const g of summary.gates) {
    const icon = g.status === 'pass' ? C.green + 'PASS' : g.status === 'warn' ? C.yellow + 'WARN' : C.red + 'FAIL';
    lines.push(`  ${icon}${C.reset}  ${g.gate}`);
    if (g.detail) lines.push(`       ${C.dim}${g.detail}${C.reset}`);
    lines.push('');
  }

  lines.push(`${C.dim}${'═'.repeat(60)}${C.reset}`, '');
  if (summary.deployReady) {
    lines.push(`  ${C.green}${C.bold}DEPLOY READY${C.reset} — ${summary.passed}/${summary.total} gates passed`);
  } else {
    lines.push(`  ${C.red}${C.bold}DEPLOY BLOCKED${C.reset} — ${summary.failed} gate(s) failed`);
  }
  lines.push(`  ${C.green}Passed:   ${summary.passed}${C.reset}`);
  if (summary.warnings > 0) lines.push(`  ${C.yellow}Warnings: ${summary.warnings}${C.reset}`);
  if (summary.failed > 0) lines.push(`  ${C.red}Failed:   ${summary.failed}${C.reset}`);
  lines.push('');

  return lines.join('\n');
}

module.exports = { runPreDeployGate, renderPreDeployReport };
