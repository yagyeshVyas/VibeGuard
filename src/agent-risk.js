'use strict';

/*
 * src/agent-risk.js — one risk score for an AI-agent deployment.
 *
 * Existing VibeGuard scores answer "how risky is this code?" This answers a
 * different question: "how risky is this agent, right now?" It aggregates:
 *
 *   config  — MCP servers the agent trusts (tool poisoning, unpinned, shells,
 *             secrets, broad filesystem grants, shadow servers, drift)
 *   skills  — skill / plugin / instruction files that shape agent behavior
 *   runtime — what the MCP firewall actually blocked, warned and scrubbed,
 *             plus behavioral anomalies in those events
 *   policy  — is there an explicit permission policy, or only defaults?
 *   audit   — is the audit trail present, writable and hash-intact?
 *
 * Score is 0-100, higher is worse. Grade A-F mirrors the scanner's scale.
 * 100% local. Zero network. Zero dependencies.
 */

const fs = require('fs');
const path = require('path');
const { auditMcp } = require('./mcp-audit');
const { scanSkills } = require('./skill-scan');
const { createLogger, verifyEntries } = require('./audit-trail');
const { createSession, recordEvent, analyzeSession } = require('./behavior');
const { coverageReport, coverageSummary } = require('./owasp-agentic');
const { loadPolicy, describePolicy } = require('./agent-policy');
const { DEFAULT_AUDIT_FILE } = require('./mcp-firewall');

const WEIGHTS = { critical: 25, high: 12, medium: 5, low: 1 };
const DOMAIN_CAP = 40;

function gradeFor(score) {
  if (score <= 9) return 'A';
  if (score <= 24) return 'B';
  if (score <= 44) return 'C';
  if (score <= 69) return 'D';
  return 'F';
}

function levelFor(score) {
  if (score === 0) return 'NONE';
  if (score <= 9) return 'LOW';
  if (score <= 24) return 'MODERATE';
  if (score <= 44) return 'ELEVATED';
  if (score <= 69) return 'HIGH';
  return 'CRITICAL';
}

function scoreFindings(findings) {
  let raw = 0;
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings || []) {
    const sev = counts[f.severity] === undefined ? 'low' : f.severity;
    counts[sev]++;
    raw += WEIGHTS[sev] || 1;
  }
  return { raw, capped: Math.min(DOMAIN_CAP, raw), counts };
}

function analyzeAuditLog(file) {
  const result = {
    file,
    exists: false,
    entries: 0,
    blocked: 0,
    warned: 0,
    scrubbed: 0,
    poisonedTools: 0,
    resultInjections: 0,
    allowed: 0,
    chainValid: true,
    brokenAt: [],
    behavior: null,
    score: 0,
    reasons: [],
  };
  let logger;
  try {
    if (!fs.existsSync(file)) return result;
    logger = createLogger(file);
  } catch (err) {
    result.reasons.push(`Audit log could not be read: ${err.message}`);
    return result;
  }
  result.exists = true;
  const entries = logger.entries;
  result.entries = entries.length;
  const verification = verifyEntries(entries);
  result.chainValid = verification.valid;
  result.brokenAt = verification.brokenAt;

  const session = createSession();
  for (const entry of entries) {
    const detail = entry.detail || {};
    if (entry.type === 'mcp_blocked') {
      result.blocked++;
      recordEvent(session, 'blocked', { tool: detail.tool, server: detail.server });
    } else if (entry.type === 'mcp_warn') {
      result.warned++;
      recordEvent(session, 'network', { tool: detail.tool, server: detail.server });
    } else if (entry.type === 'mcp_result_scrubbed') {
      result.scrubbed++;
      recordEvent(session, 'secret_access', { redactions: detail.redactions });
    } else if (entry.type === 'mcp_tool_poisoned') {
      result.poisonedTools++;
      recordEvent(session, 'tamper', { tool: detail.tool, server: detail.server });
    } else if (entry.type === 'mcp_result_injection') {
      result.resultInjections++;
      recordEvent(session, 'tamper', { patterns: detail.patterns });
    } else if (entry.type === 'mcp_call') {
      result.allowed++;
      recordEvent(session, 'file_read', { tool: detail.tool, server: detail.server });
    }
  }
  result.behavior = analyzeSession(session);
  result.score =
    Math.min(30, result.blocked * 6) +
    Math.min(30, result.poisonedTools * 15) +
    Math.min(10, result.warned * 1) +
    Math.min(10, result.scrubbed * 2) +
    Math.min(20, result.behavior.patterns.reduce((sum, p) => sum + (p.severity === 'critical' ? 20 : p.severity === 'high' ? 10 : 4), 0));
  if (!result.chainValid) {
    result.score += 15;
    result.reasons.push(`Audit chain is broken at entries ${result.brokenAt.join(', ')} — the log was edited or truncated.`);
  }
  if (result.blocked > 0) result.reasons.push(`${result.blocked} tool call(s) blocked at runtime.`);
  if (result.poisonedTools > 0) result.reasons.push(`${result.poisonedTools} poisoned tool definition(s) removed from tools/list.`);
  if (result.behavior && result.behavior.patternsCount > 0) {
    result.reasons.push(`Behavior anomalies: ${result.behavior.patterns.map((p) => p.pattern).join(', ')}.`);
  }
  result.score = Math.min(DOMAIN_CAP, result.score);
  return result;
}

// Main entry.
// opts: { auditFile, policyPath, skillPaths, noWrite, frameworks }
function computeAgentRisk(root, opts = {}) {
  const projectRoot = path.resolve(root || process.cwd());
  const config = auditMcp(projectRoot, { noWrite: opts.noWrite !== false });
  const skills = scanSkills(projectRoot, { paths: opts.skillPaths });
  const auditFile = path.resolve(projectRoot, opts.auditFile || DEFAULT_AUDIT_FILE);
  const runtime = analyzeAuditLog(auditFile);
  const policyState = loadPolicy(projectRoot, opts.policyPath);

  const configScore = scoreFindings(config.findings);
  const skillScore = scoreFindings(skills.findings);

  // A policy is not required, but running on defaults means every unknown tool
  // is trusted. That is a real (if small) amount of unmanaged agency.
  let policyScore = 0;
  const policyReasons = [];
  if (policyState.error) {
    policyScore += 15;
    policyReasons.push(policyState.error);
  } else if (!policyState.source) {
    policyScore += 6;
    policyReasons.push('No explicit MCP policy file — running on built-in defaults (unknown tools allowed).');
  }
  if (policyState.policy && policyState.policy.blockExternalNetwork !== true && (policyState.policy.allowedHosts || []).length === 0) {
    policyScore += 3;
    policyReasons.push('Egress is not allowlisted (allowedHosts is empty).');
  }
  policyScore = Math.min(10, policyScore);

  let auditScore = 0;
  const auditReasons = [];
  if (!runtime.exists) {
    auditScore += 4;
    auditReasons.push('No MCP firewall audit log yet — runtime decisions are not being recorded.');
  } else if (!runtime.chainValid) {
    auditScore += 15;
  }
  auditScore = Math.min(15, auditScore);

  // Domain caps: config and skills can each dominate; runtime is capped lower
  // so a noisy day does not automatically make the deployment an F.
  const domains = {
    config: { score: configScore.capped, raw: configScore.raw, counts: configScore.counts, findings: config.findings.length },
    skills: { score: skillScore.capped, raw: skillScore.raw, counts: skillScore.counts, findings: skills.findings.length },
    runtime: { score: runtime.score, counts: { blocked: runtime.blocked, warned: runtime.warned, scrubbed: runtime.scrubbed, poisoned: runtime.poisonedTools }, anomalies: runtime.behavior ? runtime.behavior.patterns : [] },
    policy: { score: policyScore, source: policyState.source, error: policyState.error, reasons: policyReasons },
    audit: { score: auditScore, file: auditFile, exists: runtime.exists, entries: runtime.entries, chainValid: runtime.chainValid, reasons: auditReasons },
  };

  const weighted =
    domains.config.score * 0.35 +
    domains.skills.score * 0.30 +
    domains.runtime.score * 0.20 +
    domains.policy.score * 0.10 +
    domains.audit.score * 0.05;
  // The domain caps sum to 35.75, not 100. Normalize so "everything maxed"
  // reads as 100 and the grade scale means what it says.
  const score = Math.min(100, Math.round((weighted / 35.75) * 100));

  const allFindings = [...config.findings, ...skills.findings];
  const owasp = coverageReport({ frameworks: opts.frameworks, findings: allFindings });

  const top = allFindings
    .slice()
    .sort((a, b) => (WEIGHTS[b.severity] || 1) - (WEIGHTS[a.severity] || 1))
    .slice(0, 8)
    .map((f) => ({
      severity: f.severity,
      source: f.server ? 'mcp' : 'skill',
      id: f.id || f.ruleId,
      where: f.server || f.file,
      message: f.message,
    }));

  return {
    generatedAt: new Date().toISOString(),
    root: projectRoot,
    score,
    grade: gradeFor(score),
    level: levelFor(score),
    domains,
    mcp: { servers: config.servers.length, findings: config.findings, counts: config.counts },
    skills: { scanned: skills.scannedFiles, findings: skills.findings, counts: skills.counts, grade: skills.grade },
    runtime,
    policy: { source: policyState.source, error: policyState.error, summary: describePolicy(policyState.policy, policyState.source) },
    owasp: { percent: owasp.percent, covered: owasp.totalCovered, total: owasp.totalItems, summary: coverageSummary(owasp), report: owasp },
    top,
    reasons: [...runtime.reasons, ...policyReasons, ...auditReasons],
  };
}

function renderAgentRisk(report) {
  const C = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', cyan: '\x1b[36m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  const color = report.grade === 'A' ? C.green : report.grade === 'B' ? C.green : report.grade === 'C' ? C.yellow : C.red;
  const lines = [
    `${C.bold}VibeGuard Agent Risk Score${C.reset}`,
    `${C.dim}${'─'.repeat(64)}${C.reset}`,
    '',
    `  Score:    ${color}${report.score}/100${C.reset} (${report.level})`,
    `  Grade:    ${color}${report.grade}${C.reset}`,
    `  OWASP:    ${report.owasp.covered}/${report.owasp.total} controls mapped (${report.owasp.percent}%)`,
    '',
    `${C.bold}Domains${C.reset}`,
    `  MCP config      ${String(report.domains.config.score).padStart(3)}/40   ${report.mcp.servers} server(s), ${report.mcp.findings.length} finding(s)`,
    `  Skills          ${String(report.domains.skills.score).padStart(3)}/40   ${report.skills.scanned} file(s), ${report.skills.findings.length} finding(s)`,
    `  Runtime         ${String(report.domains.runtime.score).padStart(3)}/40   ${report.runtime.blocked} blocked, ${report.runtime.poisonedTools} poisoned tool(s), ${report.runtime.scrubbed} redaction(s)`,
    `  Policy          ${String(report.domains.policy.score).padStart(3)}/10   ${report.policy.source || 'built-in defaults'}`,
    `  Audit           ${String(report.domains.audit.score).padStart(3)}/15   ${report.domains.audit.exists ? `${report.domains.audit.entries} entries, chain ${report.domains.audit.chainValid ? 'intact' : 'BROKEN'}` : 'not recording'}`,
    '',
  ];
  if (report.top.length > 0) {
    lines.push(`${C.bold}Top Risks${C.reset}`, '');
    for (const f of report.top) {
      const sc = f.severity === 'critical' ? C.red : f.severity === 'high' ? C.yellow : C.dim;
      lines.push(`  ${sc}[${f.severity}]${C.reset} ${f.id} — ${f.where}`);
      lines.push(`    ${String(f.message).slice(0, 130)}`);
    }
    lines.push('');
  }
  if (report.reasons.length > 0) {
    lines.push(`${C.bold}Signals${C.reset}`, '');
    for (const r of report.reasons) lines.push(`  ${C.yellow}•${C.reset} ${r}`);
    lines.push('');
  }
  const recommendation =
    report.grade === 'A' ? 'Agent posture is clean. Keep the firewall in the loop.' :
    report.grade === 'B' ? 'Minor exposure. Tighten the policy before adding more tools.' :
    report.grade === 'C' ? 'Review the MCP servers and skills named above before the next agent run.' :
    'Do not run this agent unattended until the critical findings are resolved.';
  lines.push(`${C.bold}Recommendation${C.reset}`, `  ${recommendation}`);
  return lines.join('\n');
}

module.exports = { computeAgentRisk, renderAgentRisk, analyzeAuditLog, gradeFor, levelFor, scoreFindings };
