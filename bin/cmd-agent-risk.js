'use strict';

/*
 * bin/cmd-agent-risk.js — agent risk score + OWASP coverage CLI.
 *
 *   vibeguard agent-risk [dir] [--json] [--frameworks agentic,mcp,llm]
 *   vibeguard owasp-coverage [dir] [--json] [--all]
 *
 * exit: 0 clean (A / full coverage), 1 risky, 2 critical-or-worse.
 */

const path = require('path');
const { computeAgentRisk, renderAgentRisk } = require('../src/agent-risk');
const { coverageReport, renderCoverage } = require('../src/owasp-agentic');

function parseFrameworks(flags) {
  const raw = flags.frameworks || flags.framework;
  if (!raw || raw === true) return undefined;
  return String(raw).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
}

function cmdAgentRisk(args, flags) {
  const root = path.resolve(flags.dir || args._[1] || '.');
  const report = computeAgentRisk(root, {
    auditFile: flags.audit,
    policyPath: flags.policy,
    skillPaths: flags.path ? [String(flags.path)] : undefined,
    frameworks: parseFrameworks(flags),
  });

  if (flags.json) {
    const { owasp, ...rest } = report;
    process.stdout.write(JSON.stringify({ ...rest, owasp: { percent: owasp.percent, covered: owasp.covered, total: owasp.total, summary: owasp.summary } }, null, 2) + '\n');
  } else {
    process.stdout.write(renderAgentRisk(report) + '\n');
  }

  const critical = (report.mcp.counts.critical || 0) + (report.skills.counts.critical || 0);
  if (critical > 0 || report.grade === 'F') return 2;
  if (report.score > 0) return 1;
  return 0;
}

function cmdOwaspCoverage(args, flags) {
  const root = path.resolve(flags.dir || args._[1] || '.');
  const frameworks = flags.all ? ['agentic', 'mcp', 'llm'] : parseFrameworks(flags);
  let findings = [];
  try {
    const { computeAgentRisk: compute } = require('../src/agent-risk');
    const risk = compute(root, { noWrite: true, frameworks });
    findings = [...(risk.mcp.findings || []), ...(risk.skills.findings || [])];
  } catch {
    // Coverage can be reported without the live scan.
  }
  const report = coverageReport({ frameworks, findings });
  if (flags.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    process.stdout.write(renderCoverage(report) + '\n');
  }
  return report.percent === 100 ? 0 : 1;
}

module.exports = { cmdAgentRisk, cmdOwaspCoverage };
