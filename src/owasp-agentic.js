'use strict';

/*
 * src/owasp-agentic.js — OWASP coverage map for agent and MCP security.
 *
 * Two frameworks, one question: "which of these risks does VibeGuard actually
 * do something about, and what exactly does it do?"
 *
 *   - OWASP Top 10 for Agentic Applications
 *   - OWASP MCP Top 10
 *   - OWASP Top 10 for LLM Applications (bonus, because MCP sits under it)
 *
 * Coverage here means a concrete control exists in this codebase: a scanner,
 * a runtime gate, a monitor, or a tamper-evident log. It does NOT mean the
 * risk is eliminated. The status vocabulary says which:
 *
 *   enforced  — a runtime control can block the action (firewall/policy/sandbox)
 *   detected  — a scanner reports it before it ships
 *   monitored — behavior and audit data expose it after the fact
 *   advisory  — guidance/config guidance only
 *
 * 100% local. Zero dependencies.
 */

const AGENTIC = {
  id: 'OWASP-AGENTIC',
  name: 'OWASP Top 10 for Agentic Applications',
  items: [
    { id: 'ASI01', name: 'Agent Goal Hijack' },
    { id: 'ASI02', name: 'Tool Misuse and Exploitation' },
    { id: 'ASI03', name: 'Identity and Privilege Abuse' },
    { id: 'ASI04', name: 'Agentic Supply Chain Vulnerabilities' },
    { id: 'ASI05', name: 'Unexpected Code Execution' },
    { id: 'ASI06', name: 'Memory and Context Poisoning' },
    { id: 'ASI07', name: 'Insecure Inter-Agent Communication' },
    { id: 'ASI08', name: 'Cascading Failures' },
    { id: 'ASI09', name: 'Human-Agent Trust Exploitation' },
    { id: 'ASI10', name: 'Rogue Agents' },
  ],
};

const MCP = {
  id: 'OWASP-MCP',
  name: 'OWASP MCP Top 10',
  items: [
    { id: 'MCP01', name: 'Token Mismanagement and Secret Exposure' },
    { id: 'MCP02', name: 'Privilege Escalation via Scope Creep' },
    { id: 'MCP03', name: 'Tool Poisoning' },
    { id: 'MCP04', name: 'Software Supply Chain Attacks and Dependency Tampering' },
    { id: 'MCP05', name: 'Command Injection and Execution' },
    { id: 'MCP06', name: 'Intent Flow Subversion' },
    { id: 'MCP07', name: 'Insufficient Authentication and Authorization' },
    { id: 'MCP08', name: 'Lack of Audit and Telemetry' },
    { id: 'MCP09', name: 'Shadow MCP Servers' },
    { id: 'MCP10', name: 'Context Injection and Over-Sharing' },
  ],
};

const LLM = {
  id: 'OWASP-LLM',
  name: 'OWASP Top 10 for LLM Applications (2025)',
  items: [
    { id: 'LLM01', name: 'Prompt Injection' },
    { id: 'LLM02', name: 'Sensitive Information Disclosure' },
    { id: 'LLM03', name: 'Supply Chain' },
    { id: 'LLM04', name: 'Data and Model Poisoning' },
    { id: 'LLM05', name: 'Improper Output Handling' },
    { id: 'LLM06', name: 'Excessive Agency' },
    { id: 'LLM07', name: 'System Prompt Leakage' },
    { id: 'LLM08', name: 'Vector and Embedding Weaknesses' },
    { id: 'LLM09', name: 'Misinformation' },
    { id: 'LLM10', name: 'Unbounded Consumption' },
  ],
};

const FRAMEWORKS = { agentic: AGENTIC, mcp: MCP, llm: LLM };

// Every check names the code that implements it. Keep module/file names here
// so an operator can audit the claim instead of trusting a badge.
const CHECKS = [
  {
    id: 'mcp.firewall.tool-poisoning',
    module: 'src/mcp-firewall.js + src/agent-policy.js',
    capability: 'MCP firewall',
    status: 'enforced',
    description: 'Scans tool names, descriptions and schemas for injection, concealment, forced invocation, encoded payloads and readOnly lies; removes poisoned tools from tools/list.',
    controls: { agentic: ['ASI01', 'ASI02', 'ASI06'], mcp: ['MCP03', 'MCP06'], llm: ['LLM01'] },
  },
  {
    id: 'mcp.audit.config',
    module: 'src/mcp-audit.js',
    capability: 'MCP config audit',
    status: 'detected',
    description: 'Audits configured servers for injection, unpinned auto-install, remote-code commands, secrets in env, over-broad filesystem grants, duplicate (shadow) servers and definition drift.',
    controls: { agentic: ['ASI02', 'ASI04', 'ASI07'], mcp: ['MCP02', 'MCP04', 'MCP07', 'MCP09'], llm: ['LLM03'] },
  },
  {
    id: 'mcp.firewall.permissions',
    module: 'src/agent-policy.js + src/mcp-firewall.js',
    capability: 'Agent permission enforcement',
    status: 'enforced',
    description: 'Per-tool allow/deny/approval rules, capability gates, project-scoped filesystem access, denied credential paths, egress allowlist, metadata-host block, argument size and call-rate limits.',
    controls: { agentic: ['ASI02', 'ASI03', 'ASI08'], mcp: ['MCP02', 'MCP07'], llm: ['LLM06'] },
  },
  {
    id: 'mcp.firewall.secrets',
    module: 'src/mcp-firewall.js + src/action-guard.js',
    capability: 'Credential and secret exfiltration prevention',
    status: 'enforced',
    description: 'Blocks secrets in tool arguments, credential-plus-destination exfiltration shapes, secrets in URLs, credential-store paths, and redacts secrets/PII from tool results before they reach the model.',
    controls: { agentic: ['ASI03', 'ASI07'], mcp: ['MCP01', 'MCP10'], llm: ['LLM02'] },
  },
  {
    id: 'agent.policy.command-guard',
    module: 'src/shell-guard.js + src/agent-policy.js',
    capability: 'Command injection / destructive command prevention',
    status: 'enforced',
    description: 'Normalizes obfuscation (base64, env indirection, subshells, quoting, $IFS) and blocks destructive or exfiltrating shell commands before an MCP shell tool runs them.',
    controls: { agentic: ['ASI05'], mcp: ['MCP05'], llm: ['LLM05'] },
  },
  {
    id: 'sandbox.execution',
    module: 'src/sandbox.js',
    capability: 'Sandboxed code execution',
    status: 'enforced',
    description: 'Executes AI-generated JavaScript with a blocked-global vm, a process-permission mode on Node 20+, stripped environment, timeout, memory cap and an audit of every blocked access attempt.',
    controls: { agentic: ['ASI05'], mcp: ['MCP05'], llm: ['LLM05'] },
  },
  {
    id: 'skill.scan',
    module: 'src/skill-scan.js',
    capability: 'Malicious package and skill detection',
    status: 'detected',
    description: 'Scans SKILL.md, AGENTS.md, CLAUDE.md, Cursor rules, Claude plugins, marketplaces and embedded MCP configs for injection, hidden Unicode, exfiltration, credential access, destructive commands, remote code and permission bypass.',
    controls: { agentic: ['ASI01', 'ASI04', 'ASI06'], mcp: ['MCP03', 'MCP04'], llm: ['LLM01', 'LLM03', 'LLM04'] },
  },
  {
    id: 'supply.packages',
    module: 'src/supply-firewall.js + src/slopsquat.js + src/deps.js + src/firewall.js',
    capability: 'Package supply chain',
    status: 'detected',
    description: 'Checks package names for typosquat/slopsquat/malicious names, lockfile and package.json install scripts, unpinned dependencies, license risk and known CVEs.',
    controls: { agentic: ['ASI04'], mcp: ['MCP04'], llm: ['LLM03'] },
  },
  {
    id: 'runtime.behavior',
    module: 'src/behavior.js + src/agent-monitor.js',
    capability: 'Autonomous agent behavior monitoring',
    status: 'monitored',
    description: 'Scores tool-call sessions for trust-building, data-gathering-before-egress, slow exfiltration, privilege escalation, repeated blocks, rapid-fire and off-hours access; surfaces them from the live firewall log.',
    controls: { agentic: ['ASI08', 'ASI09', 'ASI10'], mcp: ['MCP08'], llm: ['LLM06', 'LLM10'] },
  },
  {
    id: 'audit.trail',
    module: 'src/audit-trail.js',
    capability: 'Security audit logs and risk scoring',
    status: 'enforced',
    description: 'Append-only SHA-256 hash-chained JSONL log of every allowed, warned and blocked action; verification detects edits and deletions; agent-risk aggregates the log into a 0-100 score and A-F grade.',
    controls: { agentic: ['ASI09', 'ASI10'], mcp: ['MCP08'], llm: [] },
  },
  {
    id: 'agent.risk',
    module: 'src/agent-risk.js',
    capability: 'Risk scoring',
    status: 'enforced',
    description: 'Combines MCP config, skills, runtime firewall decisions, behavioral anomalies, permission scope and audit coverage into per-domain scores and an overall A-F grade.',
    controls: { agentic: ['ASI02', 'ASI08', 'ASI10'], mcp: ['MCP02', 'MCP08'], llm: ['LLM06'] },
  },
  {
    id: 'agent.prompt-guard',
    module: 'src/firewall.js + src/secure-prompt.js + src/llm-proxy.js',
    capability: 'Prompt injection detection',
    status: 'enforced',
    description: 'Regex + semantic classifier for instruction override, role hijack, system-prompt extraction, encoded payloads, jailbreaks and PII; can proxy an LLM API and redact/block in flight.',
    controls: { agentic: ['ASI01', 'ASI06'], mcp: ['MCP06'], llm: ['LLM01', 'LLM07'] },
  },
  {
    id: 'agent.output-sinks',
    module: 'src/agentic.js + src/rules-2026.js + src/crosstaint.js',
    capability: 'LLM output handling',
    status: 'detected',
    description: 'Detects LLM output flowing into exec/eval/SQL/HTML, tool-result injection, memory poisoning, uncapped loops, missing max_tokens and sandbox-disabled flags.',
    controls: { agentic: ['ASI05', 'ASI06', 'ASI08'], mcp: ['MCP06'], llm: ['LLM05', 'LLM06', 'LLM10'] },
  },
  {
    id: 'agent.secrets.static',
    module: 'src/scanner.js + src/entropy.js + src/gitscan.js',
    capability: 'Secret detection',
    status: 'detected',
    description: 'Scans source, build artifacts and git history for known secret formats, high-entropy tokens and committed-then-removed credentials.',
    controls: { agentic: ['ASI03'], mcp: ['MCP01'], llm: ['LLM02'] },
  },
  {
    id: 'agent.env-lock',
    module: 'src/interceptor.js + src/vault.js',
    capability: 'Credential isolation',
    status: 'enforced',
    description: 'Hides sensitive environment variables from the agent process, sanitizes AI responses, detects tamper attempts and provides an encrypted local vault.',
    controls: { agentic: ['ASI03'], mcp: ['MCP01'], llm: ['LLM02'] },
  },
  {
    id: 'compliance.mapping',
    module: 'src/compliance.js',
    capability: 'Control mapping',
    status: 'advisory',
    description: 'Maps findings to SOC2, PCI-DSS, HIPAA, GDPR, ISO27001, NIST CSF/800-53, CIS and EU AI Act for reporting.',
    controls: { agentic: ['ASI09'], mcp: ['MCP08'], llm: [] },
  },
];

const STATUS_RANK = { none: 0, advisory: 1, monitored: 2, detected: 3, enforced: 4 };

function checksForFramework(frameworkKey) {
  return CHECKS.filter((check) => (check.controls[frameworkKey] || []).length > 0);
}

function mapFindings(findings) {
  // Findings from the scanners carry mcp/agentic ids when we know them. This
  // gives the report a per-control hit count without inventing precision.
  const counts = {};
  for (const f of findings || []) {
    const ids = Array.isArray(f.owasp) ? f.owasp : [];
    for (const id of ids) counts[id] = (counts[id] || 0) + 1;
    if (f.id && /^MCP\d+$/i.test(f.id)) counts[f.id.toUpperCase()] = (counts[f.id.toUpperCase()] || 0) + 1;
  }
  return counts;
}

// opts: { frameworks: ['agentic','mcp','llm'], findings, enabled: { mcpFirewall: bool, ... } }
function coverageReport(opts = {}) {
  const selected = opts.frameworks && opts.frameworks.length ? opts.frameworks : ['agentic', 'mcp'];
  const findingCounts = mapFindings(opts.findings || []);
  const frameworks = [];

  for (const key of selected) {
    const framework = FRAMEWORKS[key];
    if (!framework) continue;
    const checks = checksForFramework(key);
    const items = framework.items.map((item) => {
      const related = checks.filter((c) => (c.controls[key] || []).includes(item.id));
      const status = related.reduce((best, c) => (STATUS_RANK[c.status] > STATUS_RANK[best] ? c.status : best), 'none');
      return {
        ...item,
        covered: related.length > 0,
        status,
        checks: related.map((c) => c.id),
        findings: findingCounts[item.id] || 0,
      };
    });
    const covered = items.filter((i) => i.covered).length;
    frameworks.push({
      id: framework.id,
      name: framework.name,
      total: items.length,
      covered,
      percent: Math.round((covered / items.length) * 100),
      items,
    });
  }

  const totalItems = frameworks.reduce((n, f) => n + f.total, 0);
  const totalCovered = frameworks.reduce((n, f) => n + f.covered, 0);
  return {
    generatedAt: new Date().toISOString(),
    frameworks,
    totalItems,
    totalCovered,
    percent: totalItems ? Math.round((totalCovered / totalItems) * 100) : 0,
    checks: CHECKS.map((c) => ({ id: c.id, capability: c.capability, status: c.status, module: c.module, description: c.description, controls: c.controls })),
  };
}

function renderCoverage(report) {
  const C = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', cyan: '\x1b[36m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  const statusColor = {
    enforced: C.green,
    detected: C.cyan,
    monitored: C.yellow,
    advisory: C.dim,
    none: C.red,
  };
  const lines = [
    `${C.bold}VibeGuard — OWASP agent + MCP coverage${C.reset}`,
    `${C.dim}${'─'.repeat(68)}${C.reset}`,
    '',
  ];
  for (const framework of report.frameworks) {
    lines.push(`${C.bold}${framework.name}${C.reset}  ${framework.covered}/${framework.total} (${framework.percent}%)`);
    for (const item of framework.items) {
      const label = (item.status === 'none' ? 'GAP' : item.status.toUpperCase()).padEnd(10);
      lines.push(`  ${item.id.padEnd(6)} ${statusColor[item.status]}${label}${C.reset} ${item.name}`);
    }
    lines.push('');
  }
  lines.push(`${C.bold}Overall: ${report.totalCovered}/${report.totalItems} controls mapped${C.reset}`);
  return lines.join('\n');
}

function coverageSummary(report) {
  return report.frameworks.map((f) => `${f.id}: ${f.covered}/${f.total} (${f.percent}%)`).join(' · ');
}

module.exports = {
  AGENTIC,
  MCP,
  LLM,
  FRAMEWORKS,
  CHECKS,
  coverageReport,
  coverageSummary,
  renderCoverage,
  mapFindings,
  checksForFramework,
};
