'use strict';

/*
 * src/agent-scan.js — AI Agent Security Posture.
 *
 * One command that answers the question generic SAST can't: "is my AI-agent
 * setup safe?" It aggregates VibeGuard's agent-era checks into a single graded
 * posture, grouped by the threat categories that actually matter for people
 * building with LLMs, agents, and MCP:
 *
 *   - MCP trust        — the MCP servers the agent trusts (src/mcp-audit.js)
 *   - AI data leakage  — PII / secrets sent to LLM providers (src/ai-guard.js + ai.*key* rules)
 *   - LLM output → sink— model output reaching exec/eval/SQL/DOM/file (ai.llm-output-*)
 *   - Prompt injection — user input in system prompt / missing guards (ai.prompt-*)
 *   - Agent capability — uncapped loops, unrestricted tool access (ai.agent-*)
 *   - Supply chain     — hallucinated packages (ai.hallucinated-import)
 *
 * Pure orchestration of already-tested modules — no new detection engine, no
 * network (slopsquat's registry check stays opt-in elsewhere). Offline.
 */

const path = require('path');

// Category assignment for agent-relevant rule IDs. Anything ai.* not matched
// falls into 'other-ai'. mcp-audit + ai-guard feed their own categories.
const CATEGORY_RULES = {
  'llm-output-to-sink': [
    'ai.llm-output-exec', 'ai.llm-output-shell', 'ai.llm-output-sql',
    'ai.llm-output-sql-v2', 'ai.llm-output-dom', 'ai.llm-output-file',
    'ai.eval-llm-output',
  ],
  'prompt-injection': [
    'ai.no-prompt-injection-guard', 'ai.prompt-injection-marker',
    'ai.prompt-extraction', 'ai.prompt-leak-via-error', 'ai.cursorrule-injection',
    'ai.model-id-injection', 'ai.model-id-user-input',
  ],
  'agent-capability': [
    'ai.agent-loop-no-cap', 'ai.agent-no-max-steps', 'ai.agent-can-access-secrets',
    'ai.agent-can-deploy', 'ai.agent-can-install-packages', 'ai.agent-can-modify-auth',
    'ai.disabled-sandbox', 'ai.data-exfil-agent', 'ai.agent-memory-poisoning',
    'ai.memory-poisoning', 'ai.adversarial-no-filter', 'ai.no-content-filter',
    'ai.no-content-filter-bypass',
  ],
  'ai-data-leakage': [
    'ai.openai-key-public', 'ai.anthropic-key-public', 'ai.browser-api-key',
    'ai.key-in-url', 'ai.agent-env-key-direct', 'ai.missing-max-tokens',
  ],
  'supply-chain': ['ai.hallucinated-import'],
  'mcp-trust': [
    'ai.mcp-command-injection', 'ai.mcp-description-injection-deep',
    'ai.mcp-path-traversal', 'ai.mcp-ssrf', 'ai.mcp-tool-no-auth',
    'ai.obfuscated-description',
  ],
};

const RULE_TO_CATEGORY = (() => {
  const m = {};
  for (const [cat, ids] of Object.entries(CATEGORY_RULES)) for (const id of ids) m[id] = cat;
  return m;
})();

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function categoryOf(ruleId) {
  if (RULE_TO_CATEGORY[ruleId]) return RULE_TO_CATEGORY[ruleId];
  if (ruleId.startsWith('ai.')) return 'other-ai';
  return null;
}

function gradeFor(counts) {
  if (counts.critical > 0) return 'F';
  if (counts.high >= 3) return 'D';
  if (counts.high > 0) return 'C';
  if (counts.medium >= 3) return 'C';
  if (counts.medium > 0) return 'B';
  return 'A';
}

function agentScan(root, opts = {}) {
  const { scan, walk } = require('./scanner');
  const { auditMcp } = require('./mcp-audit');
  const { auditAIData } = require('./ai-guard');

  const items = []; // normalized: { category, severity, ruleId, file, line, message, fix }

  // 1. Code scan — keep only agent-relevant (ai.*) findings.
  const scanRes = scan(root, { deps: false });
  for (const f of scanRes.findings) {
    const cat = categoryOf(f.ruleId);
    if (!cat) continue;
    items.push({
      category: cat, severity: f.severity, ruleId: f.ruleId,
      file: f.file, line: f.line, message: f.message, fix: f.fix,
    });
  }

  // 2. MCP trust.
  const mcp = auditMcp(root, { pin: !!opts.pin });
  for (const f of mcp.findings) {
    items.push({
      category: 'mcp-trust', severity: f.severity, ruleId: f.id,
      file: f.config, line: 1, message: f.message, fix: f.fix, server: f.server,
    });
  }

  // 3. AI data leakage — PII / user data flowing to LLM providers.
  let aiData = { findings: [] };
  try {
    const files = walk(root, []);
    aiData = auditAIData(root, files);
  } catch { /* best-effort */ }
  for (const f of aiData.findings) {
    items.push({
      category: 'ai-data-leakage', severity: f.severity, ruleId: 'ai-guard.pii-to-llm',
      file: f.file, line: f.line, message: f.message, fix: f.fix,
    });
  }

  // Aggregate.
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  const categories = {};
  for (const it of items) {
    counts[it.severity] = (counts[it.severity] || 0) + 1;
    (categories[it.category] = categories[it.category] || []).push(it);
  }
  const grade = gradeFor(counts);
  items.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);

  return {
    root: path.resolve(root),
    grade,
    counts,
    total: items.length,
    categories,
    items,
    mcpServers: mcp.servers.length,
    mcpDrifted: mcp.drifted,
    scannedFiles: scanRes.scannedFiles,
    engine: scanRes.engine,
    generatedAt: new Date().toISOString(),
  };
}

const CATEGORY_LABEL = {
  'mcp-trust': 'MCP trust',
  'ai-data-leakage': 'AI data leakage',
  'llm-output-to-sink': 'LLM output → dangerous sink',
  'prompt-injection': 'Prompt injection',
  'agent-capability': 'Agent capability / loops',
  'supply-chain': 'Supply chain (hallucinated deps)',
  'other-ai': 'Other AI risks',
};

function renderAgentScan(result) {
  const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
  const c = (x) => (useColor ? x : '');
  const R = c('\x1b[0m'), B = c('\x1b[1m'), DIM = c('\x1b[2m');
  const RED = c('\x1b[31m'), YEL = c('\x1b[33m'), GRN = c('\x1b[32m'), CYAN = c('\x1b[36m');
  const gradeColor = result.grade === 'A' ? GRN : (result.grade === 'F' || result.grade === 'D') ? RED : YEL;
  const sevColor = { critical: RED, high: YEL, medium: YEL, low: DIM };

  const out = [];
  out.push(`${B}${CYAN}VibeGuard — AI Agent Security Posture${R} ${DIM}(offline)${R}`);
  out.push(`  ${DIM}${result.scannedFiles} files · ${result.mcpServers} MCP server(s) · engine: ${result.engine ? result.engine.mode : '?'}${R}`);
  out.push(`  ${B}Agent Risk Grade: ${gradeColor}${result.grade}${R}  ${DIM}(${result.counts.critical} critical, ${result.counts.high} high, ${result.counts.medium} medium)${R}`);
  if (result.mcpDrifted && result.mcpDrifted.length) {
    out.push(`  ${RED}⚠ MCP definition drift: ${result.mcpDrifted.join(', ')} — re-review (rug-pull risk)${R}`);
  }
  out.push('');

  if (result.total === 0) {
    out.push(`  ${GRN}No agent-specific security risks found.${R}`);
    return out.join('\n');
  }

  for (const cat of Object.keys(CATEGORY_LABEL)) {
    const list = result.categories[cat];
    if (!list || !list.length) continue;
    out.push(`${B}${CATEGORY_LABEL[cat]}${R} ${DIM}(${list.length})${R}`);
    for (const it of list.slice(0, 10)) {
      const col = sevColor[it.severity] || '';
      const loc = it.file ? `${it.file}:${it.line}` : '';
      out.push(`  ${col}${it.severity.toUpperCase().padEnd(8)}${R} [${it.ruleId}] ${DIM}${loc}${R}`);
      out.push(`    ${it.message}`);
    }
    if (list.length > 10) out.push(`  ${DIM}… ${list.length - 10} more${R}`);
    out.push('');
  }
  return out.join('\n');
}

module.exports = { agentScan, renderAgentScan, categoryOf, gradeFor, CATEGORY_RULES };
