'use strict';

/*
 * `vibeguard doctor` — audit the AI coding HOST (not your project source) for
 * known compromise vectors:
 *   - hook injection via .claude/settings.json (CVE-2025-59536 class)
 *   - API-key exfil via ANTHROPIC_BASE_URL / OPENAI_BASE_URL override
 *   - MCP configs that launch suspicious commands (curl|sh, file://, etc.)
 *
 * Read-only. Scans the project's ./.claude + ./.vscode and the user's
 * ~/.claude, ~/.cursor, ~/.codeium, ~/.codex configs.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const HOME = os.homedir();
const SUSPICIOUS_CMD = /curl|wget|\|\s*(?:sh|bash)|base64\s+-d|eval\s|Invoke-Expression|iex\b|nc\s|ncat\s|python\s+-c/i;

function readJson(p) {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}
function exists(p) {
  try { return fs.existsSync(p); } catch { return false; }
}

function checkHooks(file, findings) {
  const cfg = readJson(file);
  if (!cfg || !cfg.hooks) return;
  const walk = (node) => {
    if (!node || typeof node !== 'object') return;
    if (typeof node.command === 'string' && SUSPICIOUS_CMD.test(node.command)) {
      findings.push({
        ruleId: 'doctor.hook-injection', severity: 'critical', confidence: 'high',
        title: 'Suspicious command in an AI hook',
        message: `A hook in ${file} runs a suspicious command: ${node.command.slice(0, 80)}. Malicious hooks execute automatically on tool events (CVE-2025-59536 class).`,
        fix: 'Remove or vet this hook. Never accept a repo whose .claude/settings.json injects shell hooks you did not write.',
        file, line: 1, column: 1, snippet: node.command.slice(0, 80),
      });
    }
    for (const k of Object.keys(node)) walk(node[k]);
  };
  walk(cfg.hooks);
}

function checkEnv(findings) {
  for (const v of ['ANTHROPIC_BASE_URL', 'OPENAI_BASE_URL', 'ANTHROPIC_API_URL']) {
    const val = process.env[v];
    if (val && !/^https:\/\/(?:api\.anthropic\.com|api\.openai\.com)/.test(val)) {
      findings.push({
        ruleId: 'doctor.base-url-hijack', severity: 'high', confidence: 'high',
        title: 'AI provider base URL overridden',
        message: `${v}=${val} points AI traffic (including your API key) at a non-official host — possible key exfiltration (CVE-2026-21852 class).`,
        fix: `Unset ${v} unless you deliberately use a proxy you control.`,
        file: `env:${v}`, line: 1, column: 1, snippet: `${v}=${val}`,
      });
    }
  }
}

function checkMcp(file, findings) {
  const cfg = readJson(file);
  if (!cfg) return;
  const servers = cfg.mcpServers || cfg.servers || {};
  for (const name of Object.keys(servers)) {
    const s = servers[name] || {};
    const cmd = [s.command, ...(s.args || [])].join(' ');
    if (SUSPICIOUS_CMD.test(cmd) || /file:\/\//.test(cmd)) {
      findings.push({
        ruleId: 'doctor.mcp-suspicious', severity: 'high', confidence: 'medium',
        title: 'MCP server launches a suspicious command',
        message: `MCP server "${name}" in ${file} runs: ${cmd.slice(0, 80)}. An untrusted MCP server can run arbitrary code and exfiltrate data.`,
        fix: 'Remove MCP servers you did not add; only install servers from sources you trust.',
        file, line: 1, column: 1, snippet: cmd.slice(0, 80),
      });
    }
  }
}

function runDoctor(root, opts = {}) {
  const findings = [];
  const scope = opts.scope || 'full';
  const projectFiles = [
    path.join(root, '.claude', 'settings.json'),
    path.join(root, '.claude', 'settings.local.json'),
    path.join(root, '.mcp.json'),
    path.join(root, '.vscode', 'mcp.json'),
  ];
  const hostFiles = [
    path.join(HOME, '.claude.json'),
    path.join(HOME, '.claude', 'settings.json'),
    path.join(HOME, '.cursor', 'mcp.json'),
    path.join(HOME, '.codeium', 'windsurf', 'mcp_config.json'),
  ];

  if (scope !== 'host') {
    for (const f of projectFiles) if (exists(f)) { checkHooks(f, findings); checkMcp(f, findings); }
  }
  if (scope !== 'project') {
    for (const f of hostFiles) if (exists(f)) { checkHooks(f, findings); checkMcp(f, findings); }
    checkEnv(findings);
  }
  return findings;
}

module.exports = { runDoctor };
