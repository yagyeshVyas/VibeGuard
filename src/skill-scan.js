'use strict';

/*
 * src/skill-scan.js — malicious skill / plugin / instruction-file scanner.
 *
 * Skills are the new supply chain. A SKILL.md, a CLAUDE.md, an AGENTS.md, a
 * Cursor rule, a Claude plugin manifest or a marketplace entry is text that
 * gets injected into an agent's context with high trust. An attacker who can
 * land one line in that text owns the agent's behavior without touching code.
 *
 * This scanner reads those files before the agent does and flags:
 *
 *   - prompt injection and role hijacking
 *   - invisible Unicode / bidi smuggling
 *   - data-exfiltration instructions (send secrets/webhooks, base64 .env)
 *   - credential-store access (~/.ssh, .aws, .env, browser cookies)
 *   - destructive commands (rm -rf /, del C:\, diskpart, shadow copies)
 *   - remote code loaders (curl|sh, iwr|iex, powershell -enc)
 *   - obfuscated payloads (base64 + eval, fromCharCode, hex blobs)
 *   - excessive / self-granted permissions and security-disabling text
 *   - self-modification of the agent's own instructions
 *   - malicious / typosquatted / unpinned packages named in install commands
 *   - secrets committed inside skill text
 *   - dangerous embedded MCP server definitions (sh, curl|sh, unpinned npx)
 *
 * 100% local. Zero network. Zero dependencies.
 */

const fs = require('fs');
const path = require('path');
const { scanForLeaks } = require('./action-guard');
const { checkPackage } = require('./firewall');
const { scanTextForInjection, auditServer } = require('./mcp-audit');
const { matchesAny } = require('./agent-policy');

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', 'coverage',
  '.next', '.nuxt', '.turbo', '.cache', 'vendor', '__pycache__', '.venv', 'venv',
]);
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILES = 4000;

const SEVERITY_WEIGHT = { critical: 25, high: 10, medium: 4, low: 1 };
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function normalize(p) {
  return String(p).replace(/\\/g, '/');
}

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

function snippetAt(text, index, len = 120) {
  const start = Math.max(0, index - 20);
  const end = Math.min(text.length, index + len);
  return text.slice(start, end).replace(/\s+/g, ' ').trim();
}

function isSkillFileName(rel, base) {
  const p = normalize(rel);
  const b = base.toLowerCase();
  if (b === 'skill.md' || b === 'skills.md') return true;
  if (['agents.md', 'claude.md', '.cursorrules', '.windsurfrules', '.clinerules'].includes(b)) return true;
  if (b === 'copilot-instructions.md') return true;
  if (b === 'plugin.json' || b === 'claude-plugin.json' || b === 'marketplace.json') return true;
  if (/(^|\/)\.claude-plugin\//.test(p)) return true;
  if (/(^|\/)\.claude\/(agents|commands|skills)\/.*\.(md|json)$/i.test(p)) return true;
  if (/(^|\/)\.cursor\/rules\/.*\.(md|mdc)$/i.test(p)) return true;
  if (/(^|\/)\.github\/instructions\/.*\.md$/i.test(p)) return true;
  if (/(^|\/)skills?\/[^/]+\/.*\.(md|json|ya?ml)$/i.test(p)) return true;
  if (/\.(skill|prompt|agent|mdc)$/i.test(b)) return true;
  return false;
}

function loadIgnorePaths(root) {
  try {
    const config = JSON.parse(fs.readFileSync(path.join(root, '.vibeguardrc.json'), 'utf8'));
    return Array.isArray(config.ignorePaths) ? config.ignorePaths : [];
  } catch {
    return [];
  }
}

function collectSkillFiles(root, opts = {}) {
  const files = [];
  const seen = new Set();
  const explicit = Array.isArray(opts.paths) ? opts.paths : [];
  const maxDepth = Number(opts.maxDepth || 12);
  const ignorePaths = opts.ignorePaths || loadIgnorePaths(root);

  function push(file) {
    const resolved = path.resolve(file);
    if (seen.has(resolved)) return;
    let stat;
    try { stat = fs.statSync(resolved); } catch { return; }
    if (!stat.isFile()) return;
    if (stat.size > MAX_FILE_BYTES) return;
    seen.add(resolved);
    files.push(resolved);
  }

  function walk(dir, depth) {
    if (depth > maxDepth || files.length >= MAX_FILES) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        walk(full, depth + 1);
        continue;
      }
      const rel = path.relative(root, full);
      if (!entry.isDirectory() && ignorePaths.length > 0 && matchesAny(normalize(rel), ignorePaths)) continue;
      if (isSkillFileName(rel, entry.name)) push(full);
    }
  }

  for (const item of explicit) {
    const full = path.resolve(root, item);
    let stat;
    try { stat = fs.statSync(full); } catch { continue; }
    if (stat.isDirectory()) {
      if (opts.all) {
        // Explicit directory with --all: scan every text-ish file in it.
        (function walkAll(dir, depth) {
          if (depth > maxDepth || files.length >= MAX_FILES) return;
          let entries;
          try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
          for (const entry of entries) {
            const child = path.join(dir, entry.name);
            if (entry.isSymbolicLink()) continue;
            if (entry.isDirectory()) {
              if (SKIP_DIRS.has(entry.name)) continue;
              walkAll(child, depth + 1);
            } else if (/\.(md|mdc|json|ya?ml|txt|sh|ps1|py|js|ts)$/i.test(entry.name)) {
              push(child);
            }
          }
        })(full, 0);
      } else {
        walk(full, 0);
      }
    } else {
      push(full);
    }
  }

  if (!explicit.length) walk(root, 0);

  return files;
}

// ─── Rules ──────────────────────────────────────────────────────────────────

const RULES = [
  {
    id: 'skill.prompt-injection',
    severity: 'critical',
    test: (t) => {
      const hits = scanTextForInjection(t);
      return hits.length ? { at: 0, detail: hits.join(', ') } : null;
    },
    message: (d) => `Prompt injection in agent-facing text (${d}) — the skill can hijack the agent's instructions.`,
    fix: 'Remove the injected instruction. Skills must describe a capability, never override the agent system prompt.',
  },
  {
    id: 'skill.hidden-unicode',
    severity: 'high',
    test: (t) => {
      const m = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF\u00AD]/g;
      const hits = [];
      let match;
      while ((match = m.exec(t)) !== null) hits.push(match.index);
      return hits.length ? { at: hits[0], detail: `${hits.length} invisible/control character(s)` } : null;
    },
    message: (d) => `Hidden Unicode / bidi control characters in skill text (${d}) — a Trojan-Source smuggling technique.`,
    fix: 'Strip invisible characters and re-review the text in a raw editor.',
  },
  {
    id: 'skill.exfil-instruction',
    severity: 'critical',
    test: (t) => {
      const patterns = [
        /(?:send|post|upload|transmit|exfiltrate|forward|webhook|curl|invoke-webrequest|iwr)[^\n]{0,140}(?:https?:\/\/|webhook|requestbin|pipedream|ngrok|discord\.com\/api|api\.telegram\.org)/i,
        /(?:base64|btoa|atob|encode)[^\n]{0,100}(?:\.env|secret|token|credential|password|api[_-]?key)/i,
        /(?:collect|gather|read|dump|extract)[^\n]{0,100}(?:\.env|\.ssh|\.aws|id_rsa|credentials|browser\s+cookies|cookies\.sqlite)[^\n]{0,140}(?:send|post|upload|https?:\/\/)/i,
        /!\[[^\]]*\]\(\s*https?:\/\/[^)]*(?:data|secret|token|env)=/i,
      ];
      for (const re of patterns) {
        const m = re.exec(t);
        if (m) return { at: m.index, detail: snippetAt(t, m.index) };
      }
      return null;
    },
    message: () => 'Skill instructs the agent to gather sensitive data and send it out — exfiltration text.',
    fix: 'Remove the exfiltration instruction. A skill should never ask the agent to transmit credentials or collected local data.',
  },
  {
    id: 'skill.credential-access',
    severity: 'high',
    test: (t) => {
      const patterns = [
        /(?:~\/\.ssh|\/\.ssh\/|id_rsa|id_ed25519|\.aws\/credentials|\.config\/gh|\.npmrc|\.netrc|keychain|credential\s+manager|cmdkey|security\s+find-(?:generic|internet)-password)/i,
        /(?:read|open|cat|type|get-content|dump|print|show|expose)[^\n]{0,80}(?:\.env|environment\s+variables?|process\.env)/i,
      ];
      for (const re of patterns) {
        const m = re.exec(t);
        if (m) return { at: m.index, detail: snippetAt(t, m.index) };
      }
      return null;
    },
    message: () => 'Skill instructs the agent to read credential stores or dump environment secrets.',
    fix: 'Remove the credential-access instruction. Skills must not ask for secrets.',
  },
  {
    id: 'skill.destructive-command',
    severity: 'critical',
    test: (t) => {
      const patterns = [
        /\brm\s+-rf\s+(?:\/|~|\$HOME|C:\\|\*)/i,
        /\b(?:del|erase)\s+\/[fsq][^\n]{0,40}[A-Za-z]:\\/i,
        /\b(?:format|diskpart|mkfs(?:\.\w+)?|dd\s+if=)/i,
        /\bRemove-Item\b[^\n]{0,80}-Recurse[^\n]{0,40}-Force/i,
        /\b(?:vssadmin\s+delete\s+shadows|cipher\s+\/w|bcdedit|shutdown\s+\/[rs]|reg\s+delete\s+HKLM)/i,
        /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/,
      ];
      for (const re of patterns) {
        const m = re.exec(t);
        if (m) return { at: m.index, detail: snippetAt(t, m.index) };
      }
      return null;
    },
    message: () => 'Skill contains a destructive command (disk wipe, shadow-copy deletion, recursive delete).',
    fix: 'Remove the destructive command. A skill should not delete system or user data.',
  },
  {
    id: 'skill.remote-code-execution',
    severity: 'critical',
    test: (t) => {
      const patterns = [
        /(?:curl|wget)\b[^\n|]{0,160}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python|node)\b/i,
        /\b(?:iwr|invoke-webrequest)\b[^\n]{0,160}\|\s*(?:iex|invoke-expression)/i,
        /\b(?:iex|invoke-expression)\b[^\n]{0,120}(?:downloadstring|invoke-webrequest|iwr|http)/i,
        /\bpowershell(?:\.exe)?\b[^\n]{0,80}-(?:enc|encodedcommand)\b/i,
        /\bnode\s+-e\s+["'][^"']{0,40}https?:/i,
        /\b(?:bash|sh)\s+<\(\s*(?:curl|wget)/i,
      ];
      for (const re of patterns) {
        const m = re.exec(t);
        if (m) return { at: m.index, detail: snippetAt(t, m.index) };
      }
      return null;
    },
    message: () => 'Skill pipes remote content into an interpreter (curl|sh / iwr|iex / powershell -enc) — remote code execution.',
    fix: 'Pin and vendor the code. Never execute a downloaded script as part of a skill.',
  },
  {
    id: 'skill.obfuscated-payload',
    severity: 'high',
    test: (t) => {
      const longB64 = /[A-Za-z0-9+/]{120,}={0,2}/.exec(t);
      const evasive = /\b(?:eval|Function\s*\(|atob\s*\(|fromCharCode|unescape\s*\(|Buffer\.from\s*\([^)]*base64)/i.exec(t);
      if (longB64 && evasive) return { at: longB64.index, detail: 'encoded blob + dynamic execution' };
      const hexBlob = /(?:\\x[0-9a-f]{2}){12,}/i.exec(t);
      if (hexBlob) return { at: hexBlob.index, detail: 'hex-encoded payload' };
      return null;
    },
    message: () => 'Skill contains an obfuscated payload (encoded blob combined with eval/decode).',
    fix: 'Decode the payload and replace it with readable instructions. Obfuscation has no place in a skill.',
  },
  {
    id: 'skill.excessive-permissions',
    severity: 'high',
    test: (t) => {
      const patterns = [
        /\b(?:bypassPermissions|dangerouslySkipPermissions|dangerouslyDisableSandbox|autoApprove|alwaysAllow|full[- ]access|root\s+access|admin\s+access)\b/i,
        /"allowedTools"\s*:\s*\[\s*"\*"\s*\]/i,
        /(?:ignore|disable|bypass|turn\s+off|remove)[^\n]{0,60}(?:safety|guardrail|sandbox|approval|confirmation|security\s+check)/i,
        /(?:without|no)\s+(?:asking|confirmation|approval|permission)[^\n]{0,40}/i,
      ];
      for (const re of patterns) {
        const m = re.exec(t);
        if (m) return { at: m.index, detail: snippetAt(t, m.index) };
      }
      return null;
    },
    message: () => 'Skill requests or grants excessive permissions / tells the agent to skip safety and confirmation.',
    fix: 'Scope permissions to the specific tools the skill needs. Never ship a wildcard allow or a safety bypass.',
  },
  {
    id: 'skill.self-modification',
    severity: 'high',
    test: (t) => {
      const m = /(?:edit|write|modify|append\s+to|overwrite)[^\n]{0,80}(?:AGENTS\.md|CLAUDE\.md|\.cursorrules|SKILL\.md|skill\.md|\.claude|\.cursor)[^\n]{0,40}/i.exec(t);
      if (m) return { at: m.index, detail: snippetAt(t, m.index) };
      const d = /(?:disable|uninstall|remove|kill)[^\n]{0,60}(?:vibeguard|firewall|guard|monitor|audit\s+log)/i.exec(t);
      if (d) return { at: d.index, detail: snippetAt(t, d.index) };
      return null;
    },
    message: () => 'Skill tells the agent to modify its own instructions or disable the security layer — persistence / evasion.',
    fix: 'Remove the self-modification instruction. Skills must not rewrite agent instructions or disable monitoring.',
  },
  {
    id: 'skill.secret-in-text',
    severity: 'critical',
    test: (t) => {
      const leaks = scanForLeaks(t);
      if (!leaks.secrets.length) return null;
      return { at: 0, detail: leaks.secrets.join(', ') };
    },
    message: (d) => `Hardcoded credential in skill text (${d}) — every agent and every git reader gets it.`,
    fix: 'Remove the credential, rotate it, and use an environment reference.',
    redact: true,
  },
  {
    id: 'skill.package-risk',
    severity: 'high',
    test: (t) => {
      const commands = [
        /\b(?:npx|bunx|pnpm\s+dlx)\s+(?:-y\s+|--yes\s+)?([@\w./-]+)/gi,
        /\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)\s+(?:--save\s+)?([@\w./-]+)/gi,
        /\bpip3?\s+install\s+([\w.-]+)/gi,
        /\buvx\s+([\w.-]+)/gi,
      ];
      for (const re of commands) {
        let m;
        while ((m = re.exec(t)) !== null) {
          const spec = m[1];
          const name = spec.startsWith('@') ? spec.split('@').slice(0, 2).join('@') : spec.split('@')[0];
          const result = checkPackage(name);
          const bad = result.risks.find((r) => r.action === 'block') || result.risks.find((r) => r.severity === 'high');
          const unpinned = !spec.includes('@') || (spec.startsWith('@') && !spec.slice(1).includes('@'));
          if (bad) return { at: m.index, detail: `${name}: ${bad.message}` };
          if (unpinned) return { at: m.index, detail: `${name} is unpinned` };
        }
      }
      return null;
    },
    message: (d) => `Skill installs a risky or unpinned package (${d}).`,
    fix: 'Pin the package version and verify the package before the skill installs it.',
    severityFor: (d) => (/malicious|typosquat/i.test(d) ? 'critical' : 'medium'),
  },
];

// ─── Embedded MCP definitions in skill/plugin files ─────────────────────────

function scanEmbeddedMcp(text, rel) {
  const findings = [];
  let json;
  try { json = JSON.parse(text); } catch { return findings; }
  const servers = (json && (json.mcpServers || json.servers || (json.mcp && json.mcp.servers))) || null;
  if (!servers || typeof servers !== 'object') return findings;
  for (const [name, cfg] of Object.entries(servers)) {
    if (!cfg || typeof cfg !== 'object') continue;
    for (const f of auditServer(name, cfg)) {
      findings.push({
        ruleId: `skill.${f.id.replace(/^mcp\./, 'mcp-')}`,
        severity: f.severity,
        confidence: 'high',
        file: rel,
        line: 1,
        snippet: `${name}: ${f.message.slice(0, 100)}`,
        message: f.message,
        fix: f.fix,
        category: 'mcp',
      });
    }
  }
  return findings;
}

// ─── Main scan ──────────────────────────────────────────────────────────────

function scanSkills(root, opts = {}) {
  const projectRoot = path.resolve(root || process.cwd());
  const files = collectSkillFiles(projectRoot, opts);
  const findings = [];
  const scanned = [];

  for (const file of files) {
    const rel = normalize(path.relative(projectRoot, file));
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
    scanned.push(rel);

    for (const rule of RULES) {
      let hit;
      try { hit = rule.test(text); } catch { hit = null; }
      if (!hit) continue;
      let detail = hit.detail || '';
      let snippet = snippetAt(text, hit.at || 0);
      if (rule.redact) {
        detail = detail;
        snippet = '[redacted credential]';
      }
      const severity = rule.severityFor ? rule.severityFor(detail) : rule.severity;
      findings.push({
        ruleId: rule.id,
        severity,
        confidence: 'high',
        file: rel,
        line: lineOf(text, hit.at || 0),
        snippet,
        message: rule.message(detail),
        fix: rule.fix,
        category: 'skill',
        owasp: ['ASI04', 'MCP04'],
      });
    }

    if (/\.json$/i.test(file)) {
      for (const f of scanEmbeddedMcp(text, rel)) findings.push(f);
    }
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  let score = 0;
  for (const f of findings) score += SEVERITY_WEIGHT[f.severity] || 1;
  const riskScore = Math.min(100, score);
  const grade = riskScore === 0 ? 'A' : riskScore < 20 ? 'B' : riskScore < 40 ? 'C' : riskScore < 65 ? 'D' : 'F';

  findings.sort((a, b) => (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]) || a.file.localeCompare(b.file) || a.line - b.line);

  return {
    root: projectRoot,
    scannedFiles: scanned.length,
    files: scanned,
    findings,
    counts,
    riskScore,
    grade,
    clean: findings.length === 0,
  };
}

function renderSkillReport(result) {
  const C = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', cyan: '\x1b[36m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  const lines = [
    `${C.bold}VibeGuard Skill Scanner${C.reset}`,
    `${C.dim}${'─'.repeat(64)}${C.reset}`,
    `  Files scanned: ${result.scannedFiles}`,
    `  Risk score:    ${result.riskScore}/100  Grade: ${result.grade}`,
    '',
  ];
  if (result.findings.length === 0) {
    lines.push(`  ${C.green}No malicious skill or plugin behavior found.${C.reset}`);
    return lines.join('\n');
  }
  for (const f of result.findings) {
    const color = f.severity === 'critical' ? C.red : f.severity === 'high' ? C.yellow : C.dim;
    lines.push(`  ${color}${C.bold}${f.severity.toUpperCase().padEnd(8)}${C.reset} [${f.ruleId}] ${f.file}:${f.line}`);
    lines.push(`    ${f.message}`);
    if (f.snippet && f.snippet !== '[redacted credential]') lines.push(`    ${C.dim}${f.snippet.slice(0, 140)}${C.reset}`);
    lines.push(`    ${C.green}fix:${C.reset} ${f.fix}`);
    lines.push('');
  }
  const c = result.counts;
  lines.push(`${C.bold}${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low${C.reset}`);
  return lines.join('\n');
}

module.exports = {
  scanSkills,
  collectSkillFiles,
  isSkillFileName,
  renderSkillReport,
  RULES,
  SEVERITY_WEIGHT,
};
