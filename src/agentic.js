'use strict';

/*
 * src/agentic.js — OWASP Agentic AI (ASI01–ASI10) + MCP security posture.
 *
 * This is a config-and-code posture pass layered on top of the line scanner and
 * mcp-audit.js. It looks for agent-specific composition problems that a single
 * regex line rule cannot see: how a tool is described, what its schema invites,
 * what its handler does with that invitation, and how an agent loop, memory, or
 * prompt is wired. Everything is static and offline.
 *
 * API: analyzeAgentic({ root, files }) -> findings[]
 *   files: [{ rel, content, lines }] for every scanned project file.
 *
 * Findings use the same shape as src/rules.js makeFinding():
 *   { ruleId, severity, confidence, title, message, fix, file, line, column, snippet }
 *
 * Rule IDs are all prefixed `agent2026.` so this pack can be enabled, graded,
 * or ignored independently of ai.* and mcp.* rules.
 */

const path = require('path');

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.vibeguard', 'dist', 'build', '.next', 'out',
  'coverage', '.cache', 'vendor', '.venv', 'venv', '__pycache__',
]);

const LOCKFILES = new Set([
  'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml',
  'bun.lockb', 'composer.lock', 'poetry.lock', 'Pipfile.lock', 'Gemfile.lock',
  'Cargo.lock', 'uv.lock', 'go.sum', 'mix.lock',
]);

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const MAX_BLOCK = 12000;
const MAX_FINDINGS = 500;

// ---------------------------------------------------------------------------
// File classification / normalization
// ---------------------------------------------------------------------------

function normRel(rel) {
  return String(rel || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

function baseOf(rel) {
  return path.posix.basename(normRel(rel));
}

function isSkipped(rel) {
  const parts = normRel(rel).split('/');
  for (const p of parts) if (SKIP_DIRS.has(p)) return true;
  return LOCKFILES.has(baseOf(rel));
}

function isMcpConfigFile(rel, content) {
  const base = baseOf(rel);
  const r = normRel(rel);
  if (base === '.cursorrules') return /^\s*[{[]/.test(content || '');
  if (base === '.mcp.json' || base === 'mcp.json' || base === 'claude_desktop_config.json') return true;
  if (base.endsWith('.mcp.json')) return true;
  if (r.endsWith('.cursor/mcp.json') || r.endsWith('.vscode/mcp.json')) return true;
  if (r.endsWith('.claude/settings.json')) return true;
  return false;
}

function isPromptConfigFile(rel) {
  const base = baseOf(rel);
  const r = normRel(rel);
  if (base === 'CLAUDE.md' || base === 'AGENTS.md' || base === '.cursorrules') return true;
  if (r === '.github/copilot-instructions.md' || r.endsWith('/.github/copilot-instructions.md')) return true;
  return false;
}

function isCodeFile(rel) {
  return /\.(?:js|jsx|ts|tsx|mjs|cjs|py|rb|go|java|cs|rs|php)$/i.test(rel);
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

// Replace comments and string interiors with spaces while preserving length and
// newlines. Indexes into the masked copy still address the original text, so a
// sink found in real (non-string) code can be read from the raw source.
function maskNonCode(text) {
  const out = text.split('');
  let state = null;

  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const n = text[i + 1];

    if (state === 'line') {
      if (c === '\n') state = null;
      else out[i] = ' ';
      continue;
    }
    if (state === 'block') {
      if (c === '*' && n === '/') {
        out[i] = ' ';
        out[i + 1] = ' ';
        i++;
        state = null;
      } else if (c !== '\n') {
        out[i] = ' ';
      }
      continue;
    }
    if (state) { // inside a quoted string; keep the delimiters for key parsing
      if (c === '\\') {
        out[i] = ' ';
        if (i + 1 < text.length) {
          if (text[i + 1] !== '\n') out[i + 1] = ' ';
          i++;
        }
        continue;
      }
      if (c === state) {
        state = null;
        continue;
      }
      if (c !== '\n') out[i] = ' ';
      continue;
    }

    if (c === '/' && n === '/') {
      out[i] = ' ';
      out[i + 1] = ' ';
      i++;
      state = 'line';
    } else if (c === '/' && n === '*') {
      out[i] = ' ';
      out[i + 1] = ' ';
      i++;
      state = 'block';
    } else if (c === '"' || c === "'" || c === '`') {
      state = c;
    }
  }
  return out.join('');
}

function lineOf(text, idx) {
  let line = 1;
  const end = Math.min(idx, text.length);
  for (let i = 0; i < end; i++) if (text[i] === '\n') line++;
  return line;
}

function snippetAt(lines, line) {
  return String(lines[line - 1] || '').trim().slice(0, 220);
}

function sanitizeSnippet(s) {
  return String(s || '')
    .replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g, (ch) => {
      return '<U+' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0') + '>';
    })
    .slice(0, 240);
}

function escapeRe(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function findLineOfKey(lines, key) {
  const re = new RegExp('["\\\']?' + escapeRe(key) + '["\\\']?\\s*:');
  for (let i = 0; i < lines.length; i++) if (re.test(lines[i])) return { line: i + 1, column: lines[i].search(re) + 1 };
  return { line: 1, column: 1 };
}

function lineOfPattern(lines, re) {
  for (let i = 0; i < lines.length; i++) if (re.test(lines[i])) return i + 1;
  return 1;
}

// Decode the escapes an LLM-facing description commonly carries, without eval.
function decodeEscapes(s) {
  return String(s)
    .replace(/\\u\{([0-9a-f]+)\}/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t');
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

const SECRET_PATTERNS = [
  { re: /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b/, type: 'API key' },
  { re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/, type: 'GitHub token' },
  { re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/, type: 'GitHub token' },
  { re: /\bAKIA[0-9A-Z]{16}\b/, type: 'AWS access key' },
  { re: /\bglpat-[A-Za-z0-9_-]{20,}\b/, type: 'GitLab token' },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, type: 'Slack token' },
  { re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/, type: 'Stripe key' },
  { re: /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/, type: 'private key' },
];

function isPlaceholderSecret(value) {
  const v = String(value || '');
  if (v.length < 12) return true;
  return /\$\{|process\.env|os\.environ|import\.meta|<[^>]+>|your[_-]|example|placeholder|dummy|redacted|changeme|x{6,}|\*{3,}/i.test(v);
}

function findSecret(value) {
  const v = String(value || '');
  if (!v || isPlaceholderSecret(v)) return null;
  for (const p of SECRET_PATTERNS) {
    const m = p.re.exec(v);
    if (m) return { type: p.type, value: m[0], masked: maskSecret(m[0]) };
  }
  return null;
}

function maskSecret(value) {
  if (/PRIVATE KEY/.test(value)) return '[private key redacted]';
  if (value.length <= 8) return '[redacted]';
  return value.slice(0, 6) + '…' + value.slice(-2);
}

// ---------------------------------------------------------------------------
// Stable comparison for cross-file server definitions
// ---------------------------------------------------------------------------

function stableValue(v) {
  if (Array.isArray(v)) return '[' + v.map(stableValue).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + stableValue(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

// ---------------------------------------------------------------------------
// Object / tool block helpers
// ---------------------------------------------------------------------------

function findObjectBlocks(text) {
  const blocks = [];
  const stack = [];
  let state = null;

  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const n = text[i + 1];

    if (state === 'line') {
      if (c === '\n') state = null;
      continue;
    }
    if (state === 'block') {
      if (c === '*' && n === '/') { state = null; i++; }
      continue;
    }
    if (state) {
      if (c === '\\') { i++; continue; }
      if (c === state) state = null;
      continue;
    }
    if (c === '/' && n === '/') { state = 'line'; i++; continue; }
    if (c === '/' && n === '*') { state = 'block'; i++; continue; }
    if (c === '"' || c === "'" || c === '`') { state = c; continue; }
    if (c === '{') {
      stack.push(i);
    } else if (c === '}' && stack.length) {
      const start = stack.pop();
      if (i - start <= MAX_BLOCK) blocks.push({ start, end: i });
    }
  }
  return blocks;
}

function smallestBlockAt(blocks, idx) {
  let best = null;
  for (const b of blocks) {
    if (b.start < idx && b.end > idx && (!best || (b.end - b.start) < (best.end - best.start))) best = b;
  }
  return best;
}

// Match `{`/`[`/`(` at openIdx to its closing character, aware of strings.
function matchBracket(text, openIdx) {
  const open = text[openIdx];
  const close = open === '{' ? '}' : open === '[' ? ']' : ')';
  let depth = 0;
  let state = null;

  for (let i = openIdx; i < text.length; i++) {
    const c = text[i];
    const n = text[i + 1];
    if (state === 'line') { if (c === '\n') state = null; continue; }
    if (state === 'block') { if (c === '*' && n === '/') { state = null; i++; } continue; }
    if (state) {
      if (c === '\\') { i++; continue; }
      if (c === state) state = null;
      continue;
    }
    if (c === '/' && n === '/') { state = 'line'; i++; continue; }
    if (c === '/' && n === '*') { state = 'block'; i++; continue; }
    if (c === '"' || c === "'" || c === '`') { state = c; continue; }
    if (c === open) depth++;
    else if (c === close) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return text.length - 1;
}

function extractStringAt(text, idx) {
  let i = idx;
  while (i < text.length && /\s/.test(text[i])) i++;
  const q = text[i];
  if (q !== '"' && q !== "'" && q !== '`') return null;
  let out = '';
  i++;
  for (; i < text.length && out.length < 12000; i++) {
    const c = text[i];
    if (c === '\\') {
      out += c;
      if (i + 1 < text.length) out += text[++i];
      continue;
    }
    if (c === q) return { value: decodeEscapes(out), raw: out, start: idx, end: i + 1 };
    out += c;
  }
  return { value: decodeEscapes(out), raw: out, start: idx, end: i, unterminated: true };
}

function valueAfterKey(text, key) {
  const re = new RegExp('(?:^|[{,\\s])["\\\']?' + escapeRe(key) + '["\\\']?\\s*:\\s*', 'i');
  const m = re.exec(text);
  if (!m) return null;
  let i = m.index + m[0].length;
  while (i < text.length && /\s/.test(text[i])) i++;
  if (text[i] === '{' || text[i] === '[' || text[i] === '(') {
    return text.slice(i, matchBracket(text, i) + 1);
  }
  if (text[i] === '"' || text[i] === "'" || text[i] === '`') {
    const s = extractStringAt(text, i);
    return s ? s.value : null;
  }
  return null;
}

function fieldIndex(text, key) {
  const re = new RegExp('(?:^|[{,\\s])["\\\']?' + escapeRe(key) + '["\\\']?\\s*:', 'i');
  const m = re.exec(text);
  return m ? m.index : -1;
}

// ---------------------------------------------------------------------------
// Finding collector
// ---------------------------------------------------------------------------

function makeCollector() {
  const findings = [];
  const seen = new Set();
  const add = (f) => {
    if (!f || !f.ruleId || !f.severity || !f.title || !f.message || !f.fix || !f.file) return;
    const key = `${f.ruleId}|${f.file}|${f.line || 1}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({
      ruleId: f.ruleId,
      severity: f.severity,
      confidence: f.confidence || 'medium',
      title: f.title,
      message: f.message,
      fix: f.fix,
      file: normRel(f.file),
      line: Math.max(1, Number(f.line) || 1),
      column: Math.max(1, Number(f.column) || 1),
      snippet: sanitizeSnippet(f.snippet || ''),
    });
  };
  return { findings, add };
}

// ---------------------------------------------------------------------------
// MCP server configs
// ---------------------------------------------------------------------------

function exactVersion(pkg) {
  if (!pkg) return false;
  let v = null;
  if (pkg.startsWith('@')) {
    const slash = pkg.indexOf('/');
    if (slash < 0) return false;
    const at = pkg.indexOf('@', slash + 1);
    if (at < 0) return false;
    v = pkg.slice(at + 1);
  } else if (pkg.includes('==')) {
    v = pkg.slice(pkg.indexOf('==') + 2);
  } else if (pkg.includes('@')) {
    v = pkg.slice(pkg.lastIndexOf('@') + 1);
  } else {
    return false;
  }
  return /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(v);
}

function packageArg(args) {
  for (let i = 0; i < args.length; i++) {
    const a = String(args[i]);
    if (a === '-p' || a === '--package' || a === '--from') {
      if (i + 1 < args.length) return String(args[i + 1]);
      continue;
    }
    if (a.startsWith('-')) continue;
    if (a === 'dlx' || a === 'exec') continue;
    return a;
  }
  return null;
}

function isLocalHost(hostname) {
  const h = String(hostname || '').toLowerCase();
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '[::1]' ||
    h === '0.0.0.0' || h.endsWith('.localhost');
}

function parseHttpUrl(value) {
  if (!value) return null;
  try {
    const u = new URL(String(value));
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u;
  } catch {
    return null;
  }
}

function hasAuthHeader(cfg, content) {
  const headers = cfg && cfg.headers && typeof cfg.headers === 'object' ? cfg.headers : {};
  for (const [k, v] of Object.entries(headers)) {
    if (/^(?:authorization|proxy-authorization|x-api-key|api-key|apikey|token|x-auth-token)$/i.test(k) && v) return true;
  }
  if (cfg && (cfg.bearerToken || cfg.token || cfg.apiKey)) return true;
  if (cfg && cfg.auth && typeof cfg.auth === 'object' && Object.keys(cfg.auth).length) return true;
  // smithery.yaml: headers are YAML, not a parsed object.
  if (content && /^\s*(?:authorization|api[_-]?key|x-api-key|token)\s*:/im.test(content)) return true;
  return false;
}

const APPROVE_KEYS = /^(?:autoapprove|auto_approve|alwaysallow|always_allow|autoapprovetools|alwaysallowtools|allowedtools|autoapproveall|allowalltools)$/i;
const DANGEROUS_TOOL_RE = /(?:^|[_\-.:])(?:\*|all|shell|bash|sh|exec|execute|command|terminal|run|process|spawn|write|edit|delete|remove|rm|create|move|copy|drop|truncate|fetch|http|curl|wget|network|browser|web|url|post|upload|download|request|sql|query|database|db|deploy|transfer|install|package)(?:$|[_\-.:])/i;

function dangerousAutoApproved(value) {
  if (value === true) return ['all tools'];
  if (value === false || value == null) return [];
  if (typeof value === 'string') value = [value];
  if (!Array.isArray(value)) return [];
  const hits = [];
  for (const v of value) {
    const s = String(v || '').trim();
    if (!s) continue;
    if (s === '*' || /^all$/i.test(s) || DANGEROUS_TOOL_RE.test(s)) hits.push(s);
  }
  return hits;
}

function analyzeMcpServer(server, lines, add, state) {
  const { name, cfg, rel } = server;
  const line = server.line || 1;
  const snippet = snippetAt(lines, line);
  const commandRaw = typeof cfg.command === 'string' ? cfg.command : '';
  const argv = commandRaw.trim() ? commandRaw.trim().split(/\s+/) : [];
  const command = argv[0] || '';
  const args = Array.isArray(cfg.args) ? cfg.args.map(String) : (argv.length > 1 ? argv.slice(1) : []);
  const env = cfg.env && typeof cfg.env === 'object' ? cfg.env : {};
  const cmdLine = [commandRaw, ...args].join(' ').trim();

  // 1. Unpinned auto-install (rug-pull surface).
  const cmdBase = path.posix.basename(command);
  if (/^(?:npx|bunx|pnpm|yarn)$/i.test(cmdBase)) {
    const pkg = packageArg(args);
    if (pkg && args.some((a) => /^(?:-y|--yes)$/i.test(a)) && !exactVersion(pkg)) {
      add({
        ruleId: 'agent2026.mcp-unpinned-install', severity: 'medium', confidence: 'high',
        title: 'MCP server auto-installs an unpinned package',
        message: `Server "${name}" runs "${cmdLine}", which downloads "${pkg}" with no exact version. The package's code can change between agent sessions (rug-pull).`,
        fix: `Pin the package to an exact version (e.g. "${pkg}@1.2.3") or vendor the server, and avoid -y auto-install in .mcp.json.`,
        file: rel, line, column: server.column || 1, snippet,
      });
    }
  } else if (/^(?:uvx|uv)$/i.test(cmdBase)) {
    const pkg = packageArg(args);
    if (pkg && !exactVersion(pkg)) {
      add({
        ruleId: 'agent2026.mcp-unpinned-install', severity: 'medium', confidence: 'high',
        title: 'MCP server auto-installs an unpinned package',
        message: `Server "${name}" runs "${cmdLine}", which resolves "${pkg}" at launch with no exact version. A new release can silently change the tools the agent trusts.`,
        fix: `Pin the package with an exact version (e.g. "uvx ${pkg.split('==')[0]}==1.2.3") or vendor the server.`,
        file: rel, line, column: server.column || 1, snippet,
      });
    }
  }

  // 2. Remote transport without authentication / not disabled.
  const urlText = String(cfg.url || cfg.serverUrl || cfg.httpUrl ||
    (cfg.transport && cfg.transport.url) || '');
  let remoteUrl = parseHttpUrl(urlText);
  if (!remoteUrl && /(?:^|\s)--(?:url|sse-url|server-url)\b/i.test(cmdLine)) {
    const m = cmdLine.match(/https?:\/\/[^\s'"]+/i);
    if (m) remoteUrl = parseHttpUrl(m[0]);
  }
  if (remoteUrl && !isLocalHost(remoteUrl.hostname)) {
    const authed = hasAuthHeader(cfg, server.content);
    const remoteLine = cfg.url ? findLineOfKey(lines, 'url').line : line;
    if (!authed) {
      add({
        ruleId: 'agent2026.mcp-remote-no-auth', severity: 'medium', confidence: 'high',
        title: 'Remote MCP server has no authentication header',
        message: `Server "${name}" connects to ${remoteUrl.protocol}//${remoteUrl.host} over a network transport with no Authorization/API-key header. Anyone who can reach that URL can call the agent's tools.`,
        fix: `Require an auth header (e.g. "headers": { "Authorization": "Bearer <token>" }) for the remote server, or use a local stdio server.`,
        file: rel, line: remoteLine, column: 1, snippet: snippetAt(lines, remoteLine),
      });
    }
    if (cfg.disabled !== true && cfg.enabled !== false) {
      add({
        ruleId: 'agent2026.mcp-remote-not-disabled', severity: 'low', confidence: 'medium',
        title: 'Remote MCP server is enabled by default',
        message: `Server "${name}" is a remote endpoint and has no "disabled": true guard, so every agent session connects to it automatically.`,
        fix: `Set "disabled": true in the shared config and enable the remote server explicitly only when needed.`,
        file: rel, line: remoteLine, column: 1, snippet: snippetAt(lines, remoteLine),
      });
    }
    state.remoteServers.push({ name, rel, line: remoteLine, url: remoteUrl.href, auth: authed });
  }

  // 3. Secrets committed in env / args.
  const secretStrings = [];
  for (const [k, v] of Object.entries(env)) {
    if (typeof v !== 'string') continue;
    secretStrings.push({ key: k, value: v, line: findLineOfKey(lines, k).line, env: true });
  }
  if (commandRaw) secretStrings.push({ key: 'command', value: cmdLine, line, env: false });
  const reportedSecrets = new Set();
  for (const s of secretStrings) {
    const hit = findSecret(s.value);
    if (!hit) continue;
    if (reportedSecrets.has(hit.masked)) continue;
    reportedSecrets.add(hit.masked);
    const rawLine = snippetAt(lines, s.line);
    add({
      ruleId: 'agent2026.mcp-secret-in-env', severity: 'critical', confidence: 'high',
      title: 'Secret committed in MCP server config',
      message: `Server "${name}" contains a hardcoded ${hit.type} in ${s.env ? `env var ${s.key}` : 'its command/args'}. The credential is committed to the repo and is readable by every process and agent on this machine.`,
      fix: `Remove the literal from ${rel}, reference a local environment variable or the VibeGuard vault instead, and rotate the exposed ${hit.type}.`,
      file: rel, line: s.line, column: 1,
      snippet: rawLine.includes(hit.value) ? rawLine.replace(hit.value, hit.masked) : `${s.key}: ${hit.masked}`,
    });
    state.secretRefs.push({ name, rel, line: s.line, key: s.key });
  }

  // 4. Shell wrapper / inline code execution in the server command.
  const shellBase = path.posix.basename(command);
  const shellWrapper = /^(?:sh|bash|zsh|dash|fish|ksh|cmd|cmd\.exe|powershell|powershell\.exe|pwsh|pwsh\.exe)$/i.test(shellBase) ||
    /(?:^|\s)(?:sh|bash|zsh|cmd|powershell|pwsh)\s+(?:-c|\/c)\b/i.test(cmdLine) ||
    /(?:&&|\|\||;|\$\(|`|\|\s*(?:sh|bash|zsh)\b)/.test(commandRaw);
  const inlineEval = /^(?:node|deno|bun|python\d*|perl|ruby)$/i.test(shellBase) &&
    args.some((a) => /^(?:-e|--eval|-c)$/i.test(a));
  if (shellWrapper || inlineEval) {
    add({
      ruleId: 'agent2026.mcp-shell-command', severity: 'medium', confidence: 'high',
      title: 'MCP server is launched through a shell wrapper',
      message: `Server "${name}" is started with "${cmdLine}". Shell metacharacters or an inline -e/-c payload turn the MCP config into arbitrary code execution on every agent launch.`,
      fix: `Launch a pinned executable directly (command + args array) and remove shell operators, bash -c, cmd /c, and -e/-c inline code from the config.`,
      file: rel, line, column: 1, snippet,
    });
  }

  // 5. Auto-approving dangerous tools removes the human confirmation step.
  for (const [k, v] of Object.entries(cfg)) {
    if (!APPROVE_KEYS.test(k)) continue;
    const hits = dangerousAutoApproved(v);
    if (!hits.length) continue;
    add({
      ruleId: 'agent2026.mcp-auto-approve-dangerous', severity: 'high', confidence: 'high',
      title: 'MCP config auto-approves destructive tools',
      message: `Server "${name}" sets ${k} to ${JSON.stringify(v)}, so the agent can run ${hits.slice(0, 4).join(', ')} without asking the user. A poisoned tool call becomes unattended shell/write/network access.`,
      fix: `Remove ${k} for shell, write, and network tools; require explicit user confirmation per call, and keep auto-approval to read-only tools only.`,
      file: rel, line: findLineOfKey(lines, k).line, column: 1,
      snippet: snippetAt(lines, findLineOfKey(lines, k).line),
    });
  }

  state.servers.push(server);
}

function mcpEntriesFromJson(json) {
  const maps = [];
  if (json && typeof json === 'object') {
    if (json.mcpServers && typeof json.mcpServers === 'object') maps.push(json.mcpServers);
    if (json.servers && typeof json.servers === 'object') maps.push(json.servers);
    if (json.mcp && typeof json.mcp === 'object' && json.mcp.servers && typeof json.mcp.servers === 'object') {
      maps.push(json.mcp.servers);
    }
  }
  const out = [];
  for (const map of maps) {
    for (const [name, cfg] of Object.entries(map)) {
      if (cfg && typeof cfg === 'object' && !Array.isArray(cfg)) out.push({ name, cfg });
    }
  }
  return out;
}

function analyzeMcpJson(rel, content, lines, add, state) {
  let json;
  try { json = JSON.parse(content); } catch { return; }
  for (const { name, cfg } of mcpEntriesFromJson(json)) {
    const loc = findLineOfKey(lines, name);
    analyzeMcpServer({ name, cfg, rel, line: loc.line, column: loc.column, content }, lines, add, state);
  }
}

function analyzeSmitheryYaml(rel, content, lines, add, state) {
  const nameM = content.match(/^\s*name\s*:\s*["']?([\w.-]+)["']?/m);
  const cmdM = content.match(/^\s*command\s*:\s*(.+?)\s*$/m);
  if (!cmdM && !/\bargs\s*:/.test(content)) return;

  const command = cmdM ? cmdM[1].replace(/^["']|["']$/g, '').trim() : '';
  let args = [];
  const inline = content.match(/^\s*args\s*:\s*\[([^\]]*)\]/m);
  if (inline) {
    args = inline[1].split(',').map((s) => s.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
  } else {
    const idx = lines.findIndex((l) => /^\s*args\s*:\s*$/.test(l));
    if (idx >= 0) {
      for (let j = idx + 1; j < lines.length; j++) {
        const m = lines[j].match(/^\s*-\s*(.+?)\s*$/);
        if (!m) break;
        args.push(m[1].replace(/^["']|["']$/g, ''));
      }
    }
  }

  const cfg = { command, args };
  const urlM = content.match(/^\s*url\s*:\s*["']?(https?:\/\/[^\s"']+)/m);
  if (urlM) cfg.url = urlM[1];

  const envIdx = lines.findIndex((l) => /^\s*env\s*:\s*$/.test(l));
  if (envIdx >= 0) {
    const env = {};
    for (let j = envIdx + 1; j < lines.length; j++) {
      const m = lines[j].match(/^\s+([A-Za-z_][\w]*)\s*:\s*(.+?)\s*$/);
      if (!m) break;
      env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
    if (Object.keys(env).length) cfg.env = env;
  }
  const disabledM = content.match(/^\s*disabled\s*:\s*(true|false)\s*$/m);
  if (disabledM) cfg.disabled = disabledM[1] === 'true';

  const name = nameM ? nameM[1] : (baseOf(rel).replace(/\.ya?ml$/i, '') || 'smithery');
  const line = cmdM ? lineOfPattern(lines, /^\s*command\s*:/) : 1;
  analyzeMcpServer({ name, cfg, rel, line, column: 1, content }, lines, add, state);
}

// ---------------------------------------------------------------------------
// Tool descriptions and tool objects
// ---------------------------------------------------------------------------

const STRONG_POISON = [
  { re: /ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?)/i, label: 'ignore-previous-instructions' },
  { re: /disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier|system)/i, label: 'disregard-instructions' },
  { re: /forget\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above)/i, label: 'forget-instructions' },
  { re: /(?:do\s+not|don'?t)\s+(?:tell|mention|inform|alert|reveal|disclose)/i, label: 'hide-from-user' },
  { re: /regardless\s+of\s+(?:what|any|the|your|instructions?|safety|content|rules?)/i, label: 'ignore-policy' },
  { re: /always\s+(?:call|use|invoke|run|execute|include|send|post|return)/i, label: 'always-do' },
  { re: /before\s+(?:answering|responding|calling|replying)/i, label: 'pre-answer-hook' },
  { re: /system\s+prompt/i, label: 'system-prompt-reference' },
  { re: /secretly/i, label: 'concealment' },
  { re: /\bexfiltrat(?:e|es|ed|ing)\b/i, label: 'exfiltration' },
  { re: /new\s+instructions?\s*:/i, label: 'injected-instructions' },
  { re: /never\s+refuse/i, label: 'never-refuse' },
  { re: /bypass\s+(?:safety|policy|guard|filter|restrictions?|approval)/i, label: 'safety-bypass' },
  { re: /you\s+are\s+now\s+(?:a|an|the|in)\b/i, label: 'role-override' },
];

const WEAK_POISON = [
  { re: /\byou\s+must\b/i, label: 'directive-you-must' },
  { re: /\bmust\s+not\s+(?:tell|mention|reveal|disclose)\b/i, label: 'directive-must-not' },
  { re: /\bdo\s+not\s+(?:stop|ask|check)\b/i, label: 'directive-no-stop' },
];

// Assembled from fragments so this detector does not match its own source when
// the repo is self-scanned.
const SANDBOX_FLAG_RE = new RegExp([
  'dangerously' + '_skip_permissions',
  'dangerously' + 'SkipPermissions',
  '--dangerously' + '-skip-permissions',
  'bypass' + 'Permissions',
  "permissionMode\\s*:\\s*[\"']bypass" + "Permissions[\"']",
  'auto' + 'ApproveAll',
  'allow' + 'AllTools',
  'dangerously' + 'AllowAll',
].join('|'));

const ZERO_WIDTH_RE = /[\u200B-\u200D\u2060\uFEFF\u180E]/g;
const BIDI_RE = /[\u202A-\u202E\u2066-\u2069]/g;

function analyzeToolDescription(desc, tool, rel, lines, line, add) {
  if (!desc) return;
  const text = desc;
  const rawLine = snippetAt(lines, line);

  // Hidden Unicode / bidi control characters — used to smuggle instructions.
  const zwMatches = text.match(ZERO_WIDTH_RE) || [];
  const bidiMatches = text.match(BIDI_RE) || [];
  if (zwMatches.length > 4 || bidiMatches.length > 0) {
    add({
      ruleId: 'agent2026.tool-description-hidden-unicode', severity: 'high', confidence: 'high',
      title: 'Tool description carries hidden Unicode',
      message: `Tool "${tool}" has ${zwMatches.length} zero-width character(s) and ${bidiMatches.length} bidi override(s) in its description. Hidden text can redirect the model while the visible description looks benign.`,
      fix: 'Strip zero-width and bidi control characters from all tool descriptions, and fail CI if they reappear in tool metadata.',
      file: rel, line, column: 1, snippet: rawLine,
    });
  }

  // Base64 blobs in a description are concealment, not documentation.
  const b64 = text.match(/\b[A-Za-z0-9+/]{80,}={0,2}\b/);
  if (b64 && !/https?:\/\//i.test(text)) {
    let printable = 0;
    try {
      const dec = Buffer.from(b64[0], 'base64').toString('utf8');
      if (dec.length) {
        const chars = dec.slice(0, 400);
        for (const ch of chars) if (/[\x20-\x7E\n\r\t]/.test(ch)) printable++;
        printable = printable / chars.length;
      }
    } catch { printable = 0; }
    if (printable > 0.85) {
      add({
        ruleId: 'agent2026.tool-description-encoded', severity: 'medium', confidence: 'medium',
        title: 'Tool description contains a base64 payload',
        message: `Tool "${tool}" embeds a ${b64[0].length}-character base64 blob in its description. Encoded content in tool metadata is a common way to hide injected instructions.`,
        fix: 'Remove encoded content from tool descriptions; descriptions should be short factual prose a reviewer can read.',
        file: rel, line, column: 1, snippet: rawLine,
      });
    }
  }

  // Description telling the model to send data to a host.
  const urlM = text.match(/https?:\/\/[^\s'"`)]+/i);
  if (urlM) {
    const parsed = parseHttpUrl(urlM[0]);
    const send = /\b(?:send|post|pass|forward|upload|transmit|include|attach|append|share|leak)\b/i.test(text);
    const data = /\b(?:conversation|history|messages?|context|secrets?|tokens?|keys?|credentials?|environment|env|files?|contents?|data|prompt)\b/i.test(text);
    if (parsed && !isLocalHost(parsed.hostname) && send && data) {
      add({
        ruleId: 'agent2026.tool-description-exfil-instruction', severity: 'high', confidence: 'medium',
        title: 'Tool description instructs data exfiltration',
        message: `Tool "${tool}" tells the model to send conversation/secrets data to ${parsed.host}. A tool description is executable instruction to an LLM, so this is an exfiltration directive.`,
        fix: 'Remove the URL and any send/post directive from the tool description; if the tool needs to call a host, allowlist it in code and require user confirmation.',
        file: rel, line, column: 1, snippet: rawLine,
      });
    }
  }

  // Instruction overrides. Strong signals are high; a lone weak directive is low.
  const strong = [];
  for (const p of STRONG_POISON) if (p.re.test(text)) strong.push(p.label);
  if (strong.length) {
    add({
      ruleId: 'agent2026.tool-description-poisoning', severity: 'high', confidence: 'high',
      title: 'Tool description contains instruction-override text',
      message: `Tool "${tool}" describes itself with ${strong.slice(0, 3).join(', ')}. The model reads this as an instruction, not documentation, so the tool can hijack the agent's behaviour.`,
      fix: 'Rewrite the tool description as factual capability text ("Lists files in a directory") and remove every instruction, policy, or user-directed sentence.',
      file: rel, line, column: 1, snippet: rawLine,
    });
  } else {
    const weak = [];
    for (const p of WEAK_POISON) if (p.re.test(text)) weak.push(p.label);
    if (weak.length) {
      add({
        ruleId: 'agent2026.tool-description-weak-directive', severity: 'low', confidence: 'low',
        title: 'Tool description reads as a directive',
        message: `Tool "${tool}" uses directive language (${weak.join(', ')}). It is not proof of poisoning, but tool descriptions should describe the tool, not command the model.`,
        fix: 'Rephrase the description as a factual summary of what the tool does and returns.',
        file: rel, line, column: 1, snippet: rawLine,
      });
    }
  }
}

const DESTRUCTIVE_NAME_RE = /^(?:delete|drop|exec|execute|shell|run_command|run_shell|run_command_line|shell_exec|deploy|transfer|destroy|wipe|remove|truncate|kill|format|write_file|write|install|publish)[_\-.]?/i;
const CONFIRM_RE = /\b(?:confirm|confirmed|confirmation|dryRun|dry_run|askForConfirmation|requiresConfirmation|requireConfirmation|humanApproval)\b/i;

function toolHandlerName(name) {
  const pascal = String(name).split(/[_\-.]+/).filter(Boolean)
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1)).join('');
  return 'handle' + pascal;
}

function findFunctionBody(text, name) {
  if (!name) return null;
  const escaped = escapeRe(name);
  const patterns = [
    new RegExp('(?:async\\s+)?function\\s+' + escaped + '\\s*\\([^)]*\\)\\s*\\{'),
    new RegExp('(?:const|let|var)\\s+' + escaped + '\\s*=\\s*(?:async\\s*)?(?:\\([^)]*\\)|[A-Za-z_$][\\w$]*)\\s*=>\\s*\\{'),
    new RegExp(escaped + '\\s*:\\s*(?:async\\s*)?(?:function\\s*)?\\([^)]*\\)\\s*\\{'),
  ];
  for (const re of patterns) {
    const m = re.exec(text);
    if (!m) continue;
    const open = text.indexOf('{', m.index + m[0].length - 1);
    if (open < 0) continue;
    const end = matchBracket(text, open);
    return { start: open, end, body: text.slice(open, end + 1) };
  }
  return null;
}

function schemaParamNames(schema) {
  const names = [];
  if (!schema) return names;
  const re = /["']?(?:command|cmd|sql|query|url|path|script)["']?\s*:\s*\{/gi;
  let m;
  while ((m = re.exec(schema))) {
    const n = m[0].replace(/["']/g, '').replace(/\s*:\s*\{$/, '').trim();
    if (!names.includes(n)) names.push(n);
  }
  return names;
}

function analyzeToolBlock(tool, content, rel, lines, add) {
  const blockText = content.slice(tool.block.start, tool.block.end + 1);
  const line = tool.line;

  const descIdx = fieldIndex(blockText, 'description');
  const schemaIdx = Math.max(
    fieldIndex(blockText, 'inputSchema'),
    fieldIndex(blockText, 'input_schema'),
    fieldIndex(blockText, 'parameters')
  );
  let desc = null;
  if (descIdx >= 0 && (schemaIdx < 0 || descIdx < schemaIdx)) {
    const s = extractStringAt(blockText, blockText.indexOf(':', descIdx) + 1);
    if (s && s.value) desc = s.value;
  }
  const schemaKey = fieldIndex(blockText, 'inputSchema') >= 0 ? 'inputSchema'
    : fieldIndex(blockText, 'input_schema') >= 0 ? 'input_schema'
      : fieldIndex(blockText, 'parameters') >= 0 ? 'parameters' : null;
  const schema = schemaKey ? valueAfterKey(blockText, schemaKey) : null;

  if (desc) analyzeToolDescription(desc, tool.name, rel, lines, line, add);

  // Destructive capability without a confirmation parameter.
  if (DESTRUCTIVE_NAME_RE.test(tool.name) && !CONFIRM_RE.test(schema || '') && !CONFIRM_RE.test(tool.registrationHandler || '')) {
    add({
      ruleId: 'agent2026.tool-destructive-no-confirm', severity: 'high', confidence: 'high',
      title: 'Destructive tool has no confirmation parameter',
      message: `Tool "${tool.name}" is named as a destructive action (delete/drop/exec/deploy/transfer/write) but its schema and description expose no confirm/dryRun switch. The model can invoke it unattended.`,
      fix: 'Add a required "confirm": true or "dryRun" parameter, and require an explicit human approval before the destructive branch runs.',
      file: rel, line, column: 1, snippet: snippetAt(lines, line),
    });
  }

  // Filesystem tool rooted at the whole disk.
  if (/(?:file|filesystem|fs\b|directory|read|write|list)/i.test(tool.name) && schema) {
    const directRoot = /["']?(?:root|rootDir|baseDir|allowedRoot|allowedRoots|filesystemRoot)["']?\s*:\s*["'](?:\.|\/|~|[A-Za-z]:[\\/]{1,2})["']/i.test(schema);
    const defaultRoot = /["']?(?:root|rootDir|baseDir|allowedRoot|allowedRoots|filesystemRoot)["']?\s*:\s*\{[^}]{0,400}?["']?\bdefault["']?\s*:\s*["'](?:\.|\/|~|[A-Za-z]:[\\/]{1,2})["']/i.test(schema);
    if (directRoot || defaultRoot) {
      add({
        ruleId: 'agent2026.filesystem-broad-root', severity: 'high', confidence: 'medium',
        title: 'Filesystem tool is rooted at the whole disk',
        message: `Tool "${tool.name}" exposes a filesystem root of ".", "/", "~", or a drive root. A prompt-injected path can read or write any file the agent process can reach.`,
        fix: 'Root the filesystem tool at one project directory, resolve every requested path against it, and reject paths that escape that base.',
        file: rel, line, column: 1, snippet: snippetAt(lines, line),
      });
    }
  }

  // Raw command/sql/url/path/script input that reaches a dangerous sink.
  const params = schemaParamNames(schema);
  if (params.length) {
    let body = null;
    if (tool.inlineHandler) body = tool.inlineHandler;
    else if (tool.registrationHandler) body = tool.registrationHandler;
    else {
      const h = findFunctionBody(content, toolHandlerName(tool.name));
      if (h) body = h.body;
    }
    if (body) {
      const argRef = params.map(escapeRe).join('|');
      const sinkRe = new RegExp(
        '\\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|query|raw|fetch|axios(?:\\.[a-z]+)?|requests\\.(?:get|post)|https?\\.request|eval)\\s*\\([^)]{0,300}' +
        '(?:args|input|params|arguments|ctx|request)\\s*(?:\\.|\\[\\s*["\\\']?)\\s*(?:' + argRef + ')\\b', 'i'
      );
      if (sinkRe.test(body)) {
        add({
          ruleId: 'agent2026.tool-input-to-sink', severity: 'high', confidence: 'high',
          title: 'Tool input is interpolated into a dangerous sink',
          message: `Tool "${tool.name}" accepts raw ${params.join('/')} input and its handler passes that value into a shell/query/fetch sink. A prompt-injected argument becomes command, SQL, SSRF, or path traversal.`,
          fix: 'Validate the argument against an allowlist/enum, parameterize queries, and never interpolate tool input into exec, fetch, or raw SQL.',
          file: rel, line, column: 1, snippet: snippetAt(lines, line),
        });
      }
    }
  }

  // readOnlyHint: true while the visible handler writes.
  if (/["']?readOnlyHint["']?\s*:\s*true\b/i.test(blockText)) {
    let body = tool.inlineHandler || tool.registrationHandler || null;
    if (!body) {
      const h = findFunctionBody(content, toolHandlerName(tool.name));
      if (h) body = h.body;
    }
    if (body && /\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|unlink|unlinkSync|rmSync|rmdir|mkdir|rename|truncate)\s*\(|\.(?:insert|update|delete|drop|upsert)\s*\(|(?:exec|execSync|spawn)\s*\(/i.test(body)) {
      add({
        ruleId: 'agent2026.tool-readonly-lie', severity: 'high', confidence: 'high',
        title: 'Tool claims read-only but writes',
        message: `Tool "${tool.name}" declares readOnlyHint: true, but its handler in this file performs a write/exec operation. Agents and reviewers will trust the hint and skip approval.`,
        fix: 'Remove readOnlyHint from any tool that writes, executes, or mutates state; set readOnlyHint only on handlers that exclusively read.',
        file: rel, line, column: 1, snippet: snippetAt(lines, line),
      });
    }
  }
}

function isToolScanFile(rel, content) {
  if (isSkipped(rel)) return false;
  if (content.length > 1024 * 1024) return false;
  if (/\.json$/i.test(rel)) {
    const b = baseOf(rel);
    if (b === 'package.json' || b === 'tsconfig.json' || b === 'jsconfig.json' || b === 'composer.json') return false;
    return /["'](?:inputSchema|input_schema|parameters|type)["']\s*:/.test(content) && /["']name["']\s*:/.test(content);
  }
  return /\.(?:js|jsx|ts|tsx|mjs|cjs|py)$/i.test(rel);
}

function analyzeTools(rel, content, lines, masked, blocks, add, state) {
  if (!isToolScanFile(rel, content)) return;
  const seen = new Set();

  const nameRe = /["']?name["']?\s*:\s*/g;
  let m;
  while ((m = nameRe.exec(content))) {
    if (masked[m.index] === ' ' || masked[m.index] === '\n') continue;
    const block = smallestBlockAt(blocks, m.index);
    if (!block || seen.has(block.start)) continue;
    const blockText = content.slice(block.start, block.end + 1);
    if (!/["']?(?:inputSchema|input_schema|parameters)["']?\s*:/.test(blockText)) continue;
    const nameInfo = extractStringAt(content, m.index + m[0].length);
    if (!nameInfo || !nameInfo.value) continue;
    const name = nameInfo.value.trim();
    if (!/^[A-Za-z_$][\w$.:-]{0,120}$/.test(name)) continue;
    seen.add(block.start);
    const tool = { name, block, line: lineOf(content, m.index) };
    state.toolDefs.push({ name, rel, line: tool.line });
    analyzeToolBlock(tool, content, rel, lines, add);
  }

  // server.tool('name', { description, inputSchema, annotations }, handler)
  const regRe = /\b(?:server|mcp|app|tool)\s*\.\s*(?:tool|registerTool|register_tool)\s*\(\s*(["'`])([\w.:-]+)\1\s*,\s*/g;
  while ((m = regRe.exec(content))) {
    if (masked[m.index] === ' ' || masked[m.index] === '\n') continue; // inside a string/comment
    const name = m[2];
    const argStart = m.index + m[0].length;
    if (content[argStart] !== '{') continue;
    const end = matchBracket(content, argStart);
    const block = { start: argStart, end };
    if (seen.has(block.start)) continue;
    seen.add(block.start);
    const blockText = content.slice(block.start, block.end + 1);
    if (!/["']?(?:description|inputSchema|input_schema|parameters)["']?\s*:/.test(blockText)) continue;
    // Handler is the argument after the metadata object.
    let after = block.end + 1;
    while (after < content.length && /[\s,]/.test(content[after])) after++;
    let handlerBody = null;
    if (content[after] === '(' || /^(?:async\s*)?(?:function\b|\()/.test(content.slice(after, after + 20))) {
      const openParen = content.indexOf('(', after);
      const bodyOpen = content.indexOf('{', openParen >= 0 ? openParen : after);
      if (bodyOpen >= 0 && (openParen < 0 || bodyOpen < matchBracket(content, openParen))) {
        handlerBody = content.slice(bodyOpen, matchBracket(content, bodyOpen) + 1);
      }
    } else {
      const id = content.slice(after).match(/^[A-Za-z_$][\w$]*/);
      if (id) {
        const h = findFunctionBody(content, id[0]);
        if (h) handlerBody = h.body;
      }
    }
    const tool = { name, block, line: lineOf(content, m.index), registrationHandler: handlerBody };
    state.toolDefs.push({ name, rel, line: tool.line });
    analyzeToolBlock(tool, content, rel, lines, add);
  }
}

// ---------------------------------------------------------------------------
// Agent runtime code
// ---------------------------------------------------------------------------

const LLM_CALL_RE = new RegExp(
  '(?:' +
  '\\b(?:openai|anthropic|claude|gemini|mistral|groq|ollama|llm|client|model|agent)\\s*\\.\\s*' +
  '(?:chat\\s*\\.\\s*completions|chatCompletion|ChatCompletion|completions|responses|messages|generateContent|generate_content)\\s*\\.?\\s*(?:create|stream|generate)?\\s*\\(' +
  '|\\b(?:generateText|streamText|generateObject|streamObject|generateContent|invokeLLM|callLLM|runAgent)\\s*\\(' +
  '|\\bllm\\s*\\(' +
  ')', 'i'
);

const USER_INPUT_RE = /\b(?:userInput|user_input|req\.(?:body|query|params|headers)|request\.(?:body|query|params)|message\.content|userMessage|inputText|promptText)\b/;

function systemMessageBlocks(content, blocks) {
  const candidates = [];
  for (const b of blocks) {
    const body = content.slice(b.start, b.end + 1);
    if (body.length > 4000) continue;
    if (/\brole["']?\s*:\s*["']system["']/i.test(body) && /\bcontent["']?\s*:/i.test(body)) candidates.push({ b, body });
  }
  // A message array's outer object also contains the role string; keep only the
  // innermost message objects so a neighbouring user message cannot taint the
  // analysis of the system message.
  return candidates.filter(({ b }) => !candidates.some((o) => o.b.start > b.start && o.b.end < b.end));
}

const TOOL_RESULT_RE = /\b(?:toolResult|tool_result|toolOutput|tool_output|observation|functionResult|function_result|tool\.result|result\.content)\b/i;

// Read the first fetch/axios argument, resolving a simple `const url = '...'`
// alias. Returns a parsed URL only when the host is statically knowable.
function resolveRequestUrl(content, args, beforeIdx) {
  const first = String(args || '').replace(/^\(/, '').trim();
  const lit = /^["'`](https?:\/\/[^"'`\s]+)["'`]/.exec(first);
  if (lit) return parseHttpUrl(lit[1]);
  const id = /^([A-Za-z_$][\w$]*)/.exec(first);
  if (!id) return null;
  const re = new RegExp('(?:const|let|var)\\s+' + escapeRe(id[1]) + '\\s*=\\s*["\\\'](https?:\\/\\/[^"\\\']+)["\\\']');
  const m = re.exec(content.slice(0, beforeIdx));
  return m ? parseHttpUrl(m[1]) : null;
}

function analyzeAgentCode(rel, content, lines, masked, blocks, add) {
  if (!isCodeFile(rel)) return;
  if (content.length > 1024 * 1024) return;
  const maskedLines = masked.split('\n');
  const lineStarts = [0];
  for (let i = 0; i < content.length; i++) if (content[i] === '\n') lineStarts.push(i + 1);
  const hasLLM = LLM_CALL_RE.test(masked);

  // Sandbox / permission bypass is a config fact; check it even without an LLM
  // call in the same file (the call often lives in another module).
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const t = raw.trim();
    if (!t || t.startsWith('//') || t.startsWith('#') || t.startsWith('*') || t.startsWith('/*')) continue;
    if (/^re\s*:\s*\//i.test(t) || /\bre\s*:\s*\//.test(t)) continue; // rule database, not live config
    if (SANDBOX_FLAG_RE.test(raw)) {
      add({
        ruleId: 'agent2026.sandbox-bypass', severity: 'high', confidence: 'high',
        title: 'Agent sandbox / permission gate is disabled',
        message: 'A flag or permission mode disables the agent sandbox gate, so a prompt-injected action executes without a human confirmation step.',
        fix: 'Remove the bypass flag, keep the sandbox and permission prompts enabled, and allowlist only the specific tools/paths the agent needs.',
        file: rel, line: i + 1, column: 1, snippet: snippetAt(lines, i + 1),
      });
      break;
    }
  }

  // Memory written directly from user input with no provenance label.
  for (let i = 0; i < lines.length; i++) {
    const code = maskedLines[i] || '';
    if (!/\b(?:memory|agentMemory|longTermMemory|memoryStore|conversationHistory|chatHistory)\b/i.test(code)) continue;
    if (!/\b(?:push|unshift|set|add|save|append|write)\s*\(/i.test(code)) continue;
    if (!USER_INPUT_RE.test(code)) continue;
    add({
      ruleId: 'agent2026.memory-user-input', severity: 'medium', confidence: 'medium',
      title: 'Agent memory is written from raw user input',
      message: 'User input is written into agent memory without provenance or sanitisation. A prompt injection in today\'s message becomes a trusted memory in tomorrow\'s system context.',
      fix: 'Store user content with a provenance tag, validate it, and never promote raw user text to trusted long-term memory; require review for persisted facts.',
      file: rel, line: i + 1, column: 1, snippet: snippetAt(lines, i + 1),
    });
  }

  // Raw user content upserted into a vector store / RAG index.
  for (let i = 0; i < lines.length; i++) {
    const window = maskedLines.slice(Math.max(0, i - 2), Math.min(maskedLines.length, i + 3)).join('\n');
    if (!/\b(?:vector|vectorStore|embedding|pinecone|chroma|weaviate|qdrant|faiss|milvus|rag|knowledgeBase|index)\b/i.test(window)) continue;
    if (!/\.(?:upsert|addDocuments|add|insert|index)\s*\(/i.test(maskedLines[i] || '')) continue;
    const after = maskedLines.slice(i, Math.min(maskedLines.length, i + 4)).join('\n');
    if (!USER_INPUT_RE.test(after)) continue;
    add({
      ruleId: 'agent2026.vector-store-poisoning', severity: 'medium', confidence: 'medium',
      title: 'Raw user content is upserted into a vector store',
      message: 'Request/user content is written straight into a vector store or RAG index. An attacker can plant text that is later retrieved as trusted knowledge (memory poisoning).',
      fix: 'Moderate and provenance-tag user content before indexing, isolate untrusted collections, and keep a trusted/untrusted boundary at retrieval time.',
      file: rel, line: i + 1, column: 1, snippet: snippetAt(lines, i + 1),
    });
  }

  // Conversation history posted to an external host.
  for (let i = 0; i < lines.length; i++) {
    const code = maskedLines[i] || '';
    const cm = /\b(?:fetch|axios\.(?:post|put)|sendBeacon|https?\.request)\s*\(/i.exec(code);
    if (!cm) continue;
    const callIdx = lineStarts[i] + cm.index + cm[0].lastIndexOf('(');
    const end = matchBracket(content, callIdx);
    const args = content.slice(callIdx, end + 1);
    if (!/JSON\.stringify\s*\(\s*(?:history|messages|conversation|conversationHistory|chatHistory|transcript|context)\b/i.test(args) &&
        !/\b(?:body|data|json)\s*(?::|=)\s*(?:history|messages|conversation|conversationHistory|chatHistory|transcript)\b/i.test(args)) continue;
    const parsed = resolveRequestUrl(content, args, callIdx);
    if (!parsed || isLocalHost(parsed.hostname)) continue;
    add({
      ruleId: 'agent2026.history-exfil', severity: 'critical', confidence: 'high',
      title: 'Conversation history is posted to an external host',
      message: `The agent serializes conversation history into a request body sent to ${parsed.host}. A single injected instruction can turn this into full transcript exfiltration, including secrets the user pasted.`,
      fix: 'Remove history from outbound request bodies; if remote logging is required, allowlist the host, redact secrets/PII, and require explicit opt-in.',
      file: rel, line: i + 1, column: 1, snippet: snippetAt(lines, i + 1),
    });
  }

  // Tool list loaded from a remote registry instead of a local allowlist.
  for (let i = 0; i < lines.length; i++) {
    const code = maskedLines[i] || '';
    if (!/\btools\s*:\s*(?:await\s+)?(?:fetch|axios|loadRemote|remoteTools|getRemote|registry|toolRegistry)\b/i.test(code) &&
        !/\b(?:const|let|var)\s+tools\s*=\s*(?:await\s+)?(?:fetch|loadRemote|getRemote|registry|toolRegistry)\b/i.test(code)) continue;
    add({
      ruleId: 'agent2026.tools-from-remote', severity: 'medium', confidence: 'medium',
      title: 'Tool allowlist is loaded from a remote registry',
      message: 'The agent builds its tools list from a remote source. Whoever controls that registry can add shell/write tools the developer never reviewed.',
      fix: 'Use a local, reviewed tool allowlist and pin each tool definition; fetch remote tools only behind a signed/approved manifest.',
      file: rel, line: i + 1, column: 1, snippet: snippetAt(lines, i + 1),
    });
  }

  if (!hasLLM) return;

  // Agent loop with no iteration cap.
  for (let i = 0; i < lines.length; i++) {
    const codeLine = maskedLines[i] || '';
    if (!/^\s*(?:while\s*\(\s*(?:true|1)\s*\)|for\s*\(\s*;\s*;\s*\)|do\s*\{)/.test(codeLine)) continue;
    const window = maskedLines.slice(i, Math.min(maskedLines.length, i + 60)).join('\n');
    if (!LLM_CALL_RE.test(window) && !/\bagent\s*\.\s*(?:step|run|invoke|execute)\s*\(/i.test(window)) continue;
    if (/\b(?:maxSteps|maxIterations|max_iterations|maxTurns|max_loops|maxLoops|iterationLimit|stepLimit)\b/i.test(window)) continue;
    if (/\b(?:step|iteration|iterations|count|turn|tries)\s*(?:[<>]=?|===?)\s*\d+/i.test(window)) continue;
    add({
      ruleId: 'agent2026.agent-loop-no-cap', severity: 'medium', confidence: 'medium',
      title: 'Agent loop has no iteration cap',
      message: 'An unbounded while(true)/for(;;) loop drives an LLM call locally with no maxSteps/maxIterations counter and no visible cap. A model that never returns a stop condition burns tokens and hangs the process.',
      fix: 'Add a finite maxSteps/maxIterations counter (or a deadline) and break the loop when it is reached; log the cap hit.',
      file: rel, line: i + 1, column: 1, snippet: snippetAt(lines, i + 1),
    });
  }

  // Self-recursive agent function with no visible base case.
  const fnRe = /(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{/g;
  let fm;
  while ((fm = fnRe.exec(masked))) {
    const name = fm[1];
    const open = masked.indexOf('{', fm.index + fm[0].length - 1);
    if (open < 0) continue;
    const end = matchBracket(masked, open);
    if (end <= open) continue;
    const body = masked.slice(open, end + 1);
    if (!LLM_CALL_RE.test(body)) continue;
    const callRe = new RegExp('\\b' + escapeRe(name) + '\\s*\\(', 'g');
    callRe.lastIndex = 1;
    const call = callRe.exec(body);
    if (!call) continue;
    const before = body.slice(0, call.index);
    if (/\bif\s*\([^)]*\)[^{]*\{?[^}]*\breturn\b/i.test(before) || /\b(?:baseCase|maxDepth|depth\s*[<>]=?|if\s*\([^)]*\b(?:depth|count|tries)\b)/i.test(before)) continue;
    add({
      ruleId: 'agent2026.recursive-agent-no-base', severity: 'medium', confidence: 'medium',
      title: 'Recursive agent function has no visible base case',
      message: `Function "${name}" calls itself after an LLM step with no base-case return before the recursive call. A model that keeps producing another step recurses until the stack or budget dies.`,
      fix: 'Add an explicit base case (depth/attempt cap and a terminal return) before the recursive call, and default to a bounded loop instead.',
      file: rel, line: lineOf(content, open), column: 1, snippet: snippetAt(lines, lineOf(content, open)),
    });
  }

  // Streaming LLM call without a max_tokens bound.
  const streamCallRe = /\b(?:openai|anthropic|client|ai|model)\s*\.\s*(?:chat\s*\.\s*completions|completions|responses|messages)\s*\.\s*(?:create|stream)\s*\(|\b(?:streamText|streamObject)\s*\(/gi;
  let sm;
  while ((sm = streamCallRe.exec(masked))) {
    const openParen = masked.indexOf('(', sm.index + sm[0].length - 1);
    if (openParen < 0) continue;
    const closeParen = matchBracket(masked, openParen);
    const argsRaw = content.slice(openParen, closeParen + 1);
    const isStream = /\bstream\s*[=:]\s*true\b/i.test(argsRaw) || /\.stream\s*\(/i.test(sm[0]) || /^\s*stream(?:Text|Object)\s*\(/i.test(sm[0]);
    if (!isStream) continue;
    if (/\b(?:max_tokens|maxTokens|max_output_tokens|maxOutputTokens)\b/.test(argsRaw)) continue;
    add({
      ruleId: 'agent2026.streaming-no-max-tokens', severity: 'medium', confidence: 'medium',
      title: 'Streaming LLM call has no max_tokens limit',
      message: 'A streaming LLM call sets stream: true but passes no max_tokens/maxTokens bound. A runaway generation streams until the provider or process cuts it off.',
      fix: 'Set max_tokens (or max_output_tokens) on every streaming call, and enforce a per-session token budget.',
      file: rel, line: lineOf(content, sm.index), column: 1, snippet: snippetAt(lines, lineOf(content, sm.index)),
    });
  }

  const sysBlocks = systemMessageBlocks(content, blocks);

  // User input concatenated into a system-role message.
  for (const { b, body } of sysBlocks) {
    if (!USER_INPUT_RE.test(body)) continue;
    const contentIdx = body.search(/\bcontent["']?\s*:/i);
    if (contentIdx < 0) continue;
    const valueRaw = body.slice(contentIdx, contentIdx + 400);
    const directUser = /\bcontent["']?\s*:\s*(?:userInput|user_input|req\.(?:body|query|params)|request\.(?:body|query|params)|userMessage|promptText)\b/i.test(valueRaw);
    if (!(directUser || /\$\{[^}]*\}/.test(valueRaw) || /\+\s*[A-Za-z_$]/.test(valueRaw) || /["']\s*\+/.test(valueRaw))) continue;
    if (TOOL_RESULT_RE.test(valueRaw)) continue;
    add({
      ruleId: 'agent2026.system-prompt-user-input', severity: 'high', confidence: 'high',
      title: 'User input is interpolated into the system prompt',
      message: 'A system-role message is built from request/user input. The user can rewrite the agent\'s highest-priority instructions (direct prompt injection).',
      fix: 'Keep the system prompt static; put user content in a user message, and validate/label it before sending it to the model.',
      file: rel, line: lineOf(content, b.start), column: 1, snippet: snippetAt(lines, lineOf(content, b.start)),
    });
    break;
  }

  // Shorthand `system:` / `system =` prompt property (some SDKs use it instead
  // of a role message) built from user input.
  for (let i = 0; i < lines.length; i++) {
    const code = maskedLines[i] || '';
    const sm = /\bsystem["']?\s*[:=]/i.exec(code);
    if (!sm) continue;
    const raw = lines[i];
    if (!USER_INPUT_RE.test(raw)) continue;
    const valuePart = raw.slice(sm.index);
    const direct = /\bsystem["']?\s*[:=]\s*(?:userInput|user_input|req\.(?:body|query|params)|request\.(?:body|query|params)|userMessage|promptText)\b/i.test(valuePart);
    if (!(direct || /\$\{[^}]*\}/.test(valuePart) || /\+\s*[A-Za-z_$]/.test(valuePart) || /["']\s*\+/.test(valuePart))) continue;
    add({
      ruleId: 'agent2026.system-prompt-user-input', severity: 'high', confidence: 'high',
      title: 'User input is interpolated into the system prompt',
      message: 'A shorthand system prompt is built from request/user input. The user controls the agent\'s highest-priority instruction.',
      fix: 'Keep the system prompt static and pass user content in a user message instead.',
      file: rel, line: i + 1, column: 1, snippet: snippetAt(lines, i + 1),
    });
    break;
  }

  // Tool result promoted into the system role.
  for (const { b, body } of sysBlocks) {
    if (!TOOL_RESULT_RE.test(body)) continue;
    add({
      ruleId: 'agent2026.tool-result-to-system', severity: 'high', confidence: 'medium',
      title: 'Tool result is inserted into the system prompt',
      message: 'A tool result is placed in a system-role message. Tool output is attacker-influenced data; in the system prompt it becomes an instruction the model will follow.',
      fix: 'Return tool output in a tool/assistant message (or a clearly delimited user message), never in the system role; validate and label it as untrusted data.',
      file: rel, line: lineOf(content, b.start), column: 1, snippet: snippetAt(lines, lineOf(content, b.start)),
    });
    break;
  }

  // Secrets interpolated into the agent's system prompt.
  for (const { b, body } of sysBlocks) {
    if (!/process\.env\s*(?:\.|\[)\s*["']?[A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|API)[A-Za-z0-9_]*["']?\s*\]?/i.test(body)) continue;
    add({
      ruleId: 'agent2026.secret-in-agent-prompt', severity: 'high', confidence: 'high',
      title: 'Secret is interpolated into the agent prompt',
      message: 'The system prompt interpolates a process.env secret (API key/token/password). Every model provider, log, and prompt dump now receives the credential.',
      fix: 'Never put secrets in prompts; pass credentials only through the provider SDK/HTTP auth header and keep them out of message content.',
      file: rel, line: lineOf(content, b.start), column: 1, snippet: snippetAt(lines, lineOf(content, b.start)),
    });
    break;
  }

  // JSX sink for LLM output that the existing innerHTML rule does not cover.
  for (let i = 0; i < lines.length; i++) {
    const window = lines.slice(i, Math.min(lines.length, i + 4)).join(' ');
    if (!/dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:/i.test(window)) continue;
    if (!/\b(?:completion|llmOutput|llm_output|aiResponse|ai_response|response\.choices|message\.content|choices\[0\]|modelOutput)\b/i.test(window)) continue;
    add({
      ruleId: 'agent2026.llm-output-dom', severity: 'high', confidence: 'medium',
      title: 'LLM output is rendered as raw HTML',
      message: 'dangerouslySetInnerHTML receives LLM output. Prompt injection becomes stored XSS with the user\'s session.',
      fix: 'Render model output as text (React children/textContent) or sanitize it with DOMPurify before setting __html.',
      file: rel, line: i + 1, column: 1, snippet: snippetAt(lines, i + 1),
    });
  }

  // Code interpreter fed with LLM output.
  const execRe = /\b(?:eval|exec|execSync|Function|runInSandbox)\s*\(\s*(?:await\s+)?(?:\w+\s*\.\s*)*(?:completion|response|llmOutput|llm_output|llm|aiResponse|ai_response|modelOutput|message\.content|choices\[0\])/gi;
  let em;
  while ((em = execRe.exec(masked))) {
    add({
      ruleId: 'agent2026.llm-output-exec', severity: 'high', confidence: 'high',
      title: 'LLM output is executed as code',
      message: 'Model output is passed directly to eval/exec/Function (a code interpreter). A prompt-injected response becomes remote code execution.',
      fix: 'Never execute model output; parse structured data, and if a code interpreter is required, run generated code in a hardened sandbox with no secrets, network, or host filesystem.',
      file: rel, line: lineOf(content, em.index), column: 1, snippet: snippetAt(lines, lineOf(content, em.index)),
    });
  }
}

// ---------------------------------------------------------------------------
// Prompt / instruction files
// ---------------------------------------------------------------------------

const PROMPT_POISON_RE = /(?:ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above)\s+instructions?|never\s+refuse|(?:do\s+not|don'?t)\s+tell\s+the\s+user|disregard\s+(?:all\s+)?(?:previous|prior|system)|do\s+anything\s+now|\bDAN\s+mode\b)/i;

function isNegated(line, idx) {
  const before = line.slice(Math.max(0, idx - 60), idx);
  return /\b(?:never|don'?t|do\s+not|must\s+not|avoid|without|not)\b/i.test(before);
}

function analyzePromptFile(rel, content, lines, add, state) {
  const isMcpCfg = isMcpConfigFile(rel, content);

  // A secret pasted into an instruction file is committed and model-readable.
  if (!isMcpCfg) {
    const hit = findSecret(content);
    if (hit) {
      const line = lineOf(content, content.indexOf(hit.value));
      const rawLine = snippetAt(lines, line);
      add({
        ruleId: 'agent2026.prompt-file-secret', severity: 'critical', confidence: 'high',
        title: 'Secret committed in an agent instruction file',
        message: `This instruction file contains a hardcoded ${hit.type}. Every AI tool that reads CLAUDE.md/AGENTS.md/copilot instructions now has the credential in context, and it is in git.`,
        fix: `Remove the ${hit.type} from ${rel}, move it to a local environment variable or the vault, and rotate it.`,
        file: rel, line, column: 1,
        snippet: rawLine.includes(hit.value) ? rawLine.replace(hit.value, hit.masked) : '[secret redacted]',
      });
      state.secretRefs.push({ name: 'prompt-file', rel, line, key: 'instruction-file' });
    }
  }

  const poison = PROMPT_POISON_RE.exec(content);
  if (poison) {
    add({
      ruleId: 'agent2026.prompt-instruction-poisoning', severity: 'medium', confidence: 'high',
      title: 'Agent instruction file contains overrides',
      message: `The instruction file contains "${poison[0]}". A committed rule that disables refusal or hides behaviour from the user overrides the model's safety instructions for every session.`,
      fix: 'Remove the instruction-override language; state task rules positively and keep refusal/safety behaviour intact.',
      file: rel, line: lineOf(content, poison.index), column: 1,
      snippet: snippetAt(lines, lineOf(content, poison.index)),
    });
  }

  // Instructions that read credentials and send them somewhere.
  let readAt = -1;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const cred = /(?:\.env\b|\.ssh\b|id_rsa\b|credentials?\b|secrets?\b|api[_-]?keys?\b|tokens?\b|private\s+key)/i.exec(line);
    if (!cred) continue;
    const verb = /\b(?:read|open|load|cat|access|copy|print|dump|gather|collect)\b/gi;
    let vm;
    let ok = false;
    while ((vm = verb.exec(line))) {
      if (Math.abs(vm.index - cred.index) < 50 && !isNegated(line, vm.index)) { ok = true; break; }
    }
    if (ok) { readAt = i; break; }
  }
  if (readAt >= 0) {
    let sendAt = -1;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const send = /\b(?:send|post|upload|curl|wget|exfiltrate|forward|transmit|webhook)\b/i.exec(line);
      const url = /https?:\/\/[^\s'"`)]+/i.exec(line);
      const hit = send || url;
      if (!hit) continue;
      let external = true;
      if (url) {
        const u = parseHttpUrl(url[0]);
        external = !!u && !isLocalHost(u.hostname);
      }
      if (external && !isNegated(line, hit.index)) { sendAt = i; break; }
    }
    if (sendAt >= 0) {
      add({
        ruleId: 'agent2026.prompt-exfil-instruction', severity: 'high', confidence: 'medium',
        title: 'Agent instructions tell the model to exfiltrate credentials',
        message: `The instruction file tells the agent to read credentials (${lines[readAt].trim()}) and send them somewhere (${lines[sendAt].trim()}). The model will treat this as authorised behaviour and leak secrets.`,
        fix: 'Delete the credential-reading and send instruction; if the agent needs a credential, inject a scoped secret in code, never through prompt text.',
        file: rel, line: readAt + 1, column: 1, snippet: snippetAt(lines, readAt + 1),
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Cross-file posture
// ---------------------------------------------------------------------------

function analyzeCrossFile(state, add) {
  // Same server name in multiple config files — cross-file shadowing / drift.
  const byName = new Map();
  for (const s of state.servers) {
    if (!byName.has(s.name)) byName.set(s.name, []);
    byName.get(s.name).push(s);
  }
  for (const [name, entries] of byName) {
    if (entries.length < 2) continue;
    const distinctRel = new Set(entries.map((e) => e.rel));
    if (distinctRel.size < 2) continue;
    const first = entries[0];
    const firstDef = stableValue(first.cfg);
    for (let i = 1; i < entries.length; i++) {
      const e = entries[i];
      if (e.rel === first.rel) continue;
      const differs = stableValue(e.cfg) !== firstDef;
      add({
        ruleId: 'agent2026.mcp-server-shadowing', severity: differs ? 'medium' : 'low', confidence: 'high',
        title: 'MCP server name is defined in multiple configs',
        message: `Server "${name}" is defined in both ${first.rel} and ${e.rel}${differs ? ' with different commands/URLs/env' : ' with identical settings'}. Agents may load either definition, so a change in one config silently changes what the other agent trusts (rug-pull proxy).`,
        fix: `Keep one canonical definition for "${name}" in a single shared config, remove the duplicate, and review the diff before trusting the server in either file.`,
        file: e.rel, line: e.line, column: e.column || 1, snippet: snippetAt(state.lines[e.rel] || [], e.line),
      });
    }
  }

  // Remote server + committed local secrets: a compromised remote tool can read
  // local env and send it out.
  if (state.remoteServers.length && state.secretRefs.length) {
    for (const r of state.remoteServers.slice(0, 3)) {
      const sec = state.secretRefs.find((s) => s.rel !== r.rel) || state.secretRefs[0];
      add({
        ruleId: 'agent2026.mcp-remote-local-secrets', severity: 'high', confidence: 'medium',
        title: 'Remote MCP endpoint coexists with committed secrets',
        message: `Remote MCP server "${r.name}" (${r.url}) is configured in this project, and committed MCP/prompt secrets are also present (e.g. ${sec.rel}:${sec.line}). A malicious tool behind the remote endpoint can read the local secret store and exfiltrate it.`,
        fix: 'Remove secrets from committed config, use local secret injection/vault, and require authenticated, allowlisted remote MCP endpoints.',
        file: r.rel, line: r.line, column: 1, snippet: snippetAt(state.lines[r.rel] || [], r.line),
      });
    }
  }

  // An MCP server plus a locally mounted shell tool gives the agent both a
  // trusted tool plane and unrestricted command execution.
  const shellTool = state.toolDefs.find((t) => /^(?:shell|bash|exec|execute|exec_command|run_command|run_shell|terminal|powershell|shell_exec|exec_shell)$/i.test(t.name));
  if (state.servers.length && shellTool) {
    const server = state.servers[0];
    add({
      ruleId: 'agent2026.mcp-with-shell-tool', severity: 'medium', confidence: 'medium',
      title: 'MCP tools and a shell tool are mounted together',
      message: `The project configures MCP server "${server.name}" and also defines a shell/exec tool ("${shellTool.name}"). A poisoned MCP tool can call the shell tool, turning a tool-plane compromise into host command execution.`,
      fix: 'Do not expose a shell/exec tool to an agent that also trusts MCP servers; replace the shell tool with narrow allowlisted operations and require confirmation.',
      file: shellTool.rel, line: shellTool.line, column: 1, snippet: snippetAt(state.lines[shellTool.rel] || [], shellTool.line),
    });
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

function analyzeAgentic(input) {
  const { findings, add } = makeCollector();
  if (!input || !Array.isArray(input.files)) return findings;
  const root = input.root ? path.resolve(input.root) : process.cwd();

  const files = [];
  for (const f of input.files) {
    if (!f || typeof f.content !== 'string') continue;
    let rel = normRel(f.rel);
    if (path.isAbsolute(String(f.rel || ''))) rel = normRel(path.relative(root, f.rel));
    if (!rel || rel === '.' || isSkipped(rel)) continue;
    if (f.content.indexOf('\u0000') !== -1) continue;
    const lines = Array.isArray(f.lines) ? f.lines : f.content.split(/\r?\n/);
    files.push({ rel, content: f.content, lines });
  }
  files.sort((a, b) => a.rel.localeCompare(b.rel));

  const state = {
    servers: [], remoteServers: [], secretRefs: [], toolDefs: [], lines: {},
  };

  for (const f of files) {
    state.lines[f.rel] = f.lines;
    if (isMcpConfigFile(f.rel, f.content)) {
      if (/\.[cm]?json$/i.test(f.rel) || /^\s*[{[]/.test(f.content)) {
        analyzeMcpJson(f.rel, f.content, f.lines, add, state);
      }
      if (/\bcommand\s*:|\bargs\s*:/.test(f.content) && /\.ya?ml$/i.test(f.rel)) {
        analyzeSmitheryYaml(f.rel, f.content, f.lines, add, state);
      }
    } else if (/^(?:smithery\.ya?ml)$/i.test(baseOf(f.rel))) {
      analyzeSmitheryYaml(f.rel, f.content, f.lines, add, state);
    }

    if (isPromptConfigFile(f.rel)) {
      analyzePromptFile(f.rel, f.content, f.lines, add, state);
    }

    let masked = null;
    let blocks = null;
    if (isToolScanFile(f.rel, f.content)) {
      masked = maskNonCode(f.content);
      blocks = findObjectBlocks(f.content);
      analyzeTools(f.rel, f.content, f.lines, masked, blocks, add, state);
    }
    if (isCodeFile(f.rel) || /\.(?:jsx|tsx|vue|svelte)$/i.test(f.rel)) {
      if (!masked) {
        masked = maskNonCode(f.content);
        blocks = findObjectBlocks(f.content);
      }
      analyzeAgentCode(f.rel, f.content, f.lines, masked, blocks, add);
    }
  }

  analyzeCrossFile(state, add);

  const out = findings
    .filter((f) => f.file && f.fix && f.message)
    .sort((a, b) => {
      const s = (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
      if (s) return s;
      return a.file.localeCompare(b.file) || a.line - b.line;
    })
    .slice(0, MAX_FINDINGS);

  return out;
}

module.exports = { analyzeAgentic };
