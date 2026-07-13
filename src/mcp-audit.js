'use strict';

/*
 * src/mcp-audit.js — MCP server security audit (100% offline, zero network).
 *
 * MCP is the tool-plane for AI agents (Claude Code, Cursor, Windsurf). It is a
 * young, under-secured surface. This audits the MCP servers an agent is
 * configured to trust, statically, from the config file:
 *
 *   1. Prompt injection in server args / tool descriptions (tool poisoning).
 *   2. Unpinned auto-install (`npx -y pkg`) — the server's code can silently
 *      change between runs (rug-pull) because no version is locked.
 *   3. Remote-code / shell commands (curl|sh, node <url>, raw sh/bash).
 *   4. Hardcoded secrets in the server's `env` block.
 *   5. Over-broad filesystem grants (a filesystem server rooted at / or ~).
 *   6. Definition drift: pin a hash of each server's config on first audit;
 *      on re-audit, flag any server whose config changed since you approved it
 *      (the classic MCP rug-pull — approve a benign tool, it mutates later).
 *
 * Nothing here executes a server or hits the network. It reads config only.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

let SECRET_PATTERNS = [];
try { ({ SECRET_PATTERNS } = require('./shell-guard')); } catch { /* optional */ }

// Prompt-injection / tool-poisoning signatures in text an agent will read.
const INJECTION_PATTERNS = [
  { re: /ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+instructions?/i, name: 'ignore-previous-instructions' },
  { re: /disregard\s+(?:the\s+)?(?:system\s+prompt|previous|above|all)/i, name: 'disregard-system' },
  { re: /you\s+are\s+now\s+(?:a|an|the)\b/i, name: 'role-override' },
  { re: /new\s+instructions?\s*:/i, name: 'injected-instructions' },
  { re: /<\s*\|?\s*(?:im_start|im_end|system|endoftext)\s*\|?\s*>/i, name: 'special-token-injection' },
  { re: /\[\s*system\s*\]|\bsystem\s*prompt\s*override\b/i, name: 'system-role-injection' },
];
// Invisible / bidi control chars used to smuggle hidden instructions.
const HIDDEN_CHARS_RE = /[​-‏‪-‮⁦-⁩﻿]/;

function scanTextForInjection(text) {
  const hits = [];
  if (!text || typeof text !== 'string') return hits;
  for (const p of INJECTION_PATTERNS) {
    if (p.re.test(text)) hits.push(p.name);
  }
  if (HIDDEN_CHARS_RE.test(text)) hits.push('hidden-unicode-control-chars');
  return hits;
}

// Which config files hold MCP server definitions.
function findConfigs(root) {
  const out = [];
  for (const name of ['.mcp.json', '.cursor/mcp.json', '.vscode/mcp.json']) {
    const p = path.join(root, name);
    if (fs.existsSync(p)) out.push(p);
  }
  return out;
}

// Normalize the two common shapes: { mcpServers: {...} } and { servers: {...} }.
function extractServers(json) {
  const map = json.mcpServers || json.servers || {};
  return Object.entries(map).map(([name, cfg]) => ({ name, cfg: cfg || {} }));
}

function stableHash(obj) {
  return crypto.createHash('sha256').update(JSON.stringify(obj)).digest('hex').slice(0, 16);
}

const PIN_FILE = '.vibeguard/mcp-pins.json';
function loadPins(root) {
  try { return JSON.parse(fs.readFileSync(path.join(root, PIN_FILE), 'utf8')); } catch { return {}; }
}
function savePins(root, pins) {
  const dir = path.join(root, '.vibeguard');
  try {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(root, PIN_FILE), JSON.stringify(pins, null, 2));
  } catch { /* best-effort */ }
}

function looksUnpinned(pkg) {
  // A version pin is "@1.2.3" AFTER the package name. Scoped: @scope/name@1.2.3.
  if (pkg.startsWith('@')) {
    // @scope/name[@version]
    const rest = pkg.slice(1);
    const at = rest.indexOf('@');
    return at === -1; // no version after scope/name
  }
  return !pkg.includes('@');
}

function auditServer(name, cfg) {
  const findings = [];
  const add = (severity, id, message, fix) => findings.push({ server: name, severity, id, message, fix });

  const command = String(cfg.command || '');
  const args = Array.isArray(cfg.args) ? cfg.args.map(String) : [];
  const argStr = args.join(' ');
  const env = cfg.env && typeof cfg.env === 'object' ? cfg.env : {};

  // 1. Injection in the server name, args, or any description-like field.
  const textBlob = [name, argStr, cfg.description || ''].join('\n');
  const inj = scanTextForInjection(textBlob);
  for (const kind of inj) {
    add('critical', 'mcp.tool-poisoning',
      `Server "${name}" contains a prompt-injection pattern (${kind}) an agent will read — possible tool poisoning.`,
      'Remove the injected text. Only trust MCP servers from sources you control or have reviewed.');
  }

  // 2/3. Remote-code / shell command.
  if (/^(?:sh|bash|zsh|cmd|powershell)$/i.test(command) || /\|\s*(?:sh|bash|zsh)\b/.test(argStr)) {
    add('critical', 'mcp.remote-code',
      `Server "${name}" runs a raw shell (${command || 'pipe to shell'}) — arbitrary code execution on every agent session.`,
      'Replace with a pinned, published package. Never wire a shell pipe into an MCP server.');
  }
  if (/https?:\/\//.test(argStr) && /(?:curl|wget|node|deno|bun)\b/i.test(command + ' ' + argStr)) {
    add('critical', 'mcp.remote-fetch-exec',
      `Server "${name}" fetches and runs remote code (${command}). The remote can change at any time.`,
      'Vendor the code locally or use a version-pinned registry package.');
  }

  // 2b. Unpinned auto-install via npx -y (rug-pull surface).
  if (/^(?:npx|bunx|pnpm)$/i.test(command)) {
    const auto = args.some((a) => a === '-y' || a === '--yes');
    const pkg = args.find((a) => a && !a.startsWith('-') && a !== 'dlx');
    if (pkg && looksUnpinned(pkg)) {
      add(auto ? 'high' : 'medium', 'mcp.unpinned-install',
        `Server "${name}" auto-installs "${pkg}" with no version pin — its code can change between runs (rug-pull risk).`,
        `Pin a version, e.g. "${pkg}@1.2.3", so the server code can't silently change.`);
    }
  }

  // 4. Secrets in env.
  for (const [k, v] of Object.entries(env)) {
    if (typeof v !== 'string') continue;
    for (const { re, type } of SECRET_PATTERNS) {
      if (re.test(v)) {
        add('critical', 'mcp.secret-in-config',
          `Server "${name}" has a hardcoded ${type} in env var ${k} — committed secrets leak.`,
          `Move ${k} to a local environment variable reference, and rotate the exposed credential.`);
        break;
      }
    }
  }

  // 5. Over-broad filesystem grant.
  const broadFs = args.find((a) => a === '/' || a === '~' || a === process.env.HOME || /^([A-Za-z]:[\\/])$/.test(a));
  if (broadFs && /file|fs|filesystem/i.test(name + ' ' + argStr)) {
    add('high', 'mcp.broad-filesystem',
      `Server "${name}" is granted a very broad filesystem root ("${broadFs}") — the agent can read/write your whole disk.`,
      'Scope the filesystem server to a specific project directory.');
  }

  return findings;
}

// Main entry. opts.pin = true to (re)write the pin baseline this run.
function auditMcp(root, opts = {}) {
  const configs = findConfigs(root);
  const servers = [];
  const findings = [];
  let configFound = configs.length > 0;

  const pins = loadPins(root);
  const newPins = {};
  const drifted = [];

  for (const cfgPath of configs) {
    let json;
    try { json = JSON.parse(fs.readFileSync(cfgPath, 'utf8')); } catch { continue; }
    const rel = path.relative(root, cfgPath).split(path.sep).join('/');
    for (const { name, cfg } of extractServers(json)) {
      const hash = stableHash(cfg);
      newPins[name] = hash;
      servers.push({ name, config: rel, command: cfg.command, hash });

      // Definition drift (rug-pull): known server whose config changed.
      if (pins[name] && pins[name] !== hash) {
        drifted.push(name);
        findings.push({
          server: name, severity: 'high', id: 'mcp.definition-drift',
          message: `Server "${name}" definition changed since it was last approved (rug-pull risk). Re-review before trusting it.`,
          fix: 'Diff the change against what you approved. Re-pin with --pin only after review.',
        });
      }

      for (const f of auditServer(name, cfg)) findings.push({ ...f, config: rel });
    }
  }

  // First run (no pins yet) or explicit --pin: write the baseline.
  if (opts.pin || Object.keys(pins).length === 0) savePins(root, newPins);

  const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) bySev[f.severity] = (bySev[f.severity] || 0) + 1;

  return {
    configFound,
    servers,
    findings,
    drifted,
    counts: bySev,
    pinned: opts.pin || Object.keys(pins).length === 0,
  };
}

function renderMcpAudit(result) {
  const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
  const c = (code) => (useColor ? code : '');
  const R = c('\x1b[0m'), B = c('\x1b[1m'), DIM = c('\x1b[2m');
  const RED = c('\x1b[31m'), YEL = c('\x1b[33m'), GRN = c('\x1b[32m'), CYAN = c('\x1b[36m');
  const sevColor = { critical: RED, high: YEL, medium: YEL, low: DIM };

  const out = [];
  out.push(`${B}${CYAN}VibeGuard MCP audit${R} ${DIM}(offline)${R}`);
  if (!result.configFound) {
    out.push(`  ${DIM}No MCP config found (.mcp.json / .cursor/mcp.json / .vscode/mcp.json).${R}`);
    return out.join('\n');
  }
  out.push(`  ${DIM}${result.servers.length} server(s) configured${R}`);
  out.push('');

  if (result.findings.length === 0) {
    out.push(`  ${GRN}No MCP security issues found.${R}`);
    return out.join('\n');
  }

  const order = ['critical', 'high', 'medium', 'low'];
  const sorted = result.findings.slice().sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  for (const f of sorted) {
    const col = sevColor[f.severity] || '';
    out.push(`  ${col}${B}${f.severity.toUpperCase().padEnd(8)}${R} [${f.id}] ${f.server}`);
    out.push(`    ${f.message}`);
    out.push(`    ${GRN}fix:${R} ${f.fix}`);
    out.push('');
  }
  const cc = result.counts;
  out.push(`${B}${cc.critical} critical, ${cc.high} high, ${cc.medium} medium${R}`);
  return out.join('\n');
}

module.exports = { auditMcp, auditServer, scanTextForInjection, looksUnpinned, renderMcpAudit };
