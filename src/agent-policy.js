'use strict';

/*
 * src/agent-policy.js — AI agent permission enforcement.
 *
 * A policy is a small JSON file that answers four questions before any MCP
 * tool call reaches a server:
 *
 *   1. May this tool run at all?          (tool rules / deny / approval)
 *   2. May it touch this path?            (filesystem scope + denied paths)
 *   3. May it reach this host?            (egress allowlist + metadata block)
 *   4. May this data leave the machine?   (secret / PII exfiltration checks)
 *
 * It is deliberately boring: no model, no network, no heuristics that need a
 * GPU. Deterministic rules an operator can read and diff.
 *
 * Default policy is "safe but usable": unknown tools are allowed, but
 * credential stores are denied, cloud metadata is denied, secrets in arguments
 * are blocked, shell commands go through the shell guard, writes outside the
 * project are blocked, and calls are rate-limited.
 *
 * 100% local. Zero network. Zero dependencies.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { checkCommand } = require('./shell-guard');
const { checkPackage } = require('./firewall');
const { scanForLeaks, scanForLeaksDeep, sanitizeOutbound, isExternalHost, hostOf, shannonEntropy } = require('./action-guard');
const { scanTextForInjection } = require('./mcp-audit');

const POLICY_FILES = ['.vibeguard-mcp.json', '.vibeguard/mcp-policy.json', 'vibeguard.mcp.json', 'mcp-policy.json'];

const DEFAULT_POLICY = {
  version: 1,
  // Unknown tools are allowed by default so enabling the firewall does not
  // silently break a working agent. Tighten with defaultAction: "block".
  defaultAction: 'allow',
  // Explicit tool rules: [{ match: "mcp__filesystem__write_*", action: "block", reason: "..." }]
  toolRules: [],
  // Tool name globs that always win, regardless of toolRules.
  denyTools: [],
  allowTools: [],
  // Tools that require a human decision. A headless proxy converts these to a
  // block with a clear reason instead of hanging forever.
  approvalRequired: [],
  // Capability names that are never allowed: shell, fs.write, network, ...
  blockedCapabilities: [],
  allowedCapabilities: [],
  // Filesystem scope. Relative paths resolve against the project root.
  allowedPaths: [],
  deniedPaths: [
    '**/.env',
    '**/.env.*',
    '**/.ssh/**',
    '**/.aws/credentials',
    '**/.aws/config',
    '**/.npmrc',
    '**/.netrc',
    '**/.git-credentials',
    '**/*.pem',
    '**/*.key',
    '**/id_rsa',
    '**/id_ed25519',
    '**/secrets/**',
    '**/credentials.json',
    '**/service-account*.json',
    '**/AppData/Local/Google/Chrome/User Data/**',
    '**/AppData/Roaming/Mozilla/Firefox/Profiles/**',
    '**/.config/gh/hosts.yml',
  ],
  // Reads outside the project are blocked unless listed in allowedPaths.
  enforceProjectScope: true,
  // Egress. An empty allowedHosts list means "any external host", but the
  // secret/PII checks below still apply. Put hosts here to allowlist.
  allowedHosts: [],
  deniedHosts: ['169.254.169.254', 'metadata.google.internal', 'metadata.goog'],
  // Hosts allowed to receive sensitive data (your own API, localhost, ...).
  trustedHosts: [],
  blockExternalNetwork: false,
  // Secret and PII handling.
  secretScan: true,
  allowSecretsInArgs: false,
  piiScan: true,
  piiMode: 'warn', // warn | block
  // Content defenses.
  blockPromptInjection: true,
  pinToolDefinitions: true,
  scrubToolResults: true,
  blockToolResultInjection: true,
  // Volume controls.
  maxArgumentBytes: 65536,
  maxCallsPerMinute: 240,
  // Logging.
  logAllowedCalls: true,
  // If the policy file itself cannot be parsed, fail closed instead of running
  // with defaults. Configuring this to true is strongly recommended in CI.
  failClosed: false,
};

const CAPABILITY_PATTERNS = [
  ['shell', /(^|[_\-.])(exec|shell|command|terminal|powershell|bash|spawn|run|process)([_\-.]|$)/i],
  ['code-exec', /(^|[_\-.])(eval|execute|interpreter|python|repl|code)([_\-.]|$)/i],
  ['fs.write', /(^|[_\-.])(write|edit|create|delete|remove|move|rename|copy|mkdir|rm|patch)([_\-.]|$)/i],
  ['fs.read', /(^|[_\-.])(read|cat|list|glob|grep|search|find|stat|open|head|tail)([_\-.]|$)/i],
  ['network', /(^|[_\-.])(fetch|http|request|url|browse|crawl|web|download|upload|send|post|http_get)([_\-.]|$)/i],
  ['database', /(^|[_\-.])(sql|query|database|db|table|supabase|postgres|mysql|mongo)([_\-.]|$)/i],
  ['secrets', /(^|[_\-.])(secret|env|credential|key|token|vault|password)([_\-.]|$)/i],
];

function globToRegExp(glob) {
  let out = '^';
  let i = 0;
  while (i < glob.length) {
    const ch = glob[i];
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        out += '.*';
        i += 2;
        // "**/" may match zero directories.
        if (glob[i] === '/') i++;
      } else {
        out += '[^/]*';
        i++;
      }
    } else if (ch === '?') {
      out += '[^/]';
      i++;
    } else if (ch === '[') {
      const end = glob.indexOf(']', i + 1);
      if (end === -1) {
        out += '\\[';
        i++;
      } else {
        out += glob.slice(i, end + 1);
        i = end + 1;
      }
    } else {
      out += ch.replace(/[.+^${}()|\\]/g, '\\$&');
      i++;
    }
  }
  out += '$';
  try {
    return new RegExp(out, 'i');
  } catch {
    return /$^/;
  }
}

function normalizeSlashes(p) {
  return String(p == null ? '' : p).replace(/\\/g, '/');
}

function matchesGlob(value, glob) {
  const v = normalizeSlashes(value);
  const g = normalizeSlashes(glob);
  if (!/[?*[\]]/.test(g)) return v.toLowerCase() === g.toLowerCase();
  return globToRegExp(g).test(v);
}

function matchesAny(value, globs) {
  if (!Array.isArray(globs)) return false;
  for (const glob of globs) {
    if (matchesGlob(value, glob)) return true;
  }
  return false;
}

function mergePolicy(base, override) {
  const out = { ...base };
  if (!override || typeof override !== 'object') return out;
  for (const [key, value] of Object.entries(override)) {
    if (value === undefined) continue;
    out[key] = value;
  }
  return out;
}

function loadPolicy(root, explicitPath) {
  const projectRoot = path.resolve(root || process.cwd());
  const candidates = explicitPath ? [path.resolve(projectRoot, explicitPath)] : POLICY_FILES.map((f) => path.join(projectRoot, f));
  let source = null;
  let policy = { ...DEFAULT_POLICY, projectRoot };

  for (const file of candidates) {
    let raw;
    try {
      raw = fs.readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    try {
      const parsed = JSON.parse(raw);
      policy = mergePolicy(policy, parsed);
      source = file;
      break;
    } catch (err) {
      return {
        policy: { ...DEFAULT_POLICY, projectRoot, invalidPolicy: true, failClosed: true },
        source: file,
        error: `Invalid policy JSON in ${file}: ${err.message}`,
        failedClosed: true,
      };
    }
  }

  // Normalize the shapes we accept for tool rules.
  if (policy.toolRules && !Array.isArray(policy.toolRules) && typeof policy.toolRules === 'object') {
    policy.toolRules = Object.entries(policy.toolRules).map(([match, action]) => ({ match, action }));
  }
  policy.toolRules = (policy.toolRules || []).map((rule) => {
    if (typeof rule === 'string') return { match: rule, action: 'block', reason: `tool rule: ${rule}` };
    return { ...rule, match: String(rule.match || rule.tool || '*'), action: rule.action || 'block' };
  });

  for (const key of ['denyTools', 'allowTools', 'approvalRequired', 'blockedCapabilities', 'allowedCapabilities', 'allowedPaths', 'deniedPaths', 'allowedHosts', 'deniedHosts', 'trustedHosts']) {
    if (!Array.isArray(policy[key])) policy[key] = policy[key] ? [policy[key]] : [];
  }

  const validDefaultAction = ['allow', 'warn', 'block'].includes(policy.defaultAction);
  if (!validDefaultAction) policy.invalidPolicy = true;
  policy.defaultAction = validDefaultAction ? policy.defaultAction : 'block';
  policy.piiMode = policy.piiMode === 'block' ? 'block' : 'warn';
  policy.projectRoot = projectRoot;

  return { policy, source, error: null, failedClosed: false };
}

function capabilityOf(toolName, args) {
  const name = String(toolName || '');
  const found = [];
  for (const [cap, re] of CAPABILITY_PATTERNS) {
    if (re.test(name)) found.push(cap);
  }
  // Argument shape can reveal what the tool name does not say.
  const blob = JSON.stringify(args || {});
  if (!found.length) {
    if (/"(?:command|cmd)"\s*:/.test(blob)) found.push('shell');
    else if (/https?:\/\//.test(blob)) found.push('network');
    else if (/"(?:path|file|dir|filename)"\s*:/.test(blob)) found.push('fs.read');
  }
  if (found.includes('network') && found.includes('secrets')) found.push('exfil');
  if (!found.length) found.push('generic');
  return found[0];
}

function walkStrings(value, key, out) {
  if (value == null) return;
  if (typeof value === 'string') {
    out.push({ key: key || '', value });
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((v) => walkStrings(v, key, out));
    return;
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) walkStrings(v, k, out);
  }
}

const PATH_KEY_RE = /(?:^|_)(?:path|file|filename|dir|directory|folder|root|cwd|target|source|dest|destination|location)s?$|^(?:path|paths|file|files|filename|dir|dirs|directory|folder|root|cwd|target|source|dest|destination|src|dst|location)$|(?:Path|File|Dir|Folder|Root|Target|Source|Dest|Destination)$/;
const COMMAND_KEY_RE = /^(?:command|cmd|script|shell|code|expression|eval|query|sql|input|args|arg|payload)$/i;

function expandHome(p) {
  if (p === '~') return os.homedir();
  if (typeof p === 'string' && p.startsWith('~/')) return path.join(os.homedir(), p.slice(2));
  return p;
}

function resolveCandidate(root, value) {
  const expanded = expandHome(String(value));
  if (path.isAbsolute(expanded)) return path.resolve(expanded);
  return path.resolve(root || process.cwd(), expanded);
}

function isInside(root, candidate) {
  const rel = path.relative(root, candidate);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

// Resolve junctions/symlinks and non-existent leaf paths against the nearest
// existing parent. The policy must decide on the real path, not the lexical one.
function canonicalPath(root, value) {
  const resolved = resolveCandidate(root, value);
  let existing = resolved;
  const suffix = [];
  for (let i = 0; i < 32; i++) {
    try {
      const real = fs.realpathSync.native(existing);
      return path.join(real, ...suffix.reverse());
    } catch {
      const parent = path.dirname(existing);
      if (parent === existing) break;
      suffix.push(path.basename(existing));
      existing = parent;
    }
  }
  return resolved;
}

function canonicalRoot(root) {
  try { return fs.realpathSync.native(root); } catch { return path.resolve(root); }
}

function policyUrlCheck(url, p, add) {
  const host = hostOf(url) || String(url).toLowerCase();
  if (matchesAny(host, p.deniedHosts)) {
    add('block', 'host-denied', `Tool is trying to reach denied host "${host}".`, 'Cloud metadata services are never a valid agent destination.');
  }
  if (p.blockExternalNetwork && isExternalHost(host) && !matchesAny(host, p.allowedHosts)) {
    add('block', 'external-network-blocked', `Tool is trying to reach external host "${host}" while blockExternalNetwork is on.`, 'Add the host to allowedHosts or turn off blockExternalNetwork.');
  }
  if (p.allowedHosts.length > 0 && isExternalHost(host) && !matchesAny(host, p.allowedHosts)) {
    add('block', 'host-not-allowlisted', `External host "${host}" is not in allowedHosts.`, 'Add the host to allowedHosts to permit egress.');
  }
  if (isExternalHost(host) && !matchesAny(host, p.trustedHosts)) {
    const leaks = scanForLeaks(url);
    if (leaks.secrets.length) add('block', 'secret-in-url', `${leaks.secrets.join(', ')} embedded in URL to ${host}.`, 'Never put credentials in a URL.');
  }
}

function inspectText(text, policy, add, context) {
  if (typeof text !== 'string' || text.length === 0) return;
  const deep = (policy.secretScan || policy.piiScan) ? scanForLeaksDeep(text) : null;
  if (policy.secretScan && !policy.allowSecretsInArgs) {
    const leaks = deep;
    if (leaks.secrets.length) {
      add('block', 'secret-in-arguments', `${leaks.secrets.join(', ')} would be passed to ${context}`, 'Never pass a live credential as a tool argument. Read it inside the trusted server or use a vault reference.');
    }
    if (leaks.namedSecrets.length) {
      add('block', 'named-secret-in-arguments', `credential field(s) ${leaks.namedSecrets.join(', ')} would be passed to ${context}`, 'Move credentials out of tool arguments.');
    }
    if (leaks.entropy.length) {
      add('block', 'high-entropy-secret-in-arguments', `unknown high-entropy credential material would be passed to ${context}`, 'Do not pass opaque secrets to tools; use a vault reference.');
    }
  }
  if (policy.blockPromptInjection) {
    const hits = scanTextForInjection(text);
    if (hits.length) {
      add('warn', 'prompt-injection-in-arguments', `prompt-injection pattern (${hits.slice(0, 3).join(', ')}) in text passed to ${context}`, 'Strip the injected instruction before the tool consumes it.');
    }
  }
  if (policy.piiScan) {
    const leaks = deep;
    const personal = leaks.pii.filter((t) => t !== 'ipv4' && t !== 'ipv6');
    if (personal.length) {
      add(policy.piiMode === 'block' ? 'block' : 'warn', 'pii-in-arguments', `personal data (${personal.join(', ')}) passed to ${context}`, 'Redact PII unless the destination is trusted.');
    }
  }
}

function evaluateToolCall({ root, policy, server, tool, args, strict = false }) {
  const p = policy || { ...DEFAULT_POLICY };
  const projectRoot = path.resolve(root || p.projectRoot || process.cwd());
  const strictMode = strict === true || p.mode === 'strict';
  const defaultAction = strictMode && p.defaultAction === 'allow' ? 'block' : p.defaultAction;
  const toolName = String(tool || '');
  const callArgs = args || {};
  const violations = [];
  const add = (level, id, message, fix) => violations.push({ level, id, message, fix: fix || null });
  const capability = capabilityOf(toolName, callArgs);

  if (p.invalidPolicy && p.failClosed) {
    add('block', 'policy-failed-closed', 'The security policy file could not be parsed and failClosed is enabled.', 'Fix the policy file before running the agent.');
  }

  // 1. Tool rules, deny/allow/approval lists.
  if (matchesAny(toolName, p.denyTools)) {
    add('block', 'tool-denied', `Tool "${toolName}" is denied by policy.`, 'Remove the tool from denyTools if it is meant to run.');
  }
  const explicitRule = (p.toolRules || []).find((rule) => matchesGlob(toolName, rule.match));
  if (explicitRule) {
    const action = explicitRule.action;
    const validActions = ['allow', 'warn', 'block', 'approval', 'require-approval', 'ask'];
    if (strictMode && !validActions.includes(action)) {
      add('block', 'policy-invalid-rule', `Tool rule "${explicitRule.match}" has an invalid action "${action}".`, 'Fix the policy rule; strict mode does not guess.');
    } else if (action === 'block') add('block', 'tool-rule-block', explicitRule.reason || `Tool "${toolName}" is blocked by policy rule "${explicitRule.match}".`, 'Review the rule in your MCP policy.');
    else if (action === 'warn') add('warn', 'tool-rule-warn', explicitRule.reason || `Tool "${toolName}" matched a warn rule.`, 'Review the call.');
    else if (action === 'approval' || action === 'require-approval' || action === 'ask') add('block', 'tool-approval-required', explicitRule.reason || `Tool "${toolName}" requires human approval and this proxy is headless.`, 'Approve the call interactively or remove it from approvalRequired.');
  }
  if (matchesAny(toolName, p.approvalRequired)) {
    add('block', 'tool-approval-required', `Tool "${toolName}" requires human approval and this proxy is headless.`, 'Run with an approver, or remove the tool from approvalRequired.');
  }
  if (p.allowTools.length > 0 && !matchesAny(toolName, p.allowTools) && !explicitRule) {
    add('block', 'tool-not-allowlisted', `Tool "${toolName}" is not in allowTools.`, 'Add the tool to allowTools to permit it.');
  }
  if (p.blockedCapabilities.includes(capability)) {
    add('block', 'capability-blocked', `Capability "${capability}" is blocked by policy (tool "${toolName}").`, 'Remove the capability from blockedCapabilities to permit it.');
  }
  if (p.allowedCapabilities.length > 0 && !p.allowedCapabilities.includes(capability) && !p.allowedCapabilities.includes('generic')) {
    add('block', 'capability-not-allowlisted', `Capability "${capability}" is not in allowedCapabilities.`, 'Add the capability to allowedCapabilities to permit it.');
  }
  if (defaultAction === 'block' && !explicitRule && !matchesAny(toolName, p.allowTools)) {
    add('block', 'default-deny', `Tool "${toolName}" is denied by defaultAction: block.`, 'Add an explicit allow rule for this tool.');
  } else if (defaultAction === 'warn' && !explicitRule && !matchesAny(toolName, p.allowTools)) {
    add('warn', 'default-warn', `Tool "${toolName}" matched defaultAction: warn.`, 'Review the call.');
  }

  // 2. Volume and shape.
  const argBytes = Buffer.byteLength(JSON.stringify(callArgs));
  if (p.maxArgumentBytes > 0 && argBytes > p.maxArgumentBytes) {
    add('block', 'arguments-too-large', `Tool arguments are ${argBytes} bytes (limit ${p.maxArgumentBytes}).`, 'Reduce the payload or raise maxArgumentBytes.');
  }

  const strings = [];
  walkStrings(callArgs, '', strings);
  const blob = strings.map((s) => s.value).join('\n');
  const compactBlob = strings.map((s) => s.value).join('');

  // 3. Every text/argument gets secret, PII and injection scrutiny. Scan the
  // compact form too so a credential split across arguments cannot evade a
  // pattern only because a newline was inserted.
  inspectText(blob, p, add, `tool "${toolName}" (${server || 'unknown server'})`);
  if (compactBlob !== blob) inspectText(compactBlob, p, add, `tool "${toolName}" (${server || 'unknown server'})`);

  // 4. Filesystem scope (canonical paths; junctions/symlinks resolved).
  const rootCanonical = canonicalRoot(projectRoot);
  for (const { key, value } of strings) {
    if (!PATH_KEY_RE.test(key)) continue;
    if (/^https?:\/\//i.test(value)) continue;
    if (!/[/\\]|\.(?:env|pem|key|json|ya?ml|toml|ini|conf|sql|db|txt|md|js|ts|py)$/i.test(value) && !path.isAbsolute(expandHome(value))) continue;
    const resolved = canonicalPath(projectRoot, value);
    const rel = normalizeSlashes(path.relative(rootCanonical, resolved));
    if (matchesAny(value, p.deniedPaths) || matchesAny(rel, p.deniedPaths) || matchesAny(normalizeSlashes(resolved), p.deniedPaths)) {
      add('block', 'path-denied', `Path "${value}" matches a denied path in policy.`, 'Credential stores are off-limits to agents. Remove the path from deniedPaths only if you truly intend to expose it.');
    }
    if (p.enforceProjectScope && !isInside(rootCanonical, resolved) && !matchesAny(resolved, p.allowedPaths) && !matchesAny(rel, p.allowedPaths)) {
      const level = capability === 'fs.write' ? 'block' : 'warn';
      add(level, 'path-outside-project', `Path "${value}" resolves outside the project root (${projectRoot}).`, 'Add an explicit allowedPaths entry if the agent must reach it.');
    }
  }

  // 5. URLs / egress.
  const urls = [];
  for (const { key, value } of strings) {
    if (/^https?:\/\//i.test(value)) urls.push(value);
    else if (/^(?:url|uri|endpoint|host|domain|webhook)$/i.test(key) && value) urls.push(value);
  }
  for (const url of urls) policyUrlCheck(url, p, add);

  // 6. Commands.
  if (capability === 'shell' || capability === 'code-exec') {
    for (const { key, value } of strings) {
      if (!COMMAND_KEY_RE.test(key) && capability !== 'shell') continue;
      if (value.length < 2) continue;
      const check = checkCommand(value);
      if (check.blocked) {
        add('block', 'dangerous-command', check.reason || 'Dangerous shell command blocked.', 'Use a scoped tool, or rewrite the command without the destructive/exfil component.');
        const seenWarnings = new Set();
        for (const v of (check.violations || []).slice(0, 3)) {
          const label = v.reason || v.type || 'Shell command warning.';
          if (seenWarnings.has(label) || label === check.reason) continue;
          seenWarnings.add(label);
          add('warn', `command-${v.type || 'warning'}`, label, null);
        }
      }
      // Egress policy applies to URLs embedded in shell commands too. Without
      // this, a plain `curl https://host` bypasses the host allowlist.
      for (const m of value.matchAll(/\bhttps?:\/\/[^\s"'<>]+/gi)) {
        policyUrlCheck(m[0], p, add);
      }
    }
  }

  // 6b. Runtime package firewall — independent of the tool's capability name,
  // because a "deploy" or "run" tool can still carry an install command.
  for (const { value } of strings) {
    if (value.length < 6) continue;
    const installs = [
      /(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)\s+(?:--save\s+)?([@\w./-]+)/gi,
      /(?:npx|bunx|pnpm\s+dlx)\s+(?:-y\s+|--yes\s+)?([@\w./-]+)/gi,
    ];
    for (const re of installs) {
      let m;
      while ((m = re.exec(value)) !== null) {
        const spec = m[1];
        if (!spec || spec.startsWith('-')) continue;
        const name = spec.startsWith('@') ? spec.split('@').slice(0, 2).join('@') : spec.split('@')[0];
        const pkgCheck = checkPackage(name);
        const bad = pkgCheck.risks.find((r) => r.action === 'block');
        if (bad) {
          add('block', 'malicious-package', `Package "${name}" looks malicious or typosquatted: ${bad.message}`, 'Verify the package on the registry before installing it.');
          continue;
        }
        const warn = pkgCheck.risks.find((r) => r.severity === 'high');
        if (warn) add('warn', 'risky-package', `Package "${name}": ${warn.message}`, 'Verify the package name and pin a version.');
        const unpinned = !spec.includes('@') || (spec.startsWith('@') && !spec.slice(1).includes('@'));
        if (unpinned) add('warn', 'unpinned-package', `Package "${name}" is installed without a version pin.`, 'Pin the version so the code cannot change between runs.');
      }
    }
  }

  // 7. Destination-aware exfiltration: secrets + a network sink in one call.
  if (urls.length && !p.allowSecretsInArgs) {
    const leaks = scanForLeaks(blob);
    if (leaks.secrets.length || leaks.namedSecrets.length) {
      const host = hostOf(urls[0]) || urls[0];
      if (!matchesAny(host, p.trustedHosts)) {
        add('block', 'exfiltration-attempt', `Credentials plus an outbound destination (${host}) in one tool call — exfiltration shape.`, 'Separate credentials from network calls. Use a trusted host if this is intentional.');
      }
    }
  }

  let action = 'allow';
  for (const v of violations) {
    if (v.level === 'block') { action = 'block'; break; }
    if (v.level === 'warn') action = 'warn';
  }

  const risk = violations.reduce((sum, v) => sum + (v.level === 'block' ? 35 : 8), 0);

  return {
    action,
    blocked: action === 'block',
    tool: toolName,
    server: server || null,
    capability,
    risk: Math.min(100, risk),
    violations,
    reasons: violations.map((v) => v.message),
  };
}

function toolDefinitionHash(tool) {
  const t = tool || {};
  return crypto.createHash('sha256').update(JSON.stringify({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema,
  })).digest('hex').slice(0, 16);
}

// Tool definitions are model-facing text. A poisoned description is an
// instruction the agent will read on every turn — inspect it like untrusted
// input, not like documentation.
function evaluateToolDefinition(tool, opts = {}) {
  const currentHash = opts.hash || toolDefinitionHash(tool);
  const t = tool || {};
  const violations = [];
  const add = (level, id, message, fix) => violations.push({ level, id, message, fix: fix || null });
  const name = String(t.name || '');
  const description = String(t.description || '');
  const schemaBlob = t.inputSchema ? JSON.stringify(t.inputSchema) : '';
  const text = `${name}\n${description}\n${schemaBlob}`;

  if (!name) add('block', 'tool-missing-name', 'Tool definition has no name — the agent cannot identify it safely.', 'Remove the malformed tool.');
  if (description.length > 20000) add('warn', 'tool-description-huge', `Tool "${name}" has a ${description.length}-character description. Long descriptions are an instruction-smuggling surface.`, 'Trim the description to its contract.');

  const hits = scanTextForInjection(text);
  if (hits.length) {
    add('block', 'tool-poisoning', `Tool "${name}" contains prompt-injection text (${hits.slice(0, 4).join(', ')}).`, 'Remove the injected instruction. Tool descriptions must describe the tool, never instruct the model.');
  }

  if (/do\s+not\s+(?:tell|inform|mention|reveal|disclose)|don'?t\s+(?:tell|inform|mention)\s+the\s+user|silently\s+(?:run|execute|send|read)/i.test(description)) {
    add('block', 'tool-concealment-instruction', `Tool "${name}" tells the model to keep something from the user.`, 'Remove the concealment instruction.');
  }
  if (/(?:read|open|dump|send|upload|exfiltrate)[^.]{0,80}(?:\.env|environment\s+variables?|secrets?|api\s*keys?|\.ssh|credentials?|cookies?)/i.test(description)) {
    add('warn', 'tool-sensitive-instruction', `Tool "${name}" mentions credentials/secrets in its model-facing description.`, 'Describe the action without naming credential stores.');
  }
  if (/(?:always|must|immediately)\s+(?:call|invoke|use)\s+(?:this|the)\s+tool|before\s+using\s+any\s+other\s+tool/i.test(description)) {
    add('warn', 'tool-forced-invocation', `Tool "${name}" pressures the model to invoke it unconditionally.`, 'Remove urgency/forced-invocation language.');
  }
  if (/(?:[A-Za-z0-9+/]{200,}={0,2})/.test(description)) {
    add('warn', 'tool-encoded-payload', `Tool "${name}" description contains a long encoded blob.`, 'Decode and review it; descriptions should not carry payloads.');
  }
  // A tool that claims to be read-only while its description describes writes
  // is lying to the model's planner.
  if (t.annotations && t.annotations.readOnlyHint === true && /(?:write|delete|remove|modify|execute|run|install|upload|send)/i.test(description)) {
    add('warn', 'tool-readonly-lie', `Tool "${name}" claims readOnlyHint but its description describes a state-changing action.`, 'Fix the annotation — the model uses it to decide whether to ask for confirmation.');
  }
  if (opts.expectedHash && currentHash !== opts.expectedHash) {
    add('block', 'tool-definition-drift', `Tool "${name}" definition changed since it was approved (rug-pull risk).`, 'Re-review the server and re-pin the tool only after review.');
  }

  let action = 'allow';
  for (const v of violations) {
    if (v.level === 'block') { action = 'block'; break; }
    if (v.level === 'warn') action = 'warn';
  }
  return { action, blocked: action === 'block', tool: name, violations, risk: Math.min(100, violations.reduce((s, v) => s + (v.level === 'block' ? 40 : 10), 0)) };
}

// Rate limiter shared by the proxy. Mutates `session` so a long-lived firewall
// process can enforce a call budget per minute.
function checkRateLimit(session, policy, now = Date.now()) {
  if (!session) return { allowed: true, remaining: null };
  const limit = Number(policy.maxCallsPerMinute || 0);
  if (!limit) return { allowed: true, remaining: null };
  if (!session.rateWindow || now - session.rateWindow.start >= 60000) {
    session.rateWindow = { start: now, count: 0 };
  }
  session.rateWindow.count++;
  const allowed = session.rateWindow.count <= limit;
  return { allowed, remaining: Math.max(0, limit - session.rateWindow.count), count: session.rateWindow.count, limit };
}

function describePolicy(policy, source) {
  const p = policy || DEFAULT_POLICY;
  return {
    source: source || null,
    defaultAction: p.defaultAction,
    toolRules: p.toolRules.length,
    denyTools: p.denyTools,
    approvalRequired: p.approvalRequired,
    blockedCapabilities: p.blockedCapabilities,
    enforceProjectScope: !!p.enforceProjectScope,
    allowedPaths: p.allowedPaths,
    deniedPaths: p.deniedPaths.length,
    allowedHosts: p.allowedHosts,
    deniedHosts: p.deniedHosts,
    blockExternalNetwork: !!p.blockExternalNetwork,
    secretScan: !!p.secretScan,
    piiMode: p.piiMode,
    blockPromptInjection: !!p.blockPromptInjection,
    pinToolDefinitions: !!p.pinToolDefinitions,
    scrubToolResults: !!p.scrubToolResults,
    blockToolResultInjection: !!p.blockToolResultInjection,
    maxArgumentBytes: p.maxArgumentBytes,
    maxCallsPerMinute: p.maxCallsPerMinute,
  };
}

module.exports = {
  DEFAULT_POLICY,
  POLICY_FILES,
  loadPolicy,
  mergePolicy,
  evaluateToolCall,
  evaluateToolDefinition,
  capabilityOf,
  checkRateLimit,
  describePolicy,
  matchesGlob,
  matchesAny,
  toolDefinitionHash,
  sanitizeOutbound,
  scanForLeaks,
};
