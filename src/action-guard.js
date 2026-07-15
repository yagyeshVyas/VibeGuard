'use strict';

/*
 * src/action-guard.js — Agent Action Firewall.
 *
 * Real-time exfiltration guard. Inspects an agent action BEFORE it runs
 * and blocks it if it would exfiltrate secrets or personal data, run a
 * dangerous command, or send sensitive data to an untrusted destination.
 *
 * One inspection API over every action an agent can take:
 *   { type: 'shell',   command }
 *   { type: 'network', url, body?, method? }
 *   { type: 'file-write', path, content }
 *   { type: 'prompt',  content, provider? }   // text going to an LLM
 *   { type: 'mcp',     tool, args }           // an MCP tool call
 *
 * Core rule (best-effort, not a sandbox): a hardcoded API key or a piece
 * of personal data (email, SSN, credit card, phone) should not leave the
 * machine to an external host without an explicit allow. Secrets to any
 * external destination are blocked. This catches the common exfil paths
 * (fetch, http, exec, fs) — it is not a guarantee against a determined
 * attacker with arbitrary native code execution.
 *
 * 100% local. Zero network. Zero dependencies. Fail-closed on the block path.
 */

const { checkCommand, SECRET_PATTERNS } = require('./shell-guard');
const { detectPII, redactText } = require('./pii');

// Hosts that are the local machine or a private network — sending data there is
// not exfiltration off the box.
const LOCAL_HOST_RE = /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\[::1\])$/i;
const PRIVATE_IP_RE = /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/;
// Cloud metadata endpoints — credential theft targets, ALWAYS untrusted.
const METADATA_HOST_RE = /^(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.goog)$/i;

function hostOf(url) {
  if (typeof url !== 'string') return null;
  const m = url.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]+)/i);
  if (!m) return null;
  return m[1].replace(/:\d+$/, '').toLowerCase(); // strip port
}

function isExternalHost(host) {
  if (!host) return false;
  if (METADATA_HOST_RE.test(host)) return true; // metadata = worst-case external
  if (LOCAL_HOST_RE.test(host)) return false;
  if (PRIVATE_IP_RE.test(host)) return false;
  return true;
}

// Shannon entropy in bits/char — high for random secrets, low for words/ids.
function shannonEntropy(s) {
  const freq = Object.create(null);
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  let e = 0;
  for (const k in freq) { const p = freq[k] / s.length; e -= p * Math.log2(p); }
  return e;
}

// A value that is structured, not a secret — don't treat these as unknown keys.
function looksStructured(v) {
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) return true; // UUID
  if (/^[0-9a-f]+$/i.test(v) && [32, 40, 64].includes(v.length)) return true; // md5/sha1/sha256 hash
  if (/^\d+$/.test(v)) return true; // pure number / id
  return false;
}

// A field NAMED like a credential carrying a high-entropy value = a secret, even
// if it matches no known vendor pattern. Precise: the secret-ish NAME plus real
// entropy avoids flagging random hashes/ids that aren't labelled secrets.
// High-confidence credential field names only. Deliberately excludes ambiguous
// names (token, bearer, session, auth) that are commonly legitimate auth values
// sent to APIs — those would false-positive and break real traffic. Known vendor
// key formats (sk_live_, ghp_, …) are still caught by SECRET_PATTERNS regardless
// of field name.
const NAMED_SECRET_RE =
  /["']?([\w-]*(?:api[_-]?key|secret|private[_-]?key|access[_-]?key|password|passwd|credential)[\w-]*)["']?\s*[:=]\s*["']?([A-Za-z0-9+/=_.\-]{12,})["']?/gi;

function findNamedSecrets(text) {
  const out = [];
  let m;
  NAMED_SECRET_RE.lastIndex = 0;
  while ((m = NAMED_SECRET_RE.exec(text)) !== null) {
    const name = m[1];
    const val = m[2];
    if (looksStructured(val)) continue;
    // Env-var references / placeholders are not real values.
    if (/^(?:process\.env|import\.meta|os\.environ|\$\{|xxx|changeme|your[_-]?)/i.test(val)) continue;
    if (shannonEntropy(val) < 3.2) continue; // low entropy → likely not a secret
    out.push(name);
  }
  return [...new Set(out)];
}

// Find secrets + PII in any outbound string.
function scanForLeaks(text) {
  const out = { secrets: [], pii: [], namedSecrets: [] };
  if (!text || typeof text !== 'string') return out;
  for (const { re, type } of SECRET_PATTERNS) {
    if (re.test(text)) out.secrets.push(type);
  }
  out.secrets = [...new Set(out.secrets)];
  const pii = detectPII(text, {});
  out.pii = pii.types || [];
  out.namedSecrets = findNamedSecrets(text);
  return out;
}

const RANK = { block: 2, warn: 1, allow: 0 };

// Inspect a single action. `policy.trustedHosts` (array) explicitly allows
// sending sensitive data to those hosts (e.g. your own API). `policy.piiMode`
// = 'block' (default for external) or 'warn'.
function inspectAction(action = {}, policy = {}) {
  const trusted = new Set((policy.trustedHosts || []).map((h) => String(h).toLowerCase()));
  const piiMode = policy.piiMode === 'warn' ? 'warn' : 'block';
  const type = action.type || 'generic';
  const violations = [];
  const add = (level, kind, detail) => violations.push({ level, kind, detail });

  const leakToDest = (text, host, destLabel) => {
    // External = off this machine AND not on the caller's explicit allowlist.
    const external = isExternalHost(host) && !trusted.has(host);
    if (!external) return;
    const { secrets, pii, namedSecrets } = scanForLeaks(text);
    if (secrets.length) {
      add('block', 'secret-exfiltration', `${secrets.join(', ')} would be sent to ${destLabel}`);
    }
    if (namedSecrets.length) {
      add('block', 'named-secret-exfiltration', `credential field(s) ${namedSecrets.join(', ')} (high-entropy value) would be sent to ${destLabel}`);
    }
    if (pii.length) {
      add(piiMode, 'pii-exfiltration', `personal data (${pii.join(', ')}) would be sent to ${destLabel}`);
    }
  };

  switch (type) {
    case 'shell': {
      const r = checkCommand(action.command || '');
      if (r.blocked) {
        // checkCommand already covers rm -rf, secret exfil, sensitive paths, etc.
        const sev = r.severity === 'critical' ? 'block' : 'block';
        add(sev, r.violations && r.violations[0] ? r.violations[0].type : 'dangerous-command', r.reason);
      }
      break;
    }
    case 'network': {
      const host = hostOf(action.url);
      const dest = host || action.url || 'an external host';
      // The URL itself can carry a secret (?token=...) or PII.
      leakToDest(String(action.url || ''), host, dest);
      leakToDest(typeof action.body === 'string' ? action.body : JSON.stringify(action.body || ''), host, dest);
      if (host && METADATA_HOST_RE.test(host)) {
        add('block', 'metadata-access', `request to cloud metadata endpoint ${host} — credential theft`);
      }
      break;
    }
    case 'file-write': {
      const { secrets, pii } = scanForLeaks(String(action.content || ''));
      const p = String(action.path || '');
      const publicPath = /(?:^|\/)(?:public|static|dist|www|build)\//i.test(p);
      if (secrets.length && publicPath) {
        add('block', 'secret-to-public-file', `${secrets.join(', ')} written to a web-served path (${p})`);
      } else if (secrets.length) {
        add('warn', 'secret-in-file', `${secrets.join(', ')} written to ${p} — ensure it is gitignored and not shipped`);
      }
      if (pii.length && publicPath) {
        add('block', 'pii-to-public-file', `personal data (${pii.join(', ')}) written to a web-served path (${p})`);
      }
      break;
    }
    case 'prompt':
    case 'llm': {
      const { secrets, pii, namedSecrets } = scanForLeaks(String(action.content || ''));
      const provider = action.provider || 'an LLM provider';
      if (secrets.length) add('block', 'secret-to-llm', `${secrets.join(', ')} in text sent to ${provider}`);
      if (namedSecrets.length) add('block', 'named-secret-to-llm', `credential field(s) ${namedSecrets.join(', ')} in text sent to ${provider}`);
      if (pii.length) add(piiMode, 'pii-to-llm', `personal data (${pii.join(', ')}) sent to ${provider} — redact first`);
      break;
    }
    case 'mcp': {
      const blob = JSON.stringify(action.args || {}) + ' ' + String(action.tool || '');
      const { secrets, pii } = scanForLeaks(blob);
      if (secrets.length) add('block', 'secret-in-mcp-call', `${secrets.join(', ')} passed to MCP tool ${action.tool || ''}`);
      if (pii.length) add('warn', 'pii-in-mcp-call', `personal data (${pii.join(', ')}) passed to MCP tool ${action.tool || ''}`);
      break;
    }
    default: {
      // Generic: scan any provided text; treat as external unless a host says otherwise.
      const { secrets, pii } = scanForLeaks(String(action.content || action.text || ''));
      if (secrets.length) add('block', 'secret-exposure', secrets.join(', '));
      if (pii.length) add('warn', 'pii-exposure', pii.join(', '));
    }
  }

  // Verdict = the most severe violation. Fail-closed: default allow only when
  // nothing matched.
  let verdict = 'allow';
  for (const v of violations) if (RANK[v.level] > RANK[verdict]) verdict = v.level;

  return {
    action: verdict, // 'allow' | 'warn' | 'block'
    blocked: verdict === 'block',
    type,
    violations,
    reason: violations.length ? violations[0].detail : null,
  };
}

// Redact secrets + PII from a string so it CAN be sent safely (defense-in-depth
// companion to blocking — sanitize instead of drop when the caller opts in).
function sanitizeOutbound(text) {
  if (!text || typeof text !== 'string') return text;
  let out = redactText(text).redacted; // redactText returns { redacted, ... }
  for (const { re } of SECRET_PATTERNS) {
    out = out.replace(new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g'), '[REDACTED-SECRET]');
  }
  return out;
}

module.exports = { inspectAction, scanForLeaks, sanitizeOutbound, isExternalHost, hostOf, findNamedSecrets, shannonEntropy };
