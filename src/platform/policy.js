'use strict';

/*
 * src/platform/policy.js — strict, signed policy v2 for the security gateway.
 *
 * This module is deliberately pure: no network, no filesystem reads inside the
 * evaluator, no clock unless injected. It implements the subset of
 * research/10-security-policy-schema.md needed for the strict foundation:
 *
 *   - default deny and deny-overrides
 *   - capability + principal checks
 *   - per-tool and per-resource allow/deny/approval rules
 *   - canonical path checks
 *   - URL/host egress checks (including URLs embedded in shell commands)
 *   - secret/PII/entropy inspection
 *   - signed policy documents (Ed25519 over canonical body)
 *
 * It is additive; the legacy agent-policy module remains for compatibility.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DECISION, CAPABILITIES, ERROR_CODES, VibeGuardError, assertPrincipal } = require('./contracts');
const { sha256Hex, actionDigest } = require('./canonical');
const { loadPrivateKey, loadPublicKey } = require('./identity');
const { checkCommand } = require('../shell-guard');
const { scanForLeaksDeep, isExternalHost, hostOf } = require('../action-guard');

function matchesGlob(value, glob) {
  const v = String(value == null ? '' : value);
  const g = String(glob == null ? '' : glob);
  if (g === '*') return true;
  if (!/[?*]/.test(g)) return v === g;
  const re = new RegExp('^' + g.split('').map((c) => {
    if (c === '*') return '.*';
    if (c === '?') return '.';
    return c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }).join('') + '$', 'i');
  return re.test(v);
}

function matchesAny(value, globs) {
  return Array.isArray(globs) && globs.some((g) => matchesGlob(value, g));
}

function canonicalPath(root, value) {
  const expanded = String(value).replace(/^~(?=$|[\\/])/, require('os').homedir());
  const resolved = path.isAbsolute(expanded) ? path.resolve(expanded) : path.resolve(root, expanded);
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

function inside(root, candidate) {
  const rel = path.relative(root, candidate);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function walkStrings(value, key, out) {
  if (value == null) return;
  if (typeof value === 'string') { out.push({ key: key || '', value }); return; }
  if (Array.isArray(value)) { value.forEach((v) => walkStrings(v, key, out)); return; }
  if (typeof value === 'object') for (const [k, v] of Object.entries(value)) walkStrings(v, k, out);
}

const PATH_KEY = /path|file|dir|folder|root|cwd|target|source|dest|destination|location/i;
const COMMAND_KEY = /command|cmd|script|shell|code|expression|eval|query|sql|input|args/i;

function conditionMatches(cond, ctx) {
  if (!cond) return true;
  if (typeof cond !== 'object') return false;
  const op = cond.op;
  if (op === 'and') return (cond.args || []).every((c) => conditionMatches(c, ctx));
  if (op === 'or') return (cond.args || []).some((c) => conditionMatches(c, ctx));
  if (op === 'not') return !conditionMatches((cond.args || [])[0], ctx);
  const value = getPath(ctx, cond.path);
  switch (op) {
    case 'eq': return value === cond.value;
    case 'neq': return value !== cond.value;
    case 'in': return Array.isArray(cond.value) && cond.value.includes(value);
    case 'notIn': return Array.isArray(cond.value) && !cond.value.includes(value);
    case 'contains': return String(value == null ? '' : value).includes(String(cond.value));
    case 'startsWith': return String(value == null ? '' : value).startsWith(String(cond.value));
    case 'endsWith': return String(value == null ? '' : value).endsWith(String(cond.value));
    case 'within': return typeof value === 'string' && matchesGlob(value, cond.value);
    case 'labelIn': return Array.isArray(ctx.labels) && cond.value.every((x) => ctx.labels.includes(x));
    default: return false;
  }
}

function getPath(obj, expr) {
  if (!expr || expr === '$') return obj;
  const parts = String(expr).replace(/^\$\.?/, '').split('.').filter(Boolean);
  let cur = obj;
  for (const p of parts) {
    if (cur == null) return undefined;
    cur = cur[p];
  }
  return cur;
}

function ruleMatches(rule, req, ctx) {
  const m = rule.match || {};
  if (m.principal && !matchesGlob(req.principal, m.principal)) return false;
  if (m.server && !matchesGlob(req.server, m.server)) return false;
  if (m.tool && !matchesGlob(req.tool, m.tool)) return false;
  if (m.capability) {
    const caps = Array.isArray(m.capability) ? m.capability : [m.capability];
    if (!caps.includes(req.capability)) return false;
  }
  if (rule.resources) {
    if (Array.isArray(rule.resources.paths) && rule.resources.paths.length) {
      if (!ctx.paths.some((p) => matchesAny(p.value, rule.resources.paths) || matchesAny(p.rel, rule.resources.paths) || matchesAny(p.resolved, rule.resources.paths))) return false;
    }
    if (Array.isArray(rule.resources.hosts) && rule.resources.hosts.length) {
      if (!ctx.hosts.some((h) => matchesAny(h, rule.resources.hosts))) return false;
    }
  }
  if (rule.conditions && !conditionMatches(rule.conditions, ctx)) return false;
  return true;
}

class StrictPolicyEngine {
  constructor(policy, opts = {}) {
    if (!policy || policy.schemaVersion !== '2.0') {
      throw new VibeGuardError(ERROR_CODES.POLICY_INVALID, 'policy schemaVersion must be 2.0');
    }
    if (!['strict', 'monitor', 'legacy'].includes(policy.mode)) {
      throw new VibeGuardError(ERROR_CODES.POLICY_INVALID, 'invalid policy mode');
    }
    if (policy.mode === 'strict' && (!policy.defaults || policy.defaults.decision !== 'deny')) {
      throw new VibeGuardError(ERROR_CODES.POLICY_INVALID, 'strict policy must default to deny');
    }
    this.policy = policy;
    this.root = path.resolve(opts.root || process.cwd());
    this.clock = opts.clock || (() => new Date());
    const now = this.clock();
    const issued = policy.issuedAt ? new Date(policy.issuedAt) : null;
    const expires = policy.expiresAt ? new Date(policy.expiresAt) : null;
    if (issued && Number.isFinite(issued.getTime()) && issued.getTime() > now.getTime() + 300000) {
      throw new VibeGuardError(ERROR_CODES.POLICY_INVALID, 'policy is not valid yet');
    }
    if (expires && Number.isFinite(expires.getTime()) && expires.getTime() <= now.getTime()) {
      throw new VibeGuardError(ERROR_CODES.POLICY_INVALID, 'policy has expired');
    }
    this.principalCapabilities = new Map();
    for (const subj of policy.subjects || []) {
      if (subj && subj.principal) this.principalCapabilities.set(subj.principal, subj.capabilities || []);
    }
    this.rootCanonical = canonicalRoot(this.root);
  }

  evaluate(request = {}) {
    const req = {
      principal: request.principal,
      server: request.server || '',
      tool: request.tool || '',
      capability: request.capability || '',
      args: request.arguments || request.args || {},
      labels: Array.isArray(request.labels) ? request.labels : [],
      sessionId: request.sessionId || null,
    };
    try {
      assertPrincipal(req.principal);
      if (!CAPABILITIES.includes(req.capability)) return deny('VG_AUTHORIZATION_DENIED', 'unknown capability');
      const declared = this.principalCapabilities.get(req.principal);
      if (!declared) return deny('VG_AUTHORIZATION_DENIED', 'principal is not declared in policy');
      if (!declared.includes(req.capability)) return deny('VG_AUTHORIZATION_DENIED', `principal lacks capability ${req.capability}`);

      const strings = [];
      walkStrings(req.args, '', strings);
      const actions = this._inspectArguments(req, strings);
      if (actions.deny) return actions.deny;

      const ctx = { principal: req.principal, server: req.server, tool: req.tool, args: req.args, labels: req.labels, paths: actions.paths || [], hosts: actions.hosts || [], resource: actions };
      const rules = [...(this.policy.tools || []), ...(this.policy.resources || [])];
      const matched = rules.filter((r) => ruleMatches(r, req, ctx));
      const denyRule = matched.find((r) => r.effect === 'deny');
      if (denyRule) return deny('VG_AUTHORIZATION_DENIED', denyRule.reason || 'denied by policy', denyRule.id);
      const quarantine = matched.find((r) => r.effect === 'quarantine');
      if (quarantine) return { decision: DECISION.QUARANTINE, reasonCode: 'VG_AUTHORIZATION_DENIED', matchedRules: [quarantine.id || 'quarantine'] };
      const approval = matched.find((r) => r.effect === 'approval_required');
      if (approval) {
        return {
          decision: DECISION.APPROVAL_REQUIRED,
          reasonCode: ERROR_CODES.APPROVAL_REQUIRED,
          matchedRules: [approval.id || 'approval'],
          approval: approval.approval || {},
          actionDigest: actionDigest({ server: req.server, tool: req.tool, capability: req.capability, arguments: req.args }),
        };
      }
      const allow = matched.find((r) => r.effect === 'allow');
      if (allow) {
        return { decision: DECISION.ALLOW, reasonCode: 'OK', matchedRules: [allow.id || 'allow'] };
      }
      return deny('VG_AUTHORIZATION_DENIED', 'no allow rule matched (default deny)');
    } catch (err) {
      if (err instanceof VibeGuardError) return deny(err.code, err.message);
      return deny(ERROR_CODES.POLICY_EVALUATION_ERROR, 'policy evaluation failed');
    }
  }

  _inspectArguments(req, strings) {
    const blob = strings.map((s) => s.value).join('\n') + '\n' + strings.map((s) => s.value).join('');
    const leaks = scanForLeaksDeep(blob);
    if (leaks.secrets.length || leaks.entropy.length) {
      return { deny: deny('VG_AUTHORIZATION_DENIED', 'secret/high-entropy credential material in arguments') };
    }
    if (leaks.pii.length && this.policy.data && this.policy.data.pii && this.policy.data.pii.action === 'block') {
      return { deny: deny('VG_AUTHORIZATION_DENIED', 'PII in arguments is blocked by policy') };
    }
    const paths = [];
    const hosts = [];
    for (const { key, value } of strings) {
      if (PATH_KEY.test(key) && !/^https?:\/\//i.test(value)) {
        const resolved = canonicalPath(this.root, value);
        const rel = path.relative(this.rootCanonical, resolved).replace(/\\/g, '/');
        paths.push({ value, resolved, rel });
        const denyPaths = [];
        for (const rule of this.policy.resources || []) {
          if (rule.effect === 'deny' && rule.resources && rule.resources.paths) denyPaths.push(...rule.resources.paths);
        }
        if (denyPaths.length && (matchesAny(value, denyPaths) || matchesAny(rel, denyPaths) || matchesAny(resolved, denyPaths))) {
          return { deny: deny('VG_AUTHORIZATION_DENIED', 'path matches a denied resource') };
        }
        const allowPaths = [];
        for (const rule of this.policy.resources || []) {
          if (rule.effect === 'allow' && rule.resources && rule.resources.paths) allowPaths.push(...rule.resources.paths);
        }
        if (!inside(this.rootCanonical, resolved) && !matchesAny(value, allowPaths) && !matchesAny(rel, allowPaths)) {
          return { deny: deny('VG_AUTHORIZATION_DENIED', 'path is outside the project and not explicitly allowed') };
        }
        if (this.policy.sandbox && this.policy.sandbox.filesystem && Array.isArray(this.policy.sandbox.filesystem.deny)) {
          if (matchesAny(value, this.policy.sandbox.filesystem.deny) || matchesAny(rel, this.policy.sandbox.filesystem.deny)) {
            return { deny: deny('VG_AUTHORIZATION_DENIED', 'path matches a denied sandbox mount') };
          }
        }
      }
      if (COMMAND_KEY.test(key)) {
        const cmd = checkCommand(value);
        if (cmd.blocked) return { deny: deny('VG_AUTHORIZATION_DENIED', cmd.reason || 'dangerous command') };
        for (const m of value.matchAll(/\bhttps?:\/\/[^\s"'<>]+/gi)) {
          const host = hostOf(m[0]) || m[0].toLowerCase();
          hosts.push(host);
          const allowed = this.policy.data && this.policy.data.dlp && this.policy.data.dlp.destinations && this.policy.data.dlp.destinations.allow;
          if (isExternalHost(host) && Array.isArray(allowed) && !matchesAny(host, allowed)) {
            return { deny: deny('VG_AUTHORIZATION_DENIED', `egress host not allowlisted: ${host}`) };
          }
        }
      }
    }
    return { paths, hosts };
  }
}

function deny(code, explanation, ruleId) {
  return {
    decision: DECISION.DENY,
    reasonCode: code || 'VG_AUTHORIZATION_DENIED',
    matchedRules: ruleId ? [ruleId] : [],
    obligations: [],
    explanation,
  };
}

function signPolicy(policy, opts = {}) {
  if (!opts.privateKey) throw new Error('signPolicy requires privateKey');
  const body = JSON.parse(JSON.stringify(policy));
  delete body.signature;
  const bodyHash = 'sha256:' + sha256Hex(body);
  const sig = crypto.sign(null, Buffer.from(bodyHash, 'utf8'), loadPrivateKey(opts.privateKey)).toString('base64url');
  return { ...body, signature: { alg: 'Ed25519', keyId: opts.keyId || 'policy-key', bodyHash, sig } };
}

function verifyPolicy(policy, opts = {}) {
  if (!policy || policy.schemaVersion !== '2.0') return { valid: false, reason: 'schemaVersion must be 2.0' };
  const now = opts.now ? new Date(opts.now) : new Date();
  if (policy.issuedAt && new Date(policy.issuedAt).getTime() > now.getTime() + 300000) return { valid: false, reason: 'policy is not valid yet' };
  if (policy.expiresAt && new Date(policy.expiresAt).getTime() <= now.getTime()) return { valid: false, reason: 'policy has expired' };
  const sig = policy.signature;
  if (!sig || sig.alg !== 'Ed25519' || !sig.bodyHash || !sig.sig) return { valid: false, reason: 'missing/unsupported signature' };
  if (!opts.publicKey) return { valid: false, reason: 'no public key' };
  const body = { ...policy };
  delete body.signature;
  const hash = 'sha256:' + sha256Hex(body);
  if (hash !== sig.bodyHash) return { valid: false, reason: 'policy body hash mismatch' };
  try {
    const ok = crypto.verify(null, Buffer.from(hash, 'utf8'), loadPublicKey(opts.publicKey), Buffer.from(sig.sig, 'base64url'));
    if (!ok) return { valid: false, reason: 'policy signature invalid' };
  } catch {
    return { valid: false, reason: 'policy signature verification error' };
  }
  return { valid: true };
}

function loadPolicyFile(file, opts = {}) {
  let policy;
  try { policy = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (err) {
    throw new VibeGuardError(ERROR_CODES.POLICY_INVALID, `cannot load policy: ${err.message}`);
  }
  if (policy.mode === 'strict' && !opts.allowUnsigned) {
    const v = verifyPolicy(policy, { publicKey: opts.publicKey });
    if (!v.valid) throw new VibeGuardError(ERROR_CODES.POLICY_INVALID, `strict policy is not authentic: ${v.reason}`);
  }
  return new StrictPolicyEngine(policy, opts);
}

module.exports = {
  StrictPolicyEngine,
  signPolicy,
  verifyPolicy,
  loadPolicyFile,
  matchesGlob,
  canonicalPath,
  conditionMatches,
};
