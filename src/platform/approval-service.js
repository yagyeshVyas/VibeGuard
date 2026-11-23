'use strict';

/*
 * src/platform/approval-service.js — authenticated hosted approval workflow.
 *
 * Agents request approval with a VGAT token. Humans either:
 *   - log in to the loopback UI with a scrypt password (HttpOnly session,
 *     SameSite=Strict + CSRF token), or
 *   - present a human VGAT bearer token plus a signed VGAPPROVER proof.
 *
 * The service stores tickets durably, supports multi-human quorum, signs the
 * final VGAPPROVAL token, and appends signed audit events. It is a local /
 * loopback service slice, not an enterprise IdP.
 */

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { ApprovalBroker } = require('./approval');
const { SignedAuditLog } = require('./signed-audit');
const { ERROR_CODES, VibeGuardError, safeEqual } = require('./contracts');
const { generateKeyPair, privateKeyToPem, loadPrivateKey } = require('./identity');
const { MetricsRegistry } = require('./metrics');

const SCRYPT = Object.freeze({ N: 16384, r: 8, p: 1, keylen: 32, maxmem: 64 * 1024 * 1024 });
const SESSION_TTL_SECONDS = 15 * 60;
const MAX_BODY = 64 * 1024;
const COOKIE_SESSION = 'vg_approval_session';
const COOKIE_CSRF = 'vg_approval_csrf';
const DUMMY_PASSWORD_HASH = hashPassword('invalid-dummy-password');

function b64(buf) { return Buffer.from(buf).toString('base64url'); }

function hashPassword(password) {
  const text = String(password == null ? '' : password);
  if (!text || text.length > 1024) throw new VibeGuardError(ERROR_CODES.SCHEMA_INVALID, 'password must be 1..1024 characters');
  const salt = crypto.randomBytes(16);
  const digest = crypto.scryptSync(text, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: SCRYPT.maxmem });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${b64(salt)}$${b64(digest)}`;
}

function verifyPassword(password, stored) {
  try {
    const parts = String(stored || '').split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
    const [, n, r, p, saltB64, hashB64] = parts;
    const salt = Buffer.from(saltB64, 'base64url');
    const expected = Buffer.from(hashB64, 'base64url');
    const actual = crypto.scryptSync(String(password == null ? '' : password), salt, expected.length, { N: Number(n), r: Number(r), p: Number(p), maxmem: SCRYPT.maxmem });
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

class JsonApprovalStore {
  constructor(file) {
    this.file = file ? path.resolve(file) : null;
    this.data = { tickets: [], usedTokens: [], approverKeys: {} };
    if (this.file && fs.existsSync(this.file)) {
      try {
        if (fs.lstatSync(this.file).isSymbolicLink()) throw new Error('symlink');
        this.data = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      } catch {
        throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval store is corrupt or unsafe');
      }
    }
  }

  save(broker) {
    const approverKeys = this.data.approverKeys || {};
    this.data = { ...broker.exportState(), approverKeys };
    if (!this.file) return;
    fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
    const tmp = `${this.file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
    try {
      fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
      fs.renameSync(tmp, this.file);
    } finally {
      try { fs.rmSync(tmp, { force: true }); } catch { /* ignore */ }
    }
  }
}

function json(res, status, body, headers = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...headers,
  });
  res.end(payload);
}

function html(res, status, body, headers = {}) {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
    ...headers,
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let s = '';
    req.on('data', (c) => {
      s += c;
      if (s.length > MAX_BODY) {
        reject(new VibeGuardError(ERROR_CODES.LIMIT_EXCEEDED, 'request too large', { status: 413 }));
        req.destroy();
      }
    });
    req.on('end', () => resolve(s));
    req.on('error', reject);
  });
}

function parseBody(raw, req) {
  const type = String(req.headers['content-type'] || '');
  if (type.includes('application/x-www-form-urlencoded')) return Object.fromEntries(new URLSearchParams(raw || ''));
  try { return JSON.parse(raw || '{}'); } catch { throw new VibeGuardError(ERROR_CODES.SCHEMA_INVALID, 'invalid JSON body'); }
}

function cookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    out[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return out;
}

function cookie(name, value, maxAge, secure, httpOnly) {
  return `${name}=${value}; Path=/; Max-Age=${maxAge}; SameSite=Strict${httpOnly ? '; HttpOnly' : ''}${secure ? '; Secure' : ''}`;
}

function escapeHtml(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function actionSummary(action) {
  const a = action || {};
  return `${a.server || '?'}/${a.tool || '?'} ${a.capability || ''}`.trim();
}

function truncateJson(value, max = 500) {
  try {
    const text = JSON.stringify(value);
    return text.length > max ? text.slice(0, max) + '…' : text;
  } catch { return '[unserializable]'; }
}

function loginPage(error) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>VibeGuard approval login</title><style>
body{background:#070b12;color:#d6f6ff;font-family:monospace;padding:2rem}main{max-width:34rem;margin:auto}
input,button{font:inherit;padding:.5rem;margin:.25rem 0;width:100%;box-sizing:border-box}
input{background:#0d1a24;color:#d6f6ff;border:1px solid #174455}button{background:#0e5c73;color:#fff;border:0;cursor:pointer}
.err{color:#ff8080}label{display:block;margin-top:.75rem}.hint{color:#8bb7c7;font-size:.85rem}
</style></head><body><main><h1>VibeGuard approvals</h1><p class="hint">Authenticated human access only. Sessions are HttpOnly, SameSite=Strict and expire after 15 minutes.</p>
${error ? `<p class="err">${escapeHtml(error)}</p>` : ''}
<form method="post" action="/auth/login">
<label>Human principal <input name="principal" autocomplete="username" required placeholder="human:acme/alice@example.com"></label>
<label>Password <input type="password" name="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button>
</form></main></body></html>`;
}

function dashboard(broker, session, message) {
  const tickets = [...broker.tickets.values()].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  const pending = tickets.filter((t) => t.status === 'pending');
  const decided = tickets.filter((t) => t.status !== 'pending').slice(0, 100);
  const csrf = escapeHtml(session.csrf);
  const rows = (items, allowActions) => items.map((t) => {
    const approvals = (t.approvals || []).map((a) => `${escapeHtml(a.approver)} (${escapeHtml(a.decision)})`).join('<br>') || '—';
    const action = allowActions
      ? `<form method="post" action="/approval/decision">
<input type="hidden" name="_csrf" value="${csrf}">
<input type="hidden" name="ticketId" value="${escapeHtml(t.ticketId)}">
<textarea name="reason" rows="2" placeholder="decision reason (required for deny)" maxlength="500"></textarea>
<button name="decision" value="approve">Approve</button>
<button name="decision" value="deny">Deny</button>
</form>`
      : '';
    return `<tr><td>${escapeHtml(t.ticketId)}</td><td>${escapeHtml(t.principal)}</td><td>${escapeHtml(actionSummary(t.action))}<br><span class="hint">${escapeHtml(t.actionDigest).slice(0, 24)}…</span><details><summary>action</summary><pre>${escapeHtml(truncateJson(t.action, 2000))}</pre></details></td><td>${escapeHtml(t.status)}<br><span class="hint">${(t.approvals || []).length}/${t.requiredApprovals || 1}</span></td><td>${escapeHtml(t.reason || '')}</td><td>${approvals}</td><td>${action}</td></tr>`;
  }).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>VibeGuard approvals</title><style>
body{background:#070b12;color:#d6f6ff;font-family:monospace;padding:2rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #174455;padding:.5rem;text-align:left;vertical-align:top}
button{font:inherit;padding:.35rem .6rem;margin:.15rem;background:#0e5c73;color:#fff;border:0;cursor:pointer}textarea{width:100%;background:#0d1a24;color:#d6f6ff;border:1px solid #174455}
.hint{color:#8bb7c7;font-size:.85rem}.ok{color:#7dffb0}.err{color:#ff8080}form.logout{float:right}
</style></head><body><form class="logout" method="post" action="/auth/logout"><input type="hidden" name="_csrf" value="${csrf}"><button type="submit">Sign out</button></form>
<h1>VibeGuard approvals</h1><p class="hint">Signed in as ${escapeHtml(session.principal)}. Every decision is bound to the action digest and written to the signed audit log.</p>
${message ? `<p class="ok">${escapeHtml(message)}</p>` : ''}
<h2>Pending (${pending.length})</h2><table><tr><th>Ticket</th><th>Agent</th><th>Action</th><th>Status</th><th>Request reason</th><th>Approvals</th><th>Decision</th></tr>${rows(pending, true) || '<tr><td colspan="7">No pending tickets.</td></tr>'}</table>
<h2>Recent decisions</h2><table><tr><th>Ticket</th><th>Agent</th><th>Action</th><th>Status</th><th>Request reason</th><th>Approvals</th><th></th></tr>${rows(decided, false) || '<tr><td colspan="7">No decisions yet.</td></tr>'}</table>
</body></html>`;
}

function createApprovalService(opts = {}) {
  if (!opts.broker) throw new Error('approval service requires a broker');
  if (!opts.authority) throw new Error('approval service requires an identity authority');
  const broker = opts.broker;
  const authority = opts.authority;
  const host = opts.host || '127.0.0.1';
  if (host !== '127.0.0.1' && host !== '::1' && host !== 'localhost' && opts.allowRemote !== true) {
    throw new Error('approval service is loopback-only by default; set allowRemote=true only behind TLS/auth');
  }
  const store = new JsonApprovalStore(opts.storeFile);
  if (store.data.tickets && store.data.tickets.length) broker.importState(store.data);
  for (const [principal, key] of Object.entries(store.data.approverKeys || {})) broker.rotateApproverKey(principal, key);

  let humanUsers = opts.humanUsers || {};
  if (opts.usersFile) {
    try { humanUsers = JSON.parse(fs.readFileSync(opts.usersFile, 'utf8')); } catch { throw new Error('cannot read approval users file'); }
  }
  if (!humanUsers || typeof humanUsers !== 'object' || Array.isArray(humanUsers)) throw new Error('humanUsers must be an object');
  const signingKeys = new Map();
  for (const [principal, key] of Object.entries(opts.approverSigningKeys || {})) {
    if (!String(principal).startsWith('human:')) throw new Error('approverSigningKeys principals must be human');
    try {
      const privateKey = require('./identity').loadPrivateKey(key);
      signingKeys.set(principal, privateKey);
      if (!broker.approverKeys.has(principal)) broker.approverKeys.set(principal, crypto.createPublicKey(privateKey));
    } catch { throw new Error(`invalid approver signing key for ${principal}`); }
  }

  const auditFile = opts.auditFile || (opts.storeFile ? path.join(path.dirname(path.resolve(opts.storeFile)), 'approval-audit.jsonl') : null);
  let audit = opts.audit || null;
  if (!audit && auditFile) {
    const keyFile = opts.auditKeyFile || `${auditFile}.key.pem`;
    let privateKey = opts.auditPrivateKey ? loadPrivateKey(opts.auditPrivateKey) : null;
    if (!privateKey && fs.existsSync(keyFile)) {
      try {
        if (fs.lstatSync(keyFile).isSymbolicLink()) throw new Error('symlink');
        privateKey = loadPrivateKey(fs.readFileSync(keyFile));
      } catch { throw new Error('approval audit key file is unsafe or invalid'); }
    }
    if (!privateKey) {
      privateKey = generateKeyPair().privateKey;
      fs.mkdirSync(path.dirname(keyFile), { recursive: true, mode: 0o700 });
      fs.writeFileSync(keyFile, privateKeyToPem(privateKey), { mode: 0o600 });
    }
    audit = new SignedAuditLog({ file: auditFile, tenant: broker.tenant, privateKey });
  }
  const requireAudit = opts.requireAudit !== false && Boolean(audit);
  const auditEvent = (type, detail, meta) => {
    if (!audit) return;
    try {
      audit.append(type, detail, meta || {});
      metrics.inc('vibeguard_approval_audit_events_total', { type });
    } catch (err) {
      if (requireAudit) throw new VibeGuardError(ERROR_CODES.AUDIT_UNAVAILABLE, 'approval audit sink unavailable', { status: 503 });
      throw err;
    }
  };

  const sessions = new Map();
  const attempts = new Map();
  const sessionTtl = Math.max(60, Number(opts.sessionTtlSeconds || SESSION_TTL_SECONDS));
  const maxSessions = Math.max(10, Number(opts.maxSessions || 1000));
  const secureCookies = opts.secureCookies === true;
  const requiredDecisionCapability = opts.requiredDecisionCapability || 'approval.decide';
  const requiredRequestCapability = opts.requiredRequestCapability || 'approval.request';
  const requiredReadCapability = opts.requiredReadCapability || 'approval.read';
  const requiredAdminCapability = opts.requiredAdminCapability || 'approval.admin';
  let serviceVersion = opts.version || null;
  if (!serviceVersion) { try { serviceVersion = require('../../package.json').version; } catch { /* optional */ } }
  const metrics = opts.metrics || new MetricsRegistry({ service: 'vibeguard-approval', version: serviceVersion });
  const log = opts.logger || ((level, event, fields = {}) => {
    process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), level, event, ...fields }) + '\n');
  });
  let ready = false;
  let closing = false;
  const readyChecks = () => {
    if (closing || !ready) return { ready: false, reason: closing ? 'shutting_down' : 'starting' };
    for (const dir of [store.file ? path.dirname(store.file) : null, auditFile ? path.dirname(auditFile) : null]) {
      if (!dir) continue;
      try { fs.accessSync(dir, fs.constants.W_OK); } catch { return { ready: false, reason: 'state_not_writable' }; }
    }
    return { ready: true };
  };
  const maxPendingPerPrincipal = Math.max(1, Number(opts.maxPendingPerPrincipal || 25));

  function pruneSessions() {
    const now = Date.now();
    for (const [id, session] of sessions) if (session.expiresAt <= now) sessions.delete(id);
    while (sessions.size >= maxSessions) sessions.delete(sessions.keys().next().value);
  }

  function createSession(principal) {
    pruneSessions();
    const id = b64(crypto.randomBytes(32));
    const csrf = b64(crypto.randomBytes(24));
    const session = { id, principal, csrf, createdAt: Date.now(), expiresAt: Date.now() + sessionTtl * 1000 };
    sessions.set(id, session);
    return session;
  }

  function sessionFor(req) {
    const id = cookies(req)[COOKIE_SESSION];
    if (!id) throw new VibeGuardError(ERROR_CODES.AUTH_REQUIRED, 'login required', { status: 401 });
    const session = sessions.get(id);
    if (!session || session.expiresAt <= Date.now()) {
      sessions.delete(id);
      throw new VibeGuardError(ERROR_CODES.AUTH_REQUIRED, 'session expired', { status: 401 });
    }
    session.expiresAt = Date.now() + sessionTtl * 1000;
    return session;
  }

  function csrfOk(session, req, body) {
    const value = String(req.headers['x-csrf-token'] || (body && body._csrf) || '');
    return Boolean(value) && safeEqual(value, session.csrf);
  }

  function bearer(req) {
    const header = String(req.headers.authorization || '');
    return header.startsWith('Bearer ') ? header.slice(7) : '';
  }

  function principalFromBearer(req, capability) {
    const token = bearer(req);
    if (!token) throw new VibeGuardError(ERROR_CODES.AUTH_REQUIRED, 'bearer token required', { status: 401 });
    const verified = authority.verify(token, { requiredCapabilities: capability ? [capability] : [] });
    return verified.principal;
  }

  function requireDecisionCapability(principal) {
    if (!Array.isArray(principal.capabilities) || !principal.capabilities.includes(requiredDecisionCapability)) {
      throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, `human token lacks ${requiredDecisionCapability}`, { status: 403 });
    }
  }

  function requireRequestCapability(principal) {
    if (!Array.isArray(principal.capabilities) || !principal.capabilities.includes(requiredRequestCapability)) {
      throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, `agent token lacks ${requiredRequestCapability}`, { status: 403 });
    }
  }

  function loginAllowed(ip) {
    const now = Date.now();
    const list = (attempts.get(ip) || []).filter((t) => now - t < 60000);
    attempts.set(ip, list);
    return list.length < 5;
  }

  function loginFailed(ip) {
    const now = Date.now();
    const list = (attempts.get(ip) || []).filter((t) => now - t < 60000);
    list.push(now);
    attempts.set(ip, list);
  }

  const server = http.createServer(async (req, res) => {
    const ip = (req.socket && req.socket.remoteAddress) || 'unknown';
    const requestId = String(req.headers['x-request-id'] || crypto.randomBytes(12).toString('hex')).slice(0, 128);
    const started = process.hrtime.bigint();
    let route = 'unknown';
    res.setHeader('x-request-id', requestId);
    res.once('finish', () => {
      const seconds = Number(process.hrtime.bigint() - started) / 1e9;
      metrics.inc('vibeguard_http_requests_total', { method: req.method, route, status: String(res.statusCode) });
      metrics.observe('vibeguard_http_request_duration_seconds', seconds, { method: req.method, route });
      if (route !== '/metrics') log('info', 'http_request', { request_id: requestId, method: req.method, route, status: res.statusCode, duration_ms: Math.round(seconds * 1000), ip });
    });
    try {
      const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
      route = url.pathname.startsWith('/approval/ticket/') ? '/approval/ticket/:id' : url.pathname;
      if (req.method === 'GET' && url.pathname === '/health') return json(res, 200, { status: 'ok', service: 'vibeguard-approval' });
      if (req.method === 'GET' && url.pathname === '/ready') {
        const state = readyChecks();
        return json(res, state.ready ? 200 : 503, { status: state.ready ? 'ready' : 'not_ready', ...state });
      }
      if (req.method === 'GET' && url.pathname === '/metrics') {
        if (opts.metricsToken) {
          const token = bearer(req);
          if (!token || !safeEqual(token, String(opts.metricsToken))) return json(res, 401, { error: 'metrics token required' });
        }
        metrics.set('vibeguard_approval_pending_tickets', [...broker.tickets.values()].filter((t) => t.status === 'pending').length);
        metrics.set('vibeguard_approval_active_sessions', sessions.size);
        metrics.set('vibeguard_approval_ready', readyChecks().ready ? 1 : 0);
        res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4; charset=utf-8', 'cache-control': 'no-store' });
        return res.end(metrics.render());
      }
      if (req.method === 'GET' && url.pathname === '/auth/login') return html(res, 200, loginPage());

      if (req.method === 'POST' && url.pathname === '/auth/login') {
        if (!loginAllowed(ip)) return json(res, 429, { error: 'too many login attempts' }, { 'retry-after': '60' });
        const body = parseBody(await readBody(req), req);
        const principal = String(body.principal || '');
        const user = humanUsers[principal];
        const tenant = String(principal).split(':')[1] ? String(principal).split(':')[1].split('/')[0] : '';
        const passwordOk = verifyPassword(body.password, user ? user.passwordHash : DUMMY_PASSWORD_HASH);
        const valid = Boolean(user) && tenant === broker.tenant && passwordOk;
        if (!String(principal).startsWith('human:') || !valid) {
          loginFailed(ip);
          metrics.inc('vibeguard_approval_logins_total', { result: 'failure' });
          auditEvent('approval.login_failed', { principal, ip }, { principal, decision: 'deny' });
          if (String(req.headers.accept || '').includes('text/html') || String(req.headers['content-type'] || '').includes('application/x-www-form-urlencoded')) {
            return html(res, 401, loginPage('Invalid principal or password.'));
          }
          return json(res, 401, { error: 'invalid principal or password' });
        }
        if (String(user.disabled) === 'true') {
          loginFailed(ip);
          auditEvent('approval.login_failed', { principal, ip, reason: 'disabled' }, { principal, decision: 'deny' });
          return json(res, 403, { error: 'account disabled' });
        }
        const session = createSession(principal);
        metrics.inc('vibeguard_approval_logins_total', { result: 'success' });
        auditEvent('approval.login', { principal, ip }, { principal, decision: 'allow' });
        const headers = { 'set-cookie': [
          cookie(COOKIE_SESSION, session.id, sessionTtl, secureCookies, true),
          cookie(COOKIE_CSRF, session.csrf, sessionTtl, secureCookies, false),
        ] };
        if (String(req.headers.accept || '').includes('text/html') || String(req.headers['content-type'] || '').includes('application/x-www-form-urlencoded')) {
          return html(res, 303, '', { ...headers, location: '/approval' });
        }
        return json(res, 200, { ok: true, principal, csrfToken: session.csrf, expiresAt: new Date(session.expiresAt).toISOString() }, headers);
      }

      if (req.method === 'POST' && url.pathname === '/auth/logout') {
        const session = sessionFor(req);
        const body = parseBody(await readBody(req), req);
        if (!csrfOk(session, req, body)) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'invalid CSRF token', { status: 403 });
        sessions.delete(session.id);
        auditEvent('approval.logout', { principal: session.principal }, { principal: session.principal });
        return html(res, 303, '', { location: '/auth/login', 'set-cookie': [cookie(COOKIE_SESSION, '', 0, secureCookies, true), cookie(COOKIE_CSRF, '', 0, secureCookies, false)] });
      }

      if (req.method === 'GET' && url.pathname === '/approval') {
        const session = sessionFor(req);
        const message = url.searchParams.get('ok') ? 'Decision recorded.' : '';
        return html(res, 200, dashboard(broker, session, message));
      }

      if (req.method === 'POST' && url.pathname === '/approval/request') {
        const principal = principalFromBearer(req, requiredRequestCapability);
        if (!String(principal.principalId).startsWith('agent:')) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'agent token required', { status: 403 });
        requireRequestCapability(principal);
        const body = parseBody(await readBody(req), req);
        if (!body.action) throw new VibeGuardError(ERROR_CODES.SCHEMA_INVALID, 'action is required');
        const pending = [...broker.tickets.values()].filter((t) => t.status === 'pending' && t.principal === principal.principalId).length;
        if (pending >= maxPendingPerPrincipal) throw new VibeGuardError(ERROR_CODES.LIMIT_EXCEEDED, 'too many pending approval tickets for this agent', { status: 429 });
        const requiredApprovals = opts.allowClientQuorum === true ? body.requiredApprovals : (opts.requiredApprovals || 1);
        const t = broker.request({ principal: principal.principalId, action: body.action, reason: body.reason, ttlSeconds: body.ttlSeconds, requiredApprovals });
        metrics.inc('vibeguard_approval_requests_total');
        store.save(broker);
        auditEvent('approval.requested', {
          ticketId: t.ticket.ticketId, actionDigest: t.ticket.actionDigest,
          tool: body.action.tool, server: body.action.server, requiredApprovals: t.ticket.requiredApprovals,
        }, { principal: principal.principalId });
        return json(res, 200, { ...t, approvalUrl: '/approval' });
      }

      if (req.method === 'POST' && url.pathname === '/approval/decision') {
        const body = parseBody(await readBody(req), req);
        const bearerToken = bearer(req);
        let approver;
        let proof = body.proof;
        let session = null;
        if (bearerToken) {
          const principal = principalFromBearer(req, requiredDecisionCapability);
          if (!String(principal.principalId).startsWith('human:')) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'human approver token required', { status: 403 });
          requireDecisionCapability(principal);
          approver = principal.principalId;
        } else {
          session = sessionFor(req);
          if (!csrfOk(session, req, body)) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'invalid CSRF token', { status: 403 });
          approver = session.principal;
          const signingKey = signingKeys.get(approver);
          if (!signingKey) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'no approver signing key configured for this human', { status: 403 });
          const ticket = broker.tickets.get(String(body.ticketId || ''));
          if (!ticket) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval ticket not found', { status: 404 });
          proof = ApprovalBroker.signApproverProof({
            ticketId: ticket.ticketId,
            actionDigest: ticket.actionDigest,
            nonce: ticket.nonce,
            approver,
            privateKey: signingKey,
          });
        }
        const approve = body.decision === 'approve' || body.approve === true;
        const deniedByForm = body.decision === 'deny';
        if (!approve && !deniedByForm && body.approve !== false) throw new VibeGuardError(ERROR_CODES.SCHEMA_INVALID, 'decision must be approve or deny');
        const d = broker.decide(body.ticketId, { approver, approve, proof, reason: body.reason });
        metrics.inc('vibeguard_approval_decisions_total', { decision: d.status });
        store.save(broker);
        const event = d.status === 'approved' ? 'approval.approved' : (d.status === 'denied' ? 'approval.denied' : 'approval.pending');
        auditEvent(event, {
          ticketId: d.ticket.ticketId, actionDigest: d.ticket.actionDigest,
          status: d.status, remaining: d.remaining || 0, reason: String(body.reason || '').slice(0, 500),
        }, { principal: approver, decision: d.status === 'approved' ? 'allow' : (d.status === 'denied' ? 'deny' : 'approval_required') });
        if (!bearerToken) {
          const target = `/approval?ok=${encodeURIComponent(d.ticket.ticketId)}`;
          if (String(req.headers.accept || '').includes('text/html') || String(req.headers['content-type'] || '').includes('application/x-www-form-urlencoded')) {
            return html(res, 303, '', { location: target });
          }
        }
        return json(res, 200, d);
      }

      if (req.method === 'GET' && url.pathname.startsWith('/approval/ticket/')) {
        const ticketId = decodeURIComponent(url.pathname.slice('/approval/ticket/'.length));
        const ticket = broker.tickets.get(ticketId);
        if (!ticket) return json(res, 404, { error: 'not found' });
        let principalId = null;
        let via = null;
        if (bearer(req)) {
          const principal = principalFromBearer(req, requiredReadCapability);
          principalId = principal.principalId;
          via = String(principalId).startsWith('agent:') ? 'agent' : 'human';
          if (via === 'agent' && ticket.principal !== principalId) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'ticket belongs to another agent', { status: 403 });
        } else {
          const session = sessionFor(req);
          principalId = session.principal;
          via = 'session';
        }
        const body = { ticket: publicTicketForService(ticket) };
        if (via === 'agent' && ticket.status === 'approved' && ticket.approvalToken) body.approvalToken = ticket.approvalToken;
        return json(res, 200, body);
      }

      if (req.method === 'GET' && url.pathname === '/approval/tickets') {
        const principal = principalFromBearer(req, requiredReadCapability);
        const isAgent = String(principal.principalId).startsWith('agent:');
        const list = [...broker.tickets.values()]
          .filter((t) => !isAgent || t.principal === principal.principalId)
          .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
          .slice(0, 100)
          .map((t) => publicTicketForService(t));
        return json(res, 200, { tickets: list });
      }

      if (req.method === 'POST' && url.pathname === '/approval/keys') {
        const principal = principalFromBearer(req, requiredAdminCapability);
        if (!opts.adminPrincipals || !opts.adminPrincipals.includes(principal.principalId)) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'admin principal required', { status: 403 });
        const body = parseBody(await readBody(req), req);
        if (!body.principal || !body.publicKey) throw new VibeGuardError(ERROR_CODES.SCHEMA_INVALID, 'principal and publicKey are required');
        const r = broker.rotateApproverKey(body.principal, body.publicKey);
        store.data.approverKeys = store.data.approverKeys || {};
        store.data.approverKeys[body.principal] = body.publicKey;
        store.save(broker);
        auditEvent('approval.key_rotated', { targetPrincipal: body.principal }, { principal: principal.principalId });
        return json(res, 200, r);
      }

      return json(res, 404, { error: 'not found' });
    } catch (err) {
      return json(res, err.status || 400, { error: err.message, code: err.code || 'VG_APPROVAL_INVALID' });
    }
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(Number(opts.port || 0), host, () => {
      const addr = server.address();
      ready = true;
      try { auditEvent('service.start', { host: addr.address, port: addr.port }, { principal: 'service:vibeguard/approval' }); } catch (err) { ready = false; server.close(); reject(err); return; }
      resolve({
        server,
        host: addr.address,
        port: addr.port,
        url: `http://${addr.address}:${addr.port}`,
        broker,
        store,
        audit,
        sessions,
        metrics,
        ready: () => readyChecks(),
        close: () => new Promise((r) => {
          if (closing) return r();
          closing = true;
          ready = false;
          try { auditEvent('service.stop', { reason: 'shutdown' }, { principal: 'service:vibeguard/approval' }); } catch { /* audit failure must not prevent shutdown */ }
          try { if (typeof server.closeIdleConnections === 'function') server.closeIdleConnections(); } catch { /* ignore */ }
          const timer = setTimeout(() => {
            try { if (typeof server.closeAllConnections === 'function') server.closeAllConnections(); } catch { /* ignore */ }
          }, Number(opts.shutdownTimeoutMs || 10000));
          if (timer.unref) timer.unref();
          server.close(() => { clearTimeout(timer); r(); });
        }),
      });
    });
  });
}

function publicTicketForService(t) {
  return {
    ticketId: t.ticketId,
    principal: t.principal,
    action: t.action,
    actionDigest: t.actionDigest,
    nonce: t.nonce,
    reason: t.reason,
    requiredApprovals: t.requiredApprovals || 1,
    approvals: (t.approvals || []).map((a) => ({ approver: a.approver, decision: a.decision, at: a.at })),
    createdAt: t.createdAt,
    expiresAt: t.expiresAt,
    status: t.status,
    approver: t.approver,
    decisionReason: t.decisionReason || '',
    used: !!t.usedAt,
  };
}

module.exports = { createApprovalService, JsonApprovalStore, hashPassword, verifyPassword };
