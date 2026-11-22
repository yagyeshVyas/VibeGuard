'use strict';

/*
 * src/platform/approval-service.js — hosted approval API + read-only dashboard.
 *
 * Agents request approval with a VGAT token. Human approvers authenticate with a
 * human VGAT token AND a signed VGApprover proof; the broker issues a single-use
 * VGApproval token. Tickets are persisted atomically to a JSON store and the
 * service supports approver key rotation.
 *
 * This is a local/loopback service slice, not a full IAM/SSO product.
 */

const fs = require('fs');
const path = require('path');
const http = require('http');
const { ApprovalBroker } = require('./approval');
const { ERROR_CODES, VibeGuardError } = require('./contracts');

class JsonApprovalStore {
  constructor(file) {
    this.file = file ? path.resolve(file) : null;
    this.data = { tickets: [], usedTokens: [] };
    if (this.file && fs.existsSync(this.file)) {
      try { this.data = JSON.parse(fs.readFileSync(this.file, 'utf8')); } catch { throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval store is corrupt'); }
    }
  }
  save(broker) {
    const approverKeys = this.data.approverKeys || {};
    this.data = { ...broker.exportState(), approverKeys };
    if (!this.file) return;
    fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }
}

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let s = '';
    req.on('data', (c) => { s += c; if (s.length > 64 * 1024) { reject(new VibeGuardError(ERROR_CODES.LIMIT_EXCEEDED, 'request too large')); req.destroy(); } });
    req.on('end', () => resolve(s));
    req.on('error', reject);
  });
}

function authenticate(req, authority) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) throw new VibeGuardError(ERROR_CODES.AUTH_REQUIRED, 'bearer token required', { status: 401 });
  return authority.verify(token).principal;
}

function dashboard(broker) {
  const rows = [...broker.tickets.values()].map((t) => `<tr><td>${escapeHtml(t.ticketId)}</td><td>${escapeHtml(t.principal)}</td><td>${escapeHtml(t.action && t.action.tool)}</td><td>${escapeHtml(t.status)}</td><td>${escapeHtml(t.approver || '')}</td></tr>`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>VibeGuard approvals</title><style>body{background:#070b12;color:#d6f6ff;font-family:monospace;padding:2rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #174455;padding:.5rem;text-align:left}</style></head><body><h1>VibeGuard approvals</h1><p>Read-only dashboard. Decisions require an authenticated human token and a signed approver proof via POST /approval/decision.</p><table><tr><th>Ticket</th><th>Agent</th><th>Tool</th><th>Status</th><th>Approver</th></tr>${rows}</table></body></html>`;
}

function escapeHtml(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

function createApprovalService(opts = {}) {
  if (!opts.broker) throw new Error('approval service requires a broker');
  if (!opts.authority) throw new Error('approval service requires an identity authority');
  const broker = opts.broker;
  const store = new JsonApprovalStore(opts.storeFile);
  if (store.data.tickets && store.data.tickets.length) broker.importState(store.data);
  for (const [principal, key] of Object.entries(store.data.approverKeys || {})) broker.rotateApproverKey(principal, key);
  const server = http.createServer(async (req, res) => {
    try {
      if (req.method === 'GET' && req.url === '/health') return json(res, 200, { status: 'ok', service: 'vibeguard-approval' });
      if (req.method === 'GET' && req.url === '/approval') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        return res.end(dashboard(broker));
      }
      if (req.method === 'POST' && req.url === '/approval/request') {
        const principal = authenticate(req, opts.authority);
        if (!String(principal.principalId).startsWith('agent:')) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'agent token required', { status: 403 });
        const body = JSON.parse(await readBody(req) || '{}');
        if (!body.action) throw new VibeGuardError(ERROR_CODES.SCHEMA_INVALID, 'action is required');
        const t = broker.request({ principal: principal.principalId, action: body.action, reason: body.reason, ttlSeconds: body.ttlSeconds });
        store.save(broker);
        return json(res, 200, t);
      }
      if (req.method === 'POST' && req.url === '/approval/decision') {
        const principal = authenticate(req, opts.authority);
        if (!String(principal.principalId).startsWith('human:')) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'human approver token required', { status: 403 });
        const body = JSON.parse(await readBody(req) || '{}');
        const d = broker.decide(body.ticketId, { approver: principal.principalId, approve: body.approve === true, proof: body.proof });
        store.save(broker);
        return json(res, 200, d);
      }
      if (req.method === 'POST' && req.url === '/approval/keys') {
        const principal = authenticate(req, opts.authority);
        if (!opts.adminPrincipals || !opts.adminPrincipals.includes(principal.principalId)) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'admin principal required', { status: 403 });
        const body = JSON.parse(await readBody(req) || '{}');
        if (!body.principal || !body.publicKey) throw new VibeGuardError(ERROR_CODES.SCHEMA_INVALID, 'principal and publicKey are required');
        const r = broker.rotateApproverKey(body.principal, body.publicKey);
        store.data.approverKeys = store.data.approverKeys || {};
        store.data.approverKeys[body.principal] = body.publicKey;
        store.save(broker);
        return json(res, 200, r);
      }
      return json(res, 404, { error: 'not found' });
    } catch (err) {
      return json(res, err.status || 400, { error: err.message, code: err.code || 'VG_APPROVAL_INVALID' });
    }
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(Number(opts.port || 0), opts.host || '127.0.0.1', () => {
      const addr = server.address();
      resolve({ server, host: addr.address, port: addr.port, url: `http://${addr.address}:${addr.port}`, broker, store, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

module.exports = { createApprovalService, JsonApprovalStore };
