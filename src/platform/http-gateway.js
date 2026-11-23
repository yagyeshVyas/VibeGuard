'use strict';

/*
 * src/platform/http-gateway.js — minimal authenticated Streamable HTTP MCP
 * gateway. Accepts JSON-RPC POST bodies, authenticates VGAT or JWT, evaluates
 * policy for tools/call, and delegates allowed messages to an injected handler.
 *
 * This is the first HTTP slice; full SSE/streamable event framing is a later
 * adapter. It is deliberately loopback-first, size-limited and fail-closed.
 */

const http = require('http');
const https = require('https');
const { ERROR_CODES, VibeGuardError } = require('./contracts');

const MAX_BODY = 1024 * 1024;

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new VibeGuardError(ERROR_CODES.LIMIT_EXCEEDED, 'request body exceeds 1 MiB', { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) });
  res.end(payload);
}

function authError(res, err) {
  return json(res, err.status || 401, { jsonrpc: '2.0', error: { code: -32001, message: err.message }, id: null });
}

function createHttpGateway(opts = {}) {
  const host = opts.host || '127.0.0.1';
  const port = Number(opts.port || 0);
  const authority = opts.authority;
  const jwt = opts.jwt; // { jwks, issuer, audience, scopes }
  const policy = opts.policy;
  const handler = opts.handler;
  let approvalVerifier = opts.approvalVerifier || null;
  if (!approvalVerifier && opts.approvalPublicKey) {
    const { ApprovalBroker } = require('./approval');
    approvalVerifier = new ApprovalBroker({
      issuer: opts.approvalIssuer || 'human:local/approval',
      tenant: opts.approvalTenant || 'local',
      publicKey: opts.approvalPublicKey,
      keyId: opts.approvalKeyId,
      usedTokensFile: opts.approvalUsedTokensFile,
    });
  }
  if (typeof handler !== 'function') throw new Error('http gateway requires a message handler');
  if (!policy) throw new Error('http gateway requires an authorization policy; refusing an unprotected listener');
  if (typeof policy.evaluate !== 'function') throw new Error('http gateway policy must implement evaluate()');

  async function authenticate(req) {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    if (!token) throw new VibeGuardError(ERROR_CODES.AUTH_REQUIRED, 'bearer token required', { status: 401 });
    if (authority) {
      const verified = authority.verify(token, opts.verifyOpts || {});
      return verified.principal;
    }
    if (jwt) {
      const { verifyJwt } = require('./jwt');
      const verified = verifyJwt(token, jwt);
      return { principalId: verified.claims.sub, claims: verified.claims };
    }
    throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'no authenticator configured', { status: 500 });
  }

  const server = opts.tls
    ? https.createServer(opts.tls, async (req, res) => { gatewayHandler(req, res); })
    : http.createServer(async (req, res) => { gatewayHandler(req, res); });

  function approvalToken(req, params) {
    return String(req.headers['x-vibeguard-approval'] || (params && params.approvalToken) || '');
  }

  function verifyApproval(req, params, decision) {
    const token = approvalToken(req, params);
    if (!token) return null;
    if (!approvalVerifier) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval verifier is not configured', { status: 500 });
    try {
      const approval = approvalVerifier.verifyStandalone(token, decision.actionDigest);
      if (opts.audit && typeof opts.audit.append === 'function') {
        try {
          opts.audit.append('approval.consumed', { ticketId: approval.ticketId, actionDigest: approval.actionDigest, approvers: approval.approvers }, { principal: approval.approver, decision: 'allow' });
        } catch {
          throw new VibeGuardError(ERROR_CODES.AUDIT_UNAVAILABLE, 'approval audit sink unavailable', { status: 503 });
        }
      }
      if (typeof opts.onApproval === 'function') opts.onApproval(approval, decision);
      return approval;
    } catch (err) {
      if (err instanceof VibeGuardError) {
        throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, err.message, { status: err.code === ERROR_CODES.REPLAY_DETECTED ? 401 : 403, details: { cause: err.code } });
      }
      throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval verification failed', { status: 403 });
    }
  }

  async function gatewayHandler(req, res) {
    try {
      if (req.method === 'GET' && req.url === '/health') {
        return json(res, 200, { status: 'ok', gateway: 'vibeguard', version: 1 });
      }
      if (req.method === 'GET' && req.url === '/mcp' && typeof opts.onStream === 'function') {
        const principal = await authenticate(req);
        return opts.onStream(req, res, principal);
      }
      if (req.method !== 'POST' || req.url !== '/mcp') {
        return json(res, 404, { error: 'not found' });
      }
      const principal = await authenticate(req);
      let message;
      try { message = JSON.parse(await readBody(req)); } catch {
        return json(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'invalid JSON' } });
      }
      if (Array.isArray(message)) {
        return json(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'batch messages are not supported by this gateway version' } });
      }
      if (message.method === 'tools/call' && policy) {
        const params = message.params || {};
        const decision = policy.evaluate({
          principal: principal.principalId,
          server: params.server || opts.server || 'http',
          tool: params.name,
          capability: params.capability || 'mcp.tool.invoke',
          arguments: params.arguments || {},
          sessionId: params.sessionId,
        });
        if (decision.decision === 'deny' || decision.decision === 'quarantine') {
          return json(res, 403, {
            jsonrpc: '2.0',
            id: message.id,
            error: { code: -32003, message: decision.reasonCode || 'authorization denied', data: { decision } },
          });
        }
        if (decision.decision === 'approval_required') {
          const approval = verifyApproval(req, params, decision);
          if (!approval) {
            return json(res, 202, {
              jsonrpc: '2.0',
              id: message.id,
              result: { approvalRequired: true, actionDigest: decision.actionDigest, reason: decision.reasonCode, approvalHeader: 'x-vibeguard-approval' },
            });
          }
        }
      }
      if (policy && message.method !== 'tools/call' && message.method !== 'initialize' && message.method !== 'ping') {
        const caps = {
          'resources/read': 'mcp.resource.read',
          'prompts/get': 'mcp.prompt.get',
        };
        const capability = caps[message.method] || (message.method === 'tools/list' ? null : 'mcp.protocol.unknown');
        if (capability) {
          const params = message.params || {};
          const decision = policy.evaluate({
            principal: principal.principalId,
            server: params.server || opts.server || 'http',
            tool: params.name || message.method,
            capability,
            arguments: params.arguments || {},
            sessionId: params.sessionId,
          });
          if (decision.decision === 'deny' || decision.decision === 'quarantine') {
            return json(res, 403, {
              jsonrpc: '2.0',
              id: message.id,
              error: { code: -32003, message: decision.reasonCode || 'authorization denied', data: { decision } },
            });
          }
          if (decision.decision === 'approval_required') {
            const approval = verifyApproval(req, params, decision);
            if (!approval) {
              return json(res, 202, { jsonrpc: '2.0', id: message.id, result: { approvalRequired: true, actionDigest: decision.actionDigest, approvalHeader: 'x-vibeguard-approval' } });
            }
          }
        }
      }
      if (message && message.params && Object.prototype.hasOwnProperty.call(message.params, 'approvalToken')) {
        const { approvalToken: _ignored, ...rest } = message.params;
        message = { ...message, params: rest };
      }
      const result = await handler(message, principal, { req, res });
      if (result !== undefined) return json(res, 200, { jsonrpc: '2.0', id: message.id, result });
      if (!res.writableEnded) return json(res, 200, { jsonrpc: '2.0', id: message.id, result: null });
    } catch (err) {
      if (err instanceof VibeGuardError) {
        if (err.code === ERROR_CODES.AUTH_REQUIRED || err.code === ERROR_CODES.AUTH_INVALID || err.code === ERROR_CODES.REPLAY_DETECTED) {
          return authError(res, err);
        }
        return json(res, err.status || 400, { jsonrpc: '2.0', id: null, error: { code: -32000, message: err.message } });
      }
      return json(res, 500, { jsonrpc: '2.0', id: null, error: { code: -32603, message: 'internal error' } });
    }
  }

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      const addr = server.address();
      resolve({
        server,
        protocol: opts.tls ? 'https' : 'http',
        host: addr.address,
        port: addr.port,
        url: `${opts.tls ? 'https' : 'http'}://${addr.address}:${addr.port}`,
        close: () => new Promise((res2) => {
          try { if (typeof server.closeAllConnections === 'function') server.closeAllConnections(); } catch { /* ignore */ }
          server.close(res2);
        }),
      });
    });
  });
}

module.exports = { createHttpGateway, MAX_BODY };
