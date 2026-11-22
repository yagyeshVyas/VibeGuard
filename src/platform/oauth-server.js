'use strict';

/*
 * src/platform/oauth-server.js — local OAuth 2.1 authorization-code + PKCE
 * service for the MCP HTTP bridge. EdDSA access tokens, JWKS discovery, one-use
 * authorization codes and client secrets. It is a loopback/library service, not
 * an enterprise IdP.
 */

const crypto = require('crypto');
const http = require('http');
const { signJws } = require('./identity');
const { ERROR_CODES, VibeGuardError } = require('./contracts');

function b64url(buf) { return Buffer.from(buf).toString('base64url'); }
function s256(verifier) { return b64url(crypto.createHash('sha256').update(verifier).digest()); }
function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload), 'cache-control': 'no-store' });
  res.end(payload);
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let s = '';
    req.on('data', (c) => { s += c; if (s.length > 64 * 1024) { reject(new Error('too large')); req.destroy(); } });
    req.on('end', () => { try { resolve(JSON.parse(s || '{}')); } catch { reject(new Error('invalid JSON')); } });
    req.on('error', reject);
  });
}

function createOAuthServer(opts = {}) {
  if (!opts.privateKey || !opts.publicKey) throw new Error('oauth server requires privateKey and publicKey');
  const issuer = opts.issuer || 'https://vibeguard.local';
  const audience = opts.audience || 'vibeguard-gateway';
  const keyId = opts.keyId || 'oauth-key';
  const clients = new Map(Object.entries(opts.clients || {}));
  if (!clients.size) throw new Error('oauth server requires at least one client secret');
  const codes = new Map();
  const now = opts.now || (() => new Date());
  const codeTtl = opts.codeTtlSeconds || 60;
  const tokenTtl = opts.tokenTtlSeconds || 300;

  const server = http.createServer(async (req, res) => {
    try {
      const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
      if (req.method === 'GET' && u.pathname === '/.well-known/openid-configuration') {
        return json(res, 200, { issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks`, response_types_supported: ['code'], grant_types_supported: ['authorization_code'], code_challenge_methods_supported: ['S256'] });
      }
      if (req.method === 'GET' && u.pathname === '/jwks') {
        return json(res, 200, { keys: [require('./identity').publicKeyToJwk(opts.publicKey, keyId)] });
      }
      if (req.method === 'POST' && u.pathname === '/authorize') {
        const body = await readJson(req);
        const secret = req.headers['x-client-secret'];
        if (!body.client_id || clients.get(body.client_id) !== secret) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'invalid client credentials', { status: 401 });
        if (!body.redirect_uri || !body.code_challenge) throw new VibeGuardError(ERROR_CODES.SCHEMA_INVALID, 'redirect_uri and code_challenge are required');
        const code = crypto.randomBytes(24).toString('base64url');
        codes.set(code, { clientId: body.client_id, redirectUri: body.redirect_uri, challenge: body.code_challenge, scope: String(body.scope || ''), principal: String(body.principal || 'agent:oauth/user'), expiresAt: now().getTime() + codeTtl * 1000, used: false });
        return json(res, 200, { code, expires_in: codeTtl });
      }
      if (req.method === 'POST' && u.pathname === '/token') {
        const body = await readJson(req);
        if (body.grant_type !== 'authorization_code') throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'unsupported grant_type');
        const code = codes.get(body.code);
        if (!code || code.used || code.expiresAt <= now().getTime()) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'invalid or expired authorization code');
        if (clients.get(code.clientId) !== (req.headers['x-client-secret'] || body.client_secret)) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'invalid client credentials');
        if (code.redirectUri !== body.redirect_uri) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'redirect_uri mismatch');
        if (!body.code_verifier || s256(body.code_verifier) !== code.challenge) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'PKCE verification failed');
        code.used = true;
        const iat = Math.floor(now().getTime() / 1000);
        const payload = { iss: issuer, aud: audience, sub: code.principal, scope: code.scope, iat, exp: iat + tokenTtl, jti: crypto.randomBytes(12).toString('base64url') };
        const token = signJws({ alg: 'EdDSA', typ: 'at+jwt', kid: keyId }, payload, opts.privateKey);
        return json(res, 200, { access_token: token, token_type: 'Bearer', expires_in: tokenTtl, scope: code.scope });
      }
      return json(res, 404, { error: 'not found' });
    } catch (err) {
      return json(res, err.status || 400, { error: err.message, code: err.code || 'VG_AUTH_INVALID' });
    }
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(Number(opts.port || 0), opts.host || '127.0.0.1', () => {
      const addr = server.address();
      resolve({ server, url: `http://${addr.address}:${addr.port}`, issuer, audience, keyId, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

module.exports = { createOAuthServer };
