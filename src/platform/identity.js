'use strict';

/*
 * src/platform/identity.js — local identity and capability-token primitives.
 *
 * Tokens are JWS Compact Serialization with EdDSA (Ed25519). No external
 * dependency is used; Node's crypto implements Ed25519.
 *
 * VGAT claims:
 *   iss, sub (principal), aud, iat, nbf, exp, jti, tenant, kind,
 *   capabilities, policyVersion, scope (optional), delegation (optional).
 *
 * The gateway verifies issuer, audience, expiry, capability subset, replay
 * (jti) and (when configured) the caller's tenant. Tokens are short-lived and
 * audience-bound; they are not a substitute for human approval.
 */

const crypto = require('crypto');
const { CAPABILITIES, ERROR_CODES, VibeGuardError, assertPrincipal } = require('./contracts');

const B64 = (buf) => Buffer.from(buf).toString('base64url');
const UNB64 = (s) => Buffer.from(String(s), 'base64url');
const MAX_TTL_SECONDS = 15 * 60;
const DEFAULT_SKEW_SECONDS = 30;

function generateKeyPair() {
  return crypto.generateKeyPairSync('ed25519');
}

function publicKeyToPem(publicKey) {
  return publicKey.export({ type: 'spki', format: 'pem' });
}

function privateKeyToPem(privateKey) {
  return privateKey.export({ type: 'pkcs8', format: 'pem' });
}

function publicKeyToJwk(publicKey, kid) {
  const jwk = publicKey.export({ format: 'jwk' });
  return { ...jwk, kid, use: 'sig', alg: 'EdDSA' };
}

function loadPublicKey(value) {
  if (value && typeof value === 'object' && value.type === 'public') return value;
  return crypto.createPublicKey(value);
}

function loadPrivateKey(value) {
  if (value && typeof value === 'object' && value.type === 'private') return value;
  return crypto.createPrivateKey(value);
}

function signJws(header, payload, privateKey) {
  const h = B64(JSON.stringify(header));
  const p = B64(JSON.stringify(payload));
  const input = Buffer.from(`${h}.${p}`, 'utf8');
  const sig = crypto.sign(null, input, privateKey);
  return `${h}.${p}.${sig.toString('base64url')}`;
}

function decodeJws(token) {
  if (typeof token !== 'string') throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'token must be a string');
  const parts = token.split('.');
  if (parts.length !== 3) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'malformed token');
  // Reject non-canonical base64url. Without this check, changing unused padding
  // bits can preserve the decoded signature bytes while altering the token
  // string (JWS canonicalization/malleability).
  for (const part of parts) {
    let canonical;
    try { canonical = UNB64(part).toString('base64url'); } catch { canonical = null; }
    if (!canonical || canonical !== part) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'invalid non-canonical token encoding');
  }
  let header;
  let payload;
  try {
    header = JSON.parse(UNB64(parts[0]).toString('utf8'));
    payload = JSON.parse(UNB64(parts[1]).toString('utf8'));
  } catch {
    throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'malformed token JSON');
  }
  return { header, payload, input: `${parts[0]}.${parts[1]}`, signature: parts[2] };
}

function verifyJws(token, publicKey) {
  const decoded = decodeJws(token);
  const key = loadPublicKey(publicKey);
  const ok = crypto.verify(null, Buffer.from(decoded.input, 'utf8'), key, UNB64(decoded.signature));
  if (!ok) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'invalid token signature');
  return decoded;
}

class ReplayCache {
  constructor(clock) {
    this.clock = clock || (() => Date.now());
    this.seen = new Map();
    this.max = 10000;
  }

  prune() {
    const now = this.clock();
    for (const [jti, exp] of this.seen) {
      if (exp <= now) this.seen.delete(jti);
    }
    while (this.seen.size > this.max) {
      const first = this.seen.keys().next().value;
      this.seen.delete(first);
    }
  }

  checkAndStore(jti, expMs) {
    if (!jti) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'token jti is required for replay protection');
    this.prune();
    if (this.seen.has(jti)) throw new VibeGuardError(ERROR_CODES.REPLAY_DETECTED, 'token replay detected', { status: 401 });
    this.seen.set(jti, expMs);
  }
}

class IdentityAuthority {
  constructor(opts) {
    if (!opts || !opts.issuer || !opts.tenant) throw new Error('IdentityAuthority requires issuer and tenant');
    let privateKey;
    let publicKey;
    if (opts.privateKey) {
      privateKey = loadPrivateKey(opts.privateKey);
      publicKey = opts.publicKey ? loadPublicKey(opts.publicKey) : crypto.createPublicKey(privateKey);
    } else if (opts.publicKey) {
      privateKey = null;
      publicKey = loadPublicKey(opts.publicKey);
    } else {
      const pair = generateKeyPair();
      privateKey = pair.privateKey;
      publicKey = pair.publicKey;
    }
    this.issuer = opts.issuer;
    this.tenant = opts.tenant;
    this.keyId = opts.keyId || `key_${crypto.randomBytes(4).toString('hex')}`;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.now = opts.now || (() => new Date());
    this.replay = opts.replay || new ReplayCache(() => this.now().getTime());
    this.maxTtlSeconds = opts.maxTtlSeconds || MAX_TTL_SECONDS;
    this.clockSkewSeconds = opts.clockSkewSeconds === undefined ? DEFAULT_SKEW_SECONDS : opts.clockSkewSeconds;
  }

  publicJwk() {
    return publicKeyToJwk(this.publicKey, this.keyId);
  }

  issue(request = {}) {
    if (!this.privateKey) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'identity authority is verify-only');
    const principal = assertPrincipal(request.principal || `agent:${this.tenant}/${request.agent || 'default'}`);
    const tenant = principal.split(':')[1].split('/')[0];
    if (tenant !== this.tenant) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'principal tenant does not match authority');
    const ttl = Number(request.ttlSeconds || 300);
    if (!Number.isFinite(ttl) || ttl <= 0 || ttl > this.maxTtlSeconds) {
      throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, `ttlSeconds must be 1..${this.maxTtlSeconds}`);
    }
    const capabilities = Array.isArray(request.capabilities) ? [...new Set(request.capabilities)] : [];
    for (const cap of capabilities) {
      if (!CAPABILITIES.includes(cap)) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, `unknown capability: ${cap}`);
    }
    const now = Math.floor(this.now().getTime() / 1000);
    const payload = {
      iss: this.issuer,
      sub: principal,
      aud: request.audience || 'vibeguard-gateway',
      iat: now,
      nbf: now,
      exp: now + ttl,
      jti: request.jti || crypto.randomBytes(12).toString('base64url'),
      tenant,
      kind: request.kind || 'agent',
      capabilities,
      policyVersion: request.policyVersion || null,
      scope: request.scope || null,
      delegation: request.delegation || null,
    };
    const header = { alg: 'EdDSA', typ: 'VGAT', kid: this.keyId };
    const token = signJws(header, payload, this.privateKey);
    return { token, payload, publicJwk: this.publicJwk() };
  }

  verify(token, opts = {}) {
    const decoded = decodeJws(token);
    if (decoded.header.alg !== 'EdDSA' || decoded.header.typ !== 'VGAT') {
      throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'unsupported token type/algorithm');
    }
    if (decoded.header.kid !== this.keyId) {
      throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'unknown key id');
    }
    verifyJws(token, this.publicKey);
    const p = decoded.payload;
    const now = Math.floor(this.now().getTime() / 1000);
    const skew = this.clockSkewSeconds;
    if (p.iss !== this.issuer) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'invalid issuer');
    if (p.aud !== (opts.audience || 'vibeguard-gateway')) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'invalid audience');
    if (!Number.isInteger(p.exp) || p.exp <= now - skew) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'token expired');
    if (!Number.isInteger(p.nbf) || p.nbf > now + skew) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'token not yet valid');
    if (!Number.isInteger(p.iat) || p.iat > now + skew) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'invalid issued-at');
    if (p.exp - p.iat > this.maxTtlSeconds + skew) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'token ttl exceeds maximum');
    if (!p.jti) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'missing jti');
    if (opts.tenant && p.tenant !== opts.tenant) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'tenant mismatch');
    if (opts.principal && p.sub !== opts.principal) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'principal mismatch');
    if (!Array.isArray(p.capabilities)) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'missing capabilities');
    for (const cap of p.capabilities) {
      if (!CAPABILITIES.includes(cap)) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, `unknown capability: ${cap}`);
    }
    if (opts.requiredCapabilities) {
      for (const cap of opts.requiredCapabilities) {
        if (!p.capabilities.includes(cap)) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, `missing capability: ${cap}`);
      }
    }
    if (opts.replay !== false) this.replay.checkAndStore(p.jti, p.exp * 1000);
    return {
      principal: {
        principalId: p.sub,
        kind: p.kind,
        tenantId: p.tenant,
        displayName: p.sub.split('/').slice(1).join('/'),
        status: 'active',
        capabilities: p.capabilities,
      },
      claims: p,
      header: decoded.header,
    };
  }
}

function verifyExternalJws(token, opts = {}) {
  const decoded = decodeJws(token);
  if (decoded.header.alg !== 'EdDSA') {
    throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'unsupported JWS algorithm');
  }
  if (!opts.publicKey) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'no verification key');
  verifyJws(token, opts.publicKey);
  return decoded;
}

module.exports = {
  generateKeyPair,
  publicKeyToPem,
  privateKeyToPem,
  publicKeyToJwk,
  loadPublicKey,
  loadPrivateKey,
  signJws,
  decodeJws,
  verifyJws,
  verifyExternalJws,
  ReplayCache,
  IdentityAuthority,
  MAX_TTL_SECONDS,
};
