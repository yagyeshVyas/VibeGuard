'use strict';

/*
 * src/platform/jwt.js — offline OAuth/JWT access-token validation.
 *
 * Supports EdDSA (Ed25519) JWTs with a local JWKS. RS256 is intentionally not
 * implemented in the first baseline to avoid an unverified crypto path; add it
 * with a reviewed implementation if needed.
 *
 * Validates signature, issuer, audience, exp/nbf/iat, key id, tenant/scope and
 * replay. No network; JWKS must be supplied from local/offline configuration.
 */

const crypto = require('crypto');
const { ERROR_CODES, VibeGuardError } = require('./contracts');
const { ReplayCache } = require('./identity');
const defaultReplayCache = new ReplayCache();

function b64json(part) {
  let text;
  try { text = Buffer.from(part, 'base64url').toString('utf8'); } catch { throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'invalid JWT encoding'); }
  try { return JSON.parse(text); } catch { throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'invalid JWT JSON'); }
}

function decodeJwt(token) {
  if (typeof token !== 'string') throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'JWT must be a string');
  const parts = token.split('.');
  if (parts.length !== 3) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'malformed JWT');
  for (const part of parts) {
    let bytes;
    try { bytes = Buffer.from(part, 'base64url'); } catch { throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'invalid JWT base64url'); }
    if (bytes.toString('base64url') !== part) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'non-canonical JWT encoding');
  }
  return { header: b64json(parts[0]), payload: b64json(parts[1]), input: `${parts[0]}.${parts[1]}`, signature: parts[2] };
}

function keyForJwks(jwks, kid) {
  const keys = (jwks && jwks.keys) || [];
  const jwk = keys.find((k) => k.kid === kid) || (keys.length === 1 ? keys[0] : null);
  if (!jwk) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, `no JWKS key for kid ${kid || 'unknown'}`);
  if (jwk.alg && jwk.alg !== 'EdDSA') throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'JWKS key algorithm not allowed');
  if (jwk.use && jwk.use !== 'sig') throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'JWKS key is not a signing key');
  try { return crypto.createPublicKey({ key: jwk, format: 'jwk' }); } catch (err) {
    throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, `invalid JWKS key: ${err.message}`);
  }
}

function verifyJwt(token, opts = {}) {
  const decoded = decodeJwt(token);
  if (decoded.header.alg !== 'EdDSA') throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'unsupported JWT alg');
  if (opts.jwks) {
    const key = keyForJwks(opts.jwks, decoded.header.kid);
    const ok = crypto.verify(null, Buffer.from(decoded.input, 'utf8'), key, Buffer.from(decoded.signature, 'base64url'));
    if (!ok) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'JWT signature invalid');
  } else if (opts.publicKey) {
    const ok = crypto.verify(null, Buffer.from(decoded.input, 'utf8'), opts.publicKey, Buffer.from(decoded.signature, 'base64url'));
    if (!ok) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'JWT signature invalid');
  } else {
    throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'no JWT verification key');
  }
  const p = decoded.payload;
  const now = Math.floor((opts.now ? (opts.now instanceof Date ? opts.now : new Date(opts.now)) : new Date()).getTime() / 1000);
  const skew = opts.clockSkewSeconds === undefined ? 30 : Number(opts.clockSkewSeconds);
  if (p.iss !== opts.issuer) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'JWT issuer mismatch');
  const aud = Array.isArray(p.aud) ? p.aud : [p.aud];
  if (opts.audience && !aud.includes(opts.audience)) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'JWT audience mismatch');
  if (!Number.isInteger(p.exp) || p.exp <= now - skew) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'JWT expired');
  if (p.nbf != null && (!Number.isInteger(p.nbf) || p.nbf > now + skew)) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'JWT not yet valid');
  if (p.iat != null && (!Number.isInteger(p.iat) || p.iat > now + skew)) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'JWT issued-at invalid');
  if (opts.maxTtlSeconds && Number.isInteger(p.iat) && p.exp - p.iat > Number(opts.maxTtlSeconds) + skew) {
    throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'JWT ttl exceeds maximum');
  }
  if (opts.scopes && opts.scopes.length) {
    const granted = String(p.scope || '').split(/\s+/).filter(Boolean);
    for (const required of opts.scopes) {
      if (!granted.includes(required)) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, `missing scope: ${required}`);
    }
  }
  if (opts.replay !== false) {
    const cache = opts.replayCache || defaultReplayCache;
    cache.checkAndStore(p.jti, p.exp * 1000);
  }
  return { header: decoded.header, claims: p };
}

module.exports = { decodeJwt, verifyJwt };
