'use strict';

/*
 * src/platform/delegation.js — signed, attenuated multi-agent delegation.
 *
 * A parent can delegate a subset of its capabilities to a child, up to a
 * maximum chain depth. Tokens are Ed25519 JWS with a delegation claim and are
 * verified offline. This is a library primitive; no multi-agent runtime graph
 * or cross-session store is claimed.
 */

const crypto = require('crypto');
const { CAPABILITIES, ERROR_CODES, VibeGuardError, assertPrincipal } = require('./contracts');
const { generateKeyPair, loadPrivateKey, loadPublicKey, signJws, verifyJws } = require('./identity');

class DelegationGraph {
  constructor(opts = {}) {
    if (!opts.privateKey && !opts.publicKey) {
      const pair = generateKeyPair();
      this.privateKey = pair.privateKey;
      this.publicKey = pair.publicKey;
    } else {
      this.privateKey = opts.privateKey ? loadPrivateKey(opts.privateKey) : null;
      this.publicKey = opts.publicKey ? loadPublicKey(opts.publicKey) : crypto.createPublicKey(this.privateKey);
    }
    this.issuer = opts.issuer || 'human:local/operator';
    this.tenant = opts.tenant || 'local';
    this.keyId = opts.keyId || `delegation_${crypto.randomBytes(4).toString('hex')}`;
    this.maxDepth = opts.maxDepth || 3;
    this.now = opts.now || (() => new Date());
    this.edges = new Map();
  }

  delegate({ parent, child, capabilities, depth = 0, parentCapabilities = [] } = {}) {
    if (!this.privateKey) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'delegation graph is verify-only');
    assertPrincipal(parent);
    assertPrincipal(child);
    if (parent === child) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'self-delegation is not allowed');
    if (!Array.isArray(capabilities) || !capabilities.length) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'capabilities are required');
    for (const c of capabilities) {
      if (!CAPABILITIES.includes(c)) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, `unknown capability: ${c}`);
      if (Array.isArray(parentCapabilities) && parentCapabilities.length && !parentCapabilities.includes(c)) {
        throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, `capability escalation: ${c}`);
      }
    }
    if (depth + 1 > this.maxDepth) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'delegation depth exceeded');
    const now = Math.floor(this.now().getTime() / 1000);
    const payload = {
      iss: this.issuer, sub: child, parent, aud: 'vibeguard-delegation', iat: now, exp: now + 300,
      jti: crypto.randomBytes(12).toString('base64url'), tenant: this.tenant, capabilities: [...new Set(capabilities)], depth: depth + 1,
    };
    const token = signJws({ alg: 'EdDSA', typ: 'VGDEL', kid: this.keyId }, payload, this.privateKey);
    this.edges.set(`${parent}->${child}`, { parent, child, capabilities: [...capabilities], depth: depth + 1 });
    return { token, child, capabilities: payload.capabilities, depth: payload.depth };
  }

  verify(token, { requiredCapabilities = [], expectedIssuer } = {}) {
    const decoded = verifyJws(token, this.publicKey);
    if (decoded.header.typ !== 'VGDEL' || decoded.header.alg !== 'EdDSA') throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'invalid delegation token');
    const p = decoded.payload;
    const now = Math.floor(this.now().getTime() / 1000);
    if (expectedIssuer && p.iss !== expectedIssuer) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'delegation issuer mismatch');
    if (p.aud !== 'vibeguard-delegation') throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'delegation audience mismatch');
    if (!Number.isInteger(p.exp) || p.exp <= now) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'delegation expired');
    if (p.depth > this.maxDepth) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'delegation depth exceeded');
    for (const cap of requiredCapabilities) if (!p.capabilities.includes(cap)) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, `delegation lacks capability ${cap}`);
    return { child: p.sub, parent: p.parent, capabilities: p.capabilities, depth: p.depth, claims: p };
  }

  edgesFor(principal) { return [...this.edges.values()].filter((e) => e.parent === principal || e.child === principal); }
}

module.exports = { DelegationGraph };
