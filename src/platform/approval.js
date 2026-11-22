'use strict';

/*
 * src/platform/approval.js — signed, single-use human approvals.
 *
 * An approval ticket binds a canonical action digest to a requesting agent.
 * A human approver (a different principal in the same tenant) signs a VGAPPROVAL
 * JWS. The gateway verifies the signature, digest, ticket, identity, expiry and
 * nonce before executing the action. Tokens are single-use and cannot be
 * self-approved.
 *
 * This module is intentionally in-memory for the first platform baseline.
 * Production persistence/replication belongs behind the ApprovalStore port.
 */

const crypto = require('crypto');
const { ERROR_CODES, VibeGuardError, newId } = require('./contracts');
const { signJws, verifyJws, loadPrivateKey, loadPublicKey, generateKeyPair } = require('./identity');
const { actionDigest } = require('./canonical');

class ApprovalBroker {
  constructor(opts = {}) {
    if (!opts.issuer || !opts.tenant) throw new Error('ApprovalBroker requires issuer and tenant');
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
    this.keyId = opts.keyId || `approval_${crypto.randomBytes(4).toString('hex')}`;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.now = opts.now || (() => new Date());
    this.defaultTtlSeconds = opts.defaultTtlSeconds || 300;
    this.approverKeys = new Map();
    for (const [principal, key] of Object.entries(opts.approverKeys || {})) {
      this.approverKeys.set(principal, loadPublicKey(key));
    }
    this.requireApproverProof = opts.requireApproverProof !== false;
    this.tickets = new Map();
    this.usedTokens = new Set();
  }

  request(request = {}) {
    if (!this.privateKey) throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'approval broker is verify-only');
    if (!request.principal || !String(request.principal).startsWith('agent:')) {
      throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'approval requester must be an agent principal');
    }
    const requesterTenant = String(request.principal).split(':')[1].split('/')[0];
    if (requesterTenant !== this.tenant) {
      throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'requester tenant mismatch');
    }
    if (!request.action || typeof request.action !== 'object') {
      throw new VibeGuardError(ERROR_CODES.SCHEMA_INVALID, 'approval action is required');
    }
    const ttl = Math.min(Number(request.ttlSeconds || this.defaultTtlSeconds), 900);
    if (!Number.isFinite(ttl) || ttl <= 0) throw new VibeGuardError(ERROR_CODES.SCHEMA_INVALID, 'invalid approval ttl');
    const now = this.now();
    const expires = new Date(now.getTime() + ttl * 1000);
    const ticket = {
      ticketId: newId('tkt'),
      principal: request.principal,
      action: request.action,
      actionDigest: actionDigest(request.action),
      nonce: crypto.randomBytes(16).toString('base64url'),
      reason: String(request.reason || '').slice(0, 500),
      createdAt: now.toISOString(),
      expiresAt: expires.toISOString(),
      status: 'pending',
      approver: null,
      approvalToken: null,
    };
    this.tickets.set(ticket.ticketId, ticket);
    return { ticket: publicTicket(ticket) };
  }

  decide(ticketId, decision = {}) {
    const ticket = this.tickets.get(ticketId);
    if (!ticket) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval ticket not found', { status: 404 });
    if (ticket.status !== 'pending') throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'ticket already decided');
    if (new Date(ticket.expiresAt).getTime() <= this.now().getTime()) {
      ticket.status = 'expired';
      throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval ticket expired');
    }
    const approver = String(decision.approver || '');
    if (!approver.startsWith('human:')) {
      throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approver must be a human principal');
    }
    const tenant = (x) => String(x).split(':')[1].split('/')[0];
    if (tenant(approver) !== this.tenant) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approver tenant mismatch');
    if (approver === ticket.principal) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'self-approval is not allowed');

    if (this.requireApproverProof) {
      const key = this.approverKeys.get(approver);
      if (!key) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approver has no registered verification key');
      const proof = decision.proof;
      if (!proof) throw new VibeGuardError(ERROR_CODES.AUTH_REQUIRED, 'signed approver proof is required', { status: 401 });
      const decoded = verifyJws(proof, key);
      const pp = decoded.payload;
      if (decoded.header.typ !== 'VGAPPROVER' || decoded.header.alg !== 'EdDSA') throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'invalid approver proof type');
      if (pp.aud !== 'vibeguard-approver-proof' || pp.sub !== approver) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approver proof identity mismatch');
      if (pp.ticketId !== ticket.ticketId || pp.actionDigest !== ticket.actionDigest || pp.nonce !== ticket.nonce) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approver proof does not bind this ticket/action');
      if (!Number.isInteger(pp.exp) || pp.exp <= Math.floor(this.now().getTime() / 1000)) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approver proof expired');
    }

    if (decision.approve !== true) {
      ticket.status = 'denied';
      ticket.approver = approver;
      ticket.decidedAt = this.now().toISOString();
      return { status: 'denied', ticket: publicTicket(ticket) };
    }

    const payload = {
      iss: this.issuer,
      sub: approver,
      aud: 'vibeguard-approval',
      iat: Math.floor(this.now().getTime() / 1000),
      exp: Math.floor(new Date(ticket.expiresAt).getTime() / 1000),
      jti: crypto.randomBytes(12).toString('base64url'),
      typ: 'VGAPPROVAL',
      ticketId: ticket.ticketId,
      actionDigest: ticket.actionDigest,
      nonce: ticket.nonce,
      requestedBy: ticket.principal,
    };
    const token = signJws({ alg: 'EdDSA', typ: 'VGAPPROVAL', kid: this.keyId }, payload, this.privateKey);
    ticket.status = 'approved';
    ticket.approver = approver;
    ticket.approvalToken = token;
    ticket.decidedAt = this.now().toISOString();
    return { status: 'approved', ticket: publicTicket(ticket), approvalToken: token };
  }

  static signApproverProof({ ticketId, actionDigest: digest, nonce, approver, privateKey, ttlSeconds = 120, keyId = 'approver' } = {}) {
    if (!ticketId || !digest || !nonce || !approver || !privateKey) throw new Error('approver proof requires ticketId, actionDigest, nonce, approver, privateKey');
    const now = Math.floor(Date.now() / 1000);
    const payload = { iss: approver, sub: approver, aud: 'vibeguard-approver-proof', iat: now, exp: now + Number(ttlSeconds), jti: crypto.randomBytes(12).toString('base64url'), typ: 'VGAPPROVER', ticketId, actionDigest: digest, nonce };
    return signJws({ alg: 'EdDSA', typ: 'VGAPPROVER', kid: keyId }, payload, loadPrivateKey(privateKey));
  }

  verify(ticketId, approvalToken, expectedActionDigest) {
    const ticket = this.tickets.get(ticketId);
    if (!ticket) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval ticket not found');
    if (ticket.status !== 'approved') throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'ticket is not approved');
    if (ticket.actionDigest !== expectedActionDigest) {
      throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval action digest mismatch');
    }
    if (ticket.usedAt) throw new VibeGuardError(ERROR_CODES.REPLAY_DETECTED, 'approval replay detected (already used)');
    const decoded = verifyJws(approvalToken, this.publicKey);
    if (decoded.header.typ !== 'VGAPPROVAL' || decoded.header.alg !== 'EdDSA') {
      throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'invalid approval token type');
    }
    const p = decoded.payload;
    const now = Math.floor(this.now().getTime() / 1000);
    if (p.iss !== this.issuer || p.aud !== 'vibeguard-approval') throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval issuer/audience mismatch');
    if (p.ticketId !== ticketId) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval ticket mismatch');
    if (p.actionDigest !== expectedActionDigest) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval digest mismatch');
    if (p.nonce !== ticket.nonce) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval nonce mismatch');
    if (!Number.isInteger(p.exp) || p.exp <= now) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval expired');
    if (p.sub !== ticket.approver) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval approver mismatch');
    if (this.usedTokens.has(p.jti)) throw new VibeGuardError(ERROR_CODES.REPLAY_DETECTED, 'approval replay');
    this.usedTokens.add(p.jti);
    ticket.usedAt = this.now().toISOString();
    return { approved: true, approver: p.sub, ticket: publicTicket(ticket) };
  }

  listPending() {
    return [...this.tickets.values()].filter((t) => t.status === 'pending').map(publicTicket);
  }

  verifyStandalone(approvalToken, expectedActionDigest) {
    if (!expectedActionDigest) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'action digest required');
    const decoded = verifyJws(approvalToken, this.publicKey);
    if (decoded.header.typ !== 'VGAPPROVAL' || decoded.header.alg !== 'EdDSA') {
      throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'invalid approval token type');
    }
    const p = decoded.payload;
    const now = Math.floor(this.now().getTime() / 1000);
    if (p.iss !== this.issuer || p.aud !== 'vibeguard-approval') throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval issuer/audience mismatch');
    if (p.actionDigest !== expectedActionDigest) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval digest mismatch');
    if (!Number.isInteger(p.exp) || p.exp <= now) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval expired');
    if (!p.sub || !String(p.sub).startsWith('human:')) throw new VibeGuardError(ERROR_CODES.APPROVAL_INVALID, 'approval approver is not human');
    if (this.usedTokens.has(p.jti)) throw new VibeGuardError(ERROR_CODES.REPLAY_DETECTED, 'approval replay');
    this.usedTokens.add(p.jti);
    return { approved: true, approver: p.sub, actionDigest: p.actionDigest };
  }
}

function publicTicket(t) {
  return {
    ticketId: t.ticketId,
    principal: t.principal,
    actionDigest: t.actionDigest,
    nonce: t.nonce,
    reason: t.reason,
    createdAt: t.createdAt,
    expiresAt: t.expiresAt,
    status: t.status,
    approver: t.approver,
    used: !!t.usedAt,
  };
}

module.exports = { ApprovalBroker };
