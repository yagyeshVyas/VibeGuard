'use strict';

/*
 * src/platform/contracts.js — shared platform contracts for the v2 security
 * baseline. These are deliberately small, dependency-free primitives used by
 * the policy, identity, approval, audit and gateway modules.
 *
 * The legacy v1 modules keep their public APIs; this file is additive.
 */

const crypto = require('crypto');

const DECISION = Object.freeze({
  ALLOW: 'allow',
  DENY: 'deny',
  APPROVAL_REQUIRED: 'approval_required',
  QUARANTINE: 'quarantine',
});

const ISOLATION = Object.freeze({
  NONE: 'none',
  PROCESS: 'process',
  OS: 'os',
  CONTAINER: 'container',
  MICROVM: 'microvm',
  HARDWARE_VM: 'hardware-vm',
});

const TRUST = Object.freeze({
  UNKNOWN: 'unknown',
  PENDING: 'pending',
  TRUSTED: 'trusted',
  REVOKED: 'revoked',
});

const CAPABILITIES = Object.freeze([
  'mcp.tool.invoke',
  'mcp.resource.read',
  'mcp.prompt.get',
  'mcp.server.manage',
  'mcp.protocol.unknown',
  'fs.read',
  'fs.write',
  'net.egress',
  'proc.exec',
  'secret.read',
  'secret.use',
  'sandbox.exec',
  'package.install',
  'skill.load',
  'memory.write',
  'agent.delegate',
  'policy.admin',
  'audit.read',
  'trust.admin',
  'incident.admin',
]);

const DATA_LABELS = Object.freeze([
  'public',
  'internal',
  'confidential',
  'restricted',
  'pii',
  'secret',
  'credential',
  'untrusted',
]);

const ERROR_CODES = Object.freeze({
  AUTH_REQUIRED: 'VG_AUTH_REQUIRED',
  AUTH_INVALID: 'VG_AUTH_INVALID',
  AUTHORIZATION_DENIED: 'VG_AUTHORIZATION_DENIED',
  APPROVAL_REQUIRED: 'VG_APPROVAL_REQUIRED',
  APPROVAL_INVALID: 'VG_APPROVAL_INVALID',
  POLICY_INVALID: 'VG_POLICY_INVALID',
  POLICY_UNAVAILABLE: 'VG_POLICY_UNAVAILABLE',
  POLICY_EVALUATION_ERROR: 'VG_POLICY_EVALUATION_ERROR',
  AUDIT_UNAVAILABLE: 'VG_AUDIT_UNAVAILABLE',
  AUDIT_INVALID: 'VG_AUDIT_INVALID',
  SCHEMA_INVALID: 'VG_SCHEMA_INVALID',
  LIMIT_EXCEEDED: 'VG_LIMIT_EXCEEDED',
  SANDBOX_UNAVAILABLE: 'VG_SANDBOX_UNAVAILABLE',
  SANDBOX_FAILED: 'VG_SANDBOX_FAILED',
  TRUST_UNKNOWN: 'VG_TRUST_UNKNOWN',
  POSTURE_DEGRADED: 'VG_POSTURE_DEGRADED',
  DETECTOR_ERROR: 'VG_DETECTOR_ERROR',
  REPLAY_DETECTED: 'VG_REPLAY_DETECTED',
  SSRF_BLOCKED: 'VG_SSRF_BLOCKED',
  INTERNAL: 'VG_INTERNAL',
});

class VibeGuardError extends Error {
  constructor(code, message, opts = {}) {
    super(message || code);
    this.name = 'VibeGuardError';
    this.code = code || ERROR_CODES.INTERNAL;
    this.status = opts.status || 500;
    this.retryable = !!opts.retryable;
    this.details = opts.details || null;
    this.expose = opts.expose !== false;
  }

  toJSON() {
    return {
      code: this.code,
      message: this.expose ? this.message : 'internal error',
      status: this.status,
      retryable: this.retryable,
      details: this.details,
    };
  }
}

function failClosed(code, message, opts) {
  return new VibeGuardError(code, message, { status: 403, ...(opts || {}) });
}

function nowIso(clock) {
  const d = clock && typeof clock.now === 'function' ? clock.now() : new Date();
  return (d instanceof Date ? d : new Date(d)).toISOString();
}

function newId(prefix = 'id') {
  return `${prefix}_${crypto.randomBytes(16).toString('hex')}`;
}

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function assertPrincipal(principal) {
  if (!principal || typeof principal !== 'string') {
    throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'principal is required');
  }
  if (!/^(agent|human|service|mcp-server):[A-Za-z0-9._-]+\/[A-Za-z0-9._@-]+$/.test(principal)) {
    throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, `invalid principal: ${principal}`);
  }
  return principal;
}

module.exports = {
  DECISION,
  ISOLATION,
  TRUST,
  CAPABILITIES,
  DATA_LABELS,
  ERROR_CODES,
  VibeGuardError,
  failClosed,
  nowIso,
  newId,
  safeEqual,
  assertPrincipal,
};
