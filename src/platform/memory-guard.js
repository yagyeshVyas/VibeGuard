'use strict';

/*
 * src/platform/memory-guard.js — provenance-aware local memory primitive.
 *
 * This is not a persistent memory server. It is a small guard that any memory
 * integration can call before storing/retrieving agent context: content is
 * scanned for injection/secret material, source-tagged and hash-verified.
 */

const { sha256Hex } = require('./canonical');
const { scanTextForInjection } = require('../mcp-audit');
const { scanForLeaksDeep } = require('../action-guard');
const { ERROR_CODES, VibeGuardError, assertPrincipal } = require('./contracts');

class MemoryGuard {
  constructor(opts = {}) {
    this.trustedSources = new Set(opts.trustedSources || ['human', 'system']);
    this.entries = new Map();
    this.clock = opts.clock || (() => new Date());
  }

  ingest({ id, content, source, principal, labels = [] } = {}) {
    if (!id || typeof content !== 'string') throw new VibeGuardError(ERROR_CODES.AUTH_INVALID, 'memory id and string content are required');
    if (principal) assertPrincipal(principal);
    if (!this.trustedSources.has(source)) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, `untrusted memory source: ${source}`);
    const injection = scanTextForInjection(content);
    if (injection.length) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, `memory content contains prompt injection: ${injection.join(', ')}`);
    const leaks = scanForLeaksDeep(content);
    if (leaks.secrets.length || leaks.entropy.length) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'memory content contains credential material');
    const entry = {
      id,
      content,
      source,
      principal: principal || null,
      labels: [...labels],
      hash: sha256Hex({ id, content, source, principal: principal || null }),
      createdAt: this.clock().toISOString(),
    };
    this.entries.set(id, entry);
    return this.get(id);
  }

  get(id) {
    const e = this.entries.get(id);
    if (!e) return null;
    return { ...e, labels: e.labels.slice() };
  }

  retrieve(id, principal) {
    const e = this.entries.get(id);
    if (!e) return null;
    if (e.principal && principal && e.principal !== principal) throw new VibeGuardError(ERROR_CODES.AUTHORIZATION_DENIED, 'memory entry belongs to another principal');
    if (sha256Hex({ id: e.id, content: e.content, source: e.source, principal: e.principal }) !== e.hash) {
      throw new VibeGuardError(ERROR_CODES.AUDIT_INVALID, 'memory entry integrity check failed');
    }
    return { ...e, labels: e.labels.slice() };
  }

  revoke(id) { return this.entries.delete(id); }
  list() { return [...this.entries.values()].map((e) => ({ ...e, labels: e.labels.slice() })); }
}

module.exports = { MemoryGuard };
