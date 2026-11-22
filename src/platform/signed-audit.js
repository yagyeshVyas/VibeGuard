'use strict';

/*
 * src/platform/signed-audit.js — authenticated, append-only audit events.
 *
 * Each event commits to its predecessor (previousHash), carries a SHA-256 hash
 * over its canonical body, and is signed with Ed25519. A period checkpoint
 * signs a Merkle root of the event hashes so an external verifier can anchor
 * history without replaying every event.
 *
 * This is intentionally separate from the legacy src/audit-trail.js JSONL
 * format; the legacy format remains readable via a compatibility importer.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { canonicalize, sha256Hex } = require('./canonical');
const { ERROR_CODES, VibeGuardError, newId } = require('./contracts');
const { loadPrivateKey, loadPublicKey, generateKeyPair } = require('./identity');

const GENESIS = 'GENESIS';
const SCHEMA_VERSION = '1.0';

function iso(clock) {
  const d = clock && typeof clock.now === 'function' ? clock.now() : (typeof clock === 'function' ? clock() : new Date());
  return (d instanceof Date ? d : new Date(d)).toISOString();
}

function eventBody(event) {
  return {
    schemaVersion: SCHEMA_VERSION,
    eventId: event.eventId,
    sequence: event.sequence,
    timestamp: event.timestamp,
    type: event.type,
    tenant: event.tenant || null,
    principal: event.principal || null,
    agent: event.agent || null,
    sessionId: event.sessionId || null,
    server: event.server || null,
    tool: event.tool || null,
    actionDigest: event.actionDigest || null,
    decision: event.decision || null,
    reasonCode: event.reasonCode || null,
    policyId: event.policyId || null,
    policyVersion: event.policyVersion || null,
    detail: event.detail || {},
    previousHash: event.previousHash,
  };
}

function signHash(hash, privateKey) {
  return crypto.sign(null, Buffer.from(hash, 'utf8'), privateKey).toString('base64url');
}

function verifyHashSignature(hash, signature, publicKey) {
  try {
    return crypto.verify(null, Buffer.from(hash, 'utf8'), loadPublicKey(publicKey), Buffer.from(signature, 'base64url'));
  } catch {
    return false;
  }
}

class SignedAuditLog {
  constructor(opts = {}) {
    if (!opts.file) throw new Error('SignedAuditLog requires a file path');
    this.file = path.resolve(opts.file);
    let privateKey;
    let publicKey;
    if (opts.privateKey) {
      privateKey = loadPrivateKey(opts.privateKey);
      publicKey = opts.publicKey ? loadPublicKey(opts.publicKey) : crypto.createPublicKey(privateKey);
    } else {
      if (opts.publicKey) throw new Error('SignedAuditLog: publicKey without privateKey is not supported');
      const pair = generateKeyPair();
      privateKey = pair.privateKey;
      publicKey = pair.publicKey;
    }
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.keyId = opts.keyId || `audit_${crypto.randomBytes(4).toString('hex')}`;
    this.clock = opts.clock || (() => new Date());
    this.tenant = opts.tenant || null;
    this.checkpointFile = opts.checkpointFile || `${this.file}.checkpoint.json`;
    this.anchorFile = opts.anchorFile || null;
    this.anchorLastHash = 'GENESIS';
    this.entries = [];
    this.lastHash = GENESIS;
    this._loadExisting(opts.verifyOnOpen !== false);
  }

  _loadExisting(verify) {
    if (this.anchorFile && fs.existsSync(this.anchorFile)) {
      const lines = fs.readFileSync(this.anchorFile, 'utf8').split(/\r?\n/).filter(Boolean);
      if (lines.length) {
        try { this.anchorLastHash = JSON.parse(lines[lines.length - 1]).hash || 'GENESIS'; } catch { throw new VibeGuardError(ERROR_CODES.AUDIT_INVALID, 'audit anchor is corrupt'); }
      }
    }
    if (!fs.existsSync(this.file)) return;
    const raw = fs.readFileSync(this.file, 'utf8');
    const lines = raw.split(/\r?\n/).filter(Boolean);
    for (let i = 0; i < lines.length; i++) {
      let event;
      try {
        event = JSON.parse(lines[i]);
      } catch {
        throw new VibeGuardError(ERROR_CODES.AUDIT_INVALID, `audit line ${i + 1} is not valid JSON`);
      }
      this.entries.push(event);
    }
    if (this.entries.length) this.lastHash = this.entries[this.entries.length - 1].hash;
    if (verify && this.entries.length) {
      const result = SignedAuditLog.verifyEntries(this.entries, { publicKey: this.publicKey, requireEntries: true });
      if (!result.valid) throw new VibeGuardError(ERROR_CODES.AUDIT_INVALID, 'existing audit log failed verification');
    }
  }

  append(type, detail = {}, meta = {}) {
    const sequence = this.entries.length + 1;
    const event = {
      schemaVersion: SCHEMA_VERSION,
      eventId: meta.eventId || newId('evt'),
      sequence,
      timestamp: meta.timestamp || iso(this.clock),
      type,
      tenant: meta.tenant !== undefined ? meta.tenant : this.tenant,
      principal: meta.principal || null,
      agent: meta.agent || null,
      sessionId: meta.sessionId || null,
      server: meta.server || null,
      tool: meta.tool || null,
      actionDigest: meta.actionDigest || null,
      decision: meta.decision || null,
      reasonCode: meta.reasonCode || null,
      policyId: meta.policyId || null,
      policyVersion: meta.policyVersion || null,
      detail,
      previousHash: this.lastHash,
    };
    const body = eventBody(event);
    const hash = sha256Hex(body);
    const signature = {
      alg: 'Ed25519',
      keyId: this.keyId,
      sig: signHash(hash, this.privateKey),
    };
    event.hash = hash;
    event.signature = signature;

    this._writeLine(event);
    this.entries.push(event);
    this.lastHash = hash;
    this._writeCheckpoint();
    return event;
  }

  _writeCheckpoint() {
    try {
      const cp = this.checkpoint();
      fs.writeFileSync(this.checkpointFile, JSON.stringify(cp) + '\n', { mode: 0o600 });
      try { fs.chmodSync(this.checkpointFile, 0o600); } catch { /* Windows/best effort */ }
      if (this.anchorFile) {
        const record = { schemaVersion: SCHEMA_VERSION, checkpoint: cp, previousAnchor: this.anchorLastHash, timestamp: iso(this.clock) };
        record.hash = sha256Hex(record);
        fs.mkdirSync(path.dirname(this.anchorFile), { recursive: true, mode: 0o700 });
        fs.appendFileSync(this.anchorFile, JSON.stringify(record) + '\n', { mode: 0o600 });
        this.anchorLastHash = record.hash;
      }
    } catch (err) {
      throw new VibeGuardError(ERROR_CODES.AUDIT_INVALID, `audit checkpoint write failed: ${err.message}`);
    }
  }

  _writeLine(event) {
    fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
    try { fs.chmodSync(path.dirname(this.file), 0o700); } catch { /* Windows/best effort */ }
    const fd = fs.openSync(this.file, 'a', 0o600);
    try {
      fs.writeSync(fd, JSON.stringify(event) + '\n');
      try { fs.fsyncSync(fd); } catch { /* platform may not support */ }
    } finally {
      fs.closeSync(fd);
    }
    try { fs.chmodSync(this.file, 0o600); } catch { /* Windows/best effort */ }
  }

  checkpoint() {
    if (!this.entries.length) throw new VibeGuardError(ERROR_CODES.AUDIT_INVALID, 'cannot checkpoint an empty audit log');
    const root = merkleRoot(this.entries.map((e) => e.hash));
    const body = {
      type: 'VGCHECKPOINT',
      schemaVersion: SCHEMA_VERSION,
      sequence: this.entries.length,
      lastSequence: this.entries[this.entries.length - 1].sequence,
      root,
      timestamp: iso(this.clock),
      keyId: this.keyId,
    };
    const sig = crypto.sign(null, Buffer.from(canonicalize(body), 'utf8'), this.privateKey).toString('base64url');
    return { ...body, signature: { alg: 'Ed25519', keyId: this.keyId, sig } };
  }

  static verifyFile(file, opts = {}) {
    if (!fs.existsSync(file)) {
      return { valid: false, entries: 0, brokenAt: [], reasons: ['audit file does not exist'] };
    }
    let raw;
    try { raw = fs.readFileSync(file, 'utf8'); } catch (exc) {
      return { valid: false, entries: 0, brokenAt: [], reasons: [`cannot read audit file: ${exc.message}`] };
    }
    const lines = raw.split(/\r?\n/).filter(Boolean);
    const entries = [];
    const reasons = [];
    for (let i = 0; i < lines.length; i++) {
      try { entries.push(JSON.parse(lines[i])); } catch { reasons.push(`line ${i + 1}: invalid JSON`); }
    }
    const result = SignedAuditLog.verifyEntries(entries, { ...opts, requireEntries: opts.requireEntries !== false });
    let checkpoint;
    let anchor;
    try {
      if (opts.checkpoint) checkpoint = opts.checkpoint;
      else if (opts.publicKey && fs.existsSync(`${path.resolve(file)}.checkpoint.json`)) {
        checkpoint = JSON.parse(fs.readFileSync(`${path.resolve(file)}.checkpoint.json`, 'utf8'));
      }
      if (opts.anchorFile && fs.existsSync(opts.anchorFile)) {
        const lines = fs.readFileSync(opts.anchorFile, 'utf8').split(/\r?\n/).filter(Boolean);
        if (lines.length) anchor = JSON.parse(lines[lines.length - 1]);
      }
    } catch { /* fall through to checkpoint failure below */ }
    if (anchor && opts.publicKey) {
      const cp = anchor.checkpoint;
      if (!cp) { reasons.push('anchor has no checkpoint'); result.valid = false; }
      else {
        const av = SignedAuditLog.verifyCheckpoint(cp, opts.publicKey, entries);
        if (!av.valid) { reasons.push(`external anchor: ${av.reason}`); result.valid = false; }
        else if (cp.sequence !== entries.length) { reasons.push('external anchor sequence mismatch'); result.valid = false; }
      }
    }
    if (checkpoint && entries.length) {
      if (!opts.publicKey) {
        reasons.push('checkpoint present but no public key supplied; checkpoint signature not verified');
      } else {
        const cp = SignedAuditLog.verifyCheckpoint(checkpoint, opts.publicKey, entries);
        if (!cp.valid) {
          reasons.push(`checkpoint: ${cp.reason}`);
          result.brokenAt.push(checkpoint.sequence || entries.length);
          result.valid = false;
        }
      }
    }
    return { ...result, reasons: reasons.concat(result.reasons), file: path.resolve(file) };
  }

  static verifyEntries(entries, opts = {}) {
    const brokenAt = [];
    const reasons = [];
    let prev = GENESIS;
    const ids = new Set();
    if (!Array.isArray(entries)) return { valid: false, entries: 0, brokenAt: [], reasons: ['entries is not an array'] };
    if (opts.requireEntries && entries.length === 0) {
      return { valid: false, entries: 0, brokenAt: [], reasons: ['audit log has no entries'] };
    }
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      if (!e || typeof e !== 'object') { brokenAt.push(i + 1); reasons.push(`entry ${i + 1}: not an object`); continue; }
      if (e.schemaVersion !== SCHEMA_VERSION) { brokenAt.push(e.sequence || i + 1); reasons.push(`entry ${i + 1}: schema version`); }
      if (e.sequence !== i + 1) { brokenAt.push(e.sequence || i + 1); reasons.push(`entry ${i + 1}: sequence mismatch`); }
      if (e.previousHash !== prev) { brokenAt.push(e.sequence || i + 1); reasons.push(`entry ${i + 1}: previous hash mismatch`); }
      if (ids.has(e.eventId)) { brokenAt.push(e.sequence || i + 1); reasons.push(`entry ${i + 1}: duplicate eventId`); }
      ids.add(e.eventId);
      const expected = sha256Hex(eventBody(e));
      if (e.hash !== expected) { brokenAt.push(e.sequence || i + 1); reasons.push(`entry ${i + 1}: hash mismatch`); }
      if (opts.publicKey) {
        if (!e.signature || e.signature.alg !== 'Ed25519') {
          brokenAt.push(e.sequence || i + 1); reasons.push(`entry ${i + 1}: missing signature`);
        } else if (!verifyHashSignature(e.hash, e.signature.sig, opts.publicKey)) {
          brokenAt.push(e.sequence || i + 1); reasons.push(`entry ${i + 1}: bad signature`);
        }
      }
      prev = e.hash;
    }
    const unique = [...new Set(brokenAt)];
    return { valid: unique.length === 0, entries: entries.length, brokenAt: unique, reasons };
  }

  static verifyCheckpoint(checkpoint, publicKey, entries) {
    if (!checkpoint || checkpoint.type !== 'VGCHECKPOINT') return { valid: false, reason: 'not a checkpoint' };
    const body = { ...checkpoint };
    delete body.signature;
    const sigOk = verifyHashSignature(canonicalize(body), checkpoint.signature && checkpoint.signature.sig, publicKey);
    if (!sigOk) return { valid: false, reason: 'checkpoint signature invalid' };
    if (!Array.isArray(entries) || entries.length !== checkpoint.sequence) return { valid: false, reason: 'checkpoint sequence mismatch' };
    const root = merkleRoot(entries.map((e) => e.hash));
    if (root !== checkpoint.root) return { valid: false, reason: 'checkpoint root mismatch' };
    return { valid: true, root };
  }
}

function merkleRoot(hashes) {
  if (!hashes.length) return sha256Hex('EMPTY');
  let level = hashes.slice();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      next.push(sha256Hex(left + right));
    }
    level = next;
  }
  return level[0];
}

/**
 * Adapter with the legacy logger shape (`log`, `entries`, `writeFailures`) so
 * the MCP gateway can use signed events without changing its call sites.
 */
class SignedAuditLogger {
  constructor(opts = {}) {
    this.signed = new SignedAuditLog(opts);
    this.file = this.signed.file;
    this.writeFailures = 0;
  }

  log(type, detail = {}) {
    try {
      return this.signed.append(type, detail);
    } catch (err) {
      this.writeFailures++;
      throw err;
    }
  }

  get entries() { return this.signed.entries.slice(); }
  verify() { return SignedAuditLog.verifyFile(this.file, { publicKey: this.signed.publicKey }); }
  checkpoint() { return this.signed.checkpoint(); }
}

function ensureAuditKey(projectRoot, keyFile) {
  const dir = path.join(projectRoot, '.vibeguard', 'audit');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(dir, 0o700); } catch { /* Windows */ }
  const privatePath = keyFile || path.join(dir, 'ed25519.pem');
  const publicPath = privatePath.replace(/\.pem$/i, '.pub.pem');
  let privateKey;
  let publicKey;
  if (fs.existsSync(privatePath)) {
    privateKey = loadPrivateKey(fs.readFileSync(privatePath));
    publicKey = fs.existsSync(publicPath) ? loadPublicKey(fs.readFileSync(publicPath)) : crypto.createPublicKey(privateKey);
  } else {
    const pair = generateKeyPair();
    privateKey = pair.privateKey;
    publicKey = pair.publicKey;
    fs.writeFileSync(privatePath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(publicPath, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
    try { fs.chmodSync(privatePath, 0o600); } catch { /* Windows */ }
  }
  return { privateKey, publicKey, privatePath, publicPath };
}

function createSignedLogger(file, opts = {}) {
  const projectRoot = opts.projectRoot || path.dirname(path.dirname(path.dirname(file)));
  const key = ensureAuditKey(projectRoot, opts.auditKeyFile);
  const logger = new SignedAuditLogger({
    file,
    privateKey: key.privateKey,
    publicKey: key.publicKey,
    keyId: opts.keyId || 'gateway-audit',
    tenant: opts.tenant,
    clock: opts.clock,
  });
  logger.keyInfo = key;
  return logger;
}

module.exports = {
  SignedAuditLog,
  SignedAuditLogger,
  createSignedLogger,
  ensureAuditKey,
  merkleRoot,
  eventBody,
  GENESIS,
  SCHEMA_VERSION,
};
