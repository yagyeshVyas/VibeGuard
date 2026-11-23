'use strict';

/*
 * src/platform/verification.js — cached backend verification records.
 *
 * A backend verification is host-specific evidence, not a build property.
 * The cache is deliberately short-lived and keyed by the backend suite
 * version plus the host identity, so an OS update or a new suite invalidates
 * the claim instead of silently carrying it forward.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function defaultCacheFile() {
  if (process.env.VIBEGUARD_SANDBOX_CACHE) return path.resolve(process.env.VIBEGUARD_SANDBOX_CACHE);
  return path.join(os.homedir(), '.vibeguard', 'sandbox-verification.json');
}

function hostFingerprint() {
  return {
    platform: process.platform,
    arch: process.arch,
    release: os.release(),
    node: process.versions.node,
  };
}

function readCache(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return {};
  }
}

function loadVerification(file, backendId, suiteVersion, opts = {}) {
  if (!file) return null;
  const ttl = Number.isFinite(opts.ttlMs) ? opts.ttlMs : DEFAULT_TTL_MS;
  const record = readCache(file)[backendId];
  if (!record || record.suiteVersion !== suiteVersion) return null;
  const verifiedAt = Date.parse(record.verifiedAt || '');
  if (!Number.isFinite(verifiedAt) || Date.now() - verifiedAt > ttl) return null;
  const expected = hostFingerprint();
  if (!record.host || Object.keys(expected).some((k) => record.host[k] !== expected[k])) return null;
  return record;
}

function saveVerification(file, backendId, record) {
  if (!file) return;
  const all = readCache(file);
  all[backendId] = { ...record, host: hostFingerprint() };
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(all, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
}

module.exports = { defaultCacheFile, hostFingerprint, loadVerification, saveVerification, DEFAULT_TTL_MS };
