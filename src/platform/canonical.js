'use strict';

/*
 * src/platform/canonical.js — deterministic JSON canonicalization and hashing.
 *
 * This is a dependency-free subset of RFC 8785 (JCS): object keys are sorted,
 * strings use JSON escaping, numbers use ECMAScript JSON number formatting,
 * arrays preserve order, and undefined/function/symbol/BigInt/cycles are
 * rejected. It is used for policy hashes, audit events, approvals and action
 * digests. Unknown values fail closed rather than silently producing a hash.
 */

const crypto = require('crypto');

function canonicalize(value) {
  const seen = new WeakSet();
  return serialize(value, seen);
}

function serialize(value, seen) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'string') return JSON.stringify(value);
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new Error('canonical JSON: non-finite number');
    return JSON.stringify(value);
  }
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'undefined' || t === 'function' || t === 'symbol' || t === 'bigint') {
    throw new Error(`canonical JSON: unsupported ${t}`);
  }
  if (t !== 'object') throw new Error(`canonical JSON: unsupported type ${t}`);
  if (seen.has(value)) throw new Error('canonical JSON: cycle detected');
  seen.add(value);
  let out;
  if (Array.isArray(value)) {
    out = '[' + value.map((v) => serialize(v, seen)).join(',') + ']';
  } else {
    if (value instanceof Date) {
      out = JSON.stringify(value.toISOString());
    } else {
      const keys = Object.keys(value).sort();
      out = '{' + keys.map((k) => JSON.stringify(k) + ':' + serialize(value[k], seen)).join(',') + '}';
    }
  }
  seen.delete(value);
  return out;
}

function sha256Hex(value) {
  const text = typeof value === 'string' ? value : canonicalize(value);
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function sha256Base64url(value) {
  const text = typeof value === 'string' ? value : canonicalize(value);
  return crypto.createHash('sha256').update(text, 'utf8').digest('base64url');
}

function bodyHash(value) {
  return 'sha256:' + sha256Hex(value);
}

function actionDigest(action) {
  return bodyHash({
    server: action && action.server,
    tool: action && action.tool,
    capability: action && action.capability,
    arguments: action && action.arguments !== undefined ? action.arguments : null,
  });
}

module.exports = { canonicalize, sha256Hex, sha256Base64url, bodyHash, actionDigest };
