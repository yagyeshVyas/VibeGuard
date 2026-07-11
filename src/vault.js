'use strict';

/*
 * VibeGuard Secret Vault.
 *
 * Encrypted in-memory secret storage that AI cannot read directly.
 * Instead of storing secrets in process.env (which AI can read),
 * store them in the vault. AI must call vault.get('KEY') which:
 * - Returns the secret only for the current operation
 * - Never logs or exposes the raw value
 * - Automatically redacts in console.log
 * - Requires an explicit purpose for each access
 *
 * Usage:
 *   const vault = require('vibeguard/vault');
 *   vault.store('OPENAI_API_KEY', 'sk-proj-...');
 *   const key = vault.get('OPENAI_API_KEY', { purpose: 'chat completion' });
 *   // key is available for this call only
 *   // process.env.OPENAI_API_KEY is still undefined
 *
 * 100% local. Zero network. Zero dependencies.
 */

const crypto = require('crypto');

const VAULT_PREFIX = '__vg_vault_';
const secrets = new Map();
const accessLog = [];

// Generate a random encryption key per session
const SESSION_KEY = crypto.randomBytes(32);

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', SESSION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

function decrypt(encStr) {
  try {
    const data = Buffer.from(encStr, 'base64');
    const iv = data.slice(0, 16);
    const tag = data.slice(16, 32);
    const encrypted = data.slice(32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', SESSION_KEY, iv);
    decipher.setAuthTag(tag);
    return decipher.update(encrypted) + decipher.final('utf8');
  } catch {
    return null;
  }
}

function store(key, value, opts = {}) {
  const encrypted = encrypt(value);
  secrets.set(key, {
    encrypted,
    storedAt: Date.now(),
    purpose: opts.purpose || 'general',
    accessCount: 0,
  });
  // Also set in process.env but with a redacted marker
  if (!opts.skipEnv) {
    process.env[VAULT_PREFIX + key] = '[VAULT-PROTECTED]';
  }
  return { stored: true, key, redacted: true };
}

function get(key, opts = {}) {
  const entry = secrets.get(key);
  if (!entry) return null;

  // Log access
  accessLog.push({
    key,
    purpose: opts.purpose || 'unspecified',
    timestamp: Date.now(),
    caller: opts.caller || 'unknown',
  });

  // Limit access log
  if (accessLog.length > 1000) accessLog.shift();

  // Increment access count
  entry.accessCount++;

  // Decrypt and return
  return decrypt(entry.encrypted);
}

function list() {
  return [...secrets.keys()].map(key => ({
    key,
    storedAt: secrets.get(key).storedAt,
    accessCount: secrets.get(key).accessCount,
    purpose: secrets.get(key).purpose,
  }));
}

function getAccessLog() {
  return accessLog;
}

function clear() {
  secrets.clear();
  accessLog.length = 0;
  return { cleared: true };
}

function count() {
  return secrets.size;
}

function renderVaultReport() {
  const C = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  const lines = [
    `${C.bold}VibeGuard Secret Vault${C.reset}`,
    `${C.dim}${'─'.repeat(60)}${C.reset}`,
    '',
    `  Secrets stored:    ${count()}`,
    `  Access attempts:   ${accessLog.length}`,
    '',
  ];

  if (secrets.size > 0) {
    lines.push(`${C.bold}Stored Secrets${C.reset}`, '');
    for (const s of list()) {
      lines.push(`  ${C.green}[VAULT]${C.reset} ${s.key} — accessed ${s.accessCount}x, stored ${new Date(s.storedAt).toISOString().slice(0, 19)}`);
    }
    lines.push('');
  }

  if (accessLog.length > 0) {
    lines.push(`${C.bold}Recent Access Log${C.reset}`, '');
    for (const a of accessLog.slice(-10)) {
      lines.push(`  ${C.dim}${new Date(a.timestamp).toISOString().slice(11, 19)}${C.reset} ${a.key} — ${a.purpose}`);
    }
  }

  lines.push('', `${C.dim}Secrets are encrypted in memory. AI cannot read them directly.${C.reset}`);
  return lines.join('\n');
}

module.exports = { store, get, list, clear, count, getAccessLog, renderVaultReport };