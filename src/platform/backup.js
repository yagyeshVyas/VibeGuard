'use strict';

/*
 * src/platform/backup.js — verified, portable approval-state backups.
 *
 * A backup is a directory containing copied files plus a manifest with SHA-256
 * hashes, sizes and modes. The manifest also records the signed-audit
 * checkpoint/key relationship so restore refuses a truncated or tampered audit
 * chain. Restore is verify-then-copy; it never trusts the backup directory.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { SignedAuditLog } = require('./signed-audit');
const { loadPrivateKey } = require('./identity');

const SCHEMA_VERSION = '1.0';

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function safeName(file, index) {
  const base = path.basename(file).replace(/[^A-Za-z0-9._-]/g, '_');
  return `${String(index).padStart(2, '0')}-${base}`;
}

function createBackup(opts = {}) {
  if (!opts.outDir) throw new Error('backup requires outDir');
  const outDir = path.resolve(opts.outDir);
  if (fs.existsSync(outDir) && fs.readdirSync(outDir).length) throw new Error(`backup directory is not empty: ${outDir}`);
  const files = (opts.files || []).filter(Boolean);
  if (!files.length) throw new Error('backup requires at least one file');
  fs.mkdirSync(path.join(outDir, 'files'), { recursive: true, mode: 0o700 });
  const records = [];
  files.forEach((file, index) => {
    const source = path.resolve(file);
    if (!fs.existsSync(source) || !fs.statSync(source).isFile()) throw new Error(`backup source missing: ${source}`);
    const name = safeName(source, index);
    const dest = path.join(outDir, 'files', name);
    fs.copyFileSync(source, dest, fs.constants.COPYFILE_EXCL);
    const stat = fs.statSync(source);
    fs.chmodSync(dest, 0o600);
    records.push({ name, target: path.basename(source), source, sha256: sha256File(dest), size: stat.size, mode: '600' });
  });
  const audit = opts.auditFile ? records.find((r) => path.resolve(opts.auditFile) === r.source) : null;
  const auditKey = opts.auditKeyFile ? records.find((r) => path.resolve(opts.auditKeyFile) === r.source) : null;
  const manifest = {
    schemaVersion: SCHEMA_VERSION,
    createdAt: new Date().toISOString(),
    label: opts.label ? String(opts.label).slice(0, 200) : null,
    files: records,
    audit: audit ? { file: audit.name, key: auditKey ? auditKey.name : null } : null,
  };
  fs.writeFileSync(path.join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { mode: 0o600 });
  return { outDir, manifest, verify: verifyBackup(outDir) };
}

function verifyBackup(dir) {
  const outDir = path.resolve(dir);
  const manifestPath = path.join(outDir, 'manifest.json');
  const errors = [];
  let manifest;
  try { manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')); } catch (err) {
    return { valid: false, errors: [`manifest unreadable: ${err.message}`], manifest: null };
  }
  if (manifest.schemaVersion !== SCHEMA_VERSION) errors.push(`unsupported schemaVersion: ${manifest.schemaVersion}`);
  const byName = new Map();
  for (const record of manifest.files || []) {
    const file = path.join(outDir, 'files', record.name);
    if (!fs.existsSync(file)) { errors.push(`missing file: ${record.name}`); continue; }
    const hash = sha256File(file);
    if (hash !== record.sha256) errors.push(`hash mismatch: ${record.name}`);
    if (fs.statSync(file).size !== record.size) errors.push(`size mismatch: ${record.name}`);
    byName.set(record.name, file);
  }
  if (manifest.audit) {
    if (!manifest.audit.file || !byName.has(manifest.audit.file)) errors.push('audit log missing from backup');
    if (!manifest.audit.key) errors.push('audit verification key not recorded in backup');
    else if (!byName.has(manifest.audit.key)) errors.push('audit verification key missing from backup');
    else {
      try {
        const privateKey = loadPrivateKey(fs.readFileSync(byName.get(manifest.audit.key)));
        const result = SignedAuditLog.verifyFile(byName.get(manifest.audit.file), { publicKey: crypto.createPublicKey(privateKey) });
        if (!result.valid) errors.push(`audit chain invalid: ${(result.reasons || []).join('; ')}`);
      } catch (err) {
        errors.push(`audit verification failed: ${err.message}`);
      }
    }
  }
  return { valid: errors.length === 0, errors, manifest };
}

function restoreBackup(dir, opts = {}) {
  const sourceDir = path.resolve(dir);
  const targetDir = path.resolve(opts.targetDir || '.');
  const verification = verifyBackup(sourceDir);
  if (!verification.valid) throw new Error(`backup verification failed: ${verification.errors.join('; ')}`);
  if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true, mode: 0o700 });
  const restored = [];
  for (const record of verification.manifest.files || []) {
    const source = path.join(sourceDir, 'files', record.name);
    const target = path.join(targetDir, record.target || path.basename(record.name).replace(/^\d+-/, ''));
    if (restored.includes(target)) throw new Error(`backup contains duplicate target: ${target}`);
    if (fs.existsSync(target) && opts.force !== true) throw new Error(`refusing to overwrite ${target}; pass --force`);
    const tmp = `${target}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
    try {
      fs.copyFileSync(source, tmp, fs.constants.COPYFILE_EXCL);
      fs.chmodSync(tmp, 0o600);
      fs.renameSync(tmp, target);
      restored.push(target);
    } finally {
      try { fs.rmSync(tmp, { force: true }); } catch { /* ignore */ }
    }
  }
  return { restored, verification };
}

module.exports = { createBackup, verifyBackup, restoreBackup, sha256File, SCHEMA_VERSION };
