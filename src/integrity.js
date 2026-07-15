'use strict';

/*
 * src/integrity.js — self-integrity verification.
 *
 * A security tool that has been silently patched is worse than none: an
 * attacker (or a compromised dependency's postinstall) could neuter a rule file
 * or make the action firewall always return "allow". `self-check` used to only
 * verify that modules *load* — this verifies their *content* against a manifest
 * of SHA-256 hashes generated at publish time (scripts/gen-integrity.js).
 *
 * Limits (stated honestly): this detects tampering with the guard's source. It
 * is not a full chain of trust — an attacker who rewrites both a module AND the
 * manifest defeats it. It raises the bar and catches the common case (patched
 * rules / neutered guard) that a load-only check misses. For a real trust
 * anchor, verify the package's npm provenance / signature on install.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// The modules whose integrity actually matters for security decisions.
const CRITICAL_MODULES = [
  'action-guard.js', 'shell-guard.js', 'interceptor.js', 'firewall.js',
  'pii.js', 'rules.js', 'scanner.js', 'engine.js',
  'mcp-audit.js', 'agent-scan.js', 'secure-prompt.js', 'ai-guard.js',
  'taint.js', 'taint-ast.js', 'ast.js',
];

function hashFile(p) {
  const content = fs.readFileSync(p, 'utf8').replace(/\r\n/g, '\n');
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

function computeManifest(srcDir) {
  const hashes = {};
  for (const f of CRITICAL_MODULES) {
    const p = path.join(srcDir, f);
    if (fs.existsSync(p)) hashes[f] = hashFile(p);
  }
  return { tool: 'vibeguard', generatedAt: new Date().toISOString(), algo: 'sha256', hashes };
}

// Verify the modules in `srcDir` against the shipped integrity.json.
function verifyIntegrity(srcDir) {
  srcDir = srcDir || __dirname;
  const manifestPath = path.join(srcDir, 'integrity.json');
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch {
    return { available: false, intact: null, reason: 'no integrity manifest (integrity.json) found' };
  }
  const expected = (manifest && manifest.hashes) || {};
  const modified = [];
  const missing = [];
  for (const [f, h] of Object.entries(expected)) {
    const p = path.join(srcDir, f);
    if (!fs.existsSync(p)) { missing.push(f); continue; }
    let actual;
    try { actual = hashFile(p); } catch { missing.push(f); continue; }
    if (actual !== h) modified.push(f);
  }
  return {
    available: true,
    intact: modified.length === 0 && missing.length === 0,
    modified,
    missing,
    checked: Object.keys(expected).length,
    generatedAt: manifest.generatedAt,
  };
}

module.exports = { verifyIntegrity, computeManifest, hashFile, CRITICAL_MODULES };
