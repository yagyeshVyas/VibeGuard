'use strict';

// scripts/gen-integrity.js — regenerate src/integrity.json with fresh SHA-256
// hashes of the critical security modules. Run before publish (wired into
// prepublishOnly) so the shipped package can self-verify it wasn't tampered.

const fs = require('fs');
const path = require('path');
const { computeManifest } = require('../src/integrity');

const srcDir = path.join(__dirname, '..', 'src');
const manifest = computeManifest(srcDir);
const out = path.join(srcDir, 'integrity.json');
fs.writeFileSync(out, JSON.stringify(manifest, null, 2) + '\n');
process.stdout.write(`integrity.json written: ${Object.keys(manifest.hashes).length} modules hashed.\n`);
