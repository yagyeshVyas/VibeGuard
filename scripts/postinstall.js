'use strict';

// scripts/postinstall.js — runs after npm install.
// Prints a one-line suggestion. NEVER modifies shell profiles or any file
// outside the installed package. A security tool that silently edits user
// files is doing the thing it warns about.

try {
  // Opt-out + CI quiet: a security tool should not add install-time noise or
  // surprise. VIBEGUARD_NO_POSTINSTALL=1 silences this entirely.
  if (process.env.VIBEGUARD_NO_POSTINSTALL === '1' || process.env.CI) {
    process.exit(0);
  }

  const path = require('path');
  const fs = require('fs');

  const cliPath = path.join(__dirname, '..', 'bin', 'cli.js');
  if (!fs.existsSync(cliPath)) {
    process.exit(0);
  }

  process.stderr.write('\n  VibeGuard installed. Run "vibeguard auto" to enable full protection.\n\n');
  process.exit(0);
} catch {
  process.exit(0);
}