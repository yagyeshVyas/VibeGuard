'use strict';

// cmdSbomDiff — `vibeguard sbom-diff <base> <head>`: compare two project
// snapshots (e.g. main vs. PR) and report dependency drift at supply-chain
// level (CycloneDX). 100% offline; the diff is computed from the SBOMs.

const C = {
  bold: '\x1b[1m', dim: '\x1b[2m', red: '\x1b[31m', green: '\x1b[32m',
  yellow: '\x1b[33m', cyan: '\x1b[36m', reset: '\x1b[0m',
};

function cmdSbomDiff(args, flags) {
  const baseDir = args._[1] || '.';
  const headDir = args._[2] || '.';
  const { diffSBOM } = require('../src/sbom');
  let d;
  try {
    d = diffSBOM(baseDir, headDir);
  } catch (e) {
    process.stderr.write(`sbom-diff: ${e.message}\n`);
    return 2;
  }
  if (flags.json || flags.output === 'json') {
    process.stdout.write(JSON.stringify(d, null, 2) + '\n');
    return 0;
  }
  process.stdout.write(`${C.bold}VibeGuard SBOM Diff${C.reset}\n`);
  process.stdout.write(`${C.dim}${'─'.repeat(60)}${C.reset}\n\n`);
  process.stdout.write(`  Base:    ${d.base}\n`);
  process.stdout.write(`  Head:    ${d.head}\n\n`);
  process.stdout.write(`  ${C.green}+${d.counts.added}${C.reset} added   ${C.red}-${d.counts.removed}${C.reset} removed   ${C.yellow}~${d.counts.changed}${C.reset} changed\n\n`);
  for (const c of d.added)   process.stdout.write(`  ${C.green}+${C.reset} ${c.name}@${c.version}\n`);
  for (const c of d.removed) process.stdout.write(`  ${C.red}-${C.reset} ${c.name}@${c.version}\n`);
  for (const c of d.changed) process.stdout.write(`  ${C.yellow}~${C.reset} ${c.name}: ${c.from} -> ${c.to}\n`);
  return 0;
}

module.exports = { cmdSbomDiff };
