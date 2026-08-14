'use strict';

// cmdGitScan — `vibeguard git-scan [dir]`: scan the ENTIRE git history for
// leaked secrets (Gitleaks / TruffleHog parity). A secret committed months ago
// and since deleted is still found — it lives in history.
//
//   vibeguard git-scan                      # scan the current repo's history
//   vibeguard git-scan ../other-repo        # scan another repo
//   vibeguard git-scan --since 2024-01-01   # only commits after a date
//   vibeguard git-scan --max-blobs 5000     # cap blobs examined (default 20000)
//   vibeguard git-scan --json               # machine-readable findings array
//   vibeguard git-scan --output out.json    # also write findings to a file
//
// Exit codes: 0 = clean, 1 = findings, 2 = usage / not-a-repo / git errors.
// Matches are always masked (first4****last2) — never printed raw.

const fs = require('fs');
const path = require('path');

const C = {
  bold: '\x1b[1m', dim: '\x1b[2m', green: '\x1b[32m', cyan: '\x1b[36m',
  yellow: '\x1b[33m', red: '\x1b[31m', reset: '\x1b[0m',
};

async function cmdGitScan(args, flags) {
  const dir = path.resolve(args._[1] || '.');
  const { scanGitHistory } = require('../src/gitscan');

  if (flags.help || flags.h) {
    process.stderr.write('usage: vibeguard git-scan [dir] [--since <date>] [--max-blobs N] [--max-commits N] [--json] [--output file.json]\n');
    return 2;
  }

  let result;
  try {
    result = await scanGitHistory(dir, {
      since: flags.since,
      maxBlobs: flags['max-blobs'],
      maxCommits: flags['max-commits'],
    });
  } catch (err) {
    process.stderr.write(`git-scan: ${err.message}\n`);
    return 2;
  }

  const findings = result.findings;

  if (flags.json) {
    process.stdout.write(JSON.stringify(findings, null, 2) + '\n');
  } else if (findings.length > 0) {
    process.stdout.write(`${C.bold}${C.red}${findings.length} secret(s) found in git history${C.reset}\n`);
    process.stdout.write(`${C.dim}commit | path | rule | match (redacted)${C.reset}\n`);
    for (const f of findings) {
      const sha = (f.commit || '').slice(0, 8);
      process.stdout.write(`  ${C.yellow}${sha}${C.reset} | ${f.path} | ${f.ruleId} | ${C.red}${f.match}${C.reset}\n`);
    }
    process.stdout.write(`${C.dim}${findings.length} finding(s) across ${result.stats.blobs} blob(s) (${result.stats.durationMs} ms)${C.reset}\n`);
  } else {
    process.stdout.write(`${C.green}✓${C.reset} no secrets in git history (${result.stats.blobs} blobs, ${result.stats.commits} commits, ${result.stats.durationMs} ms)\n`);
  }

  if (flags.output) {
    try {
      fs.writeFileSync(path.resolve(String(flags.output)), JSON.stringify(findings, null, 2) + '\n');
    } catch (err) {
      process.stderr.write(`git-scan: cannot write output file: ${err.message}\n`);
      return 2;
    }
  }

  return findings.length > 0 ? 1 : 0;
}

module.exports = { cmdGitScan };
