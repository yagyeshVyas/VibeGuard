'use strict';

// cmdPrScan — `vibeguard pr-scan`: review ONLY the changed lines (PR gate).
//
// Strix-compatible semantics: exit 0 = clean, 2 = vulnerabilities found
// (CI gate fails), 1 = fatal error. Diff-scoped: findings outside the changed
// lines are suppressed, so CI stays fast and pre-existing debt doesn't block
// merges — new findings do.
//
//   vibeguard pr-scan                      # working tree vs HEAD (uncommitted)
//   vibeguard pr-scan --staged             # staged changes only
//   vibeguard pr-scan --base origin/main   # commits in HEAD..origin/main... 
//                                          # (branch PR range, Strix --diff-base)
//   vibeguard pr-scan --json
//
// Taint-correct: the FULL file is analyzed (so dataflow rules stay accurate),
// but only findings whose line is an ADDED line are reported.

const { execFileSync } = require('child_process');

const C = {
  bold: '\x1b[1m', dim: '\x1b[2m', red: '\x1b[31m', green: '\x1b[32m',
  yellow: '\x1b[33m', cyan: '\x1b[36m', reset: '\x1b[0m',
};

function git(dir, args) {
  return execFileSync('git', args, { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
}

/**
 * Compute the set of added lines per file for the requested diff scope.
 * @returns {{added: Map<string, Set<number>>, files: string[]}}
 */
function addedLines(dir, scope) {
  const args = ['diff'];
  if (scope.staged) args.push('--staged');
  else if (scope.base) args.push(scope.base + '...HEAD');
  else args.push('HEAD');
  args.push('--unified=0');
  const out = git(dir, args);
  const added = new Map();
  let curFile = null;
  let curLine = 0;
  for (const raw of out.split('\n')) {
    const line = raw;
    if (line.startsWith('+++ b/')) {
      curFile = line.slice(6);
      if (!added.has(curFile)) added.set(curFile, new Set());
      continue;
    }
    if (line.startsWith('@@')) {
      // @@ -oldStart,oldLen +newStart,newLen @@
      const m = /\+(\d+)(?:,(\d+))?/.exec(line);
      curLine = m ? Number(m[1]) : 0;
      continue;
    }
    if (curFile && line.startsWith('+') && !line.startsWith('+++')) {
      added.get(curFile).add(curLine);
      curLine++;
    } else if (curFile && !line.startsWith('-')) {
      curLine++;
    }
  }
  return { added, files: [...added.keys()] };
}

async function runPrScan(dir, opts = {}) {
  const scope = { staged: !!opts.staged, base: opts.base || null };
  const { added, files } = addedLines(dir, scope);
  if (files.length === 0) {
    return { findings: [], files: [], stats: { addedLines: 0, scannedFiles: 0 } };
  }

  const { scanFileContent } = require('../src/scanner');
  const fs = require('fs');
  const path = require('path');

  const findings = [];
  let addedTotal = 0;
  for (const rel of files) {
    const lines = added.get(rel);
    addedTotal += lines.size;
    const abs = path.join(dir, rel);
    let content;
    try {
      content = fs.readFileSync(abs, 'utf8');
    } catch {
      continue; // deleted in the diff or unreadable — skip
    }
    const res = scanFileContent(abs, rel, content, null, null);
    const arr = Array.isArray(res) ? res : (res.findings || []);
    for (const f of arr) {
      if (lines.has(f.line)) findings.push(f);
    }
  }
  return { findings, files, stats: { addedLines: addedTotal, scannedFiles: files.length } };
}

async function cmdPrScan(args, flags) {
  const f = flags || {};
  const dir = args._[1] || '.';
  const json = !!f.json;

  let result;
  try {
    result = await runPrScan(dir, { staged: !!f.staged, base: f.base !== undefined && f.base !== true ? String(f.base) : null });
  } catch (err) {
    process.stderr.write(`pr-scan: fatal: ${err.message} (is ${dir} a git repo?)\n`);
    return 1; // Strix-compatible: 1 = fatal error
  }

  if (json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return result.findings.length > 0 ? 2 : 0;
  }

  process.stdout.write(`\n${C.bold}VibeGuard PR scan${C.reset} — ${dir}\n`);
  process.stdout.write(`${C.dim}${result.stats.scannedFiles} changed file(s), ${result.stats.addedLines} added line(s)${C.reset}\n\n`);
  if (result.findings.length === 0) {
    process.stdout.write(`${C.green}✓ No issues in the diff.${C.reset} Pre-existing findings outside the change are not reported.\n`);
    return 0;
  }
  for (const fnd of result.findings) {
    const sev = String(fnd.severity || 'medium');
    const color = sev === 'critical' || sev === 'high' ? C.red : sev === 'medium' ? C.yellow : C.dim;
    process.stdout.write(
      `${color}${sev.toUpperCase().padEnd(9)}${C.reset}${fnd.file}:${fnd.line} [${fnd.ruleId}] ${fnd.message || fnd.title || ''}\n`
    );
    if (fnd.fix) process.stdout.write(`  ${C.dim}fix: ${fnd.fix}${C.reset}\n`);
  }
  process.stdout.write(`\n${C.red}${result.findings.length} finding(s) in the diff — gate FAILS (exit 2).${C.reset}\n`);
  return 2; // Strix-compatible: 2 = vulnerabilities found
}

module.exports = { cmdPrScan, runPrScan };
