'use strict';

/*
 * Git-history secret scan.
 *
 * A secret committed then "removed" still lives in git history and is
 * compromised. This walks recent history (`git log -p`) and runs the secret
 * rules over ADDED lines, reporting the commit where each secret was introduced.
 *
 * Non-fatal: not a git repo / no git = empty result with a note.
 */

const { execSync, execFileSync } = require('child_process');
const { secretRules, matchAll } = require('./rules');

const isWin = process.platform === 'win32';

function git(args, cwd) {
  const opts = { cwd, timeout: 120000, maxBuffer: 128 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true };
  return (isWin ? execSync(['git', ...args].join(' '), opts) : execFileSync('git', args, opts)).toString('utf8');
}

function scanHistory(root, opts = {}) {
  // Default: recent 500 commits (fast). opts.all -> full history, every branch.
  const args = ['log', '-p', '--no-color'];
  if (opts.all) args.push('--all');
  else args.push(`--max-count=${opts.maxCount || 500}`);
  args.push('--', '.');
  let out;
  try {
    out = git(args, root);
  } catch (err) {
    return { findings: [], ran: false, note: `git history unavailable (${err.code || err.message})` };
  }

  const findings = [];
  const seen = new Set();
  let commit = '';
  let file = '';
  let addedLineNo = 0;

  for (const raw of out.split('\n')) {
    if (raw.startsWith('commit ')) {
      commit = raw.slice(7, 17);
      continue;
    }
    if (raw.startsWith('+++ b/')) {
      file = raw.slice(6);
      addedLineNo = 0;
      continue;
    }
    const hunk = /^@@ .*\+(\d+)/.exec(raw);
    if (hunk) {
      addedLineNo = parseInt(hunk[1], 10) - 1;
      continue;
    }
    if (raw.startsWith('+') && !raw.startsWith('+++')) {
      addedLineNo++;
      const line = raw.slice(1);
      for (const rule of secretRules) {
        for (const hit of matchAll(rule.re, line)) {
          if (rule.filter && !rule.filter(line, hit)) continue;
          const key = `${rule.id}:${file}:${hit.match.slice(0, 12)}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({
            ruleId: `history.${rule.id}`,
            severity: 'critical',
            confidence: 'high',
            title: `Secret in git history: ${rule.title}`,
            message: `${rule.message} Found in commit ${commit} (${file}). It remains in history even if later removed — treat as compromised.`,
            fix: `Rotate the secret now, then purge it from history (git filter-repo / BFG) and force-push.`,
            file,
            line: addedLineNo,
            column: hit.index + 1,
            snippet: `${commit} ${hit.match.slice(0, 4)}****`,
          });
        }
      }
    } else if (raw.startsWith(' ')) {
      addedLineNo++;
    }
  }
  return { findings, ran: true, note: null };
}

module.exports = { scanHistory };
