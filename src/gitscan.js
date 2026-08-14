'use strict';

// gitscan — scan a git repository's ENTIRE commit history for leaked secrets
// (Gitleaks / TruffleHog parity). A secret committed months ago and since
// deleted is still found: it lives in history.
//
//   const { scanGitHistory } = require('../src/gitscan');
//   const { findings, stats } = await scanGitHistory('.', { since: '2024-01-01' });
//
// Strategy:
//   1. Enumerate every blob ever committed: `git rev-list --objects --all`
//      (honoring --since / --max-commits passthroughs), deduped by blob sha.
//   2. Stream blob contents via `git cat-file --batch` (one long-lived process,
//      NUL-byte check on the first 8KB skips binary blobs).
//   3. Run the existing secret.* regex rules over every line (same rules +
//      filters as the working-tree scanner; matches are masked before they
//      ever reach a report).
//   4. Attribute each finding to the earliest commit that introduced its blob
//      (`git log --reverse -- <path>`, --find-object fallback).

const { spawn, execFile } = require('child_process');
const { matchAll } = require('./rules');

const MAX_BLOB_BYTES = 8 * 1024 * 1024; // bigger blobs are scanned but not buffered whole
const MAX_BLOBS_DEFAULT = 20000;

function runGit(dir, args, maxBuffer) {
  return new Promise((resolve, reject) => {
    execFile('git', args, {
      cwd: dir,
      maxBuffer: maxBuffer || 64 * 1024 * 1024,
      windowsHide: true,
      timeout: 300000,
    }, (err, stdout, stderr) => {
      if (err) {
        const e = new Error((stderr || '').trim() || err.message);
        e.code = err.code; // ENOENT = git missing, 128 = git itself failed
        reject(e);
      } else {
        resolve(stdout);
      }
    });
  });
}

// Earliest commit that introduced the blob: first line of `git log --reverse`
// for its path (oldest first). Falls back to --find-object=<sha> when the
// path-based query comes up empty.
async function earliestCommit(dir, path, sha) {
  try {
    const out = await runGit(dir, ['log', '--all', '--format=%H', '--reverse', '--', path]);
    const first = out.split('\n').map((s) => s.trim()).find((s) => s.length > 0);
    if (first) return first;
  } catch { /* fall through to --find-object */ }
  try {
    const out = await runGit(dir, ['log', '--all', '--format=%H', '--reverse', `--find-object=${sha}`]);
    const first = out.split('\n').map((s) => s.trim()).find((s) => s.length > 0);
    return first || null;
  } catch {
    return null;
  }
}

// Mask a secret exactly like src/scanner.js's redactSnippet: first4****last2.
// Never echo a full secret into a report.
function maskMatch(match) {
  if (!match) return '';
  if (match.length < 8) return '****';
  return match.slice(0, 4) + '****' + match.slice(-2);
}

// Run the secret rules over one blob's content.
function scanContent(content, blob, rules) {
  const findings = [];
  const nul = content.indexOf(0);
  if (nul !== -1 && nul < 8192) return findings; // binary blob — skip
  const text = content.toString('utf8');
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 4000) continue; // minified blob line — skip
    for (const rule of rules) {
      for (const hit of matchAll(rule.re, line)) {
        if (rule.filter && !rule.filter(line, hit)) continue;
        findings.push({
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity || 'critical',
          path: blob.path,
          blobSha: blob.sha,
          line: i + 1,
          column: hit.index + 1,
          match: maskMatch(hit.match),
        });
      }
    }
  }
  return findings;
}

// Stream every blob through `git cat-file --batch`: write "<sha>\n", read
// "<sha> blob <size>\n<content>\n". One request in flight at a time.
function forEachBlobContent(dir, blobs, fn) {
  return new Promise((resolve, reject) => {
    if (blobs.length === 0) return resolve();
    const child = spawn('git', ['cat-file', '--batch'], {
      cwd: dir,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });

    let buf = Buffer.alloc(0);
    let phase = 'header'; // 'header' | 'content' | 'skip'
    let curSize = 0;
    let skipRemaining = 0;
    let idx = 0;
    let current = null;
    let done = false;
    let scanErr = null;

    const timer = setTimeout(() => {
      done = true;
      child.kill();
      reject(new Error('git cat-file timed out'));
    }, 300000);

    const requestNext = () => {
      if (done) return;
      current = blobs[idx++];
      if (!current) {
        child.stdin.end();
        return;
      }
      child.stdin.write(current.sha + '\n');
    };
    requestNext();

    child.stdout.on('data', (chunk) => {
      if (done) return;
      buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
      while (true) {
        if (phase === 'header') {
          const nl = buf.indexOf(10);
          if (nl === -1) break;
          const header = buf.slice(0, nl).toString('utf8');
          buf = buf.slice(nl + 1);
          const parts = header.split(' ');
          if (parts.length === 3 && parts[1] === 'blob') {
            curSize = parseInt(parts[2], 10) || 0;
            phase = curSize > MAX_BLOB_BYTES ? 'skip' : 'content';
            skipRemaining = curSize;
          } else {
            // "<sha> missing" or a non-blob object — skip and move on.
            current = null;
            requestNext();
          }
        } else if (phase === 'content') {
          if (buf.length >= curSize + 1) {
            const content = buf.slice(0, curSize);
            buf = buf.slice(curSize + 1); // trailing newline after content
            phase = 'header';
            if (current) {
              const b = current;
              current = null;
              try { fn(b, content); } catch (err) { if (!scanErr) scanErr = err; }
            }
            requestNext();
          } else {
            break;
          }
        } else {
          // 'skip' — oversized blob: consume and discard without buffering.
          if (buf.length >= skipRemaining + 1) {
            buf = buf.slice(skipRemaining + 1);
            phase = 'header';
            current = null;
            requestNext();
          } else {
            skipRemaining -= buf.length;
            buf = Buffer.alloc(0);
            break;
          }
        }
      }
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      if (!done) {
        done = true;
        reject(err);
      }
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (done) return;
      done = true;
      if (scanErr) reject(scanErr);
      else if (code !== 0) reject(new Error(`git cat-file failed (${code}): ${stderr.trim()}`));
      else resolve();
    });
  });
}

async function scanGitHistory(dir, opts) {
  opts = opts || {};
  const t0 = Date.now();
  const maxBlobs = Math.max(1, parseInt(opts.maxBlobs, 10) || MAX_BLOBS_DEFAULT);

  const revArgs = ['rev-list', '--objects', '--all'];
  if (opts.since) revArgs.push(`--since=${opts.since}`);
  if (opts.maxCommits) revArgs.push(`--max-count=${Math.max(1, parseInt(opts.maxCommits, 10) || 1)}`);

  let out;
  try {
    out = await runGit(dir, revArgs, 128 * 1024 * 1024);
  } catch {
    const e = new Error(`not a git repository: ${dir}`);
    e.code = 'NOT_A_REPO';
    throw e;
  }

  // Parse "<blobSha> <path>" lines; commit/tree lines have no path (skip).
  const blobs = [];
  const seen = new Set();
  for (const line of out.split('\n')) {
    const sp = line.indexOf(' ');
    if (sp === -1) continue;
    const sha = line.slice(0, sp);
    const p = line.slice(sp + 1).trim();
    if (!/^[0-9a-f]{40}$/.test(sha) || !p || seen.has(sha)) continue;
    seen.add(sha);
    blobs.push({ sha, path: p });
    if (blobs.length >= maxBlobs) break;
  }

  // Commit count for stats (honors --since so the numbers stay consistent).
  let commits = 0;
  try {
    const countArgs = ['rev-list', '--all', '--count'];
    if (opts.since) countArgs.push(`--since=${opts.since}`);
    commits = parseInt((await runGit(dir, countArgs)).trim(), 10) || 0;
  } catch { /* best-effort */ }

  const rules = require('./rules');
  const secretRules = rules.secretRules.filter((r) => r.re);

  const findings = [];
  let scanned = 0;
  await forEachBlobContent(dir, blobs, (blob, content) => {
    scanned++;
    for (const f of scanContent(content, blob, secretRules)) findings.push(f);
  });

  // Attribution: earliest commit per path (only runs for blobs with findings).
  const commitCache = new Map();
  for (const f of findings) {
    if (!commitCache.has(f.path)) {
      commitCache.set(f.path, await earliestCommit(dir, f.path, f.blobSha));
    }
    f.commit = commitCache.get(f.path);
  }

  // Dedupe identical hits (same rule, path, line, match) across history.
  const unique = [];
  const keys = new Set();
  for (const f of findings) {
    const k = `${f.ruleId}:${f.path}:${f.line}:${f.match}`;
    if (keys.has(k)) continue;
    keys.add(k);
    unique.push(f);
  }

  return {
    findings: unique,
    stats: { blobs: scanned, commits, durationMs: Date.now() - t0 },
  };
}

module.exports = { scanGitHistory, maskMatch };
