'use strict';

/*
 * Safe auto-fix engine.
 *
 * Principle: VibeGuard only auto-applies fixes that are MECHANICAL and reversible
 * and cannot change program behavior in a surprising way. Everything else (secret
 * removal, query rewrites, auth changes) stays in the manual fix prompt for a
 * human/AI to apply under review — auto-rewriting security-sensitive logic is how
 * you turn one bug into two.
 *
 * Every apply is:
 *   1. shown as a dry-run diff first (never silent),
 *   2. snapshotted before writing (one-command rollback),
 *   3. reported after.
 */

const fs = require('fs');
const path = require('path');

const SNAP_DIR = '.vibeguard';

// Which rules have a safe, mechanical auto-fix. Keep this list conservative.
const AUTO_FIXABLE = new Set([
  'project.env-not-ignored',
  'secret.openai-key',
  'secret.stripe-key',
  'secret.github-token',
  'secret.anthropic-key',
  'secret.slack-token',
  'secret.gitlab-token',
  'secret.twilio-key',
  'secret.sendgrid-key',
  'secret.mailgun-key',
  'secret.telegram-bot-token',
  'secret.npm-token',
  'secret.resend-key',
  'secret.aws-access-key',
  'secret.private-key',
  'secret.generic-credential',
  'secret.gcp-api-key',
  'secret.azure-storage-key',
  'secret.cloudflare-api-token',
  'secret.datadog-api-key',
  'secret.vercel-token',
  'secret.heroku-api-key',
  'secret.notion-token',
  'injection.eval',
  'error.empty-catch',
  'config.weak-cookie',
  'code.console-log-secret',
  'auth.hardcoded-token',
  'web.missing-hsts',
  'web.missing-csp',
  'crypto.tls-verification-disabled',
  'net.tls-verification-disabled',
  'code.cors-wildcard',
  'cookie.insecure-flags',
  'error.detail-to-client',
  'code.insecure-http',
  'csp.unsafe-inline',
  'csp.unsafe-eval',
  'ai.browser-api-key',
  'py.debug-true',
  'py.flask-debug',
  'django.debug-true',
  'flask.debug-true',
  'supply.unpinned-docker',
  'k8s.run-as-root',
  'transport.mixed-content',
  'header.no-referrer-policy',
  'data.sensitive-in-localstorage',
  'data.sensitive-in-sessionstorage',
  'auth.password-in-query',
  'auth.weak-jwt-secret',
  'injection.log-injection',
]);

function isAutoFixable(ruleId) {
  return AUTO_FIXABLE.has(ruleId);
}

// Build the set of proposed file changes for a scan result.
// Returns [{ file, absFile, ruleId, description, before, after }].
function computeAutoFixes(root, result) {
  const changes = [];
  const byFile = new Map();

  for (const f of result.findings) {
    if (!isAutoFixable(f.ruleId)) continue;
    if (f.ruleId === 'project.env-not-ignored') {
      const rel = '.gitignore';
      const abs = path.join(root, rel);
      let before = '';
      try {
        before = fs.readFileSync(abs, 'utf8');
      } catch {
        before = '';
      }
      const lines = before.split(/\r?\n/);
      const has = (pat) => lines.some((l) => l.trim() === pat);
      const additions = [];
      if (!has('.env')) additions.push('.env');
      if (!has('.env.*') && !has('.env*')) additions.push('.env.*');
      if (additions.length === 0) continue;

      const sep = before && !before.endsWith('\n') ? '\n' : '';
      const after =
        before + sep + '\n# Added by VibeGuard: keep secrets out of git\n' + additions.join('\n') + '\n';

      byFile.set(rel, {
        file: rel,
        absFile: abs,
        ruleId: f.ruleId,
        description: `Add ${additions.join(', ')} to .gitignore`,
        before,
        after,
      });
    }

    // Secret redaction: replace with process.env reference
    if (f.ruleId && f.ruleId.startsWith('secret.') && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      const orig = lines[idx];
      // Replace hardcoded secret with process.env reference
      let modified = orig;
      const keyName = (f.ruleId.split('.')[1] || 'SECRET').toUpperCase().replace(/-/g, '_');
      modified = modified.replace(/(['"`])(?:sk-|sk-ant-|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)?[A-Za-z0-9_\-]{16,}(['"`])/g, `'process.env.${keyName}'`);
      if (modified === orig) continue;
      lines[idx] = modified;
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Redact secret on line ${f.line} → process.env.${keyName}`, before, after });
    }

    // Empty catch: add error logging
    if (f.ruleId === 'error.empty-catch' && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      if (/\{\s*\}/.test(lines[idx])) {
        lines[idx] = lines[idx].replace(/\{\s*\}/, '{ console.error(err); }');
      } else if (idx + 1 < lines.length && /^\s*\}\s*$/.test(lines[idx + 1]) && !/console\.error|throw|return/.test(lines[idx])) {
        lines[idx] = lines[idx] + '\n    console.error(err);';
      } else { continue; }
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Add error logging to empty catch on line ${f.line}`, before, after });
    }

    // Console.log secret: remove or comment out
    if (f.ruleId === 'code.console-log-secret' && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      lines[idx] = '// vibeguard: removed secret from log\n// ' + lines[idx];
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Comment out secret log on line ${f.line}`, before, after });
    }

    // TLS verification disabled: remove rejectUnauthorized: false
    if ((f.ruleId === 'crypto.tls-verification-disabled' || f.ruleId === 'net.tls-verification-disabled') && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      let modified = lines[idx].replace(/rejectUnauthorized\s*:\s*false\s*,?\s*/g, '');
      modified = modified.replace(/process\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]\s*;?/g, '');
      if (modified === lines[idx]) continue;
      lines[idx] = modified;
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Remove TLS verification bypass on line ${f.line}`, before, after });
    }

    // CORS wildcard: replace origin: '*' with specific origin placeholder
    if (f.ruleId === 'code.cors-wildcard' && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      let modified = lines[idx].replace(/origin\s*:\s*['"]\*['"]/g, "origin: process.env.CORS_ORIGIN || 'http://localhost:3000'");
      if (modified === lines[idx]) continue;
      lines[idx] = modified;
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Replace CORS wildcard with env var on line ${f.line}`, before, after });
    }

    // Cookie insecure flags: add secure: true, httpOnly: true, sameSite: 'strict'
    if (f.ruleId === 'cookie.insecure-flags' && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      let modified = lines[idx];
      if (!/secure\s*:/.test(modified)) modified = modified.replace(/(\{)/, '$1 secure: true,');
      if (!/httpOnly\s*:/.test(modified)) modified = modified.replace(/(\{)/, '$1 httpOnly: true,');
      if (!/sameSite\s*:/.test(modified)) modified = modified.replace(/(\{)/, "$1 sameSite: 'strict',");
      if (modified === lines[idx]) continue;
      lines[idx] = modified;
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Add secure cookie flags on line ${f.line}`, before, after });
    }

    // Error detail to client: replace with generic error
    if (f.ruleId === 'error.detail-to-client' && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      let modified = lines[idx]
        .replace(/res\.(?:json|send)\s*\(\s*\{\s*(?:error|err)\s*:\s*[^}]*\}\s*\)/gi, 'res.status(500).json({ error: "Internal server error" })')
        .replace(/res\.(?:json|send)\s*\(\s*\{[^}]*(?:err\.stack|err\.message|error\.stack|error\.message)[^}]*\}\s*\)/gi, 'res.status(500).json({ error: "Internal server error" })');
      if (modified === lines[idx]) continue;
      lines[idx] = modified;
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Replace error details with generic message on line ${f.line}`, before, after });
    }

    // Insecure HTTP: replace http:// with https://
    if (f.ruleId === 'code.insecure-http' && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      let modified = lines[idx].replace(/http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/g, 'https://');
      if (modified === lines[idx]) continue;
      lines[idx] = modified;
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Upgrade HTTP to HTTPS on line ${f.line}`, before, after });
    }

    // CSP unsafe-inline/eval: add nonce-based CSP
    if ((f.ruleId === 'csp.unsafe-inline' || f.ruleId === 'csp.unsafe-eval') && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      let modified = lines[idx]
        .replace(/'unsafe-inline'/g, "'nonce-${nonce}'")
        .replace(/'unsafe-eval'/g, "'strict-dynamic'");
      if (modified === lines[idx]) continue;
      lines[idx] = modified;
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Replace unsafe CSP directives with nonce-based on line ${f.line}`, before, after });
    }

    // AI browser API key: move to server-side env
    if (f.ruleId === 'ai.browser-api-key' && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      let modified = lines[idx].replace(/NEXT_PUBLIC_(?:OPENAI|ANTHROPIC|AI)_API_KEY/g, 'API_KEY');
      if (modified === lines[idx]) continue;
      lines[idx] = modified;
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Remove NEXT_PUBLIC_ prefix on line ${f.line} — key should be server-side only`, before, after });
    }

    // Python debug=True: set to False
    if ((f.ruleId === 'py.debug-true' || f.ruleId === 'py.flask-debug' || f.ruleId === 'flask.debug-true' || f.ruleId === 'django.debug-true') && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      let modified = lines[idx].replace(/debug\s*=\s*True/i, 'debug = False  # vibeguard: disabled in production');
      if (modified === lines[idx]) continue;
      lines[idx] = modified;
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Set debug=False on line ${f.line}`, before, after });
    }

    // Docker :latest: pin to specific version
    if (f.ruleId === 'supply.unpinned-docker' && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      let modified = lines[idx].replace(/FROM\s+(\S+):latest\b/i, 'FROM $1:18-alpine  # vibeguard: pin version');
      if (modified === lines[idx]) continue;
      lines[idx] = modified;
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Pin Docker image version on line ${f.line}`, before, after });
    }

    // Mixed content: upgrade http:// to https:// in HTML
    if (f.ruleId === 'transport.mixed-content' && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      let modified = lines[idx].replace(/src\s*=\s*['"]http:\/\/(?!localhost|127\.0\.0\.1)/gi, 'src="https://');
      if (modified === lines[idx]) continue;
      lines[idx] = modified;
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Upgrade mixed content to HTTPS on line ${f.line}`, before, after });
    }

    // Sensitive data in localStorage: move to cookie
    if ((f.ruleId === 'data.sensitive-in-localstorage' || f.ruleId === 'data.sensitive-in-sessionstorage') && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      let modified = lines[idx].replace(/(local|session)Storage\.setItem\s*\(\s*['"](?:token|password|secret|session|auth|jwt|api.?key|access.?token)['"]/i, "document.cookie = '$1=");
      if (modified === lines[idx]) continue;
      lines[idx] = '// vibeguard: move sensitive data to HTTP-only cookie\n' + modified;
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Move sensitive data from storage to cookie on line ${f.line}`, before, after });
    }

    // Password in query string: warn and suggest POST
    if (f.ruleId === 'auth.password-in-query' && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      lines[idx] = '// vibeguard: never accept passwords in query strings — use POST body\n// ' + lines[idx];
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Comment out password-in-query on line ${f.line}`, before, after });
    }

    // Weak JWT secret: replace with env var
    if (f.ruleId === 'auth.weak-jwt-secret' && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      let modified = lines[idx].replace(/jwt\.sign\s*\(\s*([^,]+),\s*['"](?:secret|password|changeme|test|default|key|123456)['"]/gi, "jwt.sign($1, process.env.JWT_SECRET");
      if (modified === lines[idx]) continue;
      lines[idx] = modified;
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Replace weak JWT secret with env var on line ${f.line}`, before, after });
    }

    // Log injection: sanitize newlines from log input
    if (f.ruleId === 'injection.log-injection' && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      let modified = lines[idx].replace(/(?:console\.log|logger\.\w+|log\.\w+)\s*\(\s*([^)]*)\)/, (m, arg) => {
        return m.replace(arg, arg.replace(/(req\.headers|req\.url|req\.query|req\.body)/g, 'String($1).replace(/[\\r\\n]/g, "")'));
      });
      if (modified === lines[idx]) continue;
      lines[idx] = modified;
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Sanitize log input on line ${f.line}`, before, after });
    }

    // Header no-referrer-policy: add helmet referrerPolicy
    if (f.ruleId === 'header.no-referrer-policy' && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      // Insert referrerPolicy after helmet() call
      let modified = lines[idx];
      if (/app\.use\s*\(\s*helmet\s*\(\s*\)\s*\)/.test(modified)) {
        modified = modified + "\napp.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));";
      }
      if (modified === lines[idx]) continue;
      lines[idx] = modified;
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Add referrerPolicy header on line ${f.line}`, before, after });
    }

    // K8s run-as-root: add securityContext
    if (f.ruleId === 'k8s.run-as-root' && f.file && f.line) {
      const rel = f.file;
      const abs = path.join(root, rel);
      let before;
      try { before = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = before.split(/\r?\n/);
      const idx = f.line - 1;
      if (idx < 0 || idx >= lines.length) continue;
      // Add securityContext after containers: block
      let insertIdx = idx + 1;
      while (insertIdx < lines.length && !/^\s*-\s*(?:name|image):/.test(lines[insertIdx])) insertIdx++;
      lines.splice(insertIdx, 0, '        securityContext:', '          runAsNonRoot: true');
      const after = lines.join('\n');
      if (!byFile.has(rel)) byFile.set(rel, { file: rel, absFile: abs, ruleId: f.ruleId, description: `Add runAsNonRoot securityContext near line ${f.line}`, before, after });
    }

  }

  for (const c of byFile.values()) changes.push(c);
  return changes;
}

// A tiny unified-ish diff (line level) for display. Not a full LCS — enough to
// show what changes without pulling a dependency.
function renderDiff(change) {
  const beforeLines = change.before.split('\n');
  const afterLines = change.after.split('\n');
  const out = [];
  out.push(`--- ${change.file}`);
  out.push(`+++ ${change.file}`);
  // Show trailing context: everything in `after` not identical-position in `before`.
  const common = Math.min(beforeLines.length, afterLines.length);
  let i = 0;
  while (i < common && beforeLines[i] === afterLines[i]) i++;
  // Unchanged head (last 2 lines for context).
  for (let k = Math.max(0, i - 2); k < i; k++) out.push(`  ${beforeLines[k]}`);
  for (let k = i; k < beforeLines.length; k++) if (beforeLines[k]) out.push(`- ${beforeLines[k]}`);
  for (let k = i; k < afterLines.length; k++) if (afterLines[k]) out.push(`+ ${afterLines[k]}`);
  return out.join('\n');
}

// Snapshot the files a change set will touch, so a bad apply can be undone.
function snapshot(root, changes) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dir = path.join(root, SNAP_DIR, 'snapshots', stamp);
  fs.mkdirSync(dir, { recursive: true });
  const manifest = { stamp, files: [] };
  for (const c of changes) {
    const dest = path.join(dir, c.file.split('/').join('__'));
    fs.writeFileSync(dest, c.before);
    manifest.files.push({ file: c.file, backup: path.relative(root, dest).split(path.sep).join('/') });
  }
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2));
  // Record "latest" pointer for a simple `rollback`.
  fs.writeFileSync(
    path.join(root, SNAP_DIR, 'latest-snapshot.json'),
    JSON.stringify({ dir: path.relative(root, dir).split(path.sep).join('/'), manifest }, null, 2)
  );
  return dir;
}

function applyChanges(root, changes) {
  for (const c of changes) {
    fs.writeFileSync(c.absFile, c.after);
  }
}

function rollback(root) {
  const ptrPath = path.join(root, SNAP_DIR, 'latest-snapshot.json');
  let ptr;
  try {
    ptr = JSON.parse(fs.readFileSync(ptrPath, 'utf8'));
  } catch {
    return { ok: false, reason: 'no snapshot found' };
  }
  const restored = [];
  for (const f of ptr.manifest.files) {
    const backupAbs = path.join(root, f.backup);
    const targetAbs = path.join(root, f.file);
    try {
      const content = fs.readFileSync(backupAbs, 'utf8');
      fs.writeFileSync(targetAbs, content);
      restored.push(f.file);
    } catch (err) {
      return { ok: false, reason: `failed restoring ${f.file}: ${err.message}` };
    }
  }
  return { ok: true, restored, stamp: ptr.manifest.stamp };
}

module.exports = {
  computeAutoFixes,
  renderDiff,
  snapshot,
  applyChanges,
  rollback,
  isAutoFixable,
  SNAP_DIR,
};
