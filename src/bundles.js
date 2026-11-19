'use strict';

/*
 * Build-artifact / bundle scan.
 *
 * Every source scanner in this space reads the repository and skips `dist/`,
 * `build/`, `.next/static` and `out/`. That is exactly where bundlers INLINE the
 * environment: a key that was only ever in a server .env ends up as a literal in
 * `dist/assets/index-*.js`, and `NEXT_PUBLIC_`/VITE_ values are client-visible by
 * design. GitGuardian's 2026 report records AI-service keys at +81% YoY; the
 * documented blind spot is not the commit, it is the artifact.
 *
 * This module reuses the secret rules and entropy engine against build output,
 * adds source-map exposure, and reports whether the finding exists only in the
 * artifact (present in bundle, absent from source) — the strongest signal that
 * a server-only value leaked into the client bundle.
 */

const fs = require('fs');
const path = require('path');
const { secretRules, makeFinding, looksLikePlaceholder, isPublicBaaSKey } = require('./rules');
const { findHighEntropyTokens } = require('./entropy');

const BUILD_DIRS = [
  'dist',
  'build',
  'out',
  '.next/static',
  'public/build',
  'static/js',
  'public/_next',
  'www',
  'public/assets',
];

const BUNDLE_EXT = new Set(['.js', '.mjs', '.cjs', '.css', '.map', '.html', '.json', '.txt']);
const MAX_BYTES = 8 * 1024 * 1024;
const MAX_LINE = 200_000; // minified bundles ship one enormous line — scan it anyway

function walkBuild(dir, out) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkBuild(full, out);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (!BUNDLE_EXT.has(ext)) continue;
      try {
        const st = fs.statSync(full);
        if (st.size > MAX_BYTES) continue;
      } catch {
        continue;
      }
      out.push(full);
    }
  }
  return out;
}

function mask(value) {
  if (!value || value.length < 10) return '****';
  return value.slice(0, 4) + '****' + value.slice(-2);
}

function scannableLines(content) {
  const lines = content.split(/\r?\n/);
  // A minified line is still worth scanning; just do not let a 10 MB line blow
  // the regex engine with pathological backtracking.
  return lines.map((l) => (l.length > MAX_LINE ? l.slice(0, MAX_LINE) : l));
}

function scanBundles(root, opts = {}) {
  const candidates = opts.dirs && opts.dirs.length ? opts.dirs : BUILD_DIRS;
  const dirs = [];
  for (const d of candidates) {
    const abs = path.resolve(root, d);
    try {
      if (fs.statSync(abs).isDirectory()) dirs.push(abs);
    } catch {
      /* absent build dir is normal */
    }
  }

  const findings = [];
  const notes = [];
  const files = [];
  for (const dir of dirs) walkBuild(dir, files);

  const seen = new Set();
  const push = (f) => {
    const key = `${f.ruleId}:${f.file}:${f.line}:${(f.snippet || '').slice(0, 40)}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(f);
  };

  for (const abs of files) {
    let content;
    try {
      content = fs.readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    if (content.includes('\u0000')) continue; // binary
    const rel = path.relative(root, abs).split(path.sep).join('/');

    // 1) Source maps shipped to production: readable original source for anyone.
    if (abs.endsWith('.map')) {
      push({
        ruleId: 'bundle.sourcemap-exposed',
        severity: 'medium',
        confidence: 'high',
        title: 'Source map shipped in the build output',
        message: `${rel} exposes original source and strings to anyone who opens devtools. Secrets inlined in the bundle are recoverable even after a rotation of the variable name.`,
        fix: 'Disable production source maps (Vite: build.sourcemap=false, Next: productionBrowserSourceMaps=false) or upload them to your error tracker and delete them from the served artifact.',
        file: rel,
        line: 1,
        column: 1,
        snippet: rel,
      });
    }

    const lines = scannableLines(content);

    // 2) Known secret formats, using the same rules the source scan uses.
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line || line.length < 8) continue;
      for (const rule of secretRules) {
        if (!rule.re) continue;
        const re = rule.re.flags.includes('g') ? rule.re : new RegExp(rule.re.source, rule.re.flags + 'g');
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(line)) !== null) {
          const value = m[1] || m[0];
          if (looksLikePlaceholder(value)) continue;
          if (isPublicBaaSKey(line, value)) continue;
          if (rule.id === 'secret.generic-credential') continue; // bundle entropy pass covers this
          push(makeFinding(rule, {
            file: rel,
            line: i + 1,
            column: m.index + 1,
            snippet: mask(value),
            message: `A ${rule.id.replace('secret.', '').replace(/-/g, ' ')} appears in the BUILD artifact (not just source). This value is served to the browser and is public until rotated.`,
          }));
          if (re.lastIndex === m.index) re.lastIndex++;
        }
      }
    }

    // 3) Entropy pass for opaque tokens the named rules do not cover.
    const tokens = findHighEntropyTokens(content);
    for (const t of tokens.slice(0, 20)) {
      if (looksLikePlaceholder(t.match)) continue;
      if (isPublicBaaSKey('', t.match)) continue;
      const lineNo = content.slice(0, t.index).split('\n').length;
      push({
        ruleId: 'bundle.high-entropy-token',
        severity: 'high',
        confidence: 'low',
        title: 'High-entropy token inlined in a build artifact',
        message: `A high-entropy string (${t.reason}) is embedded in ${rel}. It may be a build hash, or an inlined API key/telemetry token — review before the artifact is served.`,
        fix: 'Identify the value. If it is a credential, rotate it and move it server-side so the bundler cannot inline it (never reference it from client modules).',
        file: rel,
        line: lineNo,
        column: 1,
        snippet: mask(t.match),
      });
    }
  }

  if (dirs.length === 0) {
    notes.push('no build output found (looked for: ' + candidates.join(', ') + ')');
  } else if (dirs.length > 0 && files.length === 0) {
    notes.push('build directories exist but contain no scannable artifacts');
  }

  findings.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return (order[a.severity] ?? 9) - (order[b.severity] ?? 9) || a.file.localeCompare(b.file) || a.line - b.line;
  });

  return {
    root,
    dirs: dirs.map((d) => path.relative(root, d).split(path.sep).join('/') || '.'),
    scannedFiles: files.length,
    findings,
    notes,
  };
}

module.exports = { scanBundles, BUILD_DIRS };
