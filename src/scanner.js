'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Stable fingerprint: survives line moves (no line number), used for SARIF
// partialFingerprints and the scan --new-only baseline diff.
function fingerprintOf(f) {
  return crypto
    .createHash('sha1')
    .update(`${f.ruleId} ${f.file} ${(f.snippet || '').trim()}`)
    .digest('hex')
    .slice(0, 16);
}
const rules = require('./rules');
const {
  SEVERITY_ORDER,
  lineRules,
  fileRules,
  crossFileRules,
  makeFinding,
  matchAll,
  requiredLiteral,
  isCommentLine,
} = rules;

// Load optional project config (.vibeguardrc.json / vibeguard.config.json).
// Currently supports { "shapingFunctions": ["toDTO", ...] } to extend the
// redaction allowlist. Best-effort: bad/missing config = defaults.
function loadConfig(root) {
  for (const name of ['.vibeguardrc.json', 'vibeguard.config.json']) {
    try {
      const p = path.join(root, name);
      if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, 'utf8'));
    } catch {
      /* ignore malformed config */
    }
  }
  return {};
}

// Directories we never walk into.
const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.vibeguard', // our own cache/baseline artifacts — never scan them
  'dist',
  'build',
  '.next',
  'out',
  'coverage',
  '.cache',
  'vendor',
  '.venv',
  'venv',
  '__pycache__',
]);

// Only text-ish source/config files. Everything else is skipped as binary/noise.
const SCAN_EXT = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.rb', '.php', '.go', '.java', '.cs', '.rs',
  '.sh', '.bash', '.sql',
  '.json', '.yml', '.yaml', '.toml', '.ini', '.xml',
  '.env', '.html', '.vue', '.svelte',
  '.txt', '.md', '.pem', '.key',
  '.tf', '.hcl', '.dockerfile',
]);

// Files without a "normal" extension we still want to read (dotfiles etc.).
const SCAN_BASENAMES = new Set([
  '.env', '.env.local', '.env.development', '.env.production',
  '.npmrc', 'Dockerfile', '.dockerenv',
]);

const MAX_FILE_BYTES = 2 * 1024 * 1024; // 2MB — skip anything huge.

function shouldScanFile(filePath) {
  const base = path.basename(filePath);
  if (base === '.vibeguard-baseline.json') return false; // our own artifact
  if (SCAN_BASENAMES.has(base)) return true;
  if (base.startsWith('.env')) return true;
  const ext = path.extname(filePath).toLowerCase();
  return SCAN_EXT.has(ext);
}

// Files staged for commit (git diff --cached), as a Set of absolute paths.
// Returns null when not a git repo / git unavailable, so the caller can decide.
function getStagedFiles(root) {
  try {
    const { execFileSync } = require('child_process');
    const out = execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACM'], {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const set = new Set();
    for (const rel of out.split(/\r?\n/)) {
      const t = rel.trim();
      if (t) set.add(path.resolve(root, t));
    }
    return set;
  } catch {
    return null; // not a git repo, or git not installed
  }
}

// Recursively collect scannable files.
function walk(dir, out, rootStat) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(full, out, rootStat);
    } else if (entry.isFile()) {
      if (!shouldScanFile(full)) continue;
      try {
        const st = fs.statSync(full);
        if (st.size > MAX_FILE_BYTES) continue;
      } catch {
        continue;
      }
      out.push(full);
    }
  }
  return out;
}

// Naive check: is character offset `idx` inside a quoted string literal on this
// line? Tracks ' " ` state left-to-right. Used to suppress code-pattern matches
// that are actually text (e.g. the word eval() inside a message string).
function isInsideString(line, idx) {
  let quote = null;
  for (let i = 0; i < idx && i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === '\\') i++; // skip escaped char
      else if (c === quote) quote = null;
    } else if (c === '"' || c === "'" || c === '`') {
      quote = c;
    }
  }
  return quote !== null;
}

// Cheap binary sniff: NUL byte in the first chunk.
function looksBinary(buf) {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

// `diag` (optional): a collector { degraded: [] } into which each analysis pass
// records a failure instead of swallowing it silently. A security scanner that
// fails open MUST surface that it did so — a quietly-skipped pass is a coverage
// hole the user never sees. Backward compatible: omit diag and behavior is old.
function scanFileContent(absPath, relPath, content, tree, diag) {
  const noteDegraded = (pass, err) => {
    if (diag && Array.isArray(diag.degraded)) {
      diag.degraded.push({ file: relPath, pass, error: String((err && err.message) || err || 'unknown') });
    }
  };
  let findings = [];
  const lines = content.split(/\r?\n/);

  // fileFilter depends only on the path, not the line — compute the applicable
  // rule set ONCE per file instead of re-testing (and recompiling) a fileFilter
  // regex on every line. Compiled fileFilters are cached on the rule object.
  const activeRules = [];
  for (const rule of lineRules) {
    if (rule.fileFilter) {
      let ff = rule._ffRe;
      if (!ff) {
        ff = typeof rule.fileFilter === 'string' ? new RegExp(rule.fileFilter) : rule.fileFilter;
        rule._ffRe = ff;
      }
      if (!ff.test(relPath)) continue;
    }
    // Precompute a mandatory literal once per rule (cached). '' = none extractable.
    if (rule._lit === undefined) rule._lit = requiredLiteral(rule.re.source) || '';
    activeRules.push(rule);
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 4000) continue; // minified blob line — skip.
    const commented = isCommentLine(line);
    const lineLower = line.toLowerCase();
    for (const rule of activeRules) {
      if (rule.skipComments && commented) continue;
      // Cheap literal prefilter: if the rule's mandatory literal isn't on this
      // line, the regex cannot match — skip it without running the regex.
      if (rule._lit && !lineLower.includes(rule._lit)) continue;
      for (const hit of matchAll(rule.re, line)) {
        if (rule.skipInString && isInsideString(line, hit.index)) continue;
        if (rule.filter && !rule.filter(line, hit, lines)) continue;
        findings.push(
          makeFinding(rule, {
            file: relPath,
            line: i + 1,
            column: hit.index + 1,
            snippet: redactSnippet(line.trim(), hit.match),
          })
        );
      }
    }
  }

  // Dataflow/taint analysis: follows user input across lines to a dangerous sink.
  try {
    const { analyzeTaint } = require('./taint');
    for (const t of analyzeTaint(content, lines, relPath, tree)) findings.push(t);
  } catch (err) {
    noteDegraded('taint', err);
  }

  // Python taint analysis for .py files (advanced multi-pass engine)
  if (relPath && relPath.endsWith('.py')) {
    try {
      const { analyzePythonTaintAdvanced } = require('./taint-py');
      for (const t of analyzePythonTaintAdvanced(content, lines, relPath)) findings.push(t);
    } catch (err) {
      // Fallback to legacy engine
      try {
        const { analyzePythonTaint } = require('./engine');
        for (const t of analyzePythonTaint(content, lines, relPath)) findings.push(t);
      } catch (e) {
        noteDegraded('python-taint', e);
      }
    }
  }

  // Optional AST pass (acorn) — precise eval/exec/Function/mass-assignment/nosql.
  try {
    const { analyzeAst, AST_SUPERSEDES } = require('./ast');
    const ast = analyzeAst(content, relPath, tree); // tree cached by the caller
    if (ast.parsed) {
      // AST is precise for these categories — drop the regex heuristics for this
      // file so we don't double-report or carry their false positives.
      findings = findings.filter((f) => !AST_SUPERSEDES.has(f.ruleId));
    }
    for (const a of ast.findings) findings.push(a);
  } catch (err) {
    noteDegraded('ast', err);
  }

  // File-level rules (need whole-file context).
  for (const rule of fileRules) {
    let hits = [];
    try {
      hits = rule.run(content, lines, relPath) || [];
    } catch (err) {
      noteDegraded(`file-rule:${rule.id || 'unknown'}`, err);
      hits = [];
    }
    for (const h of hits) {
      findings.push(
        makeFinding(rule, {
          file: relPath,
          line: h.line,
          column: h.column || 1,
          snippet: h.snippet,
          message: h.message,
          fix: h.fix,
          severity: h.severity, // per-hit overrides (makeFinding falls back to rule)
          confidence: h.confidence,
          ruleId: h.ruleId,
          title: h.title,
        })
      );
    }
  }

  // Plugin file-level rules (v2 plugin system).
  try {
    const { getPluginFileRules } = require('./plugin');
    const pFileRules = getPluginFileRules();
    for (const rule of pFileRules) {
      let hits = [];
      try {
        hits = rule.run(content, lines, relPath) || [];
      } catch (err) {
        noteDegraded(`plugin-file-rule:${rule.id || 'unknown'}`, err);
        hits = [];
      }
      for (const h of hits) {
        findings.push(
          makeFinding(rule, {
            file: relPath,
            line: h.line,
            column: h.column || 1,
            snippet: h.snippet,
            message: h.message,
            fix: h.fix,
            severity: h.severity,
            confidence: h.confidence,
            ruleId: h.ruleId,
            title: h.title,
          })
        );
      }
    }
  } catch { /* plugin file rules are best-effort */ }

  return findings;
}

// Never echo a full secret back into a report/log. Show a masked snippet.
function redactSnippet(line, match) {
  if (!match || match.length < 8) return truncate(line);
  const masked = match.slice(0, 4) + '****' + match.slice(-2);
  return truncate(line.split(match).join(masked));
}

function truncate(s) {
  return s.length > 160 ? s.slice(0, 157) + '...' : s;
}

// ---------------------------------------------------------------------------
// Project-level rules
// ---------------------------------------------------------------------------

function projectScan(root) {
  const findings = [];
  const gitignorePath = path.join(root, '.gitignore');
  let gitignore = '';
  try {
    gitignore = fs.readFileSync(gitignorePath, 'utf8');
  } catch {
    gitignore = '';
  }
  const ignoreLines = gitignore
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

  const envIsIgnored = ignoreLines.some((l) =>
    /^\.env($|\.|\/|\*)/.test(l) || l === '.env*' || l === '*.env'
  );

  // .env present but not gitignored -> critical.
  const envFiles = ['.env', '.env.local', '.env.production', '.env.development'];
  for (const name of envFiles) {
    const p = path.join(root, name);
    if (fs.existsSync(p)) {
      if (!envIsIgnored) {
        findings.push({
          ruleId: 'project.env-not-ignored',
          severity: 'critical',
          title: '.env not in .gitignore',
          message: `${name} exists but is not covered by .gitignore — secrets can be committed and pushed.`,
          fix: `Add ".env" (and ".env.*") to .gitignore, then remove it from git history if already committed (git rm --cached ${name}).`,
          file: name,
          line: 1,
          column: 1,
          snippet: `${name} present, .gitignore does not cover it`,
        });
      }
    }
  }

  // A committed .git folder inside a subpath, or a tracked .env that is world-exposed
  // via a public dir — flag .env living under a web/public/static dir.
  const exposedDirs = ['public', 'static', 'dist', 'www'];
  for (const d of exposedDirs) {
    for (const name of ['.env', '.env.local']) {
      const p = path.join(root, d, name);
      if (fs.existsSync(p)) {
        findings.push({
          ruleId: 'project.env-exposed',
          severity: 'critical',
          title: '.env inside a public directory',
          message: `${d}/${name} sits in a publicly served directory and may be downloadable.`,
          fix: `Move ${name} out of ${d}/ and load config from environment variables.`,
          file: `${d}/${name}`,
          line: 1,
          column: 1,
          snippet: `${d}/${name} is web-served`,
        });
      }
    }
  }

  // package.json present but no lockfile -> non-reproducible installs.
  if (fs.existsSync(path.join(root, 'package.json'))) {
    const lockfiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json'];
    if (!lockfiles.some((l) => fs.existsSync(path.join(root, l)))) {
      findings.push({
        ruleId: 'package.no-lockfile',
        severity: 'low',
        confidence: 'high',
        title: 'No dependency lockfile',
        message: 'package.json exists but no lockfile is committed — installs are not reproducible and pull the newest matching versions (supply-chain drift).',
        fix: 'Commit a lockfile (package-lock.json / yarn.lock / pnpm-lock.yaml).',
        file: 'package.json',
        line: 1,
        column: 1,
        snippet: 'no lockfile found',
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Grading
// ---------------------------------------------------------------------------

const TIER = ['critical', 'high', 'medium', 'low'];

// Grade off EFFECTIVE severity: low-confidence findings are heuristics ("review
// this"), so they count one tier lower and low-confidence 'low' is ignored for
// the grade. This keeps a single heuristic hint from tanking an otherwise clean
// project, while confirmed issues still drive the grade hard.
function effectiveSeverity(f) {
  if (f.confidence === 'low') {
    const i = TIER.indexOf(f.severity);
    return TIER[i + 1] || null; // low-confidence 'low' -> null (ignored)
  }
  return f.severity;
}

// Minimal glob -> RegExp: supports *, **, and gitignore-style "**/" (zero+ dirs).
function globToRe(glob) {
  const esc = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const body = esc.replace(/\*\*\/|\*\*|\*/g, (m) =>
    m === '**/' ? '(?:.*/)?' : m === '**' ? '.*' : '[^/]*'
  );
  return new RegExp('^' + body + '$');
}

// Inline suppression comments:
//   // vibeguard-ignore-line [rule1, rule2]      -> suppress on this line
//   // vibeguard-ignore-next-line [rule1, ...]   -> suppress on the next line
// No rule list = suppress everything on the target line. Works with //, #, /* */.
function buildIgnoreMap(lines) {
  const map = new Map(); // targetLine(1-based) -> Set(ruleIds) | '*'
  const re = /(?:\/\/|#|\/\*|\*)\s*vibeguard-ignore(-next)?-line\b([^*\n]*)/i;
  for (let i = 0; i < lines.length; i++) {
    const m = re.exec(lines[i]);
    if (!m) continue;
    const target = m[1] ? i + 2 : i + 1; // next-line -> i+2 (1-based)
    const rulesPart = (m[2] || '').replace(/\*\/.*/, '').trim();
    const rules = rulesPart
      ? rulesPart.split(/[\s,]+/).filter(Boolean)
      : '*';
    const existing = map.get(target);
    if (existing === '*' || rules === '*') map.set(target, '*');
    else map.set(target, new Set([...(existing || []), ...rules]));
  }
  return map;
}

function applyInlineSuppressions(findings, contents) {
  const byFile = new Map();
  for (const c of contents) byFile.set(c.rel, buildIgnoreMap(c.lines));
  return findings.filter((f) => {
    const map = byFile.get(f.file);
    if (!map) return true;
    const entry = map.get(f.line);
    if (!entry) return true;
    if (entry === '*') return false;
    return !entry.has(f.ruleId);
  });
}

// Apply project config: drop ignored rules/paths, remap severities.
// config = { ignoreRules:[ruleId], ignorePaths:[glob], ignore:[{rule,path}],
//            severityOverrides:{ruleId: 'low'} }
function applyConfigFilters(findings, config) {
  if (!config || typeof config !== 'object') return findings;
  const ignoreRules = new Set(Array.isArray(config.ignoreRules) ? config.ignoreRules : []);
  const ignorePathRes = (Array.isArray(config.ignorePaths) ? config.ignorePaths : []).map(globToRe);
  const pairIgnores = (Array.isArray(config.ignore) ? config.ignore : []).filter(
    (x) => x && typeof x === 'object'
  );
  const sevOverride = config.severityOverrides && typeof config.severityOverrides === 'object'
    ? config.severityOverrides
    : {};
  const validSev = new Set(['critical', 'high', 'medium', 'low']);

  return findings
    .filter((f) => {
      if (ignoreRules.has(f.ruleId)) return false;
      if (ignorePathRes.some((re) => re.test(f.file))) return false;
      for (const pair of pairIgnores) {
        const ruleMatch = !pair.rule || pair.rule === f.ruleId;
        const pathMatch = !pair.path || globToRe(pair.path).test(f.file) || f.file.includes(pair.path);
        if (ruleMatch && pathMatch) return false;
      }
      return true;
    })
    .map((f) => {
      const ov = sevOverride[f.ruleId];
      if (ov && validSev.has(ov)) return { ...f, severity: ov };
      return f;
    });
}

function computeGrade(findings) {
  // Reported counts are the real severities (what the user sees).
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  // Grade counts use effective severity.
  const g = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    const s = effectiveSeverity(f);
    if (s) g[s] += 1;
  }

  let grade;
  if (g.critical > 0) grade = 'F';
  else if (g.high > 0) grade = g.high >= 3 ? 'D' : 'C';
  else if (g.medium > 0) grade = g.medium >= 3 ? 'C' : 'B';
  else if (g.low > 0) grade = 'B';
  else grade = 'A';

  return { grade, counts };
}

// Collapse noise: on a single file:line, a specific rule supersedes the generic
// credential catch-all (e.g. a weak session secret shouldn't also report as a
// bare "hardcoded credential"). Also drop exact duplicate (ruleId+file+line).
//
// Additionally: when a dataflow-confirmed taint.* finding and a structural ast.*
// finding land on the same file:line and describe the same vulnerability category,
// keep only the taint finding (higher confidence) and drop the ast.* duplicate.
// Map: taint.command-injection ↔ ast.command-injection, etc.
const TAINT_TO_AST = {
  'taint.command-injection': 'ast.command-injection',
  'taint.sql-injection': 'ast.sql-injection',
  'taint.code-injection': 'ast.eval-dynamic',
  'taint.path-traversal': 'ast.path-traversal',
  'taint.ssrf': 'ast.ssrf',
};

function dedupeFindings(findings) {
  const linesWithSpecific = new Set();
  for (const f of findings) {
    if (f.ruleId !== 'secret.generic-credential') {
      linesWithSpecific.add(`${f.file}:${f.line}`);
    }
  }

  // Build a set of taint.* ruleIds that fired, keyed by file:line, so we can
  // drop the corresponding ast.* finding on the same file:line.
  const taintKeys = new Set();
  for (const f of findings) {
    if (TAINT_TO_AST[f.ruleId]) {
      taintKeys.add(`${f.file}:${f.line}:${TAINT_TO_AST[f.ruleId]}`);
    }
  }

  const seen = new Set();
  const out = [];
  for (const f of findings) {
    if (
      f.ruleId === 'secret.generic-credential' &&
      linesWithSpecific.has(`${f.file}:${f.line}`)
    ) {
      continue; // superseded by a more specific rule
    }
    // Drop ast.* finding when a taint.* finding already covers the same file:line.
    const astCounterpart = Object.entries(TAINT_TO_AST).find(([, ast]) => ast === f.ruleId);
    if (astCounterpart && taintKeys.has(`${f.file}:${f.line}:${f.ruleId}`)) {
      continue; // superseded by the dataflow-confirmed taint finding
    }
    const key = `${f.ruleId}:${f.file}:${f.line}:${f.column}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

function sortFindings(findings) {
  return findings.slice().sort((a, b) => {
    const s = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (s !== 0) return s;
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    return a.line - b.line;
  });
}

/**
 * Scan a directory. Returns a structured result object.
 * @param {string} dir
 * @param {object} [opts]
 */
function scan(dir, opts = {}) {
  const root = path.resolve(dir);
  // Apply project config (extends the redaction allowlist). Reset each scan so
  // config never leaks between runs (important for tests / MCP long sessions).
  const config = loadConfig(root);
  rules.configure(config);

  // Reset and load plugins early — before the file scan loop — so that
  // plugin fileRules and crossFileRules are available in scanFileContent.
  try {
    const { loadPlugins, resetPlugins } = require('./plugin');
    resetPlugins();
    loadPlugins(root, config);
  } catch { /* plugins are best-effort */ }

  const allFiles = walk(root, [], null);

  // Incremental mode: only scan files whose content changed since the last scan
  // (SHA-256 hash cache under .vibeguard/cache). First run has an empty cache so
  // everything is "changed" (full scan, populates cache); later runs are near
  // instant. Cross-file analysis needs ALL files, so it is skipped here — this
  // mode is per-file (line/AST/taint), intended for pre-commit / watch loops.
  let files = allFiles;
  let incremental = null;
  let staged = null;
  if (opts.staged) {
    // Git-aware: scan only files staged for the current commit. Perfect for a
    // pre-commit hook — fast and scoped to exactly what's being committed.
    const stagedSet = getStagedFiles(root);
    if (stagedSet) {
      files = allFiles.filter((abs) => stagedSet.has(path.resolve(abs)));
      staged = { total: allFiles.length, scanned: files.length };
    }
  } else if (opts.changed) {
    const { getChangedFiles } = require('./engine');
    const res = getChangedFiles(root, allFiles);
    files = res.changed;
    incremental = { total: res.total, scanned: res.changed.length, cached: res.cached };
  }
  // Both modes scan a partial file set → cross-file analysis (which needs the
  // whole project) must be skipped and reported as such.
  const partialScan = !!incremental || !!staged;

  let findings = [];
  const contents = []; // {rel, content, lines} for cross-file analysis
  const trees = new Map(); // rel -> parsed AST (one parse per file, shared)
  const astMod = require('./ast');

  // Engine mode + coverage diagnostics. `astAvailable` is false when the acorn
  // optional deps aren't installed → precise eval/exec/taint/mass-assignment
  // passes silently downgrade to regex. We surface that instead of hiding it.
  const astAvailable = astMod.isAvailable();
  const diag = { degraded: [] };
  const parseFailed = []; // JS/TS files acorn IS installed for but couldn't parse

  for (const abs of files) {
    let buf;
    try {
      buf = fs.readFileSync(abs);
    } catch {
      continue;
    }
    if (looksBinary(buf)) continue;
    const rel = path.relative(root, abs).split(path.sep).join('/');
    const content = buf.toString('utf8');
    // Parse JS/TS once here; the AST pass, interprocedural, and cross-file all reuse it.
    let tree = null;
    if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/.test(rel)) {
      try {
        tree = astMod.parseSource(content, rel);
      } catch {
        tree = null;
      }
      if (tree) trees.set(rel, tree);
      // acorn installed but this file didn't parse → AST rules skipped for it.
      // (When acorn is absent entirely that's engine-mode, reported separately.)
      else if (astAvailable) parseFailed.push(rel);
    }
    findings = findings.concat(scanFileContent(abs, rel, content, tree, diag));
    contents.push({ rel, content, lines: content.split(/\r?\n/) });
  }

  // Cross-file passes need the WHOLE project in `contents`. In a partial scan
  // (--changed / --staged) we only loaded a subset, so skip them (they would
  // produce wrong results from a partial view) — the documented tradeoff.
  if (!partialScan) {
  // Cross-file taint: request data flowing across module boundaries into a sink.
  try {
    const { analyzeCrossFile } = require('./crosstaint');
    for (const cf of analyzeCrossFile(contents, trees)) findings.push(cf);
  } catch {
    /* cross-file taint is optional (needs acorn) */
  }

  // Cross-file rules see every file at once (e.g. Supabase RLS across migrations).
  for (const rule of crossFileRules) {
    let hits = [];
    try {
      hits = rule.run(contents) || [];
    } catch {
      hits = [];
    }
    for (const h of hits) {
      findings.push(
        makeFinding(rule, {
          file: h.file,
          line: h.line,
          column: h.column || 1,
          snippet: h.snippet,
          message: h.message,
          fix: h.fix,
        })
      );
    }
  }

  // Plugin cross-file rules (v2 plugin system).
  try {
    const { getPluginCrossFileRules } = require('./plugin');
    const pCrossRules = getPluginCrossFileRules();
    for (const rule of pCrossRules) {
      let hits = [];
      try {
        hits = rule.run(contents) || [];
      } catch {
        hits = [];
      }
      for (const h of hits) {
        findings.push(
          makeFinding(rule, {
            file: h.file,
            line: h.line,
            column: h.column || 1,
            snippet: h.snippet,
            message: h.message,
            fix: h.fix,
          })
        );
      }
    }
  } catch { /* plugin cross-file rules are best-effort */ }
  } // end !incremental cross-file block

  findings = findings.concat(projectScan(root));

  // Dependency vulnerabilities (opt-in; the CLI enables it by default, unit
  // tests leave it off so they stay offline and deterministic).
  let depsInfo = null;
  if (opts.deps) {
    try {
      const { scanDependencies } = require('./deps');
      const dep = scanDependencies(root);
      findings = findings.concat(dep.findings);
      depsInfo = { ran: dep.ran, notes: dep.notes };
    } catch (err) {
      depsInfo = { ran: { npm: false, pip: false }, notes: [String(err && err.message)] };
    }
  }

  // Deep mode: fold in external best-in-class scanners if present (opt-in).
  let externalInfo = null;
  if (opts.deep) {
    try {
      const { runExternal } = require('./external');
      const ext = runExternal(root);
      findings = findings.concat(ext.findings);
      externalInfo = { ran: ext.ran, notes: ext.notes };
    } catch (err) {
      externalInfo = { ran: {}, notes: [String(err && err.message)] };
    }
  }

  // --no-suppress (opts.noSuppress): report everything, ignoring inline
  // `vibeguard-ignore` comments and the heuristic FP filter. Config policy
  // (ignoreRules/ignorePaths) is deliberate, versioned, and kept. This gives CI
  // a trust mode that a careless/hostile inline comment in a PR cannot silence.
  let suppressedFindings = [];
  if (!opts.noSuppress) {
    findings = applyInlineSuppressions(findings, contents);
    const { applyInlineSuppressionsWithCount } = require('./suppress');
    const supResult = applyInlineSuppressionsWithCount(findings, contents);
    findings = supResult.kept;
    suppressedFindings = supResult.suppressed;
  }
  findings = applyConfigFilters(findings, config);

  // Merge plugin line rules (file/cross-file rules already applied above)
  try {
    const { getPluginRules } = require('./plugin');
    const pluginRules = getPluginRules();
    if (pluginRules.length > 0) {
      const { matchAll, makeFinding } = require('./rules');
      for (const [rel, content] of Object.entries(contents)) {
        const lines = content.split(/\r?\n/);
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const commented = /^\s*(\/\/|#|--|\/\*)/.test(line);
          for (const rule of pluginRules) {
            if (rule.skipComments && commented) continue;
            for (const hit of matchAll(rule.re, line)) {
              findings.push(
                makeFinding(rule, {
                  file: rel,
                  line: i + 1,
                  column: hit.index + 1,
                  snippet: line.trim().slice(0, 200),
                })
              );
            }
          }
        }
      }
    }
  } catch {
    /* plugins are best-effort */
  }

  findings = dedupeFindings(findings);

  // Context-aware false positive suppression (skipped under --no-suppress).
  if (!opts.noSuppress) {
    try {
      const { suppressFindings } = require('./suppress');
      findings = findings.filter((f) => {
        const matching = contents.find((c) => c.rel === f.file);
        if (matching) {
          return suppressFindings([f], matching.content, f.file).length > 0;
        }
        return true;
      });
    } catch { /* suppression is best-effort */ }
  }

  findings = sortFindings(findings);
  for (const f of findings) f.fingerprint = fingerprintOf(f);

  const { grade, counts } = computeGrade(findings);

  // Coverage transparency: engine mode + every pass that failed open. Callers
  // (CLI, MCP, CI) can warn the user that a scan ran degraded rather than let a
  // silent parse/taint failure masquerade as a clean result.
  const engine = {
    astAvailable,
    mode: astAvailable ? 'ast' : 'regex-only',
  };
  const diagnostics = {
    degradedPasses: diag.degraded,
    parseFailedFiles: parseFailed,
    degradedFileCount: new Set([...diag.degraded.map((d) => d.file), ...parseFailed]).size,
  };

  return {
    root,
    scannedFiles: files.length,
    findings,
    suppressedFindings,
    suppressedCount: suppressedFindings.length,
    grade,
    counts,
    depsInfo,
    externalInfo,
    engine,
    diagnostics,
    incremental, // null on a full scan; {total, scanned, cached} with --changed
    staged, // null unless --staged; {total, scanned}
    generatedAt: new Date().toISOString(),
  };
}

module.exports = {
  scan,
  scanFileContent,
  computeGrade,
  sortFindings,
  walk,
  shouldScanFile,
  SKIP_DIRS,
};
