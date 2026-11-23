'use strict';

/*
 * benchmarks/external/run.js — reproducible external-code security benchmark.
 *
 * Targets are pinned by repository + commit. The runner:
 *   1. fetches the exact commit into a local cache (or verifies an existing one);
 *   2. hashes the working tree and the label file;
 *   3. scans the target with VibeGuard's real scanner, deps/plugins disabled;
 *   4. scores only the labeled file/line ranges (unlabeled findings are ignored);
 *   5. writes a deterministic JSON/Markdown report.
 *
 * `--offline` never touches the network. `--verify` is offline and compares a
 * fresh run against the committed report. `--gate` compares metrics against
 * benchmarks/external/baseline.json.
 *
 * Scope is deliberately small: this is an external regression benchmark, not a
 * representative precision/recall study. Whole-repository findings are ignored.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const MANIFEST_PATH = path.join(__dirname, 'manifest.json');
const DEFAULT_CACHE = path.join(__dirname, '.cache');
const REPORT_JSON = path.join(ROOT, 'reports', 'external-benchmark.json');
const REPORT_MD = path.join(ROOT, 'reports', 'external-benchmark.md');
const BASELINE = path.join(__dirname, 'baseline.json');

function readJson(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function round(value) { return Number(Number(value).toFixed(4)); }

function walkFiles(dir, skipNames = new Set()) {
  const out = [];
  const stack = [dir];
  while (stack.length) {
    const current = stack.pop();
    let entries;
    try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch { continue; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (skipNames.has(entry.name)) continue;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile() || entry.isSymbolicLink()) out.push(full);
    }
  }
  return out.sort();
}

function hashDirectory(dir, opts = {}) {
  const hash = crypto.createHash('sha256');
  const skip = new Set(['.git', '.vibeguard', 'node_modules']);
  const skipFiles = opts.skipFiles || new Set();
  const normalizeEol = opts.normalizeEol === true;
  for (const file of walkFiles(dir, skip)) {
    const rel = path.relative(dir, file).split(path.sep).join('/');
    if (skipFiles.has(rel)) continue;
    let stat;
    try { stat = fs.lstatSync(file); } catch { continue; }
    if (stat.isSymbolicLink()) {
      hash.update(`L\0${rel}\0${fs.readlinkSync(file)}\0`);
      continue;
    }
    const bytes = fs.readFileSync(file);
    const content = normalizeEol ? Buffer.from(bytes.toString('utf8').replace(/\r\n/g, '\n'), 'utf8') : bytes;
    hash.update(`F\0${rel}\0${content.length}\0`);
    hash.update(content);
    hash.update('\0');
  }
  return hash.digest('hex');
}

function hashTextFile(file) { return sha256(fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n')); }

function runGit(args, cwd, timeout = 180000) {
  const result = spawnSync('git', args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout,
    windowsHide: true,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
  });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${(result.stderr || result.stdout || result.error || '').toString().trim().slice(0, 500)}`);
  }
  return String(result.stdout || '').trim();
}

function ensureTarget(target, opts = {}) {
  const cacheRoot = path.resolve(opts.cacheDir || DEFAULT_CACHE);
  const repoDir = path.join(cacheRoot, target.id);
  const metaPath = path.join(cacheRoot, `${target.id}.json`);
  const offline = opts.offline === true;

  if (opts.refresh) {
    fs.rmSync(repoDir, { recursive: true, force: true });
    fs.rmSync(metaPath, { force: true });
  }
  if (!fs.existsSync(path.join(repoDir, '.git'))) {
    if (offline) throw new Error(`offline: cache missing for ${target.id} at ${repoDir}`);
    fs.rmSync(repoDir, { recursive: true, force: true });
    fs.mkdirSync(repoDir, { recursive: true });
    runGit(['init', '-q'], repoDir);
    runGit(['config', 'core.autocrlf', 'false'], repoDir);
    runGit(['config', 'core.eol', 'lf'], repoDir);
    runGit(['remote', 'add', 'origin', target.repo], repoDir);
    runGit(['fetch', '-q', '--depth', '1', 'origin', target.commit], repoDir);
    runGit(['checkout', '-q', 'FETCH_HEAD'], repoDir);
  }

  const head = runGit(['rev-parse', 'HEAD'], repoDir);
  if (head !== target.commit) {
    if (offline) throw new Error(`offline: ${target.id} cache is at ${head}, expected ${target.commit}`);
    throw new Error(`${target.id} cache is at ${head}, expected ${target.commit}; rerun with --refresh`);
  }

  const treeHash = runGit(['rev-parse', 'HEAD^{tree}'], repoDir);
  const fileHash = hashDirectory(repoDir);
  let previous = null;
  try { previous = readJson(metaPath); } catch { /* first run */ }
  if (previous && previous.fileHash && previous.fileHash !== fileHash) {
    throw new Error(`${target.id} working tree hash changed (${previous.fileHash} -> ${fileHash}); rerun with --refresh`);
  }
  fs.mkdirSync(cacheRoot, { recursive: true });
  fs.writeFileSync(metaPath, JSON.stringify({ target: target.id, repo: target.repo, commit: head, treeHash, fileHash }, null, 2) + '\n');
  return { repoDir, commit: head, treeHash, fileHash };
}

function ruleMatches(ruleId, patterns) {
  return (patterns || []).some((pattern) => {
    if (pattern.endsWith('*')) return ruleId.startsWith(pattern.slice(0, -1));
    return ruleId === pattern;
  });
}

function isAlert(finding) {
  if (!finding || finding.confidence === 'low') return false;
  return finding.severity === 'critical' || finding.severity === 'high' || finding.severity === 'medium';
}

function findingInCase(finding, testCase) {
  if (finding.file !== testCase.file) return false;
  if (Number.isInteger(testCase.line)) return finding.line === testCase.line;
  if (Array.isArray(testCase.lines)) return finding.line >= testCase.lines[0] && finding.line <= testCase.lines[1];
  return true;
}

function scoreTarget(target, labels, findingsRaw, manifest) {
  const findings = findingsRaw.map((f) => ({
    file: String(f.file || '').split(path.sep).join('/'),
    line: Number(f.line) || 0,
    ruleId: String(f.ruleId || ''),
    severity: String(f.severity || ''),
    confidence: String(f.confidence || ''),
  })).sort((a, b) => (a.file + ':' + a.line + ':' + a.ruleId).localeCompare(b.file + ':' + b.line + ':' + b.ruleId));

  const cases = [];
  const categoryTotals = {};
  let tp = 0;
  let fp = 0;
  let fn = 0;

  const bump = (category, key) => {
    if (!categoryTotals[category]) categoryTotals[category] = { tp: 0, fp: 0, fn: 0 };
    categoryTotals[category][key]++;
  };

  for (const testCase of labels.cases || []) {
    const inRange = findings.filter((finding) => findingInCase(finding, testCase));
    const alerts = inRange.filter(isAlert);
    let verdict;
    let matchedRule = null;
    if (testCase.benign) {
      if (alerts.length) {
        verdict = 'FP';
        fp += alerts.length;
        bump('benign', 'fp');
      } else {
        verdict = 'TN';
      }
    } else {
      const patterns = manifest.categories[testCase.category] || [];
      const matched = alerts.filter((finding) => ruleMatches(finding.ruleId, patterns));
      const unexpected = alerts.filter((finding) => !ruleMatches(finding.ruleId, patterns));
      if (matched.length) {
        verdict = 'TP';
        tp++;
        matchedRule = matched[0].ruleId;
        bump(testCase.category, 'tp');
      } else {
        verdict = 'FN';
        fn++;
        bump(testCase.category, 'fn');
      }
      if (unexpected.length) {
        fp += unexpected.length;
        bump('unexpected-rule', 'fp');
      }
    }
    cases.push({
      id: testCase.id,
      file: testCase.file,
      line: testCase.line || null,
      lines: testCase.lines || null,
      category: testCase.category || 'benign',
      cwe: testCase.cwe || null,
      benign: testCase.benign === true,
      verdict,
      matchedRule,
      findings: alerts,
    });
  }

  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  const caseFiles = new Set((labels.cases || []).map((c) => c.file));
  const unsupported = (labels.unsupported || []).map((item) => ({ ...item }));
  return {
    metrics: { tp, fp, fn, precision: round(precision), recall: round(recall), f1: round(f1) },
    categories: categoryTotals,
    cases,
    unsupported,
    ignoredFindings: findings.filter((f) => !caseFiles.has(f.file)).length,
    scopeFindings: findings.filter((f) => caseFiles.has(f.file)).length,
  };
}

function gitOrNull(args) {
  const result = spawnSync('git', args, {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
    timeout: 30000,
    windowsHide: true,
  });
  return result.status === 0 ? String(result.stdout || '').trim() : null;
}

function scannerIdentity() {
  const pkg = readJson(path.join(ROOT, 'package.json'));
  const tree = gitOrNull(['rev-parse', 'HEAD:src']);
  const blob = gitOrNull(['rev-parse', 'HEAD:package.json']);
  const dirty = gitOrNull(['status', '--porcelain', '--', 'src', 'package.json']);
  const worktree = `${hashDirectory(path.join(ROOT, 'src'), { skipFiles: new Set(['integrity.json']), normalizeEol: true })}:${hashTextFile(path.join(ROOT, 'package.json'))}`;
  return {
    name: pkg.name,
    version: pkg.version,
    // Git tree/blob ids are byte-identical across checkout platforms. If the
    // scanned source or package manifest is dirty, fall back to a content hash
    // so the report describes what actually ran.
    sourceHash: tree && blob && dirty === '' ? `git:${tree}:${blob}` : `worktree:${worktree}`,
  };
}

function targetReport(target, labels, cache, scanResult, manifest) {
  const score = scoreTarget(target, labels, scanResult.findings, manifest);
  return {
    id: target.id,
    repo: target.repo,
    commit: cache.commit,
    treeHash: cache.treeHash,
    fileHash: cache.fileHash,
    labelsHash: hashTextFile(path.join(__dirname, target.labels)),
    license: target.license || null,
    metrics: score.metrics,
    categories: score.categories,
    cases: score.cases,
    unsupported: score.unsupported,
    ignoredFindings: score.ignoredFindings,
    scopeFindings: score.scopeFindings,
    scan: {
      scannedFiles: scanResult.scannedFiles,
      totalFindings: scanResult.findings.length,
      engine: scanResult.engine,
    },
  };
}

function buildReport(opts = {}) {
  const manifest = readJson(MANIFEST_PATH);
  const targets = (manifest.targets || []).filter((target) => !opts.target || target.id === opts.target);
  if (!targets.length) throw new Error(`no target matched ${opts.target}`);
  const results = [];
  for (const target of targets) {
    process.stderr.write(`[external-benchmark] ${target.id} @ ${target.commit.slice(0, 12)}…\n`);
    const cache = ensureTarget(target, opts);
    const labels = readJson(path.join(__dirname, target.labels));
    if (labels.target !== target.id) throw new Error(`label target mismatch for ${target.id}`);
    if (labels.commit !== target.commit) throw new Error(`label commit mismatch for ${target.id}`);
    process.stderr.write(`[external-benchmark] scanning ${cache.repoDir}\n`);
    const scanResult = require(path.join(ROOT, 'src', 'scanner')).scan(cache.repoDir, manifest.scannerOptions || {});
    results.push(targetReport(target, labels, cache, scanResult, manifest));
  }

  const overall = results.reduce((acc, item) => {
    acc.tp += item.metrics.tp;
    acc.fp += item.metrics.fp;
    acc.fn += item.metrics.fn;
    return acc;
  }, { tp: 0, fp: 0, fn: 0 });
  overall.precision = round(overall.tp + overall.fp ? overall.tp / (overall.tp + overall.fp) : 0);
  overall.recall = round(overall.tp + overall.fn ? overall.tp / (overall.tp + overall.fn) : 0);
  overall.f1 = round(overall.precision + overall.recall ? (2 * overall.precision * overall.recall) / (overall.precision + overall.recall) : 0);

  return {
    schemaVersion: '1.0',
    benchmark: manifest.benchmark,
    scanner: scannerIdentity(),
    environment: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
    },
    scope: 'labeled file/line ranges only; unlabeled findings are ignored',
    targets: results,
    overall,
    limitations: [
      'The label set is curated, not a representative sample of all vulnerabilities.',
      'Whole-repository findings are ignored to avoid scoring deliberate Juice Shop noise outside the labels.',
      'The target commit is pinned; changing the commit requires re-labeling.',
      'Metrics are reproducible only with the same scanner source hash and target hashes.',
      'This benchmark measures detection output, not exploitation or runtime enforcement.',
    ],
  };
}

function stableReport(report) {
  return {
    benchmark: report.benchmark,
    scanner: report.scanner,
    scope: report.scope,
    targets: report.targets.map((target) => ({
      id: target.id,
      commit: target.commit,
      treeHash: target.treeHash,
      labelsHash: target.labelsHash,
      metrics: target.metrics,
      categories: target.categories,
      cases: target.cases,
      unsupported: target.unsupported,
      ignoredFindings: target.ignoredFindings,
      scopeFindings: target.scopeFindings,
    })),
    overall: report.overall,
  };
}

function diffReports(expected, actual) {
  const left = stableReport(expected);
  const right = stableReport(actual);
  const differences = [];
  const walk = (a, b, prefix) => {
    if (JSON.stringify(a) === JSON.stringify(b)) return;
    if (a && b && typeof a === 'object' && typeof b === 'object' && !Array.isArray(a) && !Array.isArray(b)) {
      const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
      for (const key of [...keys].sort()) walk(a[key], b[key], prefix ? `${prefix}.${key}` : key);
      return;
    }
    differences.push(`${prefix}: expected ${JSON.stringify(a)}, got ${JSON.stringify(b)}`);
  };
  walk(left, right, '');
  return differences;
}

function pct(value) { return `${(value * 100).toFixed(1)}%`; }

function renderMarkdown(report) {
  const lines = [];
  lines.push('# Reproducible External Security Benchmark');
  lines.push('');
  lines.push('<!-- EXTERNAL-BENCHMARK:START -->');
  lines.push('<!-- Generated by benchmarks/external/run.js; do not edit manually. -->');
  lines.push('');
  lines.push(`**Benchmark:** \`${report.benchmark}\`  `);
  lines.push(`**Scanner:** \`${report.scanner.name}@${report.scanner.version}\`  `);
  lines.push(`**Scanner source hash:** \`${report.scanner.sourceHash}\`  `);
  lines.push(`**Scope:** ${report.scope}`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push('| Target | Commit | TP | FP | FN | Precision | Recall | F1 |');
  lines.push('|---|---|---:|---:|---:|---:|---:|---:|');
  for (const target of report.targets) {
    lines.push(`| ${target.id} | \`${target.commit.slice(0, 12)}\` | ${target.metrics.tp} | ${target.metrics.fp} | ${target.metrics.fn} | ${pct(target.metrics.precision)} | ${pct(target.metrics.recall)} | ${pct(target.metrics.f1)} |`);
  }
  lines.push(`| **OVERALL** | | **${report.overall.tp}** | **${report.overall.fp}** | **${report.overall.fn}** | **${pct(report.overall.precision)}** | **${pct(report.overall.recall)}** | **${pct(report.overall.f1)}** |`);
  lines.push('');
  for (const target of report.targets) {
    lines.push(`## ${target.id}`);
    lines.push('');
    lines.push(`- Repository: ${target.repo}`);
    lines.push(`- Commit: \`${target.commit}\``);
    lines.push(`- Git tree: \`${target.treeHash}\``);
    lines.push(`- Working-tree hash: \`${target.fileHash}\``);
    lines.push(`- Labels hash: \`${target.labelsHash}\``);
    lines.push(`- Files scanned: ${target.scan.scannedFiles}; total findings: ${target.scan.totalFindings}; engine: ${target.scan.engine.mode}`);
    lines.push('');
    lines.push('| Case | File | Line | Category | Verdict | Rule |');
    lines.push('|---|---|---|---|---|---|');
    for (const item of target.cases) {
      lines.push(`| ${item.id} | \`${item.file}\` | ${item.line || (item.lines ? item.lines.join('-') : 'file')} | ${item.category} | ${item.verdict} | ${item.matchedRule ? '`' + item.matchedRule + '`' : ''} |`);
    }
    lines.push('');
    if (target.unsupported.length) {
      lines.push('### Recorded coverage gaps (not scored)');
      lines.push('');
      for (const gap of target.unsupported) lines.push(`- \`${gap.id}\` — ${gap.file}:${gap.line} (${gap.cwe}): ${gap.reason}`);
      lines.push('');
    }
  }
  lines.push('## Reproduce');
  lines.push('');
  lines.push('```bash');
  lines.push('node benchmarks/external/run.js --refresh --update-baseline');
  lines.push('node benchmarks/external/run.js --offline --verify');
  lines.push('node benchmarks/external/run.js --gate');
  lines.push('```');
  lines.push('');
  lines.push('## Limitations');
  lines.push('');
  for (const item of report.limitations) lines.push(`- ${item}`);
  lines.push('');
  lines.push('<!-- EXTERNAL-BENCHMARK:END -->');
  return lines.join('\n') + '\n';
}

function writeReport(report) {
  fs.mkdirSync(path.dirname(REPORT_JSON), { recursive: true });
  fs.writeFileSync(REPORT_JSON, JSON.stringify(report, null, 2) + '\n');
  fs.writeFileSync(REPORT_MD, renderMarkdown(report));
}

function baselineFrom(report) {
  const targets = {};
  for (const target of report.targets) targets[target.id] = { metrics: target.metrics, categories: target.categories };
  return { schemaVersion: '1.0', benchmark: report.benchmark, scannerSourceHash: report.scanner.sourceHash, targets, overall: report.overall };
}

function gate(report) {
  if (!fs.existsSync(BASELINE)) throw new Error(`baseline missing at ${path.relative(ROOT, BASELINE)}; run with --update-baseline`);
  const baseline = readJson(BASELINE);
  if (baseline.benchmark !== report.benchmark) throw new Error('baseline benchmark id mismatch');
  const failures = [];
  if (baseline.scannerSourceHash !== report.scanner.sourceHash) failures.push('scanner source hash changed; regenerate the baseline only after reviewing metric changes');
  for (const target of report.targets) {
    const expected = baseline.targets[target.id];
    if (!expected) { failures.push(`${target.id}: no baseline entry`); continue; }
    for (const key of ['precision', 'recall', 'f1']) {
      if (target.metrics[key] + 1e-9 < expected.metrics[key]) failures.push(`${target.id}.${key}: ${target.metrics[key]} < ${expected.metrics[key]}`);
    }
    for (const [category, values] of Object.entries(expected.categories || {})) {
      const actual = target.categories[category] || { tp: 0, fp: 0, fn: 0 };
      for (const key of ['tp', 'fp', 'fn']) {
        if (actual[key] !== values[key]) failures.push(`${target.id}.${category}.${key}: ${actual[key]} != ${values[key]}`);
      }
    }
  }
  if (failures.length) throw new Error(`external benchmark gate failed:\n  ${failures.join('\n  ')}`);
}

function parseArgs(argv) {
  const opts = { cacheDir: DEFAULT_CACHE, offline: false, refresh: false, gate: false, verify: false, updateBaseline: false, json: false, target: null };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--offline') opts.offline = true;
    else if (arg === '--refresh') opts.refresh = true;
    else if (arg === '--gate') opts.gate = true;
    else if (arg === '--verify') { opts.verify = true; opts.offline = true; }
    else if (arg === '--update-baseline') opts.updateBaseline = true;
    else if (arg === '--json') opts.json = true;
    else if (arg === '--target') opts.target = argv[++i];
    else if (arg === '--cache-dir') opts.cacheDir = path.resolve(argv[++i]);
    else if (arg === '--report') opts.report = path.resolve(argv[++i]);
    else throw new Error(`unknown argument: ${arg}`);
  }
  return opts;
}

function committedReport() {
  const result = spawnSync('git', ['show', `HEAD:${path.relative(ROOT, REPORT_JSON).split(path.sep).join('/')}`], {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
    timeout: 30000,
    windowsHide: true,
  });
  if (result.status === 0 && result.stdout) return JSON.parse(result.stdout);
  if (fs.existsSync(REPORT_JSON)) return readJson(REPORT_JSON);
  return null;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const report = buildReport(opts);
  if (opts.verify) {
    const expected = committedReport();
    if (!expected) throw new Error(`no committed report at ${path.relative(ROOT, REPORT_JSON)}; run without --verify first`);
    const differences = diffReports(expected, report);
    if (differences.length) {
      process.stderr.write(`external benchmark verification FAILED (${differences.length} difference(s)):\n  ${differences.slice(0, 20).join('\n  ')}\n`);
      process.exitCode = 1;
    } else {
      process.stderr.write(`external benchmark verification passed: ${report.targets.length} target(s), ${report.overall.tp} TP / ${report.overall.fp} FP / ${report.overall.fn} FN\n`);
    }
    return;
  }
  if (opts.gate) gate(report);
  if (opts.updateBaseline) fs.writeFileSync(BASELINE, JSON.stringify(baselineFrom(report), null, 2) + '\n');
  if (opts.report) {
    const target = path.resolve(opts.report);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, JSON.stringify(report, null, 2) + '\n');
  } else {
    writeReport(report);
  }
  if (opts.json) process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  else {
    process.stdout.write(`external benchmark: ${report.targets.length} target(s), TP=${report.overall.tp} FP=${report.overall.fp} FN=${report.overall.fn} precision=${pct(report.overall.precision)} recall=${pct(report.overall.recall)} F1=${pct(report.overall.f1)}\n`);
    process.stdout.write(`report: ${path.relative(ROOT, REPORT_JSON)}\n`);
  }
}

if (require.main === module) {
  try { main(); } catch (err) { process.stderr.write(`external benchmark error: ${err.message}\n`); process.exit(1); }
}

module.exports = { parseArgs, ruleMatches, isAlert, findingInCase, scoreTarget, hashDirectory, stableReport, diffReports, buildReport, renderMarkdown, baselineFrom, gate };
