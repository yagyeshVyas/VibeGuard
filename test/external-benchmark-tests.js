'use strict';

/*
 * Unit tests for the reproducible external benchmark runner.
 * These do not fetch or scan the external target; the real run is a separate
 * command (benchmarks/external/run.js) with cache/verify/gate semantics.
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  ruleMatches,
  isAlert,
  scoreTarget,
  hashDirectory,
  diffReports,
} = require('../benchmarks/external/run');

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

const manifest = {
  categories: {
    'sql-injection': ['taint.sql-injection', 'code.sql-injection'],
    'hardcoded-secret': ['secret.*'],
  },
};

function labels(cases) {
  return { target: 'fixture', commit: '0'.repeat(40), cases };
}

test('rule patterns support exact ids and trailing wildcards', () => {
  assert.strictEqual(ruleMatches('taint.sql-injection', ['taint.sql-injection']), true);
  assert.strictEqual(ruleMatches('secret.generic-credential', ['secret.*']), true);
  assert.strictEqual(ruleMatches('code.insecure-http', ['secret.*']), false);
  assert.strictEqual(ruleMatches('taint.sql-injection', []), false);
});

test('alerts require medium+ severity and non-low confidence', () => {
  assert.strictEqual(isAlert({ severity: 'high', confidence: 'high' }), true);
  assert.strictEqual(isAlert({ severity: 'medium', confidence: 'medium' }), true);
  assert.strictEqual(isAlert({ severity: 'low', confidence: 'high' }), false);
  assert.strictEqual(isAlert({ severity: 'high', confidence: 'low' }), false);
});

test('scoreTarget counts TP, FN, unexpected-rule FP and benign FP', () => {
  const cases = [
    { id: 'tp', file: 'a.js', line: 10, category: 'sql-injection' },
    { id: 'fn', file: 'b.js', line: 20, category: 'sql-injection' },
    { id: 'wrong-rule', file: 'c.js', line: 30, category: 'hardcoded-secret' },
    { id: 'benign-noisy', file: 'd.js', benign: true },
    { id: 'benign-only-low', file: 'e.js', benign: true },
  ];
  const findings = [
    { file: 'a.js', line: 10, ruleId: 'taint.sql-injection', severity: 'high', confidence: 'high' },
    { file: 'c.js', line: 30, ruleId: 'code.insecure-http', severity: 'medium', confidence: 'medium' },
    { file: 'd.js', line: 1, ruleId: 'code.insecure-http', severity: 'medium', confidence: 'medium' },
    { file: 'e.js', line: 1, ruleId: 'taint.sql-injection', severity: 'high', confidence: 'low' },
  ];
  const score = scoreTarget({ id: 'fixture' }, labels(cases), findings, manifest);
  assert.deepStrictEqual(score.metrics, { tp: 1, fp: 2, fn: 2, precision: 0.3333, recall: 0.3333, f1: 0.3333 });
  assert.deepStrictEqual(score.categories['sql-injection'], { tp: 1, fp: 0, fn: 1 });
  assert.deepStrictEqual(score.categories['hardcoded-secret'], { tp: 0, fp: 0, fn: 1 });
  assert.deepStrictEqual(score.categories['unexpected-rule'], { tp: 0, fp: 1, fn: 0 });
  assert.deepStrictEqual(score.categories.benign, { tp: 0, fp: 1, fn: 0 });
  assert.strictEqual(score.cases.find((c) => c.id === 'tp').matchedRule, 'taint.sql-injection');
  assert.strictEqual(score.cases.find((c) => c.id === 'fn').verdict, 'FN');
  assert.strictEqual(score.cases.find((c) => c.id === 'wrong-rule').verdict, 'FN');
  assert.strictEqual(score.ignoredFindings, 0);
});

test('line ranges and ignored findings are deterministic', () => {
  const cases = [{ id: 'range', file: 'a.js', lines: [10, 12], category: 'sql-injection' }];
  const findings = [
    { file: 'a.js', line: 11, ruleId: 'taint.sql-injection', severity: 'high', confidence: 'high' },
    { file: 'other.js', line: 1, ruleId: 'secret.generic-credential', severity: 'high', confidence: 'high' },
  ];
  const score = scoreTarget({ id: 'fixture' }, labels(cases), findings, manifest);
  assert.strictEqual(score.metrics.tp, 1);
  assert.strictEqual(score.ignoredFindings, 1);
});

test('stable report ignores environment but detects metric drift', () => {
  const base = {
    benchmark: 'fixture',
    scanner: { name: 'vibeguard', version: '1.0.0', sourceHash: 'abc' },
    scope: 'scoped',
    targets: [{
      id: 't', commit: '0'.repeat(40), treeHash: 't', fileHash: 'f', labelsHash: 'l',
      metrics: { tp: 1, fp: 0, fn: 0, precision: 1, recall: 1, f1: 1 },
      categories: {}, cases: [], unsupported: [], ignoredFindings: 0, scopeFindings: 1,
    }],
    overall: { tp: 1, fp: 0, fn: 0, precision: 1, recall: 1, f1: 1 },
  };
  const same = { ...base, environment: { node: 'different' } };
  assert.deepStrictEqual(diffReports(base, same), []);
  const drifted = JSON.parse(JSON.stringify(base));
  drifted.targets[0].metrics.tp = 0;
  assert(diffReports(base, drifted).length > 0);
});

test('hashDirectory is deterministic and can normalize line endings', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-ext-hash-'));
  try {
    fs.writeFileSync(path.join(dir, 'a.js'), 'const a = 1;\r\n');
    fs.writeFileSync(path.join(dir, 'b.js'), 'const b = 2;\n');
    const first = hashDirectory(dir, { normalizeEol: true });
    const second = hashDirectory(dir, { normalizeEol: true });
    assert.strictEqual(first, second);
    fs.writeFileSync(path.join(dir, 'a.js'), 'const a = 1;\n');
    assert.strictEqual(hashDirectory(dir, { normalizeEol: true }), first);
    fs.writeFileSync(path.join(dir, 'a.js'), 'const a = 3;\n');
    assert.notStrictEqual(hashDirectory(dir, { normalizeEol: true }), first);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('manifest and labels are internally consistent and pinned', () => {
  const root = path.join(__dirname, '..', 'benchmarks', 'external');
  const data = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));
  assert.strictEqual(data.schemaVersion, '1.0');
  assert(data.targets.length >= 1);
  for (const target of data.targets) {
    assert(/^[0-9a-f]{40}$/.test(target.commit), `${target.id} commit must be a full SHA-1`);
    assert(target.repo.startsWith('https://'), `${target.id} repo must be https`);
    const labelPath = path.join(root, target.labels);
    assert(labelPath.startsWith(root + path.sep), `${target.id} labels must stay inside the benchmark directory`);
    const label = JSON.parse(fs.readFileSync(labelPath, 'utf8'));
    assert.strictEqual(label.target, target.id);
    assert.strictEqual(label.commit, target.commit);
    assert(Array.isArray(label.cases) && label.cases.length > 0);
    for (const item of label.cases) {
      assert(item.id && item.file, `${target.id} case needs id/file`);
      assert(!item.file.includes('..'), `${target.id} case path must not traverse`);
      if (!item.benign) assert(data.categories[item.category], `${target.id} unknown category ${item.category}`);
    }
  }
});

module.exports = { tests };
