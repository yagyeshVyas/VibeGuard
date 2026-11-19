'use strict';

// v1.9 tests: reachability-native scanning, exploit chains, bundle scanning.

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scan } = require('../src/scanner');
const { scanBundles } = require('../src/bundles');

function tmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-19-'));
  for (const [name, content] of Object.entries(files)) {
    const full = path.join(dir, name);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

const tests = [];

tests.push({
  name: 'reachability: findings are annotated by default and --live drops dead code',
  fn() {
    const dir = tmpProject({
      'server.js': [
        "const app = require('express')();",
        "const db = require('./lib/db');",
        "app.get('/api/users/:id', (req, res) => {",
        '  const row = db.get(req.params.id);',
        '  res.json(row);',
        '});',
        'app.listen(3000);',
      ].join('\n'),
      'lib/db.js': "module.exports = { get(id) { return eval(id); } };\n",
      'lib/dead.js': "function unused(input) { return eval(input); }\n",
    });
    const r = scan(dir, { minConfidence: 'medium' });
    assert(r.surface, 'surface runs by default');
    const dead = r.findings.find((f) => f.file === 'lib/dead.js');
    assert(dead && dead.surface, 'dead file finding annotated');
    assert.strictEqual(dead.surface.reach, 'dead');
    const live = r.findings.find((f) => f.file === 'lib/db.js');
    assert(live && live.surface && live.surface.reach !== 'dead', 'imported sink is reachable');

    const rl = scan(dir, { minConfidence: 'medium', liveOnly: true });
    assert.strictEqual(rl.findings.filter((f) => f.file === 'lib/dead.js').length, 0, 'dead findings filtered');
    assert(rl.findings.some((f) => f.file === 'lib/db.js'), 'live findings kept');
    assert(rl.reach.dead === 0, 'reach summary reports zero dead after filtering');
  },
});

tests.push({
  name: 'reachability: --reachability-grade demotes dead-code findings one tier',
  fn() {
    const dir = tmpProject({
      'server.js': "const app = require('express')();\napp.get('/health', (req, res) => res.json({ ok: true }));\napp.listen(3000);\n",
      'tools/script.js': "function run(x) { return eval(x); }\nmodule.exports = run;\n",
    });
    const plain = scan(dir, { minConfidence: 'medium' });
    const graded = scan(dir, { minConfidence: 'medium', reachabilityGrade: true });
    const criticalPlain = plain.findings.some((f) => f.severity === 'critical' && f.surface && f.surface.reach === 'dead');
    assert(criticalPlain, 'dead critical exists in the plain scan');
    assert.strictEqual(plain.grade, 'F', 'plain scan grades the dead critical as F');
    assert.notStrictEqual(graded.grade, 'F', 'reachability grading demotes the dead critical');
  },
});

tests.push({
  name: 'chains: unauthenticated route → command injection becomes an RCE chain',
  fn() {
    const dir = tmpProject({
      'server.js': [
        "const app = require('express')();",
        "const { execSync } = require('child_process');",
        "app.get('/api/ls', (req, res) => {",
        '  const out = execSync("ls " + req.query.dir);',
        '  res.send(String(out));',
        '});',
        'app.listen(3000);',
      ].join('\n'),
    });
    const r = scan(dir, { minConfidence: 'medium' });
    const chain = r.surface.chains.find((c) => c.impact === 'remote code execution');
    assert(chain, 'RCE chain produced: ' + JSON.stringify(r.surface.chains.slice(0, 2)));
    assert.strictEqual(chain.precondition, 'no authentication');
    assert(chain.narrative.includes('/api/ls'));
  },
});

tests.push({
  name: 'chains: IDOR endpoint produces a chain without any rule firing',
  fn() {
    const dir = tmpProject({
      'server.js': [
        "const app = require('express')();",
        'function handler(req, res) {',
        '  const { userId } = req.params;',
        '  res.json(db.getByUserIdAndThreshold(userId));',
        '}',
        "app.get('/allocations/:userId', handler);",
        'app.listen(3000);',
      ].join('\n'),
    });
    const r = scan(dir, { minConfidence: 'medium' });
    const chain = r.surface.chains.find((c) => c.kind === 'idor');
    assert(chain, 'IDOR chain produced');
    assert.strictEqual(chain.cwe, 'CWE-639');
    assert(chain.entrypoint.path === '/allocations/:userId');
  },
});

tests.push({
  name: 'bundle-scan: secrets inlined in dist/ and exposed source maps are caught',
  fn() {
    const dir = tmpProject({
      'dist/assets/app-9f2c.js': 'const stripe="sk_live_' + 'FAKEKEY1234567890ABCD' + '";fetch("/x");\n',
      'dist/assets/app-9f2c.js.map': '{"version":3,"sources":["src/index.ts"]}\n',
      'dist/assets/style-1.css': 'body{margin:0}\n',
      'src/index.ts': 'export const ok = 1;\n',
    });
    const res = scanBundles(dir);
    const ids = res.findings.map((f) => f.ruleId);
    assert(ids.includes('secret.stripe-live-key'), 'stripe key caught in bundle: ' + ids.join(','));
    assert(ids.includes('bundle.sourcemap-exposed'), 'source map exposure caught');
    assert(res.scannedFiles >= 3, 'artifacts scanned');
  },
});

tests.push({
  name: 'bundle-scan: a clean build is quiet, and missing build output reports a note',
  fn() {
    const clean = tmpProject({
      'dist/assets/app-1.js': 'const a="hello world";console.log(a);\n',
      'dist/assets/app-1.css': 'body{margin:0}\n',
    });
    const res = scanBundles(clean);
    assert.strictEqual(res.findings.length, 0, 'clean bundle: ' + JSON.stringify(res.findings.map((f) => f.ruleId)));

    const empty = tmpProject({ 'src/index.js': 'export const x = 1;\n' });
    const none = scanBundles(empty);
    assert(none.notes.some((n) => /no build output/.test(n)), 'missing build dirs are stated');
  },
});

const exported = tests.map((t) => {
  const f = t.fn;
  Object.defineProperty(f, 'name', { value: t.name, configurable: true });
  return f;
});

module.exports = { tests: exported };
