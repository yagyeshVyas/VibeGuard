'use strict';

/*
 * Regression tests for the v1.7 dataflow-depth pass.
 *
 * These lock down a class of bug that is far worse than a missed finding: the
 * scanner reporting a confident "Grade A — no issues" on code that is trivially
 * exploitable. Textbook inline SQL injection did exactly that, because the AST
 * taint pass deferred any argument containing a source to the regex layer, and
 * the regex layer either rated it below the default confidence floor or had no
 * rule for it at all.
 *
 * Every case here is asserted against the DEFAULT scan — the same filtering a
 * user gets from a bare `vibeguard scan`. A finding that only shows up under
 * --all is not protection.
 *
 * Run: node test/taint-depth-tests.js   (standalone)
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scan, scanFileContent, dedupeFindings, TAINT_SUPERSEDES } = require('../src/scanner');
const { isAvailable } = require('../src/ast');

const tests = [];
function test(name, fn) {
  Object.defineProperty(fn, 'name', { value: name });
  tests.push(fn);
}

/* Scan a single snippet exactly as the product would: rule passes + dedupe. */
function analyze(filename, code) {
  return dedupeFindings(scanFileContent('x/' + filename, filename, code, null));
}

/* What a user actually sees: default min-confidence is medium. */
function visible(filename, code) {
  return analyze(filename, code)
    .filter((f) => f.confidence !== 'low')
    .map((f) => f.ruleId);
}

function tmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-taint-'));
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}

// ---------------------------------------------------------------------------
// The headline bug: a clean grade on live SQL injection
// ---------------------------------------------------------------------------

test('a DEFAULT scan never reports Grade A on inline SQL injection', () => {
  if (!isAvailable()) return;
  const dir = tmpProject({
    'route.js': 'db.query(`SELECT * FROM users WHERE id = ${req.body.id}`);',
  });
  const result = scan(dir, { deps: false });
  const shown = result.findings.filter((f) => f.confidence !== 'low');
  assert(shown.length > 0, 'textbook SQLi must not scan clean at default confidence');
  assert(
    shown.some((f) => f.ruleId === 'taint.sql-injection'),
    'expected taint.sql-injection, got: ' + shown.map((f) => f.ruleId).join(',')
  );
  assert.notStrictEqual(result.grade, 'A', 'a file with live SQLi cannot be Grade A');
});

test('interpolated and concatenated sources both reach the sink', () => {
  if (!isAvailable()) return;
  const shapes = {
    'tpl.js': 'db.query(`SELECT * FROM u WHERE id = ${req.body.id}`);',
    'concat.js': 'db.query("SELECT * FROM u WHERE id = " + req.body.id);',
    'via-var.js': 'const q = `SELECT * FROM u WHERE id=${req.body.id}`;\ndb.query(q);',
    'bare.js': 'db.query(req.body.sql);',
  };
  for (const [name, code] of Object.entries(shapes)) {
    assert(
      visible(name, code).includes('taint.sql-injection'),
      `${name} should report taint.sql-injection, got: ${visible(name, code).join(',') || 'nothing'}`
    );
  }
});

test('laundered sources still reach the sink', () => {
  if (!isAvailable()) return;
  const shapes = {
    'destructure.js': 'const { id } = req.body;\ndb.query(`SELECT * FROM u WHERE id=${id}`);',
    'reassign.js': 'let a = req.query.q;\nlet b = a;\ndb.query(`SELECT * FROM u WHERE n=${b}`);',
    'optchain.js': 'db.query(`SELECT * FROM u WHERE id=${req.body?.id}`);',
    'nested.js': 'db.query(`SELECT * FROM u WHERE f=${req.body.filters[0]}`);',
  };
  for (const [name, code] of Object.entries(shapes)) {
    assert(
      visible(name, code).includes('taint.sql-injection'),
      `${name} should be detected, got: ${visible(name, code).join(',') || 'nothing'}`
    );
  }
});

// ---------------------------------------------------------------------------
// Return-value taint: the helper-accessor direction
// ---------------------------------------------------------------------------

test('taint flows back out of a helper that returns a param-derived value', () => {
  if (!isAvailable()) return;
  assert(
    visible('h1.js', 'function getId(r) { return r.body.id; }\ndb.query(`SELECT * FROM u WHERE id=${getId(req)}`);')
      .includes('taint.sql-injection'),
    'function declaration form'
  );
  assert(
    visible('h2.js', 'const getId = (r) => r.body.id;\ndb.query(`SELECT * FROM u WHERE id=${getId(req)}`);')
      .includes('taint.sql-injection'),
    'expression-bodied arrow form'
  );
  assert(
    visible('h3.js', 'function getCmd(r) { return r.body.cmd; }\nrequire("child_process").exec(getCmd(req));')
      .includes('taint.command-injection'),
    'shell sink through a helper'
  );
});

test('return-value taint requires a real source at the call site', () => {
  if (!isAvailable()) return;
  // Same helper shape, but nothing attacker-controlled is ever passed in.
  const cases = {
    'non-source.js':
      'function getId(o) { return o.body.id; }\nconst cfg = { body: { id: 1 } };\ndb.query(`SELECT * FROM u WHERE id=${getId(cfg)}`);',
    'sanitized.js':
      'function getId(r) { return parseInt(r.body.id, 10); }\ndb.query(`SELECT * FROM u WHERE id=${getId(req)}`);',
    'constant.js':
      'function label(r) { return "fixed"; }\ndb.query(`SELECT * FROM u WHERE n=\'${label(req)}\'`);',
  };
  for (const [name, code] of Object.entries(cases)) {
    assert.deepStrictEqual(visible(name, code), [], `${name} must stay clean`);
  }
});

// ---------------------------------------------------------------------------
// Precision: input is present but neutralised
// ---------------------------------------------------------------------------

test('sanitizers, allowlists and argument position keep safe code clean', () => {
  if (!isAvailable()) return;
  const safe = {
    'parseint.js': 'const id = parseInt(req.body.id, 10);\ndb.query(`SELECT * FROM u WHERE id=${id}`);',
    'escaped.js': "db.query(`SELECT * FROM u WHERE n='${db.escape(req.body.n)}'`);",
    'allowlist.js':
      'const A = ["id","name"];\nconst col = A.includes(req.query.s) ? req.query.s : "id";\ndb.query(`SELECT * FROM u ORDER BY ${col}`);',
    'parameterized.js': 'db.query("SELECT * FROM u WHERE id = ?", [req.body.id]);',
    'const-tpl.js': 'const T = "users";\ndb.query(`SELECT * FROM ${T} WHERE id = ?`, [req.body.id]);',
    'spawn-array.js': 'const { spawn } = require("child_process");\nspawn("git", ["log", req.body.ref]);',
  };
  for (const [name, code] of Object.entries(safe)) {
    assert.deepStrictEqual(visible(name, code), [], `${name} must not fire`);
  }
});

test('only argv/env are taint sources on the process namespace', () => {
  if (!isAvailable()) return;
  // Launching a child Node process is not command injection. Treating every
  // process.* property as attacker input made this the scanner's own worst
  // false positive.
  const clean = visible(
    'spawn-node.js',
    'const { spawn } = require("child_process");\nspawn(process.execPath, [scriptPath], { cwd: dir });'
  );
  assert(!clean.includes('taint.command-injection'), 'process.execPath is not attacker input');

  // argv and env genuinely carry outside input and must still fire.
  assert(
    visible('argv.js', 'const { exec } = require("child_process");\nexec(`ls ${process.argv[2]}`);')
      .includes('taint.command-injection'),
    'process.argv is a source'
  );
  assert(
    visible('env.js', 'const { exec } = require("child_process");\nexec(`ls ${process.env.DIR}`);')
      .includes('taint.command-injection'),
    'process.env is a source'
  );
});

// ---------------------------------------------------------------------------
// Supersession: one vulnerability, one finding
// ---------------------------------------------------------------------------

test('a dataflow-confirmed finding suppresses its weaker counterparts', () => {
  if (!isAvailable()) return;
  const ids = visible('concat.js', 'db.query("SELECT * FROM u WHERE id = " + req.body.id);');
  assert(ids.includes('taint.sql-injection'), 'strong rule reports');
  for (const weak of TAINT_SUPERSEDES['taint.sql-injection']) {
    assert(!ids.includes(weak), `${weak} should be superseded, got: ${ids.join(',')}`);
  }
  // One line, one vulnerability, one finding.
  assert.strictEqual(ids.length, 1, 'expected exactly one finding, got: ' + ids.join(','));
});

test('overlapping Go SQL rules collapse to the highest-confidence one', () => {
  const all = analyze(
    'q.go',
    'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", r.URL.Query().Get("id")))'
  ).map((f) => f.ruleId);
  assert(all.includes('go.sql-injection'), 'the specific rule reports');
  assert(!all.includes('go.sql-format'), 'go.sql-format superseded');
  assert(!all.includes('go.sql-fmt-sprintf'), 'go.sql-fmt-sprintf superseded');
});

// ---------------------------------------------------------------------------
// Failing open must be visible
// ---------------------------------------------------------------------------

test('a crash in the AST taint pass is recorded as degraded coverage', () => {
  const { analyzeTaint } = require('../src/taint');
  const code = 'const x = req.body.id;\ndb.query(`SELECT ${x}`);';
  let degraded = null;
  // A malformed tree forces the AST path to throw; analysis must fall back to
  // regex AND say that it did. Silently downgrading to the weaker engine is how
  // a scanner reports a clean grade on code it never actually analyzed.
  const bogusTree = { type: 'Program', get body() { throw new Error('boom'); } };
  const out = analyzeTaint(code, code.split(/\r?\n/), 'a.js', bogusTree, (err) => {
    degraded = err;
  });
  assert(degraded instanceof Error, 'the AST failure must be surfaced, not swallowed');
  assert.strictEqual(degraded.message, 'boom', 'the original error is passed through');
  assert(Array.isArray(out), 'analysis still falls back to the regex engine');
});

test('the scanner turns a degraded taint pass into visible diagnostics', () => {
  // End to end: the callback above is only useful if scanFileContent records
  // it, because that is what --strict and the CLI banner read.
  const diag = { degraded: [] };
  const code = 'const x = req.body.id;\ndb.query(`SELECT ${x}`);';
  scanFileContent('x/a.js', 'a.js', code, { type: 'Program', get body() { throw new Error('boom'); } }, diag);
  assert(
    diag.degraded.some((d) => d.pass === 'taint-ast'),
    'a failed AST taint pass must appear in diagnostics, got: ' + JSON.stringify(diag.degraded)
  );
});

module.exports = { tests };

if (require.main === module) {
  let pass = 0;
  let fail = 0;
  for (const t of tests) {
    try {
      t();
      pass++;
      console.log('  ok  ' + t.name);
    } catch (e) {
      fail++;
      console.log('  FAIL ' + t.name + '\n       ' + (e.stack || e.message));
    }
  }
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}
