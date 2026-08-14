'use strict';

/*
 * Standalone tests for `vibeguard pr-scan` (bin/cmd-pr-scan.js).
 * Crafted temp git repos: a pre-existing finding OUTSIDE the diff must stay
 * unreported; a secret ADDED in the diff must be reported with exit 2.
 * Run: node test/pr-scan-tests.js  (merged into run.js by the orchestrator).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const assert = require('assert');

function git(dir, args) {
  return execFileSync('git', args, { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
}

function tmpRepo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vgpr-'));
  git(dir, ['init', '-q']);
  git(dir, ['config', 'user.name', 'test']);
  git(dir, ['config', 'user.email', 't@t']);
  git(dir, ['config', 'commit.gpgsign', 'false']);
  for (const [name, content] of Object.entries(files)) {
    const full = path.join(dir, name);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  git(dir, ['add', '-A']);
  git(dir, ['commit', '-q', '-m', 'init']);
  return dir;
}

// runtime-constructed secret so self-scan stays Grade A
const TOKEN = 'sk-proj-' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' + '123456';

async function testDiffOnlyReportsAddedLines() {
  const dir = tmpRepo({
    'app.js': 'const x = 1;\n',
    'legacy.js': 'const KEY = ' + JSON.stringify(TOKEN) + ';\n', // pre-existing secret, NOT in diff
  });
  fs.appendFileSync(path.join(dir, 'app.js'), '\nconst apiKey = ' + JSON.stringify(TOKEN) + ';\n');
  const { runPrScan } = require('../bin/cmd-pr-scan');
  const result = await runPrScan(dir, {});
  const ids = result.findings.map((f) => f.file + ':' + f.line + ':' + f.ruleId);
  assert(result.findings.length >= 1, 'added secret must be reported, got: ' + ids.join(', '));
  assert(result.findings.every((f) => f.file === 'app.js'), 'findings must be in the changed file only');
  assert(!result.findings.some((f) => f.file === 'legacy.js'), 'pre-existing finding must NOT be reported');
}

async function testCleanDiffExitZero() {
  const dir = tmpRepo({ 'app.js': 'const x = 1;\n' });
  fs.appendFileSync(path.join(dir, 'app.js'), '\nconst y = 2; // safe addition\n');
  const { runPrScan } = require('../bin/cmd-pr-scan');
  const result = await runPrScan(dir, {});
  assert.strictEqual(result.findings.length, 0, 'clean diff must have 0 findings');
}

async function testStagedScope() {
  const dir = tmpRepo({ 'app.js': 'const x = 1;\n' });
  fs.appendFileSync(path.join(dir, 'app.js'), '\nconst z = ' + JSON.stringify(TOKEN) + ';\n');
  git(dir, ['add', '-A']);
  const { runPrScan } = require('../bin/cmd-pr-scan');
  const result = await runPrScan(dir, { staged: true });
  assert(result.findings.length >= 1, 'staged secret must be reported');
}

async function testBaseRangeScope() {
  const dir = tmpRepo({ 'app.js': 'const x = 1;\n' });
  git(dir, ['checkout', '-q', '-b', 'feature']);
  fs.appendFileSync(path.join(dir, 'app.js'), '\nconst w = ' + JSON.stringify(TOKEN) + ';\n');
  git(dir, ['add', '-A']);
  git(dir, ['commit', '-q', '-m', 'add secret']);
  const { runPrScan } = require('../bin/cmd-pr-scan');
  const result = await runPrScan(dir, { base: 'master' });
  assert(result.findings.length >= 1, 'PR-range secret must be reported');
}

async function testCliExitCodes() {
  const dir = tmpRepo({ 'app.js': 'const x = 1;\n' });
  fs.appendFileSync(path.join(dir, 'app.js'), '\nconst v = ' + JSON.stringify(TOKEN) + ';\n');
  const { cmdPrScan } = require('../bin/cmd-pr-scan');
  const code = await cmdPrScan({ _: ['pr-scan', dir] }, {});
  assert.strictEqual(code, 2, 'findings must exit 2 (Strix-compatible)');

  const dir2 = tmpRepo({ 'app.js': 'const x = 1;\n' });
  const code2 = await cmdPrScan({ _: ['pr-scan', dir2] }, {});
  assert.strictEqual(code2, 0, 'clean must exit 0');

  const code3 = await cmdPrScan({ _: ['pr-scan', 'C:/nonexistent-dir-xyz'] }, {});
  assert.strictEqual(code3, 1, 'fatal must exit 1');
}

const tests = [
  testDiffOnlyReportsAddedLines,
  testCleanDiffExitZero,
  testStagedScope,
  testBaseRangeScope,
  testCliExitCodes,
];

module.exports = { tests };

if (require.main === module) {
  let passed = 0;
  const failures = [];
  (async () => {
    for (const t of tests) {
      try {
        await t();
        passed++;
        console.log('ok   - ' + t.name);
      } catch (err) {
        failures.push({ name: t.name, err });
        console.log('FAIL - ' + t.name + ': ' + (err && err.message ? err.message : String(err)));
      }
    }
    console.log('\n' + passed + ' passed, ' + failures.length + ' failed');
    if (failures.length > 0) process.exit(1);
  })();
}
