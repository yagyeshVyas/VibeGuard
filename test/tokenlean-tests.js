'use strict';

/*
 * Tests for TLAP — the token-lean agent protocol (src/tokenlean.js).
 *
 * The properties that matter, and that these lock down:
 *   1. Lossless-by-default: every finding location survives clustering.
 *   2. Never silently lossy: if a budget cuts findings, the payload says so
 *      and explicitly denies being an all-clear.
 *   3. Risk-ranked: under a tight budget, criticals outlive lows.
 *   4. Deterministic: same input, byte-identical output.
 *   5. Actually cheaper: lean beats pretty JSON on a realistic finding set.
 *
 * Run: node test/tokenlean-tests.js   (standalone)
 */

const assert = require('assert');
const tl = require('../src/tokenlean');

const tests = [];
function test(name, fn) {
  Object.defineProperty(fn, 'name', { value: name });
  tests.push(fn);
}

function finding(over) {
  return Object.assign(
    {
      ruleId: 'secret.openai-key',
      severity: 'critical',
      confidence: 'high',
      message: 'Hardcoded OpenAI API key.',
      fix: 'Move the key to an environment variable and rotate it.',
      file: 'src/api/route.ts',
      line: 3,
      fingerprint: Math.random().toString(16).slice(2, 10),
    },
    over
  );
}

function fakeResult(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return {
    grade: counts.critical ? 'F' : 'A',
    counts,
    scannedFiles: 42,
    root: '/tmp/x',
    findings,
  };
}

test('estimateTokens is monotonic and roughly 3-5 chars per token on code', () => {
  assert.strictEqual(tl.estimateTokens(''), 0);
  const sample = 'const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;';
  const t = tl.estimateTokens(sample);
  const ratio = sample.length / t;
  assert(ratio > 2.0 && ratio < 6.0, `chars/token out of band: ${ratio}`);
  assert(
    tl.estimateTokens(sample + sample) > t,
    'doubling the text must raise the estimate'
  );
});

test('clustering collapses repeated rules but keeps every location', () => {
  const findings = [
    finding({ file: 'src/a.ts', line: 3 }),
    finding({ file: 'src/a.ts', line: 9 }),
    finding({ file: 'src/b.ts', line: 14 }),
    finding({ ruleId: 'code.sql-injection', severity: 'high', file: 'src/db.ts', line: 7, message: 'SQLi', fix: 'Parameterize.' }),
  ];
  const clusters = tl.clusterFindings(findings);
  assert.strictEqual(clusters.length, 2, 'two distinct rules => two clusters');
  const secret = clusters.find((c) => c.ruleId === 'secret.openai-key');
  assert.strictEqual(secret.count, 3, 'all three occurrences counted');
  const lines = secret.files.flatMap((f) => f.lines);
  assert.deepStrictEqual(lines.sort((a, b) => a - b), [3, 9, 14], 'no location lost');
});

test('identical lines in one file are de-duplicated, not double-counted', () => {
  const clusters = tl.clusterFindings([
    finding({ file: 'src/a.ts', line: 3 }),
    finding({ file: 'src/a.ts', line: 3 }),
  ]);
  assert.strictEqual(clusters[0].files[0].lines.length, 1, 'same file:line listed once');
});

test('path dictionary only fires when it actually saves characters', () => {
  const many = Array.from({ length: 6 }, (_, i) => `src/components/dashboard/w${i}.tsx`);
  const dict = tl.buildPathDict(many);
  assert(dict.length >= 1, 'a repeated long prefix earns a slot');
  assert.strictEqual(
    tl.applyDict('src/components/dashboard/w0.tsx', dict),
    dict[0].token + 'w0.tsx'
  );
  // A single short path is not worth a legend line.
  assert.strictEqual(tl.buildPathDict(['a/b.ts']).length, 0);
});

test('risk ranking puts confirmed criticals above pattern-only lows', () => {
  const crit = tl.riskScore(finding({ severity: 'critical', confidence: 'high' }));
  const low = tl.riskScore(finding({ ruleId: 'style.x', severity: 'low', confidence: 'low', file: 'docs/readme.md' }));
  assert(crit > low, 'critical must outrank low');
  const confirmed = tl.riskScore(
    finding({ ruleId: 'taint.sql-injection', severity: 'high', message: 'flows into SQL (dataflow-confirmed)' })
  );
  const pattern = tl.riskScore(finding({ ruleId: 'code.sql-like', severity: 'high', message: 'looks like SQL' }));
  assert(confirmed > pattern, 'dataflow-confirmed must outrank pattern-only at equal severity');
});

test('a budget keeps criticals and reports what it dropped', () => {
  const findings = [
    finding({ severity: 'critical', file: 'src/a.ts', line: 1 }),
    ...Array.from({ length: 30 }, (_, i) =>
      finding({
        ruleId: 'style.rule' + i,
        severity: 'low',
        confidence: 'low',
        message: 'A fairly wordy low-severity message that costs real tokens ' + i,
        fix: 'Some remediation advice that also costs real tokens ' + i,
        file: `src/x${i}.ts`,
        line: i,
      })
    ),
  ];
  const out = tl.renderLean(fakeResult(findings), { budget: 160 });
  assert(out.tokens <= 200, `budget overrun: ${out.tokens}`);
  assert(out.text.includes('secret.openai-key'), 'the critical survives the budget');
  assert(out.omitted > 0, 'something was dropped');
  assert(/more finding\(s\) over budget/.test(out.text), 'drop is disclosed');
  assert(/NOT an all-clear/.test(out.text), 'truncated output must refuse to read as clean');
});

test('an unbudgeted render drops nothing', () => {
  const findings = Array.from({ length: 25 }, (_, i) =>
    finding({ ruleId: 'r' + i, file: `src/f${i}.ts`, line: i })
  );
  const out = tl.renderLean(fakeResult(findings));
  assert.strictEqual(out.omitted, 0);
  for (let i = 0; i < 25; i++) assert(out.text.includes('r' + i), 'rule ' + i + ' present');
});

test('degraded coverage warnings survive compression', () => {
  const r = fakeResult([finding({})]);
  r.engine = { mode: 'regex-only' };
  r.diagnostics = { degradedFileCount: 4 };
  const out = tl.renderLean(r);
  assert(/regex-only/.test(out.text), 'engine mode disclosed');
  assert(/not an all-clear/i.test(out.text), 'degraded scan must not read as clean');
  assert(/4 file\(s\) partially analyzed/.test(out.text), 'degraded file count disclosed');
});

test('a clean scan renders in a handful of tokens', () => {
  const out = tl.renderLean(fakeResult([]));
  assert(out.tokens < 30, `clean scan should be tiny, got ${out.tokens}`);
  assert(/^VG Grade A \| clean/.test(out.text), 'header states the grade in words: ' + out.text);
});

test('lean beats pretty JSON on a realistic finding set', () => {
  const findings = Array.from({ length: 40 }, (_, i) =>
    finding({ file: `src/components/dashboard/widget${i}.tsx`, line: i + 1 })
  );
  const s = tl.leanStats(fakeResult(findings));
  assert(s.leanTokens < s.jsonTokens, 'lean must be smaller');
  assert(s.savedPct > 50, `expected >50% saving on a repetitive set, got ${s.savedPct}%`);
  assert.strictEqual(s.clusters, 1, '40 identical-rule findings collapse to one cluster');
});

test('render is deterministic', () => {
  const findings = [
    finding({ file: 'src/b.ts', line: 2 }),
    finding({ ruleId: 'code.xss', severity: 'high', file: 'src/a.ts', line: 5, message: 'XSS', fix: 'Escape.' }),
    finding({ file: 'src/a.ts', line: 1 }),
  ];
  const a = tl.renderLean(fakeResult(findings)).text;
  const b = tl.renderLean(fakeResult(findings.slice().reverse())).text;
  assert.strictEqual(a, b, 'output must not depend on input ordering');
});

test('delta mode answers "unchanged" in one line, and reports new findings', () => {
  const base = fakeResult([finding({ fingerprint: 'aaaa', file: 'src/a.ts', line: 1 })]);
  const snap = tl.snapshotOf(base);
  const same = tl.deltaReport(base, snap);
  assert.strictEqual(same.unchanged, true);
  assert(same.tokens < 40, `unchanged answer should be tiny, got ${same.tokens}`);
  assert(!/CRIT/.test(same.text), 'unchanged answer should not re-list findings');

  const grown = fakeResult([
    finding({ fingerprint: 'aaaa', file: 'src/a.ts', line: 1 }),
    finding({ fingerprint: 'bbbb', ruleId: 'code.sql-injection', severity: 'high', file: 'src/db.ts', line: 9, message: 'SQLi', fix: 'Parameterize.' }),
  ]);
  const d = tl.deltaReport(grown, snap);
  assert.strictEqual(d.unchanged, false);
  assert.strictEqual(d.newCount, 1);
  assert(/code.sql-injection/.test(d.text), 'the new finding is shown');
  assert(!/secret.openai-key/.test(d.text), 'the already-reported finding is not repeated');
});

test('delta mode counts resolved findings', () => {
  const before = tl.snapshotOf(
    fakeResult([finding({ fingerprint: 'aaaa' }), finding({ fingerprint: 'bbbb' })])
  );
  const after = fakeResult([finding({ fingerprint: 'aaaa' })]);
  const d = tl.deltaReport(after, before);
  assert.strictEqual(d.resolved, 1);
  assert.strictEqual(d.newCount, 0);
});

test('compactText clamps arbitrary tool output and says so', () => {
  const big = 'alpha beta gamma delta epsilon '.repeat(400);
  const out = tl.compactText(big, 100);
  assert(tl.estimateTokens(out) < tl.estimateTokens(big), 'must shrink');
  assert(/truncated/.test(out), 'truncation disclosed');
  assert(/PARTIAL — not an all-clear/.test(out), 'clipped output must not read as clean');
  // Under budget: untouched.
  assert.strictEqual(tl.compactText('short', 1000), 'short');
  assert.strictEqual(tl.compactText(big, 0), big, 'no budget => no clamping');
});

test('lean fix plan states remediation once per rule, not once per site', () => {
  const findings = Array.from({ length: 12 }, (_, i) =>
    finding({ file: `src/api/r${i}.ts`, line: i + 1 })
  );
  const plan = tl.renderLeanFixPlan(fakeResult(findings));
  const fixLines = plan.split('\n').filter((l) => l.trim().startsWith('fix:'));
  assert.strictEqual(fixLines.length, 1, '12 sites of one rule => one fix line');
  assert(/x12/.test(plan), 'site count is stated');
  for (let i = 0; i < 12; i++) assert(plan.includes(`r${i}.ts:${i + 1}`), 'site ' + i + ' listed');
  // The diagnosis is dropped in a fix plan; the remediation is the payload.
  assert(!plan.includes('Hardcoded OpenAI API key.'), 'message omitted from a fix plan');
});

test('lean fix plan is clean-safe and budget-aware', () => {
  assert(/clean/.test(tl.renderLeanFixPlan(fakeResult([]))), 'nothing to fix reads as clean');
  const many = Array.from({ length: 40 }, (_, i) =>
    finding({ ruleId: 'r' + i, file: `src/f${i}.ts`, line: i, fix: 'Remediation text number ' + i })
  );
  const plan = tl.renderLeanFixPlan(fakeResult(many), { budget: 150 });
  assert(tl.estimateTokens(plan) <= 200, 'budget respected');
  assert(/NOT a complete plan/.test(plan), 'an incomplete plan must say so');
});

test('snapshot hash ignores finding order', () => {
  const a = fakeResult([finding({ fingerprint: 'x1' }), finding({ fingerprint: 'x2' })]);
  const b = fakeResult([finding({ fingerprint: 'x2' }), finding({ fingerprint: 'x1' })]);
  assert.strictEqual(tl.snapshotOf(a).hash, tl.snapshotOf(b).hash);
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
