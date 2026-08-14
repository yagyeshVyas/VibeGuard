'use strict';

/*
 * Standalone tests for:
 *   - src/entropy.js            (shannonEntropy, findHighEntropyTokens)
 *   - src/rules.js              (secret.high-entropy-token rule, match fn)
 *   - src/scanner.js            (match-function hook in the fileRules loop)
 *
 * Run:  node test/entropy-tests.js
 * Exit: 0 = all pass, 1 = any failure. Prints "N passed, M failed".
 *
 * NOTE for the orchestrator: these tests are merged into test/run.js later.
 * Every test is a self-contained `function testX()` that throws on failure.
 * There is NO test() registration here — the runner at the bottom just calls
 * the functions in `tests`.
 *
 * Fixture hygiene: VibeGuard self-scans clean, so every secret-shaped string
 * is built at RUNTIME from short chunks (< 24 chars each) — no literal in this
 * file matches a secret regex at the source level.
 */

const assert = require('assert');
const { shannonEntropy, findHighEntropyTokens } = require('../src/entropy');
const { fileRules } = require('../src/rules');
const { scanFileContent } = require('../src/scanner');

// ---------------------------------------------------------------------------
// Runtime-built fixture material (keeps this file self-scan clean)
// ---------------------------------------------------------------------------
const J = (...parts) => parts.join('');

// Brief positive #1: 43-char mixed-case alnum token (entropy ~5.15).
const T_APIKEY = J('x7Q2mZ9pL4', 'kR8wT1nC6v', 'B3yH5jF0aD', '8sG2uE4iK7', 'oQ1');
// Brief positive #2: base64 of "foobarbazqux1234567890abcdefghijklmnopqrstuvwxyz"
// (decoded entropy ~5.0 >= 3.5, so the base64-of-plain-text exclusion does NOT
// swallow it — it must fire).
const T_B64 = J('Zm9vYmFyYmF', '6cXV4MTIzND', 'U2Nzg5MGFiY', '2RlZmdoaWpr', 'bG1ub3BxcnN', '0dXZ3eHl6');
// Brief negative #8: 41-char token on a line with NO key context.
const T_NOCTX = J('Kd9pQ2mZ7xL4', 'rW8tN1cV6bY3', 'hJ5fA0sD2gU4', 'eI7kO');
// JWT segments (header.payload.signature).
const JWT_H = J('eyJhbGciOiJIUzI1', 'NiIsInR5cCI6Ik', 'pXVCJ9');
const JWT_P = J('eyJzdWIiOiIxMjM0', 'NTY3ODkwIiwibm', 'FtZSI6IkpvaG4g', 'RG9lIn0');
const JWT_S = J('SflKxwRJSMeKKF2Q', 'T4fwpMeJf36POk', '6yJV_adQssw5c');
// Firebase web API key (public by design — must never fire).
const FIREBASE = J('AIzaSyD-12345', '67890abcdefg', 'hijklmnopqrs', 'tuv');

const POS_APIKEY = 'const api_key = "' + T_APIKEY + '";';
const POS_B64 = 'OPENAI_API_TOKEN = "' + T_B64 + '";';
const NEG_SHA = 'const sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";';
const NEG_UUID = 'const id = "550e8400-e29b-41d4-a716-446655440000";';
const NEG_SENT = 'const message = "hello world this is a normal sentence with enough words";';
const NEG_URL = 'const url = "https://api.example.com/v1/' + 'very-long-endpoint-' + 'path-here-123456";';
const NEG_SEMVER = 'const version = "1.2.3-alpha.20240101+build.5";';
const NEG_NOCTX = 'const x = "' + T_NOCTX + '";';
const NEG_JWT = 'const token = "' + JWT_H + '.' + JWT_P + '.' + JWT_S + '";';
const NEG_B64TEXT = 'const api_key = "' + Buffer.from('hello world '.repeat(4).trim(), 'utf8').toString('base64') + '";';
const HEX32 = '0123456789abcdef'.repeat(2); // md5 length
const HEX40 = '0123456789abcdef'.repeat(2) + '01234567'; // sha1 length
const HEX64 = '0123456789abcdef'.repeat(4); // sha256/sha512 length
const HEX48 = '0123456789abcdef'.repeat(3); // ambiguous 24-64 (not a checksum length)

function entropyRule() {
  const rule = fileRules.find((r) => r.id === 'secret.high-entropy-token');
  assert.ok(rule, 'secret.high-entropy-token rule must be registered in fileRules');
  return rule;
}

// Call the rule's match fn the way the brief's tests do: bare content, no ctx
// (so no suppression) — except when a ctx override is given.
function ruleHits(content, ctx) {
  return entropyRule().match(content, ctx);
}

// ---------------------------------------------------------------------------
// Engine tests
// ---------------------------------------------------------------------------
function testShannonEntropyBasics() {
  assert.strictEqual(shannonEntropy(''), 0, 'empty string entropy is 0');
  assert.strictEqual(shannonEntropy('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), 0, 'single char entropy is 0');
  assert.strictEqual(shannonEntropy('00000000000000000000000000000000'), 0, 'repeated char entropy is 0');
  const e = shannonEntropy(T_APIKEY);
  assert.ok(e >= 4.0, 'random alnum token entropy >= 4.0, got ' + e);
  assert.ok(e <= 6.0, 'sanity upper bound, got ' + e);
  assert.ok(shannonEntropy('hello world hello world hello world hello world') < 3.5, 'repetitive prose is low entropy');
}

function testFindHighEntropyTokensShape() {
  const content = 'const a = 1;\nconst api_key = "' + T_APIKEY + '";\n';
  const hits = findHighEntropyTokens(content);
  assert.strictEqual(hits.length, 1, 'one hit expected, got ' + hits.length);
  const h = hits[0];
  assert.strictEqual(h.match, T_APIKEY, 'match is the token');
  assert.strictEqual(h.line, 2, '1-based line number');
  assert.ok(h.entropy >= 4.0, 'entropy field present and >= 4.0');
  assert.ok(typeof h.reason === 'string' && h.reason.length > 0, 'reason field present');
  // index must point at the token inside the multi-line content
  assert.strictEqual(content.slice(h.index, h.index + T_APIKEY.length), T_APIKEY, 'index points at the token');
}

// ---------------------------------------------------------------------------
// Brief POSITIVES (must fire)
// ---------------------------------------------------------------------------
function testApiKeyAssignmentFires() {
  assert.strictEqual(ruleHits(POS_APIKEY).length, 1, 'api_key assignment must fire');
  const e = findHighEntropyTokens(POS_APIKEY)[0];
  assert.ok(e.entropy >= 4.0, 'fixture entropy >= 4.0, got ' + e.entropy);
}

function testApiTokenBase64Fires() {
  const hits = ruleHits(POS_B64);
  assert.strictEqual(hits.length, 1, 'OPENAI_API_TOKEN base64 must fire');
  assert.strictEqual(hits[0].match, T_B64, 'matched token is the base64 value');
}

// ---------------------------------------------------------------------------
// Brief NEGATIVES (must NOT fire)
// ---------------------------------------------------------------------------
function testSha256HashDoesNotFire() {
  assert.strictEqual(ruleHits(NEG_SHA).length, 0, 'sha256 hex must not fire');
}

function testUuidDoesNotFire() {
  assert.strictEqual(ruleHits(NEG_UUID).length, 0, 'UUID must not fire');
}

function testNormalSentenceDoesNotFire() {
  assert.strictEqual(ruleHits(NEG_SENT).length, 0, 'normal sentence must not fire');
}

function testUrlDoesNotFire() {
  assert.strictEqual(ruleHits(NEG_URL).length, 0, 'URL must not fire');
}

function testSemverDoesNotFire() {
  assert.strictEqual(ruleHits(NEG_SEMVER).length, 0, 'semver-ish version must not fire');
}

function testNoKeyContextDoesNotFire() {
  assert.strictEqual(ruleHits(NEG_NOCTX).length, 0, 'token without key context must not fire (context gate)');
}

// ---------------------------------------------------------------------------
// Extra exclusions
// ---------------------------------------------------------------------------
function testBase64OfPlainTextDoesNotFire() {
  assert.strictEqual(ruleHits(NEG_B64TEXT).length, 0, 'base64 of plain text must not fire');
}

function testJwtDoesNotFire() {
  assert.strictEqual(ruleHits(NEG_JWT).length, 0, 'JWT-shaped token must not fire');
}

function testChecksumLengthHexDoesNotFire() {
  for (const hex of [HEX32, HEX40, HEX64]) {
    const src = 'const api_key = "' + hex + '";';
    assert.strictEqual(ruleHits(src).length, 0, 'checksum-length hex (' + hex.length + ') must not fire even with key context');
  }
}

function testUniformHexFiresOnlyWithContext() {
  const withCtx = 'const api_key = "' + HEX48 + '";';
  const withoutCtx = 'const zz = "' + HEX48 + '";';
  const h = ruleHits(withCtx);
  assert.strictEqual(h.length, 1, 'ambiguous 48-hex with key context fires (entropy exactly 4.0)');
  assert.strictEqual(h[0].match, HEX48, 'matched token is the hex string');
  assert.strictEqual(ruleHits(withoutCtx).length, 0, 'ambiguous 48-hex without context must not fire');
}

function testPublicBaaSKeyDoesNotFire() {
  const src = "const apiKey = '" + FIREBASE + "';";
  assert.strictEqual(ruleHits(src, { lines: src.split(/\r?\n/) }).length, 0, 'Firebase web API key must not fire');
}

// ---------------------------------------------------------------------------
// Context gate window (±2 lines)
// ---------------------------------------------------------------------------
function testContextWindowPlusMinusTwo() {
  const src = 'const cfg = 1;\nconst value = "' + T_APIKEY + '";\nconst api_key = cfg;\n';
  const hits = ruleHits(src);
  assert.strictEqual(hits.length, 1, 'key identifier two lines below the token still gates it in');
}

function testContextBeyondTwoLinesDoesNotFire() {
  const src = 'const cfg = 1;\nconst value = "' + T_APIKEY + '";\nconst other = 2;\nconst third = 3;\nconst api_key = cfg;\n';
  assert.strictEqual(ruleHits(src).length, 0, 'key identifier three lines away must not gate it in');
}

// ---------------------------------------------------------------------------
// Rule entry + suppression
// ---------------------------------------------------------------------------
function testRuleEntryShape() {
  const rule = entropyRule();
  assert.strictEqual(rule.severity, 'high', 'severity high');
  assert.strictEqual(rule.confidence, 'medium', 'confidence medium');
  assert.strictEqual(typeof rule.match, 'function', 'match is a function');
  assert.strictEqual(rule.re, undefined, 're is omitted (function-based rule)');
  assert.strictEqual(typeof rule.message, 'string', 'message present');
  assert.strictEqual(typeof rule.fix, 'string', 'fix present');
}

function testPriorSecretFindingSuppression() {
  const src = 'const api_key = "' + T_APIKEY + '";\n';
  const lines = src.split(/\r?\n/);
  // No prior findings -> fires.
  assert.strictEqual(ruleHits(src, { lines }).length, 1, 'control: fires without prior findings');
  // A secret.* finding on the same line suppresses (no double-report).
  const ctx = {
    lines,
    findings: [{ ruleId: 'secret.generic-credential', line: 1 }],
  };
  assert.strictEqual(ruleHits(src, ctx).length, 0, 'line already flagged by a secret rule must not double-report');
}

// ---------------------------------------------------------------------------
// Scanner hook (end to end)
// ---------------------------------------------------------------------------
function testScannerHookEndToEnd() {
  // Bare (unquoted) token with key context — no other rule knows this shape.
  const pos = 'const api_key = ' + T_APIKEY + ';\n';
  const posFindings = scanFileContent('t.js', 't.js', pos, null);
  const mine = posFindings.filter((f) => f.ruleId === 'secret.high-entropy-token');
  assert.strictEqual(mine.length, 1, 'scanner must emit secret.high-entropy-token for bare token');
  assert.strictEqual(mine[0].line, 1, 'finding line');
  assert.strictEqual(mine[0].column, 'const api_key = '.length + 1, 'finding column points at the token');
  assert.ok(mine[0].snippet.includes(T_APIKEY.slice(0, 4) + '****'), 'snippet masks the token');

  // Same token WITHOUT key context — nothing fires.
  const neg = 'const x = ' + T_NOCTX + ';\n';
  const negFindings = scanFileContent('t.js', 't.js', neg, null);
  assert.strictEqual(negFindings.filter((f) => f.ruleId === 'secret.high-entropy-token').length, 0, 'no-context token must not fire through the scanner');
}

function testScannerNoDoubleReport() {
  // Quoted api_key: secret.generic-credential owns it; the entropy rule must
  // not double-report the same line.
  const src = POS_APIKEY + '\n';
  const findings = scanFileContent('t.js', 't.js', src, null);
  const ids = findings.map((f) => f.ruleId);
  assert.ok(ids.includes('secret.generic-credential'), 'generic-credential fires on quoted api_key');
  assert.ok(!ids.includes('secret.high-entropy-token'), 'high-entropy-token must not double-report');
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------
const tests = [
  testShannonEntropyBasics,
  testFindHighEntropyTokensShape,
  testApiKeyAssignmentFires,
  testApiTokenBase64Fires,
  testSha256HashDoesNotFire,
  testUuidDoesNotFire,
  testNormalSentenceDoesNotFire,
  testUrlDoesNotFire,
  testSemverDoesNotFire,
  testNoKeyContextDoesNotFire,
  testBase64OfPlainTextDoesNotFire,
  testJwtDoesNotFire,
  testChecksumLengthHexDoesNotFire,
  testUniformHexFiresOnlyWithContext,
  testPublicBaaSKeyDoesNotFire,
  testContextWindowPlusMinusTwo,
  testContextBeyondTwoLinesDoesNotFire,
  testRuleEntryShape,
  testPriorSecretFindingSuppression,
  testScannerHookEndToEnd,
  testScannerNoDoubleReport,
];

module.exports = { tests };

if (require.main === module) {
  let passed = 0;
  const failures = [];
  for (const t of tests) {
    try {
      t();
      passed++;
      console.log('ok   - ' + t.name);
    } catch (err) {
      failures.push({ name: t.name, err });
      console.log('FAIL - ' + t.name + ': ' + (err && err.message ? err.message : String(err)));
    }
  }

  console.log('\n' + passed + ' passed, ' + failures.length + ' failed');
  if (failures.length > 0) process.exit(1);
}
