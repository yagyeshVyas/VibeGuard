'use strict';

// CLI exit-path tests: what a command writes must survive the process exit.
//
// `vibeguard scan . --json | jq` is a documented CI flow. A piped stdout is
// non-blocking on Linux/macOS, so `process.exit()` used to return before libuv
// had written everything past the pipe buffer (~64 KiB): the report arrived
// unterminated while the exit code still looked correct. Redirecting stdout to
// a regular file hid it, because a file fd accepts writes synchronously. These
// tests assert the pipe path specifically — a truncation bug passes every
// file-redirect test there is.

const assert = require('assert');
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'cli.js');
const HELPER = path.join(ROOT, 'src', 'cli-exit.js');
const PIPE_BUFFER_BYTES = 64 * 1024;

// One report well past the pipe buffer, built once: the scan is the slow part
// and every assertion below is about its bytes, not about scanning.
let bigDir = null;
function bigProject() {
  if (bigDir) return bigDir;
  bigDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-pipe-'));
  for (let i = 0; i < 96; i++) {
    const n = String(i).padStart(4, '0');
    fs.writeFileSync(
      path.join(bigDir, 'app' + n + '.js'),
      [
        `const openaiKey${n} = "sk-proj-FAKEKEY${n}ABCDEFGHIJKLMNOP";`,
        `const awsKey${n} = "AKIAFAKEKEY${n}ABCDEFGH";`,
        `const stripeKey${n} = "sk_live_FAKEKEY${n}ABCDEFGHIJKLMNOP";`,
        '',
      ].join('\n')
    );
  }
  process.on('exit', () => {
    try {
      fs.rmSync(bigDir, { recursive: true, force: true });
    } catch {
      /* best effort on a temp dir */
    }
  });
  return bigDir;
}

function runCli(args, stdio) {
  return cp.spawnSync(process.execPath, [CLI, ...args], {
    stdio: stdio || ['ignore', 'pipe', 'pipe'],
    encoding: 'buffer',
    maxBuffer: 64 * 1024 * 1024,
    cwd: ROOT,
  });
}

const tests = [];

tests.push({
  name: 'piped --json report larger than the pipe buffer arrives complete; exit code is separate',
  fn() {
    const res = runCli(['scan', bigProject(), '--json']);
    assert.strictEqual(res.stderr.toString('utf8'), '', 'a --json scan reports on stdout only');
    assert(
      res.stdout.length > PIPE_BUFFER_BYTES,
      `report must exceed one pipe buffer over a pipe, got ${res.stdout.length} bytes`
    );

    // JSON.parse throws on an unterminated string — which is exactly how the
    // truncated report failed before exitWhenFlushed().
    const report = JSON.parse(res.stdout.toString('utf8'));
    assert(report.root, 'parsed report has a root');
    assert(report.findings.length >= 96, `parsed report kept every finding, got ${report.findings.length}`);

    // The exit code must be asserted after parsing, not inferred from the
    // presence of output: a truncated run still exited 1.
    assert.strictEqual(res.status, 1, 'findings still exit 1 over a pipe');
  },
});

tests.push({
  name: 'pipe and regular-file redirect produce byte-identical reports and the same exit code',
  fn() {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-pipe-out-'));
    const outFile = path.join(outDir, 'report.json');
    try {
      const piped = runCli(['scan', bigProject(), '--json']);
      const fd = fs.openSync(outFile, 'w');
      let filed;
      try {
        filed = runCli(['scan', bigProject(), '--json'], ['ignore', fd, 'pipe']);
      } finally {
        fs.closeSync(fd);
      }
      const onDisk = fs.readFileSync(outFile);
      assert(onDisk.length > PIPE_BUFFER_BYTES, 'the file redirect is past the pipe buffer too');
      assert.strictEqual(piped.stdout.length, onDisk.length, 'pipe output must not be shorter than the file');
      // `generatedAt` is the only field that legitimately differs between two
      // scans; everything else must match byte for byte.
      const normalize = (s) => s.replace(/"generatedAt": "[^"]*"/, '"generatedAt": "<ts>"');
      assert.strictEqual(
        normalize(piped.stdout.toString('utf8')),
        normalize(onDisk.toString('utf8')),
        'same report both ways'
      );
      assert.strictEqual(piped.status, filed.status, 'same exit code both ways');
    } finally {
      fs.rmSync(outDir, { recursive: true, force: true });
    }
  },
});

tests.push({
  name: 'clean report over a pipe parses and exits 0',
  fn() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-pipe-clean-'));
    try {
      fs.writeFileSync(path.join(dir, 'ok.js'), 'module.exports = 1;\n');
      const res = runCli(['scan', dir, '--json']);
      const report = JSON.parse(res.stdout.toString('utf8'));
      assert.strictEqual(report.findings.length, 0, 'clean project has no findings');
      assert.strictEqual(res.status, 0, 'clean project exits 0');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  },
});

tests.push({
  name: 'exitWhenFlushed drains a 300 KiB stdout payload before exiting with its code',
  fn() {
    // The helper is the shared exit path for every command; drive it directly so
    // a regression there fails here instead of only on macOS CI.
    const script = [
      `const { exitWhenFlushed } = require(${JSON.stringify(HELPER)});`,
      "process.stdout.write('x'.repeat(300 * 1024));",
      'exitWhenFlushed(3);',
    ].join('\n');
    const res = cp.spawnSync(process.execPath, ['-e', script], {
      stdio: ['ignore', 'pipe', 'pipe'],
      encoding: 'buffer',
      maxBuffer: 64 * 1024 * 1024,
    });
    assert.strictEqual(res.stdout.length, 300 * 1024, 'every queued byte reached the pipe');
    assert.strictEqual(res.status, 3, 'the requested exit code is preserved');
  },
});

tests.push({
  name: '--version over a pipe exits 0 with a single parseable line',
  fn() {
    const res = runCli(['--version']);
    assert.strictEqual(res.status, 0, '--version exits 0');
    assert.match(res.stdout.toString('utf8').trim(), /^\d+\.\d+\.\d+/, 'stdout is the bare version');
  },
});

const exported = tests.map((t) => {
  const f = t.fn;
  Object.defineProperty(f, 'name', { value: t.name, configurable: true });
  return f;
});

module.exports = { tests: exported };
