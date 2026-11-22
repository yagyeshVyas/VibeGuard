/*
 * Independent microbenchmark used by REPRODUCIBLE_BENCHMARKS.md.
 * Usage:
 *   node research/benchmark-compare.js <repo-root> [fixture-dir]
 *
 * Runs the same 5,000 benign tool-call evaluations and a scan of a generated
 * fixture. It does not modify the repository; the fixture is temp by default.
 */
const path = require('path');
const fs = require('fs');
const os = require('os');
const { performance } = require('perf_hooks');

const root = process.argv[2];
if (!root) throw new Error('repo root required');
const { createEngine } = require(path.join(root, 'src/mcp-firewall'));
const { scan } = require(path.join(root, 'src/scanner'));
const fixture = process.argv[3] || fs.mkdtempSync(path.join(os.tmpdir(), 'vg-bench-fixture-'));
if (!fs.existsSync(path.join(fixture, 'src'))) {
  fs.mkdirSync(path.join(fixture, 'src'), { recursive: true });
  for (let i = 0; i < 100; i++) fs.writeFileSync(path.join(fixture, 'src', `f${i}.js`), `const x = ${i}; console.log(x);\n`.repeat(20));
}
const engine = createEngine({ root, policy: {}, logger: { log() {} } });
for (let i = 0; i < 100; i++) engine.checkToolCall('s', 'echo', { text: 'hello' });
const cpu0 = process.cpuUsage(); const t0 = performance.now();
for (let i = 0; i < 5000; i++) engine.checkToolCall('s', 'echo', { text: 'hello' });
const t1 = performance.now(); const cpu1 = process.cpuUsage(cpu0);
const rss = process.memoryUsage().rss;
const s0 = performance.now(); const result = scan(fixture); const s1 = performance.now();
console.log(JSON.stringify({
  root,
  calls: 5000,
  callMs: Number((t1 - t0).toFixed(1)),
  callOpsPerSec: Number((5000 / (t1 - t0) * 1000).toFixed(0)),
  callCpuMs: Number(((cpu1.user + cpu1.system) / 1000).toFixed(1)),
  rssMB: Number((rss / 1024 / 1024).toFixed(1)),
  scanMs: Number((s1 - s0).toFixed(1)),
  findings: result.findings ? result.findings.length : null,
}, null, 2));
