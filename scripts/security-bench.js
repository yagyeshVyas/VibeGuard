'use strict';

/*
 * scripts/security-bench.js — reproducible local performance measurements for
 * the v2 security primitives. No network. Results are environment-specific;
 * the report records hardware/Node so numbers are not comparable across
 * machines without context.
 */

const os = require('os');
const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');
const { IdentityAuthority } = require('../src/platform/identity');
const { StrictPolicyEngine } = require('../src/platform/policy');
const { SignedAuditLog } = require('../src/platform/signed-audit');
const { scanTextForInjection } = require('../src/mcp-audit');
const { runInProcess } = require('../src/sandbox');
const { createEngine } = require('../src/mcp-firewall');

function nowMs() { return performance.now(); }
function bench(name, iterations, fn) {
  const times = [];
  const start = nowMs();
  for (let i = 0; i < iterations; i++) {
    const t0 = nowMs();
    fn(i);
    times.push(nowMs() - t0);
  }
  const total = nowMs() - start;
  times.sort((a, b) => a - b);
  return {
    name,
    iterations,
    totalMs: Number(total.toFixed(2)),
    opsPerSec: Number(((iterations / total) * 1000).toFixed(1)),
    p50Ms: Number(times[Math.floor(times.length * 0.5)].toFixed(4)),
    p95Ms: Number(times[Math.floor(times.length * 0.95)].toFixed(4)),
  };
}

function main() {
  const auth = new IdentityAuthority({ issuer: 'human:bench/security', tenant: 'bench' });
  const roots = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-bench-'));
  const policy = new StrictPolicyEngine({
    schemaVersion: '2.0',
    policyId: 'bench',
    policyVersion: '1',
    mode: 'strict',
    defaults: { decision: 'deny' },
    subjects: [{ principal: 'agent:bench/ci', capabilities: ['fs.read', 'mcp.tool.invoke'] }],
    tools: [{ id: 'allow-read', effect: 'allow', match: { tool: 'read_file', capability: 'fs.read' }, resources: { paths: ['src/**'] } }],
  }, { root: roots });
  const text = 'normal developer documentation with no instruction at all. '.repeat(16);

  const results = [];
  results.push(bench('identity.issue+verify', 1000, () => {
    const t = auth.issue({ principal: 'agent:bench/ci', capabilities: ['fs.read'], ttlSeconds: 300 });
    auth.verify(t.token, { replay: false });
  }));
  results.push(bench('policy.evaluate', 5000, () => {
    policy.evaluate({ principal: 'agent:bench/ci', server: 'files', tool: 'read_file', capability: 'fs.read', arguments: { path: 'src/index.js' } });
  }));
  results.push(bench('detect.injectionScan.1KB', 2000, () => scanTextForInjection(text)));

  const auditFile = path.join(roots, 'audit.jsonl');
  const audit = new SignedAuditLog({ file: auditFile, tenant: 'bench' });
  const auditStart = nowMs();
  for (let i = 0; i < 200; i++) audit.append('bench.event', { i }, { principal: 'agent:bench/ci', decision: 'allow' });
  const auditMs = nowMs() - auditStart;
  results.push({ name: 'audit.append+fsync', iterations: 200, totalMs: Number(auditMs.toFixed(2)), opsPerSec: Number(((200 / auditMs) * 1000).toFixed(1)) });
  const vStart = nowMs();
  const verification = SignedAuditLog.verifyFile(auditFile, { publicKey: audit.publicKey });
  results.push({ name: 'audit.verify', iterations: 200, totalMs: Number((nowMs() - vStart).toFixed(2)), valid: verification.valid });

  if (require('../src/sandbox').processIsolationSupported()) {
    results.push(bench('sandbox.process.spawn+run', 5, () => runInProcess('const x = 1 + 2; x', { timeout: 2000 })));
  }

  const gateway = createEngine({ root: roots, policy: {}, logger: { log() {} } });
  results.push(bench('mcp.engine.checkToolCall', 2000, () => gateway.checkToolCall('bench', 'read_file', { path: 'src/index.js' })));

  const report = {
    generatedAt: new Date().toISOString(),
    node: process.version,
    platform: `${os.platform()} ${os.release()} (${process.arch})`,
    cpu: (os.cpus()[0] && os.cpus()[0].model) || 'unknown',
    memoryBytes: os.totalmem(),
    iterationsNote: 'Wall-clock measurements on this machine only; use the same environment for comparisons.',
    results,
  };
  const outArg = process.argv.indexOf('--out');
  if (outArg !== -1 && process.argv[outArg + 1]) {
    fs.mkdirSync(path.dirname(path.resolve(process.argv[outArg + 1])), { recursive: true });
    fs.writeFileSync(path.resolve(process.argv[outArg + 1]), JSON.stringify(report, null, 2) + '\n');
  }
  console.log(JSON.stringify(report, null, 2));
}

main();
