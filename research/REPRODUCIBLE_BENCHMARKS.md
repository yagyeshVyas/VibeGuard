# VibeGuard — Reproducible Benchmarks

**Date:** 2026-11-21/22  
**Machine:** Windows 11, 11th Gen Intel i5-11400H, 34,111,545,344 bytes RAM  
**Runtime:** Node v24.14.0 (current); baseline worktree same machine  
**Baseline revision:** `2ce5b36` in a detached `git worktree` with the current
`node_modules` junctioned (no dependency difference for scanner/core probes).

All timings are local wall-clock microbenchmarks, not capacity guarantees.
They were run without network traffic or real credentials.

---

## 1. Commands

```bash
# Full security microbenchmark (writes reports/benchmark.json)
node scripts/security-bench.js --out reports/benchmark.json

# Current vs baseline tool-call/scan comparison
node research/benchmark-compare.js "D:\vibe guard" <fixture>
node research/benchmark-compare.js <baseline-worktree> <fixture>

# Startup (PowerShell, 7 runs)
Measure-Command { node bin/cli.js --version }

# Full suite / platform suite
npm test
node test/run-platform.js
npx -y node@18 test/run.js
npx -y node@20 test/run-platform.js
npx -y node@22 test/run-platform.js
```

Baseline worktree creation:

```bash
git worktree add --detach "$env:TEMP\vg-base-verify" 2ce5b36
# junction current node_modules for a fair core/scanner comparison
```

---

## 2. Current vs baseline

### 2.1 Benign tool-call evaluation (5,000 calls, `echo`, short text)

| Metric | v1.10 baseline | Current v2 tree | Change |
|---|---:|---:|---:|
| Wall time | 47.2 ms | 622.3 ms | ~13.2× slower |
| Throughput | 105,982 ops/s | 8,035 ops/s | ~92% lower |
| CPU time | 78 ms | 703 ms | ~9× CPU |
| RSS after loop | 53.3 MB | 53.3 MB | no measurable difference |
| Added latency/call | ~0.009 ms | ~0.124 ms | ~0.115 ms |

Strict-mode equivalent (5,000 calls, explicit allowlist):

| Metric | Baseline | Current |
|---|---:|---:|
| Throughput | 94,833 ops/s | ~6,356–6,500 ops/s |
| CPU (5,000) | ~53 ms | ~704–787 ms |

**Interpretation:** the current security path adds meaningful CPU/latency for a
tiny call. Absolute per-call overhead is sub-millisecond, but high-QPS use needs
profiling and a fast path/caching strategy. This is a real regression, not a
theoretical one. The scanner itself is unchanged.

### 2.2 Scanner performance (generated JS fixture)

| Fixture | Baseline | Current | Notes |
|---|---:|---:|---|
| 100 files / 2,000 findings | 531 ms | 525 ms | within variance |
| 500 files / 10,000 findings | 2,913 ms | 2,915 ms | within variance |

### 2.3 CLI startup (7 runs, `--version`)

| Baseline | Current |
|---:|---:|
| 101.7 ms average | 94.5 ms average |

Startup is effectively unchanged/slightly faster; the security modules are not
all loaded for `--version`.

---

## 3. Current security primitive microbenchmarks

From `reports/benchmark.json` (Windows, Node 24):

| Operation | Iterations | Throughput | p50 / p95 |
|---|---:|---:|---:|
| identity issue+verify | 1,000 | 3,752 ops/s | 0.250 / 0.343 ms |
| strict policy evaluate | 5,000 | 3,359 ops/s | 0.283 / 0.382 ms |
| injection scan (1 KB) | 2,000 | 16,182 ops/s | 0.058 / 0.066 ms |
| signed audit append+fsync (checkpoint sidecar) | 200 | 169 ops/s | — |
| signed audit verify (200 entries) | 200 | 36.2 ms total | — |
| process sandbox spawn+run | 5 | 13.4 ops/s | 74.3 / 78.2 ms |
| MCP engine check (path args) | 2,000 | 1,464 ops/s | 0.661 / 0.835 ms |

The audit append is slower than the pre-checkpoint measurement (~303 ops/s)
because each event now also writes a signed checkpoint sidecar. This is a
deliberate integrity tradeoff; production needs buffered/batched checkpointing
with an external anchor.

---

## 4. Memory and CPU caveats

- RSS in the comparison loop was ~53.3 MB for both trees; not a max/peak value.
- The full test suite's memory was not instrumented; no claim is made.
- CPU percentages are process CPU time for the loop, not system-wide.
- No long-running soak, disk-full, file-descriptor, or concurrent-session test
  was performed.
- Full suite wall time was affected by running parallel platform/Node/Linux
  suites; only the isolated benchmark numbers above should be compared.

## 5. Reproducibility limits

- Test suite counts are exact for the recorded commands; hardware timings vary.
- The baseline worktree shares `node_modules`; dependency-resolution timing is
  not measured.
- The process/vm sandbox numbers are unverified execution modes, not an OS
  sandbox; do not use them as isolation evidence.
- No benchmark result is a certification or a production capacity claim.

## 6. Detection corpus (small, curated)

```bash
node test/corpus/run.js --gate
```

Current result: prompt precision 1.0 / recall 1.0; tool precision 1.0 /
recall 1.0; zero misses/false positives on 23 prompt + 13 tool samples. This is
a regression seed, **not** a representative precision/recall benchmark. The
corpus is intentionally small and must be expanded with multilingual,
paraphrased, mutation and schema cases before making quality claims.
