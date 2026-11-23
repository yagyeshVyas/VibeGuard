# Reproducible External Security Benchmark

This directory contains VibeGuard's **external-code** benchmark: a pinned
third-party repository, a curated file/line label set, and a deterministic
scorer. It exists because the 119-case corpus in `test/benchmark/` is built by
this project and therefore flatters it.

## What is measured

Targets are pinned by repository + commit. For each target:

1. Fetch the exact commit into `benchmarks/external/.cache/<id>` (or verify the
   cached checkout).
2. Hash the working tree and label file.
3. Run VibeGuard's real scanner with dependency/plugin passes disabled.
4. Score **only the labeled file/line ranges**:
   - vulnerable case: a medium+ confidence finding in the range whose rule
     matches the expected category = TP; none = FN; unexpected rule = FP;
   - benign case: any medium+ confidence finding in the file = FP.
5. Write `reports/external-benchmark.json` and `.md` with hashes, per-case
   verdicts, metrics and recorded coverage gaps.

Findings outside the labeled files/ranges are counted as `ignoredFindings` and
do not affect precision/recall. This is deliberate: Juice Shop is full of
intentionally vulnerable test fixtures and challenge snippets, and scoring the
whole repo against this small label set would be misleading in both directions.

## Current target

| Target | Commit | License |
|---|---|---|
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | `c9f99228d9d56afb5f5ca7925376292f7fa44b13` | MIT |

Labels live in `labels/owasp-juice-shop.json`. They cover SQL injection, code
injection, path traversal, SSRF, XSS, hardcoded secrets and insecure randomness,
plus three benign modules. One business-logic IDOR case is recorded as an
**unsupported coverage gap** and is not scored.

## Commands

```bash
# First run (or after changing a target/label): fetch and record the baseline
node benchmarks/external/run.js --refresh --update-baseline

# Reproduce offline and compare against the committed report
node benchmarks/external/run.js --offline --verify

# CI gate: fail if metrics or per-category counts regress against baseline.json
node benchmarks/external/run.js --gate

# Inspect one target / print JSON
node benchmarks/external/run.js --target owasp-juice-shop --offline --json
```

`--refresh` re-fetches and resets the cache. `--offline` never touches the
network and fails if the cache is missing or dirty. `--verify` is offline and
exits non-zero on any stable-field difference from `reports/external-benchmark.json`.

## Reproducibility contract

A report is reproducible when these match:

- `benchmark` id;
- `scanner.sourceHash` (SHA-256 of `src/` excluding generated `integrity.json`,
  line endings normalized, plus `package.json`);
- target `commit`, Git `treeHash`, working-tree `fileHash`, `labelsHash`;
- per-target metrics, category counts, case verdicts and recorded gaps.

The report deliberately has no wall-clock timestamp. The environment (Node,
OS) is recorded separately and ignored by `--verify`.

## Adding a target

1. Add a pinned entry to `manifest.json` with a full 40-hex commit.
2. Add `labels/<id>.json` whose `target` and `commit` match exactly.
3. Add accepted rule patterns to `manifest.categories` if a new category is
   needed.
4. Run `--refresh --update-baseline`, then review the diff before committing
   the report and baseline.

## Limitations

- The label set is curated, not a statistically representative sample.
- It measures detection output, not exploitation, runtime enforcement or
  business-logic coverage.
- Metrics depend on the scanner source hash; any `src/` change requires a
  deliberate baseline update, which is what the gate enforces.
- The target is deliberately vulnerable code. The scanner reads it; it never
  installs dependencies, executes target code or contacts target services.
