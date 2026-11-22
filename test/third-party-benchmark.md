# Independent / third-party run: OWASP Juice Shop

This page records a scan of an externally maintained codebase, run so that
VibeGuard's behavior can be inspected on code its author did not write and did
not tune the corpus against. It sits **alongside** the self-built benchmark in
[`test/benchmark/benchmark-results.md`](benchmark/benchmark-results.md); it does
not replace it.

## What was run

| Item | Value |
|---|---|
| Target | [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) |
| Target revision | `c9f99228d9d56afb5f5ca7925376292f7fa44b13` (shallow clone of `master`, 2026-11-22) |
| Scanner | VibeGuard `1.13.0`, repo commit `85fe1eeff8704f16c909eaf3b5461bc385eef8ce` |
| Run date | 2026-11-22 |
| Platform | Windows 11, Node.js v24.14.0 |

Commands (CLI entry verified from `package.json` `bin.vibeguard` → `bin/cli.js`):

```bash
git clone --depth 1 https://github.com/juice-shop/juice-shop.git ../juice-shop
node bin/cli.js scan ../juice-shop > test/juice-shop-results.txt
node bin/cli.js scan ../juice-shop --sarif > test/juice-shop-results.sarif
```

`--sarif` is the flag this release implements (see `bin/cli.js`); the equivalent
`--output sarif` form was not used. Both runs scanned the same checkout and
produced the same 1,181 findings.

## Why Juice Shop

Juice Shop is maintained by OWASP, is not authored by this project, is widely
used as a deliberately-vulnerable target for security tooling, and contains
realistic Node/TypeScript service code, an Angular frontend, Terraform, CI
workflows, and a large test suite. That mix is a useful sanity check that the
scanner does not fall over on a real repository and that its findings are
inspectable by a third party.

## Raw result

| Metric | Value |
|---|---|
| Files scanned | 1,057 |
| Total findings | 1,181 |
| Grade | **F** |
| Critical | 209 |
| High | 286 |
| Medium | 120 |
| Low | 566 |
| Exit code | 1 (findings at/above the default fail threshold) |

Artifacts: [`juice-shop-results.txt`](juice-shop-results.txt) (human output),
[`juice-shop-results.sarif`](juice-shop-results.sarif) (SARIF 2.1.0, 1,181
results).

Top rule IDs by count:

| Rule | Count |
|---|---|
| `code.insecure-http` | 558 |
| `secret.generic-credential` | 202 |
| `secret.high-entropy-token` | 112 |
| `jwt2026.token-in-localstorage` | 70 |
| `secret.high-entropy` | 57 |
| `iac.terraform` | 30 |
| `crypto2026.timing-unsafe-compare` | 28 |
| `pii.secret-in-response` | 15 |
| `taint.path-traversal` | 8 |
| `ast.nosql-injection` | 7 |
| `taint.sql-injection` | 6 |

## What looks like a genuine hit

- `routes/login.ts` and `routes/search.ts` — taint-tracked SQL construction
  (`taint.sql-injection`). These are real, intentionally planted SQL-injection
  sinks.
- `routes/userProfile.ts:65` and `routes/captcha.ts:22` — `eval()` on
  request-derived data (`taint.code-injection`, `ast.eval-dynamic`).
- `lib/insecurity.ts:21` — a hard-coded RSA private key used to sign Juice
  Shop's demo JWTs. Real key material in the tree, deliberately public in this
  project.
- `data/static/users.yml` — plaintext demo account passwords. Flagged as
  credentials; the values are intentionally published fixtures, but the pattern
  of a "credential-like" line is exactly what the rule targets.
- Terraform and GitHub Actions misconfiguration hits (`iac.*`) point at real
  configuration files rather than prose.

## Where it is noisy (false positives observed)

These are reported plainly because the point of this page is credibility, not a
better-looking number:

- **558 `code.insecure-http` findings are dominated by non-issues.** 385 are
  under `frontend/src`, largely vendored Three.js assets
  (`frontend/src/assets/private/*.js`) whose license headers contain `http://`
  URLs, plus Angular `*.spec.ts` files pointing at `http://localhost:3000`.
  Others are plain-HTTP references in data/config files.
- **~529 of 1,181 findings are under test/fixture paths** (`test/`, `*.spec.ts`,
  `data/static/`). Juice Shop keeps deliberately vulnerable examples and demo
  credentials there.
- **`secret.generic-credential` (202) and `secret.high-entropy*` (169) include
  demo and documentation strings**, e.g. `.ai/skills/write-tests/patterns/api.md`
  sample logins and `lib/antiCheat.ts` challenge-ID lists.
- **`ast.command-injection`** also fires inside `lib/codingChallenges.ts`, which
  stores intentionally vulnerable code snippets as challenge material, and
  inside vendored `three.js`.
- Two `taint.sql-injection` hits are in `data/static/codefixes/` — code-fix
  samples, not reachable application code.

## What this run does **not** measure

- **No precision/recall.** Juice Shop has no line-level ground-truth labels, so
  a true/false-positive classification per finding is not computable the way the
  self-built corpus allows. The counts above are raw rule output, not a score.
- **No coverage claim.** Juice Shop's challenge set is dominated by
  business-logic and access-control flaws (basket/IDOR, privilege escalation,
  workflow abuse). VibeGuard does not attempt those, so a clean or noisy result
  here says nothing about detecting them.
- **Not a substitute for the regression corpus.** The 119/119 result on the
  self-built corpus remains a regression gate only; this page is a
  reproducibility and sanity check on third-party code.

Treat this as evidence that the scanner runs end-to-end on an unfamiliar
repository and that its output is inspectable. Do not read it as a benchmark
score, and do not compare it to the 100% F1 figure.
