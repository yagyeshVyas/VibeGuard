# Changelog

All notable changes to VibeGuard are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Fail-loud coverage tracking. Every analysis pass (taint, python-taint, AST,
  file-rules) that errors is now recorded instead of silently swallowed. Scan
  results carry `engine` (`ast` | `regex-only`) and `diagnostics`
  (degraded passes, parse-failed files, degraded file count). The CLI prints a
  loud banner when running `regex-only` (acorn missing) or when any file was
  only partially analyzed — a degraded scan no longer masquerades as clean.
- `vibeguard scan --strict` — exit code 3 when any file scanned degraded, so CI
  never trusts an incomplete result. **Note:** existing CI configs that add
  `--strict` will now hard-fail on degraded scans (intended).
- Benchmark quality gate: `node test/benchmark/run.js --gate` fails (exit 2) if
  overall precision/recall/F1 regress below a floor (P≥80% / R≥78% / F1≥80%;
  override via `VIBEGUARD_BENCH_MIN_*`). Wired into CI so detection quality
  regressions block merges.
- ReDoS / pathological-input regression tests + coverage-transparency tests.
- Engine mode + degraded-coverage now surfaced in JSON output and the MCP
  `scan` tool (payload + summary) so agents don't treat a degraded scan as an
  all-clear.
- `VIBEGUARD_NO_POSTINSTALL=1` (and CI auto-detect) to silence the install
  message.
- README `Coverage & Limits` section: honest per-language detection-depth
  matrix, engine-mode explainer, fail-loud explainer, and an explicit "the
  shell guard is a mistake-catcher, not a sandbox" statement.
- `vibeguard auto` — one-command full autonomous protection. Activates
  daemon (file watcher), pre-commit hook, post-edit hook, and shell guard.
  Idempotent. `--stop` reverses everything and restores backups. `--status`
  shows what's active. `--ci` for pipeline mode. `--fix` for safe auto-fixes.
  `--no-shell` to skip shell hook. `--strict` to block on HIGH too.
- `src/auto.js` orchestrator composing existing modules (scanner, daemon,
  hook, shell-guard). All state under `.vibeguard/auto.json`.
- Shell hook FP fix: default-allow policy. Unknown commands are allowed.
  Only block on known dangerous patterns. Fail-open on module load errors.
  Both `shell-hook.sh` and `shell-hook.ps1` now try multiple module paths
  and never block when VibeGuard can't load.

### Performance
- Incremental scanning: `vibeguard scan --changed` only rescans files whose
  content changed since the last scan (SHA-256 hash cache under
  `.vibeguard/cache`). Warm re-scan of an unchanged tree drops from ~600ms to
  ~5ms in local testing (~100×+). Per-file only — cross-file taint/rules are
  skipped in this mode and the CLI says so; run a full scan for those. Intended
  for pre-commit and watch loops.
- Fixed: the scanner no longer walks its own `.vibeguard/` cache/baseline
  artifacts (added to the skip-dirs list).
- Scanner ~50% faster (108ms → 54ms/file on the repo's own source). Three
  behavior-preserving changes, verified identical findings + unchanged benchmark
  (95 TP / 15 FP / 16 FN):
  1. Memoize the global-flag regex per rule — the hot path was recompiling a
     fresh `RegExp` per rule *per line* (~64% of scan time).
  2. Hoist the `fileFilter` check out of the per-line loop (it depends only on
     the path) and cache the compiled filter.
  3. Provably-safe literal prefilter: skip a rule when a mandatory literal from
     its regex is absent from the line, avoiding the regex entirely. Never
     introduces a false negative (bails on alternation, ignores optional/grouped
     literals). Guarded by unit tests + a throughput regression test.

### Changed
- Shell guard normalizer hardened. Now substitutes ALL variable assignments
  (previously only the first, a real bypass: `A=rm; B=-rf; $A $B /`), handles
  `$IFS` word-splitting and `/usr/bin/rm`, and iterates to a fixpoint so layered
  obfuscation unwinds. Still, by design, a mistake-catcher — not a sandbox.
- CI workflow renamed `test.yml` → `ci.yml` to match the README status badge.
- Taint analysis upgraded from regex-only to scope-aware, AST-based dataflow
  (`taint-ast.js`). Sources/sinks matched on AST nodes (MemberExpression /
  CallExpression), not text. Respects block/function scope with shadowing,
  clears taint on clean reassignment, recognizes sanitizers (parseInt,
  path.basename, DOMPurify.sanitize, etc. — configurable array). Tracks
  cross-function taint within a file via intra-function fixpoint. All
  AST-confirmed findings carry `confidence: "high"` and `dataflow: true`.
  Regex taint retained as fallback for unparseable files. Finding object
  shape unchanged (ruleId/severity/title/message/fix preserved).

### Added
- Cross-file taint analysis via import/export graph (`crosstaint.js`)
- Optional AST mode with acorn + acorn-typescript (`ast.js`)
- `vibeguard doctor` — AI host security audit (hook injection, base URL hijack, MCP config)
- `vibeguard history` — git history secret scan
- `vibeguard watch` — re-scan on file change
- `vibeguard rules` / `vibeguard explain` — rule listing and documentation
- Live key verification (`--verify-keys`) for OpenAI + Stripe
- Inline suppressions (`vibeguard-ignore-line` / `vibeguard-ignore-next-line`)
- Project config (`.vibeguardrc.json`) with ignoreRules, ignorePaths, severityOverrides
- .gitignore-aware secret scanning
- Stable finding fingerprints for SARIF + baseline diffing
- External scanner support: semgrep, gitleaks, bandit
- 15 secret types (GitHub, Slack, GitLab, Twilio, SendGrid, Mailgun, Telegram, npm, Resend, connection strings, public-LLM-key)
- AI security rules (browser-api-key, disabled-sandbox, eval-llm-output, prompt-injection-marker)
- Injection rules (prototype pollution, ReDoS, XXE, CRLF)
- Framework rules (Prisma raw, React dangerous HTML, reflected XSS)
- IaC rules (Dockerfile, GitHub Actions, Terraform)
- Package hygiene (unpinned deps, dangerous scripts, no lockfile)
- 63 tests, all passing

## [0.1.0] - Initial release
- Core scanner with secrets, injection, auth, config, PII rules
- Fix → verify loop with baseline + rollback
- MCP server (5 tools)
- Live URL scan
- Badge generation
- One-command multi-client installer
- Pre-commit hook
- GitHub Actions CI template
- SARIF 2.1.0 output
- Zero runtime dependencies (scanner)
