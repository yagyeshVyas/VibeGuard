# Changelog

All notable changes to VibeGuard are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
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

### Changed
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
