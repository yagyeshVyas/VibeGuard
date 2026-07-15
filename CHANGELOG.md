# Changelog

All notable changes to VibeGuard are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added — Phase 1: Compliance + MCP Tools + Breadth
- 4 new MCP tools (82 total): `generate_sbom`, `dep_reachability`,
  `scan_container_image`, `license_compliance`.
- `vibeguard sbom [dir]` — CycloneDX 1.5 SBOM from `package-lock.json` +
  source import graph. Marks which deps are actually imported in code.
  `src/sbom.js`.
- `vibeguard reachability [dir]` — cross-references CVE results against
  the actual import graph. Separates reachable vulns (imported — fix first)
  from transitive-only (lower priority).
- `vibeguard container-scan <image>` — shells out to `trivy` for container
  image vulnerability scanning. Graceful fallback when trivy absent.
- `vibeguard license [dir]` — checks `package.json` licenses against an
  allowlist (MIT/ISC/BSD/Apache/0BSD). `--allow GPL-3.0` adds custom
  licenses. Flags GPL/AGPL/unlicensed.
- 4 new compliance frameworks (10 total): NIST CSF 2.0, OWASP ASVS L1/L2/L3,
  CIS Controls v8, NIST SP 800-53 Rev. 5. `src/compliance.js`,
  `src/rules-pack.js` `COMPLIANCE_MAP`.
- Fixed PCI-DSS from 3.2.1 control IDs to actual v4.0 IDs (6.2.4, 8.3.2, etc.).
- 3 new AI client installers (15 total): Copilot CLI, Amazon Q Developer,
  Sourcegraph Cody. `src/install.js`.
- 3 new CI templates (7 total): Bitbucket Pipelines, Travis CI, Buildkite.
  `ci-templates/`.

### Changed — Phase 0: Honesty Fixes
- `deep_scan` reframed from "LLM-powered deep review" (overclaim) to
  "agentic deep review" — emits structured review contracts for the
  consuming AI client. VibeGuard never calls an LLM. `src/mcp-server.js`.
- Sandbox `vm` limits documented honestly: Node `vm` is not a security
  boundary, memory cap is unenforced. `src/sandbox.js`, `README.md`.
- Stale test floors bumped: 200+ → 500+ rules, 40/54 → 78+ MCP tools.
- README honest-scope expanded: sandbox vm, AI-safety recall 57%, taint
  JS/TS-only, VibeGuard never calls LLM.

### Added
- Self-integrity verification. `vibeguard self-check` now cryptographically
  verifies the CONTENT of its critical security modules (action-guard,
  shell-guard, interceptor, firewall, rules, scanner, taint, mcp-audit, …)
  against a shipped SHA-256 manifest (`src/integrity.json`), not just that they
  load. Detects a patched/neutered guard — e.g. `inspectAction` rewritten to
  always allow, or a rule file gutted — which a load-only check missed. Manifest
  is regenerated on `prepublishOnly` (and via `npm run integrity`). Honest limit:
  detects source tampering, not a full chain of trust; verify npm provenance for
  the trust anchor. `src/integrity.js`, `scripts/gen-integrity.js`.
- Agent Action Firewall — `vibeguard guard-action` + `guard_action` MCP tool +
  `src/action-guard.js` (`inspectAction`). Real-time exfiltration guard:
  inspect any agent action (shell / network / file-write / prompt / MCP call)
  BEFORE it runs and block secret or personal-data exfiltration. Hard rule — an
  API key or PII (email, SSN, credit card, phone) should not leave to an external
  host: secrets blocked unconditionally, PII blocked (or warn), local/allowlisted
  hosts permitted. Also blocks cloud-metadata credential theft, secrets written
  to web-served paths, and secrets in LLM prompts. `sanitizeOutbound()` redacts
  instead of dropping. 100% offline, fail-closed on the block path. A guard, not
  a sandbox.
- `vibeguard agent-scan` — AI Agent Security Posture (new `agent_scan` MCP tool
  too). One graded verdict — "is my AI-agent setup safe?" — aggregating every
  agent-era check into threat categories: MCP-server trust, PII/secret leakage
  to LLM providers, LLM output reaching exec/eval/SQL/DOM, prompt injection,
  agent capability/loop safety, and hallucinated dependencies. Pure offline
  orchestration of already-tested modules (mcp-audit + ai-guard + the `ai.*`
  rule family). `--fail-on <level>` to gate CI.
- `vibeguard mcp-audit` — MCP server security audit (new `mcp_audit` MCP tool
  too). Audits the MCP servers an agent is configured to trust
  (`.mcp.json` / `.cursor/mcp.json` / `.vscode/mcp.json`) for tool poisoning
  (prompt injection in server args/descriptions), unpinned auto-install
  (`npx -y` rug-pull surface), remote-code / shell commands, hardcoded secrets
  in `env`, over-broad filesystem grants, and **definition drift** — a server
  whose config changed since you approved it (classic MCP rug-pull). 100%
  offline: reads config only, never runs a server. Pins server-definition
  hashes under `.vibeguard/mcp-pins.json`; `--pin` re-baselines after review.
- `vibeguard scan --staged` — scan only git-staged files. Ideal for a
  pre-commit hook: fast and scoped to exactly what's being committed. Per-file
  only (cross-file analysis skipped, and the CLI says so).
- `vibeguard scan --no-suppress` — CI trust mode. Ignores inline
  `vibeguard-ignore` comments and the heuristic false-positive filter so a
  careless or hostile inline comment in a PR cannot silence a gate. Deliberate
  project config (ignoreRules/ignorePaths) is still honored.
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

### Fixed
- Interceptor: wrapped `fs.readFileSync` called itself instead of the saved
  original, causing infinite recursion / stack overflow on any uncached file
  read after activation. Now calls the original. Regression test added.

### Changed
- Agent Action Firewall now blocks UNKNOWN-format secrets, not just known vendor
  patterns. An outbound field named like a credential (`apiKey`, `secret`,
  `password`, `client_secret`, `private_key`, `access_key`, …) carrying a
  high-entropy value is blocked from leaving to an external host — so a custom
  API key or session secret that matches no known regex can't exfiltrate either.
  Precise by design: the credential NAME plus real entropy avoids false
  positives on content hashes, UUIDs, ids, env-var references, and low-entropy
  placeholders (all verified). Ambiguous names (token/bearer/session) are
  intentionally excluded to avoid breaking legitimate auth traffic.
- Runtime interceptor now delegates to the unified Agent Action Firewall
  (`action-guard.inspectAction`). Every wrapped `fetch` / `http` / `exec` /
  `execSync` call is checked with the hardened, shared logic — so obfuscated
  commands (base64, `$IFS`, variable indirection) and secrets embedded in a
  request URL are now blocked at runtime, which the interceptor's old naive
  `.includes()` check missed. `CONFIG.allowDomains` are honored as trusted
  destinations. Protection is automatic once the interceptor is active — no
  per-call `guard_action` needed.
- Python taint analysis rewritten as single-pass taint propagation (still pure
  JS — no external parser, keeps VibeGuard zero-dependency and offline). Tracks
  tainted variables through intermediate assignments (`q = "..." + data` →
  `execute(q)`) and clears taint on clean reassignment. Fixes false positives
  where a tainted name merely appeared near an unrelated sink. Parameterized SQL
  (`execute("... %s ...", (params,))`) and inline-sanitized sinks
  (`eval(int(x))`, `os.system(shlex.quote(x))`) are not flagged; unsafe
  concatenation / f-string flows still fire.
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
