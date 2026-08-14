# Changelog

All notable changes to VibeGuard are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added — v1.5 active-security pass (beat Strix.ai on the active front)
- **`vibeguard pentest <url>`** — active web/API probe suite, zero deps, deterministic
  (Strix.ai-class "autonomous pentesting" without the LLM). ~20 probe families:
  security headers (CSP/HSTS/XFO/XCTO/RP/PP + HSTS max-age + CSP unsafe-inline),
  CORS (reflected origin / null / wildcard+creds), open redirect (10 paths × 10
  params × 4 payloads), exposed files (30+ paths, content-signature + 404-baseline
  FP guards), GraphQL introspection (`__typename` gate + extended endpoints),
  verbose errors (≥2 stack markers), rate limiting (auth endpoints, OWASP API8),
  JWT alg:none (4 case variants) + weak-HMAC (opt-in `--token`), TLS version/cert
  validity, cookie flags, banner disclosure. Every finding: severity + CWE +
  evidence + curl reproduction. Exit 0/1/2.
- **`--verify-ssrf` — out-of-band SSRF proof-of-exploit**: local callback listener
  + form (action, input) harvesting + query-param fuzzing; target fetching the
  listener URL = deterministic proof (Strix's "proof for every finding").
  Live demo: CRITICAL web.ssrf-proof, callback observed, parameter: url.
- **`vibeguard pr-scan`** — PR review gate, Strix-compatible exit codes
  (0 clean / 2 findings / 1 fatal). Added-lines-only reporting (full-file taint
  analysis, findings filtered to changed lines); scopes: working tree, `--staged`,
  `--base <ref>...HEAD`.
- **`vibeguard fix --apply --verify`** — retest loop: re-scan after applying
  snapshot-backed fixes, report ✓/⚠ per finding ("fix verified" parity).
- **`vibeguard pre-deploy --pentest-url <url>`** — 14th deploy gate: live pentest;
  critical/high fail the gate, medium warns. runPreDeployGate is now async.
- **Engine fixes (taint-ast.js):** process.stdout/stderr, console, logger and
  client/transport objects (req/socket/upstreamReq) are excluded from the
  res.send/write/end XSS sink — CLI tools logging user input are no longer FPs.
- Suite: 468 → **480 tests** (pentest +7 incl. pre-deploy gate E2E, pr-scan +5).
  Self-scan Grade A on 291 files.


### Added — v1.4 power pass (git history · runtime LLM guard · evasion decoders)
- **`vibeguard git-scan`** — scans a repo's ENTIRE git history for leaked secrets
  (Gitleaks/TruffleHog parity). Blob-level enumeration via `git rev-list --objects --all`
  + streaming `git cat-file --batch`, dedupe by blob sha, binary skip, commit attribution
  for every finding. Flags: `--since`, `--max-commits`, `--max-blobs`, `--json`.
  Suite: 431 → 435 tests.
- **`vibeguard llm-proxy`** — OpenAI-compatible local guard proxy (Lakera-class, free,
  offline, zero deps). `POST /v1/chat/completions` (JSON + SSE streaming), `GET /v1/models`,
  `POST /v1/completions` + `/v1/embeddings` passthrough. Scans prompts AND responses for
  secrets (`secret.*` rules), PII (`pii.js`), prompt injection (deterministic patterns).
  Modes: `block` (403), `redact` (in-place masking incl. streaming deltas), `report`.
  Streaming SSE is scanned per chunk; a violating stream is destroyed mid-flight.
  `--system-prompt-file` detects the model echoing your own system prompt.
  Suite: +12 tests (incl. `testSystemPromptLeak`).
- **`src/injection-decode.js`** — deterministic evasion decoders: base64, `\xNN`/`\uNNNN`
  escapes, ROT13 (whole-line), zero-width chars + homoglyph normalization. 4 new rules:
  `ai.prompt-injection-encoded-base64`, `-escapes`, `-rot13`, `ai.prompt-injection-obfuscated`.
  Phrase-gated: fires only when decoded text contains a canonical injection phrase.
- **Entropy upgrade** — `src/entropy.js` + `secret.high-entropy-token` rule: catches
  unquoted `.env`-style tokens (key-like context gate, ±2 lines) and hex-charset secrets;
  keeps the existing quoted-string `secret.high-entropy` rule; dedupes against specific
  `secret.*` findings and excludes public BaaS keys (Firebase `AIza…`, Supabase anon).
  Scanner fileRules loop now supports `match(content, ctx)` function rules.
- **Custom user rules** — `.vibeguardrc.json` → `"customRules": [{ id, severity, title, re,
  message, fix }]`; compiled at configure() time, invalid regexes skipped (never crash),
  re-added on every scan, cleared between scans (no config leakage).
- **CWE/OWASP metadata** on rules.js core groups (secret/injection/ai/pii) — SARIF parity
  with Semgrep/Bearer metadata consumers.
- Suite: 435 → **468 tests** (entropy +21, llm-proxy +12, git-scan +4). Rules: 766 → **771**.


### Added — Keyless open GIFs (no API key)
- New `vibeguard gif <query>` CLI command and `gif_search` MCP tool (84th tool).
  Fetches open GIFs with **zero API keys** using byte-verified open backends:
  cataas cat GIFs (+ text overlay via `/cat/gif/says/<text>`), yesno.wtf
  yes/no reactions. Dead/key-walled backends skipped: Tenor (needs key),
  GIPHY demo key (now 401), Klipy (auth wall), Reddit JSON (IP-blocked).
- New `src/gif.js` engine: single-redirect HTTPS fetch, GIF magic-byte
  verification, cataas 500-fallback, `downloadGif()` save-to-disk.
- Offline regression test for the routing logic (never selects a key-walled
  backend). Suite 430 → 431 passed.

### Fixed — Dogfood + dependency hygiene
- **Autofix bug:** the `error.empty-catch` autofix rewrote `catch {}` as
  `catch { console.error(err); }` — `err` is not bound in an optional catch
  clause, so every autofixed file threw `ReferenceError: err is not defined`
  at runtime. Now it emits `catch (err) { console.error(err); }` (or reuses an
  existing binding: `catch (e) {}` → `catch (e) { console.error(e); }`). New
  regression test executes the fixed output in a VM to prove no ReferenceError.
- **Demo site false positive:** `website/index.html` demo placeholder contained
  a hardcoded `sk-proj-…` string (example text), which the scanner correctly
  flagged as `secret.openai-key`. Replaced with inert `<KEY>` placeholders —
  VibeGuard's own repo scan went from **Grade F → Grade A** (0 findings / 275
  files).
- **Dependency vulnerabilities (npm audit → 0):** `@hono/node-server`
  (1.19.14 → 2.1.0, path traversal), `ip-address` (10.2.0 → 10.4.0, SSRF
  class), `brace-expansion` (5.0.9), `fast-uri` (4.1.2), `hono` (≥4.12.34) —
  all transitive via `@modelcontextprotocol/sdk`, pinned through
  `package.json` `overrides`. The SDK's own range permits these versions.
- **Lint hygiene:** eslint now ignores `**/.vibeguard/` (autofix snapshot
  store) — `no-unused-vars` warnings back to the 120s, still 0 errors.
- **MCP robustness:** `scan_secrets_history` handler tolerates both a bare
  array and the `{ findings, … }` shape from `history.scanHistory()` (was
  `findings.map is not a function`).

### Fixed — Agent interop (MCP)
- **Critical:** the MCP `tools/call` handler read the tool name from the request
  object instead of `req.params`, so every agent (Claude Code, Cursor, Windsurf,
  Codex, Hermes, …) got `Unknown tool: undefined` on ANY of the 82 tools. Now
  reads `req.params` per the SDK contract; verified with a live JSON-RPC stdio
  handshake and a new regression test (`mcp: full stdio handshake —
  initialize, tools/list, tools/call`) that speaks the protocol like a real
  client, so this class of bug cannot ship again.
- Added `scripts/live-mcp-check.js` — standalone MCP health check that boots the
  server, handshakes, lists tools, calls `scan_project` + `check_code`, and
  verifies unknown-tool errors name the tool.
- Lint hygiene: removed dead code + unused vars in `src/taint-ast.js`
  (warnings 125 → 121). Benchmark unchanged: 96.0% F1, 428/428 tests.
- `src/install.js`: added a **Hermes Agent** installer (16th client). Detects
  `$HERMES_HOME/config.yaml` and emits safe `hermes config set` instructions for
  the `mcp_servers.vibeguard` entry — it never hand-edits the YAML. README count
  updated to 16 AI clients.

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
