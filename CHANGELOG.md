# Changelog

All notable changes to VibeGuard are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added — v1.10: real-time MCP firewall, agent permissions, OWASP coverage

- **`vibeguard mcp-firewall`** — a stdio JSON-RPC proxy between an MCP client
  and an MCP server. Tool definitions are scanned for poisoning and hash-pinned;
  `tools/call` requests are enforced against policy before forwarding (blocked
  calls never reach the server); tool results are scrubbed of secrets/PII before
  they reach the model. Modes: proxy by configured server name, ad-hoc command,
  one-call check, offline self-test, audit status, configured-server listing.
- **`src/agent-policy.js`** — deterministic permission engine: tool
  allow/deny/approval rules, capability classes, project-scoped filesystem
  access, denied credential stores, egress and metadata-host policy, trusted
  hosts, argument-size and per-minute call limits, fail-closed policy errors.
- **`src/skill-scan.js` / `vibeguard skill-scan`** — scans SKILL.md, AGENTS.md,
  CLAUDE.md, Cursor rules, Claude agents/skills, plugin and marketplace
  manifests and embedded MCP configs for injection, hidden Unicode,
  exfiltration instructions, credential access, destructive commands, remote
  code loaders, obfuscation, permission bypass, self-modification, risky
  packages and secrets.
- **`src/agent-risk.js` / `vibeguard agent-risk`** — one 0-100 score and A-F
  grade across MCP configuration, skills, runtime decisions, policy scope and
  audit integrity.
- **`src/owasp-agentic.js` / `vibeguard owasp-coverage`** — maps controls to the
  OWASP Agentic AI Top 10 and OWASP MCP Top 10 (20/20 mapped), with explicit
  enforced/detected/monitored/advisory statuses; optional LLM Top 10.
- **`src/agent-monitor.js` / `vibeguard agent-monitor`** — runtime report and
  `--watch` tail over the hash-chained firewall audit log, with behavior
  anomalies (trust building, data gathering, slow exfiltration, privilege
  escalation, repeated blocks, tamper).
- **Audit trail hardened** — correct hash-chain verification (previous
  implementation never failed on a modified entry), JSONL persistence,
  `createLogger(file)`, and tamper detection over long-lived logs.
- **Sandbox process isolation** — `runInProcess` and
  `vibeguard sandbox --isolation process`: separate Node process, permission
  model, blocked module loads, stripped env, memory cap, hard timeout. `auto`
  chooses it on Node 20+; Node 18 keeps the vm sandbox.
- **MCP tools** — `mcp_firewall`, `scan_skills`, `agent_risk`,
  `owasp_coverage`, `agent_monitor`; `sandbox_exec` gains `isolation`.
- **CLI fixes** — crashes in `dep-firewall` and `audit-trail` output paths
  (undefined `Creset`/`C_reset`), `audit-trail export` path argument, and a PII
  detector false positive that read IPv4 addresses as phone numbers.
- 26 new tests including a live stdio proxy test; docs in `MCP-FIREWALL.md`.

### Added — v1.9: live-code reachability, exploit chains, build-artifact scan

- **Reachability-native scans.** The entrypoint graph now runs on every scan and
  annotates findings `direct` / `imported` / `dead`. `--live` drops findings in
  code no route can reach; ordering puts live findings first at equal severity;
  `--reachability-grade` counts dead-code findings one tier lower. Juice Shop
  measured 306 live vs 3,157 dead findings — the noise control competitors sell
  as "reachability", computed offline in ~0.2 s per 1,000 files.
- **Exploit chains.** `attack-surface` emits `precondition → entrypoint → sink →
  impact` chains with CWE ids: unauthenticated POST → command injection → RCE;
  `/allocations/:userId` → IDOR → cross-user access; SSRF → metadata credential
  theft. Deterministic — no model call, no variance, no bill.
- **`vibeguard bundle-scan` + `scan_bundle` MCP tool.** Scans `dist/`, `build/`,
  `out/`, `.next/static`, `static/js` for inlined secret formats (reusing all 75
  secret rules), high-entropy tokens, and shipped source maps. Closes the
  documented blind spot: the commit is clean, the artifact leaks.
- **MCP:** `scan_bundle`; `scan_project` gains `live` and `reachabilityGrade`;
  `attack_surface` returns chains.
- 564 tests, 0 failures.

### Added — v1.8: attack surface, authorization intelligence, backdoor decoding

**The release that scans what AI code actually gets wrong.** Built from the
2025-2026 evidence base (Veracode GenAI report: 45% of generated samples ship an
OWASP Top-10 flaw; CSA/CodeRabbit: 1.91x IDOR in AI-co-authored PRs; GitGuardian
2026: AI-assisted commits leak secrets at 3.2% vs 1.5%; Escape.tech: 65% of
vibe-coded apps had a security issue).

- **`vibeguard attack-surface` + `attack_surface` MCP tool.** Extracts every
  entrypoint across Next.js (App Router, Pages API, **Server Actions**), Express,
  Fastify, Hono, NestJS, tRPC, Supabase Edge Functions, serverless handlers,
  FastAPI/Flask/Django, Rails, Gin/Echo and MCP tool registrations. Resolves
  router mounts and middleware chains, then joins entrypoints × findings ×
  import reachability: which route is reachable *now*, which finding is
  exploitable from it, and which findings sit in dead code.
- **Authorization intelligence** (`src/routes.js`, `src/surface.js`): handler
  extent by brace matching, in-body guard detection (auth/getServerSession/
  requireUser/…), IDOR detection (object fetched by `params.id` with no
  owner/tenant predicate), unguarded state-changing routes, Server Actions that
  are public RPC endpoints, middleware matchers that exclude `/api`.
- **118 new rules in the 2026 pack** (`src/rules-2026.js`): IDOR/mass-assignment,
  Next.js public-env secrets and middleware bypass, Supabase RLS *correctness*
  (`USING (true)`, SECURITY DEFINER without `search_path`, service_role in the
  client), Firebase rules, JWT (decode-not-verify, alg:none, weak fallback,
  cookies), LLM output handling (exec/SQL/HTML, system-prompt injection, no
  max_tokens, unbounded agent loops), weak crypto (md5 passwords, Math.random
  tokens, ECB, static IV), CWE-117 log injection, 13 new secret formats
  (OpenRouter, Groq, HuggingFace, NVIDIA, Replicate, Supabase PAT, service_role
  JWT, …), CI script injection, compose/Docker/Terraform exposure, SSRF, SSTI,
  open redirect, header injection, upload limits, postMessage origin checks.
- **Backdoor / obfuscation engine** (`src/obfuscation.js`, `scan_backdoors` MCP
  tool): multi-layer decode (base64/hex/unicode/fromCharCode/rot13), encoded
  payloads in executable position, javascript-obfuscator fingerprints,
  fetch→eval loaders, curl|sh, PowerShell `-enc`, remote imports, hidden
  Unicode/bidi, and behavioural co-occurrence (exec + network + env = dropper).
  Skips minified vendor bundles to stay quiet on real projects.
- **AST coverage fix (critical).** Every `.jsx` file failed to parse (no JSX
  plugin) and every `.tsx` file crashed the walker
  (`No walker function defined for node type JSXElement`), silently degrading the
  AST/taint pass on most React/Next code. Both fixed: JSX parser + JSX walkers
  merged into `acorn-walk`'s base. Self-scan degraded files: 27 → 0.
- **Route intelligence hardened on real apps.** Handler references (`profileHandler.displayProfile`, `isLoggedIn`) now resolve to their AST ranges across files and constructor instances, middleware arguments count as guards, prefix guards (`app.use("/api/X", isAuthorized())`) apply to routes beneath them, Express `app.route(...).get(...)` chains are extracted, and tests/codefix fixtures are excluded. On OWASP NodeGoat: 20/22 routes correctly guarded and the real `/allocations/:userId` IDOR detected; on Juice Shop: 149 entrypoints (was 313 with test fixtures), 145 guarded. Unresolvable Express handlers report `auth: unknown` instead of a false "unguarded" claim.
- **`.rules` files are now scanned** — Firebase rules were never read before.
- **`--version`** prints the version instead of accidentally running a scan.
- Rule count 743 → 861, MCP tools 85 → 87.

### Fixed — v1.7 dataflow-depth pass (a clean grade on live SQL injection)
- **CRITICAL: textbook SQL injection scanned as `Grade A, no issues`.**
  `db.query(`SELECT * FROM users WHERE id = ${req.body.id}`)` — the most common
  shape of SQLi in AI-generated code — produced a confident all-clear on a
  default scan. Root cause: the AST taint pass skipped any sink argument for
  which `exprIsSource()` was true, deferring to the regex layer. That predicate
  returns true for a TemplateLiteral or concatenation that merely *interpolates*
  a source, so the taint pass stepped aside for constructed strings while the
  regex layer — matching different text — either missed them or rated them below
  the default medium-confidence floor. Nobody reported the finding.
  Fix: new `exprIsBareSource()` limits deferral to a source used verbatim, and
  the three code-execution-grade sinks (`taint.sql-injection`,
  `taint.command-injection`, `taint.code-injection`) never defer at all.
  `db.query(req.body.sql)` was invisible for the same reason and is now caught.
- **Laundered sources now tracked**: destructuring, reassignment chains,
  optional chaining, nested index access, and `spawn("sh", ["-c", ...])`.
- **Return-value taint across function boundaries.** The engine already followed
  taint INTO a helper (param → sink); it now follows it back OUT
  (`function getId(r) { return r.body.id }` → `db.query(...getId(req)...)`).
  Records only the parameter index, so it fires only when the call site passes
  an actual source — sanitizing helpers, constant-returning helpers, and calls
  with non-source arguments stay clean.
- **`process` is no longer a blanket taint source.** Only `argv`, `argv0` and
  `env` carry outside input. Treating every `process.*` property as attacker
  input made `spawn(process.execPath, [script])` — the standard way to launch a
  child Node process — report as command injection. Caught by dogfooding: it was
  the scanner's own worst false positive after the deferral fix.
- **The AST taint pass no longer fails open silently.** A crash there dropped
  analysis to the weaker regex engine with no signal at all — every
  dataflow-confirmed finding disappeared while the scan still printed a clean
  grade. `analyzeTaint()` now takes an `onDegrade` callback and the scanner
  records it as a `taint-ast` degraded pass, so the CLI warns and `--strict`
  refuses to report clean. (Discovered by causing it: a temporal-dead-zone bug
  wiped every taint finding and nothing said a word.)

### Changed
- `TAINT_TO_AST` → **`TAINT_SUPERSEDES`**, generalised from "taint shadows ast"
  to "the higher-fidelity finding shadows every weaker counterpart on the same
  line". One vulnerability now yields one finding: `taint.sql-injection` covers
  `ast.sql-injection`, `code.sql-injection`, `db.sql-template-literal` and
  `injection.orm-raw-user`; `taint.path-traversal` covers
  `upload.filename-path-traversal`; and `go.sql-injection` collapses
  `go.sql-format` + `go.sql-fmt-sprintf`, which used to triple-report a single
  `fmt.Sprintf` injection.
- Exported `TAINT_SUPERSEDES` and `dedupeFindings` from `src/scanner.js`.

### Added
- **Harder benchmark corpus** (120 → 136 files): 8 laundered-source recall cases
  and 8 adversarial precision cases (`parseInt`, `db.escape`, allowlist
  ternaries, parameterized queries, `spawn` arg arrays, constant table names,
  sanitizing and constant-returning helpers) — every one puts `req.` inside or
  beside a dangerous sink without being a bug.
- **Benchmark scorer now measures what users see.** It applies `dedupeFindings`
  (previously it scored raw pre-dedupe rule hits, counting both halves of a
  deliberately de-duplicated pair) and credits an expected rule when a rule that
  supersedes it fired instead — which cannot excuse a real miss, since a finding
  that is neither present nor superseded still scores FN.
  Result: **119/119 cases, 0 FP, 0 FN** (previously 96.0% F1, 4 FP, 5 FN).
  A saturated corpus means the corpus stopped being hard, not that the scanner
  is complete — stated as such in the README.
- 11 regression tests (`test/taint-depth-tests.js`), all asserted against a
  DEFAULT scan: a finding only visible under `--all` is not protection.
  **508 tests total, 0 failures.**
- Corrected `stripe-key.js` benchmark expectation, which required
  `secret.generic-credential` alongside `secret.stripe-live-key`.
  `dedupeFindings` has always suppressed the generic rule when a specific one
  covers the line; the expectation described pre-dedupe output.


### Added — v1.6 token-lean pass (TLAP: treat the agent's context window as a budget)
- **`src/tokenlean.js` — TLAP, the Token-Lean Agent Protocol.** Every scanner in
  this space answers an AI agent with pretty-printed JSON: two-space indentation,
  repeated object keys, and the same `message` + `fix` string duplicated once per
  occurrence. TLAP encodes the same information — no findings dropped silently —
  in a line-oriented, de-duplicated, dictionary-compressed form. Four levers:
  no pretty JSON, cluster by rule (rule text is a property of the rule, not of
  the occurrence), path-prefix dictionary, and a risk-ranked budget.
  Measured on this repo: **64,076 → 5,492 estimated tokens, a 91.4% cut** on a
  463-finding / 293-file scan. Zero new dependencies.
- **`vibeguard scan --lean`** — the lean dialect from the CLI.
- **`--budget <n>` / `VIBEGUARD_TOKEN_BUDGET`** — a hard token ceiling. The budget
  is spent highest-risk first: severity × confidence, with dataflow-confirmed,
  exploitable (taint/secret/idor/auth/ssrf…) and security-hotspot-path findings
  outranking pattern-only matches at equal severity. Whatever does not fit is
  reported as an explicit rollup with per-severity counts and the rule ids, and
  the payload states `NOT an all-clear`. Truncation can never read as clean.
- **`--lean --delta`** — delta scans against a stored fingerprint snapshot
  (`.vibeguard/tlap-snapshot.json`, shared by the CLI and the MCP server). When
  nothing changed the whole answer is one line, ~20 tokens instead of ~5,000;
  otherwise only new findings are listed and resolved ones are counted.
- **`vibeguard tokens [dir]`** (+ `token_report` MCP tool) — reproduce the savings
  claim on any repository. `--json` for machine output.
- **MCP: lean is now the default dialect** for `scan_project` and `suggest_fixes`
  (`format: "json"` restores the old payload; `budget` and `delta` are per-call
  arguments). Lean fix plans state each remediation once per rule and drop the
  diagnosis — when the task is "apply the fix", the diagnosis is not the payload.
- **Layer 14 — context-window budget guard.** Any of the 85 MCP tools is clamped
  to the configured budget before returning, so a single large payload cannot
  evict an agent's working memory. Truncation is always disclosed.
- Offline token estimator (no tokenizer dependency, ~±10% of a real BPE count).
  Deterministic: identical input produces byte-identical output.
- 17 new tests covering losslessness, budget behaviour, risk ordering, delta
  mode, determinism, and the "never silently lossy" guarantee. **497 total, 0 failures.**

### Fixed
- Transitive advisories cleared via `overrides`: `fast-uri` → ^4.2.1 (host
  confusion / SSRF via IPv6 normalization), `hono` → >=4.13.8 (`toSSG()` path
  escape, `parseBody()` memory exhaustion), `qs` → >=6.15.4 (array-limit bypass,
  DoS). Self-scan back to **Grade A** on 293 files.
- `outputResult`'s lean path no longer joins a user-supplied scan root with a
  path inside the CLI: snapshot persistence moved into `src/tokenlean.js` behind
  a resolved-root helper, clearing 5 self-reported `taint.path-traversal`
  findings at the source rather than suppressing them.


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

