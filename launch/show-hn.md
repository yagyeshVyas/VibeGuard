# Show HN: VibeGuard – offline security scanner for AI-generated code

**Title:** Show HN: VibeGuard – offline security scanner for AI-generated code

**Body:**

I built a security scanner that runs entirely on your machine and catches the mistakes AI coding tools make: hardcoded API keys, open Supabase/Firebase databases, SQL injection via template literals, prompt injection in system prompts, and LLM output piped to exec/eval.

It's not another Semgrep. The specific gap I saw: AI tools (Claude Code, Cursor, Lovable, Bolt) generate code fast but leave security holes that no one checks before shipping. Existing SAST tools are either paid, cloud-based, or don't catch AI-specific patterns like prompt injection in code or LLM output reaching shell calls.

**What it does:**
- 698 rules across 14 languages (JS/TS/Python/Go/Java/Ruby/PHP/C#/Rust/Kotlin/Swift/Bash/SQL/YAML)
- AST-based taint analysis (not just regex) — traces `req.body.x` through template literals, function params, and object properties to sinks like `exec()`, `db.query()`, `innerHTML`
- Cross-file taint — catches `req.body` passed to an imported helper that hits a sink
- AI-specific rules: prompt injection in system prompts, LLM output to exec/eval, agent loop without cap, MCP tool poisoning, user PII sent to LLM APIs
- One-command layered protection: `vibeguard auto` starts a daemon (auto-scans on file change), installs git pre-commit hook, arms a shell guard that blocks `rm -rf` / `sudo` / `curl|sh` before execution
- MCP server integration for Claude Code, Cursor, Windsurf — auto-scans every file the AI edits

**Benchmark (honest, not rounded up):**

| Category | Precision | Recall | F1 |
|----------|-----------|--------|-----|
| injection | 87.5% | 91.3% | 89.4% |
| secrets | 100% | 100% | 100% |
| xss | 100% | 100% | 100% |
| path-traversal | 90.0% | 100% | 94.7% |
| ai-safety | 100% | 100% | 100% |
| **OVERALL** | **91.7%** | **95.1%** | **93.3%** |

Measured on a self-built corpus of 121 files. I know self-built corpora flatter the tool — I plan to run against OWASP Benchmark next.

**What it does NOT do:**
- Prove your app is safe
- Catch business logic flaws
- Replace a security review
- Work as a sandbox (the shell guard is accident prevention, not escape prevention — a determined adversary can bypass it)

**Privacy:** Zero telemetry. Zero network calls by default. Everything runs locally. The only opt-in network features are CVE lookups (OSV.dev) and URL header scans.

**Stack:** Node.js, CommonJS, zero runtime dependencies except the MCP SDK. acorn is optional (enables AST taint analysis when installed).

**Links:** [GitHub](https://github.com/yagyeshVyas/VibeGuard) | [npm](https://www.npmjs.com/package/@yagyeshvyas/vibeguard)

I'd genuinely like criticism on:
1. The benchmark methodology — is a self-built corpus meaningful, or should I wait for OWASP results before publishing numbers?
2. The AI-specific rules — are there patterns I'm missing?
3. The shell guard approach — is fail-open the right default?