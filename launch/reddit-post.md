# Reddit Post — r/vibecoding

**Title:** I built a free scanner that catches the security holes AI tools leave in your code

**Body:**

Every vibecoding project I've seen has the same problems: hardcoded API keys, Supabase databases with no RLS, SQL injection from template literals, and `dangerouslySetInnerHTML` with user input. Nobody checks before shipping.

I built VibeGuard to fix this. It's a CLI tool that scans your project locally — no cloud, no telemetry, no signup.

```
$ npx @yagyeshvyas/vibeguard scan

VibeGuard security scan
./my-lovable-app

CRITICAL  api/route.ts:3  [secret.openai-key]
  OpenAI API key hardcoded in server code
  fix: Move to environment variable.

HIGH      db/query.ts:5   [taint.sql-injection]
  User input flows into SQL query via template literal (dataflow-confirmed)
  fix: Use parameterized queries.

Grade D  (12 files)  1 critical  3 high  2 medium  1 low

Run vibeguard fix to auto-fix 4 issues
```

**What it catches that other scanners miss:**
- AI-specific stuff: prompt injection in system prompts, LLM output piped to `exec()`, agent loops with no cap, user PII sent to OpenAI API without redaction
- Supabase/Firebase: missing RLS, fake RLS policies (`USING (true)`), service-role keys in client components
- AST taint analysis: traces `req.body.x` through variables, template literals, and function calls to sinks — not just regex matching

**One command for full protection:**
```bash
vibeguard auto    # daemon + git hook + shell guard + post-edit hook
```

This starts a background daemon that auto-scans every file change, installs a git pre-commit hook that blocks on critical, and arms a shell guard that blocks `rm -rf` and `curl|sh` before they execute.

**Wire into Claude Code / Cursor:**
```bash
claude mcp add vibeguard -- npx @yagyeshvyas/vibeguard mcp
```

Every file Claude edits gets auto-scanned. If it writes a leaked key, you see a red warning instantly.

**Honest benchmark:** 93.3% F1 on a 121-file corpus. Full breakdown in the [README](https://github.com/yagyeshVyas/VibeGuard#benchmark).

**What it doesn't do:** Prove your app is safe. Catch logic bugs. Replace a real security review. It catches the mechanical holes AI tools create by default.

[GitHub](https://github.com/yagyeshVyas/VibeGuard) | [npm](https://www.npmjs.com/package/@yagyeshvyas/vibeguard)

Free forever. MIT. Zero telemetry. Star if it helps.