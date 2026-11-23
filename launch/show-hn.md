# Show HN: VibeGuard – offline security scanner for AI-coded apps

**Title:** Show HN: VibeGuard – offline security scanner for AI-coded apps

**Body:**

I built VibeGuard after reviewing AI-generated apps that shipped hardcoded API
keys, open Supabase/Firebase rules, SQL injection through template literals and
LLM output passed into `exec`.

It is a local scanner and MCP/runtime firewall. No account, no telemetry, no
cloud upload. `npx @yagyeshvyas/vibeguard scan .` runs on the repo you point it
at.

**What is new in 1.14.0**

- 861 rules, 95 MCP tools, 18 languages.
- Verified Windows AppContainer isolation (Job Object, no network capability),
  with a live verification suite; macOS hardware-VM backend is implemented but
  needs a trusted guest image and is verified only on macOS.
- Authenticated human approval service: password login, CSRF, quorum, signed
  single-use approvals, signed audit and graceful shutdown.
- MCP firewall: tool poisoning, secret exfiltration, path/command rules,
  response inspection and kill-on-block.
- Reproducible external benchmark pinned to an OWASP Juice Shop commit; a small
  curated label set, not a representative precision/recall study.
- 653 tests, 50/50 platform tests, independent in-session security audit in the
  repository.

**What it does not do**

- Prove an app is safe.
- Detect business-logic flaws or IDOR comprehensively.
- Replace code review or a real pentest.
- Make the macOS VM claim without a guest image and a passing verification run.
- Hide a saturated self-built benchmark: 119/119 means the corpus is easy, not
  that the scanner is perfect.

**Try it**

```bash
npx -y @yagyeshvyas/vibeguard@1.14.0 scan .
npx -y @yagyeshvyas/vibeguard@1.14.0 scan . --json
```

**What I want from HN**

I am looking for independent evaluations, not stars: run it on a repository you
own, report one useful finding, one false positive and one false negative, and
tell me where the documentation or CLI lied to you.

Feedback form:
https://github.com/yagyeshVyas/VibeGuard/issues/new?template=independent-feedback.yml

I will not pay for reviews or publish invented testimonials. Known limits:
https://github.com/yagyeshVyas/VibeGuard/blob/master/docs/ADOPTION.md
