# Reddit post — r/vibecoding

**Title:** I built a free offline scanner for the security bugs AI coding tools leave behind

**Body:**

Every vibecoded project I review has the same shape: an API key in a client
file, a Supabase table with no RLS, a template literal in a SQL query, and an
LLM response passed to `exec`. The code ships because it runs.

VibeGuard is a local scanner and MCP/runtime firewall for that gap:
`npx @yagyeshvyas/vibeguard scan .` No signup, no telemetry, no upload.

**v1.14.0, honest scope**

- 861 rules, 95 MCP tools, 18 languages.
- MCP firewall and human approval service for agent tool calls, with signed
  single-use approvals and signed audit.
- Verified Windows AppContainer isolation; macOS hardware VM is implemented but
  requires a trusted guest image and verification on macOS.
- 654 tests and a pinned external Juice Shop benchmark. That benchmark is a
  small curated label set, not a precision/recall ranking. The self-built
  119/119 corpus is saturated; read it as a regression gate.
- Independent in-session security audit is in the repo, including the bugs it
  found and fixed.

**What it will not do:** prove an app safe, catch business-logic flaws, or replace
a review.

If you try it on your repo, I want the unflattering version: one useful finding,
one false positive, one missed vulnerability, and the install/doc step that
wasted your time.

Feedback form:
https://github.com/yagyeshVyas/VibeGuard/issues/new?template=independent-feedback.yml

No paid reviews, no referral scheme, no invented testimonials.
