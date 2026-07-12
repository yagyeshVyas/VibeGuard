# Security Policy

## Reporting a Vulnerability

If you discover a vulnerability in VibeGuard itself, please **do not** open a public issue.

Report it privately:

1. Email: **yagyesh.vyas.security@gmail.com** (or use GitHub's private vulnerability reporting)
2. Include: description, reproduction steps, and impact assessment
3. You will receive a response within 48 hours

## Scope

This policy covers the VibeGuard scanner and its CLI/MCP tooling. It does **not** cover vulnerabilities found in the code you scan with VibeGuard — those are the responsibility of the code's author.

## Responsible Disclosure

- We credit responsible reporters in release notes (unless you prefer to remain anonymous)
- We do not pursue legal action against good-faith security researchers
- Please give us reasonable time to fix and publish before disclosing publicly

## Security Measures in This Repo

- Zero runtime dependencies (supply-chain attack surface = 0)
- AST mode uses `acorn` in `optionalDependencies` — the scanner works without it
- All tests run in CI on every push and PR
- No network calls by default (`scan`, `fix`, `auto`, `mcp`, `install`)
- The runtime interceptor wraps `fetch`, `http.request`, `child_process.exec`, and `fs.readFileSync` to block outbound secrets and PII