---
name: vibeguard-security-audit
description: Multi-phase security audit of a codebase using VibeGuard — deterministic rules, dataflow, secret history, agent/MCP policy, and live web checks. Use when asked to "security audit", "find vulnerabilities", "check this repo for security issues", or before shipping/deploying.
---

# VibeGuard security audit

Run this audit in order. Every phase produces machine-readable evidence; never
report a finding you did not see in a VibeGuard output. Stop and ask before
applying fixes.

## Phase 0 — scope (30 seconds)

```bash
vibeguard doctor .
```

If `doctor` reports a missing engine or degraded coverage, say so in the report.
Check `docs/STATUS.md` for what this install actually verifies.

## Phase 1 — full scan (deterministic evidence)

```bash
vibeguard scan . --json > scan.json
vibeguard scan . --lean          # token-compact view for your context window
```

Read `grade`, `counts` and every `findings[]` entry. Rule ids are stable — quote
them (`secret.stripe-live-key`, `taint.sql-injection`, `iac.kubernetes`, ...).

## Phase 2 — the parts a plain lint misses

```bash
vibeguard pr-scan --staged --json      # only changed lines (PR gate)
vibeguard history . --json             # secrets in git history
vibeguard skill-scan . --json          # agent skills / MCP configs / prompt injection
vibeguard agent-risk . --json          # MCP + agent posture, OWASP coverage
vibeguard attack-surface . --json      # entrypoints x auth x reachability
```

## Phase 3 — prove it (live, read-only)

```bash
vibeguard webscan https://your-deploy.example --json   # HTTPS/CORS/exposed files/TLS
vibeguard redteam --endpoint https://llm.internal/v1 --model <model> --json
```

`webscan` sends safe GET/OPTIONS probes only; `--allow-private` is required for
loopback targets. `redteam` without `--endpoint` prints the versioned probe suite
for PyRIT/Garak instead of running it.

## Phase 4 — fix and re-verify

```bash
vibeguard fix . --apply --verify    # safe auto-fixes are snapshotted; verifies each
vibeguard scan . --json             # must be clean (or explain the delta)
vibeguard rollback .                # undo the last batch if anything regressed
```

## Phase 5 — report

Answer in this shape, and keep it short:

1. **Grade + counts** from the final `scan --json`.
2. **Findings** grouped by severity: rule id, file:line, why it is exploitable, fix.
3. **Coverage honesty**: degraded files, missing engines, `--strict` failures.
4. **What was re-verified** after fixes (deltas only).

Rules for the agent:
- Never invent a vulnerability; if the scanner did not report it, it goes in a
  "manual review" section, clearly marked unverified.
- Never paste a secret value into the report — use the redacted snippet VibeGuard
  prints.
- Do not run `--verify-keys` (it sends keys to providers) unless the user asked.
