# VibeGuard vs. the 2026 security-tool field

Measured 2026-11-26. Two evidence sources per tool:

1. **Repository/source analysis** for complete open-source trees (REA's own routing
   rule: a complete source repo is analyzed with normal repository tools, not REA).
2. **REA reverse-engineering** of shipped artifacts where an artifact exists:
   `inspect-go-binary` on the Windows release binaries (Trivy 0.76.2, Nuclei
   3.11.1, TruffleHog 3.100.1, Infisical CLI 0.45.15), `analyze-javascript-application`
   on `@openai/codex-security@0.11.0` (1,289 files → 3,252 JS modules, 2,081
   functions, 235k source ranges), and `inspect-artifact` on the Semgrep 1.187.0
   and PyRIT 1.2.1 wheels. REA v6.7.0; artifacts hash-pinned by the tool per run.

Stars/licences are from `gh api` on the date above. Nothing here is a claim that
another tool is bad — each column is what it is genuinely best at.

## Matrix

| Tool | ★ | License | Core strength | What VibeGuard answers in 1.16.0 |
|---|---:|---|---|---|
| **Strix** | 77.7k | Apache-2.0 | LLM agents in a Kali sandbox; findings rejected without a PoC + CVSS 3.1 vector | `webscan` proves the live HTTP surface (safe GET/OPTIONS), `pentest`/`attack-surface`/`redteam` cover the rest deterministically, in seconds, with no model or Docker |
| **Cloudflare Security Audit Skill** | 78.7k | MIT | Multi-phase audit skill with coverage ledger and `needs_validation` (no severity) | `install-skill` ships an equivalent phased audit skill wired to real commands; VibeGuard's findings are machine-generated, not prose |
| **Trivy** | 39.8k | Apache-2.0 | Image/OS CVE DB, 9 IaC dialects, SBOM in/out, Aho-Corasick secret prefilter | `scan` covers IaC (Docker/K8s/Terraform/compose/actions) offline; `sbom`, `container-scan`, `cve` handle artifacts (OSV instead of Trivy DB); no 100 MB DB download |
| **Nuclei** | 33.3k | MIT | 11 protocol engines, signed community templates | `webscan` = safe fixed active checks; `pentest` = deterministic probe families with curl repro; no template fetch, no third-party exploitation |
| **Infisical** | 30.8k | MIT + ee/ | Secrets control plane: versioning, rotation, PKI, PAM, agent vault | `vault` (local at-rest), `guard-action` + MCP firewall stop credential egress at the agent boundary; zero infrastructure |
| **TruffleHog** | 29.7k | AGPL-3.0 | 895 detectors + live verification + chained decoders | `history` scans git history; `--verify-keys` now verifies **11 providers** (OpenAI, Stripe, GitHub, GitLab, Slack, SendGrid, Mailgun, npm, Telegram, DigitalOcean, Heroku) — offline-unless-asked |
| **SkillSpector** | 27.8k | Apache-2.0 | Deep agent-skill analysis, OSV deps, baselines, SARIF | `skill-scan` scans skills/MCP/instruction files; **new**: `--pin` hashes reviewed skills and reports `skill.rug-pull` on any later change |
| **Semgrep** | 18.0k | LGPL-2.1 | Real AST matching + taint, 4k+ rule registry, autofix, `--test` | 861 rules + AST/taint, zero install cost; **new** GitHub annotation mode + PR workflow template for the same CI UX |
| **Codex Security** | 14.4k | Apache-2.0 | LLM validation of exploitability, sealed scan artifacts, patch verification | `pre-deploy`, `fix --apply --verify`, `compliance --export` gives a digest-pinned evidence pack; deterministic and offline (no source leaves the machine) |
| **Claude Code Security Review** | 7.1k | MIT | Diff-aware LLM review with inline PR comments | `pr-scan` is diff-scoped and deterministic; **new** `--github` emits inline annotations and `ci-templates/github-actions-vibeguard-pr.yml` posts the summary |
| **PyRIT** | 5.1k | MIT | 100+ attack converters, 17 targets, multi-turn campaigns | **new** `redteam` ships an OWASP LLM01/02/06/07 probe suite with canary/injection/exfil detectors; offline it prints the suite for PyRIT to consume |
| **Comp AI** | 2.1k | AGPL-3.0 | Compliance lifecycle: frameworks, evidence tasks, auditor portal | `compliance` maps findings to 10 frameworks; **new** `compliance --export` writes a schema-versioned, SHA-256-pinned evidence pack reviewers can diff |

## What each tool actually wins at (honest)

- **Strix** proves chains a static scanner cannot: auth bypass, races, session
  state. VibeGuard does not execute target exploits. It counters with
  deterministic checks that finish in seconds and never touch third-party infra.
- **Cloudflare's skill** models uncertainty better (`needs_validation` carries no
  severity). VibeGuard reports only rule-backed findings, so its grade is
  conservative by construction; the trade is that it cannot reason about an
  unknown bug class at all without a rule.
- **Trivy** covers container/OS CVEs with a maintained DB and 9 IaC dialects with
  Rego. VibeGuard's IaC coverage is rule-based and offline; for OS package CVEs it
  uses OSV on demand.
- **Nuclei** has thousands of maintained templates and 11 protocol engines.
  VibeGuard's `webscan` is a fixed, safe probe set — narrower by design.
- **Infisical** is a control plane (rotation, PKI, sessions); VibeGuard is a
  scanner plus an agent-boundary guard, not a secrets server.
- **TruffleHog** has 895 detectors and iterative multi-encoding decoders; VibeGuard
  has far fewer detectors and single-pass rules, but verifies 11 providers and
  never phones home unless asked.
- **SkillSpector** has YARA, OSV lookups and an LLM filter stage; VibeGuard's
  `skill-scan` is regex/taint-based and now has rug-pull pinning.
- **Semgrep** has a parsed-AST rule language, a 4k rule registry and `--test`;
  VibeGuard is dependency-light and AI-specific, not a general SAST platform.
- **Codex Security** validates exploitability with a model and seals artifacts;
  VibeGuard's evidence pack is a digest, not a full sealed manifest yet.
- **Claude Code Security Review** reasons over repo conventions in a diff;
  VibeGuard's PR gate is rule-based. VibeGuard's README warns about the same
  prompt-injection surface the Anthropic action documents for itself.
- **PyRIT** has multi-turn Crescendo/PAIR/TAP campaigns; VibeGuard's `redteam` is
  single-turn probes only.
- **Comp AI** runs the audit lifecycle (tasks, reviewers, auditor portal);
  VibeGuard emits code evidence and a digest a reviewer can attach to theirs.

## The defensible ground

None of the twelve is offline-by-contract, zero-telemetry, dependency-light and
agent-runtime aware at once. VibeGuard is:

- **deterministic** — same repo, same findings, no model drift, no API key;
- **offline** — the scanner never contacts a provider unless `--verify-keys` is
  passed explicitly; nothing leaves the machine;
- **agent-aware** — MCP firewall, tool-definition pinning, skill scanning and
  action guard cover the runtime plane the code scanners above ignore;
- **one install** — `npx @yagyeshvyas/vibeguard` and one binary for scan, IaC,
  secrets, MCP, sandbox, compliance, web checks and red-team.

Reproduce the artifact evidence: `npx -y rea-agents@6.7.0 inspect-go-binary
trivy.exe` and `analyze-javascript-application package/` (see the release notes in
CHANGELOG for the versions).
