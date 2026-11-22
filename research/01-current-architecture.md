# VibeGuard Current Architecture

**Audit date:** 2026-11-21  
**Repository:** https://github.com/yagyeshVyas/VibeGuard  
**Audited revision:** `2ce5b36` (v1.10.0, `master`)  
**Working tree:** clean at audit start  
**Scope:** source, tests, CI, release workflow, packaging, website claims; no source changes made for this audit.

---

## 1. Executive summary

VibeGuard is a real, substantial security codebase, not a README-only project. At this revision it contains:

- an offline source/secret/SAST scanner with 861 registered rules;
- an MCP server exposing 93 tools;
- a new MCP firewall/proxy with tool-definition pinning, policy evaluation, result scrubbing and a hash-chained audit log;
- a skill/plugin scanner, a unified agent risk score, an OWASP coverage report, and a process-isolated sandbox.

The baseline engineering checks are real:

| Check | Observed result |
|---|---|
| Local full test suite | **594 passed, 0 failed** |
| MCP firewall self-test | **11/11 scenarios passed** |
| OWASP Agentic + MCP coverage | **20/20 items mapped** by the tool |
| Integrity manifest | **30 modules verified** by `self-check` |
| CI | success on Node 18, 20 and 22 (`CI` run 44974128995) |
| Publish workflow | success, but npm and release steps skipped without `NPM_TOKEN` (run 44974139516) |
| Live website | v1.10 content verified after deployment |

Those checks establish build/test health. They **do not** establish security. The audit found two Critical implementation flaws that allow arbitrary code execution/escape from the advertised boundaries, plus multiple High bypasses in the firewall, policy, detection and audit layers. The most important architectural fact is:

> VibeGuard currently has good *detection breadth* and useful *advisory controls*, but it does not yet have a trustworthy **enforcement boundary**. Several controls are opt-in, pattern-based, or client-side, and the sandbox is not an OS isolation boundary.

This document describes what exists. The gaps are enumerated in `03-security-gaps.md`.

---

## 2. Repository inventory

### 2.1 Runtime shape

```
User / AI client (Claude Code, Cursor, Codex, ...)
        │  stdio JSON-RPC
        ▼
┌──────────────────────────────┐
│ MCP client                   │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐        .vibeguard-mcp.json
│ vibeguard mcp-firewall       │◄────── policy (project root)
│  - tools/list inspection     │
│  - tools/call enforcement    │
│  - tool result scrubbing     │
│  - audit JSONL               │
└──────────────┬───────────────┘
               │ stdio JSON-RPC
               ▼
┌──────────────────────────────┐
│ MCP server (local process)   │
└──────────────────────────────┘

Separate CLI paths:
  vibeguard scan ──► scanner/plugin loader ──► rules, AST, taint, PII, secrets
  vibeguard mcp-audit ──► reads .mcp.json/.cursor/.vscode config
  vibeguard skill-scan ──► scans skill/plugin/instruction files
  vibeguard agent-risk ──► auditMcp + scanSkills + firewall log + policy
  vibeguard mcp ──► stdio MCP server with 93 tools
```

### 2.2 Core modules

| Module | Role | Trust position |
|---|---|---|
| `src/mcp-firewall.js` | Bidirectional MCP proxy, tool-definition inspection, result scrubbing, audit logging | Enforcement point, but only for clients configured to use it |
| `src/agent-policy.js` | Deterministic policy engine: tool rules, capabilities, paths, hosts, secrets, rate limits | Policy parser and evaluator; project-supplied policy |
| `src/skill-scan.js` | Scans `SKILL.md`, `AGENTS.md`, `CLAUDE.md`, plugin/marketplace/embedded MCP definitions | Detection only |
| `src/agent-risk.js` | Aggregates MCP config, skills, runtime log, policy and audit into a 0-100 score/A-F grade | Reporting; no enforcement |
| `src/agent-monitor.js` | Reads the audit JSONL, derives behavior anomalies, tails the log | Monitoring; no kill/block |
| `src/owasp-agentic.js` | Static control-to-framework mapping and coverage report | Reporting; statuses are declared, not runtime-derived |
| `src/mcp-audit.js` | Static MCP server/config audit, tool poisoning, unpinned installs, drift | Detection; reads config, never runs servers |
| `src/firewall.js` | Prompt-level regex + token classifier, capability/exfil checks | Detection; regex/heuristic |
| `src/action-guard.js` | Shell/network/file/prompt/MCP action inspection | Detection/recommendation |
| `src/shell-guard.js` | Shell command normalizer and dangerous-command denylist | Detection; POSIX-centric |
| `src/sandbox.js` | `vm` sandbox, optional `isolated-vm`, process-permission mode | Execution boundary; not an OS sandbox |
| `src/audit-trail.js` | Append-only JSONL SHA-256 hash chain, logger factory | Audit integrity; no signing/key |
| `src/mcp-server.js` | 93 MCP tools over stdio | Integration surface; no authentication |
| `src/scanner.js` | File walk, rule engine, plugin loading | Scans untrusted repositories; **auto-executes plugins** |
| `src/plugin.js` | Auto-discovers `vibeguard-rules-*` and config `plugins` | Arbitrary `require()` of target-controlled code |
| `src/install.js` | Writes MCP client configs | Writes user/project config |
| `src/integrity.js` | SHA-256 manifest verifier | Detects accidental tampering, not a root of trust |
| `bin/cli.js` | CLI surface, 90+ commands | Main user entry point |
| `scripts/gen-integrity.js` | Regenerates manifest at publish | Release-time hash generation |

### 2.3 Test and release inventory

- `test/run.js` is a zero-dependency runner; it imports 10 standalone suites, including `test/mcp-firewall-tests.js` (30 tests).
- `test/mcp-firewall-tests.js` includes a real stdio proxy test that spawns `bin/cli.js` and a fixture MCP server.
- CI matrix: Node 18, 20, 22 on `ubuntu-latest`; steps: `npm ci`, `npm test`, `npm run lint`, benchmark gate, coverage.
- Publish workflow: triggered by `v*` tag or manual dispatch; runs `npm ci`, `npm test`; publishes only when `NPM_TOKEN` exists; creates a GitHub release only in that same branch.
- Release state at audit: tag `v1.10.0` exists and a GitHub release was created manually; npm registry still served `1.3.0` because no `NPM_TOKEN` was configured.

---

## 3. Claim verification

The README and website contain several strong claims. The table below separates verified claims from claims that are only partly true or need qualification.

| Claim | Code evidence | Verification / qualification |
|---|---|---|
| 861 rules | `scripts/counts.js`; rule registry | Verified by live count (`rules: 861`) |
| 93 MCP tools | `src/mcp-server.js:TOOLS` | Verified by `tools/list` and count script |
| 594 tests | `test/run.js` and CI | Verified locally and in CI |
| “Real-time MCP firewall” | `src/mcp-firewall.js` | Real stdio proxy and enforcement, but only for `tools/call`/`tools/list`; see F-03 |
| “Poisoned tools are removed” | `inspectToolList` in `src/mcp-firewall.js` | Works for the six patterns in `src/mcp-audit.js`; bypassable (F-08) |
| “Dangerous calls never reach the server” | `onClientMessage` in `src/mcp-firewall.js` | True for evaluated `tools/call`; policy can default to allow (F-05) and paths/schemes bypass (F-06/F-11) |
| “Secrets/PII scrubbed before the model sees them” | `scrubResult` in `src/mcp-firewall.js` | True for known patterns and PII; unknown entropy/base64/split secrets bypass (F-07) |
| “Hash-chained, tamper-evident audit” | `src/audit-trail.js` | Chain detects edits only if entries are not recomputed; it is not signed/authenticated (F-04) |
| “OWASP Agentic AI + MCP Top 10 coverage: 20/20” | `src/owasp-agentic.js` | Static mapping, not runtime verification; MCP06 name is wrong and AISVS is absent (F-14) |
| “Process-isolated sandbox” | `src/sandbox.js` | Process mode exists, but host-object escape and network egress are possible (F-02) |
| “100% offline” | README lines 16, 61, 109 | New agent paths are offline, but existing commands (`url`, `cve`, `pentest`, `proxy`, `llm-proxy`, GIF) use network; claim needs qualification (F-28) |
| “Zero telemetry” | no telemetry code found | Verified by inspection of the repo; no phone-home in new modules |
| “Zero dependencies” | `package.json` | Runtime dependency `@modelcontextprotocol/sdk` and optional acorn packages exist; “zero dependencies” is not literally true and should be qualified (existing packaging claim) |
| “Self-check detects tampering” | `src/integrity.js` | Detects module edits against a manifest; manifest itself is unsigned and can be rewritten (F-04/F-13) |
| “Skill/plugin detection” | `src/skill-scan.js` | Real rules, but bypassable with ordinary natural-language instructions (F-10) |
| “Installer wires MCP safely” | `src/install.js:21-28` | Defaults to unpinned `npx -y vibeguard mcp`; `mcp-audit` flags the project’s own `.mcp.json` as high risk (F-16) |

---

## 4. Data flow and trust boundaries

### 4.1 MCP request path

1. Client writes newline-delimited JSON-RPC to stdout/stdin.
2. Proxy buffers bytes until newline (`src/mcp-firewall.js:544-548`), parses JSON, and routes by `method`.
3. `tools/call` is evaluated by `evaluateToolCall` (`src/agent-policy.js:309-475`), then may be blocked locally or forwarded.
4. Server response is parsed and, for `tools/call`, passed through `scrubResult` (`src/mcp-firewall.js:324-351`).
5. Every verdict is appended to a JSONL log via `createLogger` (`src/audit-trail.js:115-131`).

### 4.2 Trust boundaries

| Boundary | Trusted side | Untrusted side | Enforced? |
|---|---|---|---|
| System prompt vs user/retrieved text | System/client | User, web, email, documents, MCP results | Partly; regex/token classifier only |
| Agent vs MCP server | Client | Server tools, descriptions, resources, prompts | Partly; only `tools/list` and `tools/call` are inspected |
| Agent vs host filesystem | Policy | Tool arguments and symlinks | Partly; string-level path checks, no `realpath` |
| Agent vs network egress | Policy | URLs and shell commands | Partly; shell commands bypass host policy |
| Policy file vs repository | Operator | Project `.vibeguard-mcp.json` | Not authenticated; target repo can supply permissive policy |
| Plugin vs scanner process | Operator | Target repo `node_modules` and `.vibeguardrc` | **No**; plugin code is `require()`d |
| Sandbox vs host OS | Host | Untrusted code | **No** for `vm`; process mode is still same-user, network-capable |
| Audit log vs attacker | Append-only file | Anyone with write access | Hash chain only; forgeable |
| Release artifact vs registry | npm/GitHub | Tampered package/manifest | SHA-256 manifest, no signature/provenance in current release |

### 4.3 Platform notes

- CI executes only `ubuntu-latest`.
- `processIsolationSupported()` requires Node 20+ (`src/sandbox.js:207-212`); Node 18 uses the `vm` path, which the audit found fully escapable.
- Windows testing was performed locally on Node 24; destructive Windows shell commands were not detected (F-15).
- macOS has no CI coverage and no OS-specific sandbox; POSIX path assumptions are mostly shared with Linux.

---

## 5. Verified strengths

These are real and worth preserving:

1. **Deterministic policy engine.** `src/agent-policy.js` is readable, testable, and does not call a model or network. The test suite covers default denies, allowlists, rate limits, secrets, hosts and drift.
2. **Real stdio integration test.** The proxy test is not a mock; it spawns a fixture MCP server and verifies that blocked calls do not reach it.
3. **Defense in depth for known patterns.** Tool poisoning, shell commands, PII, known secret formats, prompt-injection phrases and Windows/Unix skill patterns are covered by several layers.
4. **Hash-chained logs with a clean model.** The chain implementation is now correct for sequential edits, and the monitor verifies it. This is a good base for HMAC/signed receipts.
5. **Offline-first new runtime modules.** `mcp-firewall`, `agent-policy`, `skill-scan`, `agent-risk`, `agent-monitor` and `owasp-agentic` do not make network calls.
6. **Release discipline improving.** Integrity manifest covers 30 security modules; CI matrix and benchmark gate run on every push; publish workflow uses npm provenance when a token is present.

---

## 6. Audit method and reproducibility

The audit used three evidence classes:

1. **Static source inspection** of every module relevant to the 15 requested areas.
2. **Black-box probes** against the actual modules from a temporary directory; no VibeGuard source file was modified. Probes used Node 24.14.0 on Windows 11. The sandbox probe used a local loopback TCP listener only; no external network destination was contacted.
3. **Primary standards and project sources**, retrieved 2026-11-21:
   - OWASP Agentic Top 10 2026: https://genai.owasp.org/download/52117/
   - OWASP MCP Top 10 2025 (beta): https://owasp.org/projects/mcp-top-10
   - OWASP AISVS 1.01: https://github.com/OWASP/AISVS/releases and https://raw.githubusercontent.com/OWASP/AISVS/main/1.01/dist/AISVS-1.01.pdf
   - OWASP LLM Top 10 2026: https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
   - Pipelock: https://github.com/pipelab-org/pipelock
   - Snyk Agent Scan: https://github.com/snyk/agent-scan
   - Cisco MCP Scanner: https://github.com/cisco-ai-defense/mcp-scanner
   - Semgrep MCP docs: https://docs.semgrep.dev/mcp/overview
   - Gitleaks: https://github.com/gitleaks/gitleaks
   - Trivy: https://www.trivy.dev/docs/latest/guide/target/sbom/
   - Promptfoo MCP testing: https://www.promptfoo.dev/docs/red-team/mcp-security-testing/
   - gVisor: https://gvisor.dev/docs/
   - E2B/Firecracker: https://docs.e2b.dev/faq/security-and-compliance and https://github.com/e2b-dev/infra/blob/main/docs/ARCHITECTURE.md

The audit did **not** run an external penetration test against a live deployment, fuzz every parser, or test macOS/Linux sandbox escapes. Those are explicitly listed as unverified in `03-security-gaps.md`.

---

## 7. Architectural conclusion

The codebase has the right ingredients for an agent security platform:

- a policy engine,
- a proxy,
- a scanner suite,
- a behavior log,
- a sandbox abstraction,
- a standards mapping,
- a release pipeline.

The missing piece is **enforcement integrity**. In its current form:

- the sandbox does not contain hostile code;
- the scanner can execute target-controlled plugin code;
- the proxy only covers part of the MCP protocol;
- the policy can be permissive by default and is string-based;
- detection is pattern-based and bypassable;
- the audit log is not authenticated;
- the standards report is a static claim.

The prioritized remediation is in `07-prioritized-roadmap.md`.
