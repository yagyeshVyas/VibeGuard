# VibeGuard Standards and Compliance Assessment

**Audit date:** 2026-11-21  
**Revision:** `2ce5b36` / v1.10.0  
**Scope:** OWASP Agentic AI Top 10, OWASP MCP Top 10, OWASP AISVS 1.01, OWASP LLM Top 10 2026, and the existing compliance mapping.

---

## 1. Current standards baseline

| Standard | Current version at audit date | Status in VibeGuard | Primary source |
|---|---|---|---|
| OWASP Top 10 for Agentic Applications | 2026 (December 2025) | Catalog present; statuses static | https://genai.owasp.org/download/52117/ |
| OWASP MCP Top 10 | 2025, **beta** (Phase 3) | Catalog present; one item name wrong | https://owasp.org/projects/mcp-top-10 |
| OWASP AISVS | **1.01** (October 2026; 213 active requirements) | **Absent** | https://github.com/OWASP/AISVS/releases |
| OWASP Top 10 for LLM Applications | **2026** (August 2026) | Catalog still labeled 2025, old ordering | https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ |
| OWASP ASVS | 5.0 | Some finding mapping in README/compliance, not a full verification | Existing compliance module |
| SOC 2 / PCI-DSS / HIPAA / GDPR / ISO 27001 / NIST / CIS / EU AI Act | Code mapping only | `src/compliance.js` maps findings; no runtime control attestation | Not independently verified |

Important status distinction:

- OWASP **MCP Top 10 is still a beta** according to the OWASP project page (“Phase 3 – Beta Release and Pilot Testing – We are here right now”). Any claim of “MCP Top 10 compliance” must state the beta version and the snapshot date.
- OWASP **AISVS 1.01** explicitly says it assumes ASVS verification at the matching level. VibeGuard has no AISVS mapping or evidence.
- OWASP **LLM Top 10 2026** changed ordering and names relative to 2025 (e.g., LLM03 is now Excessive Agency; LLM08 is Hidden Context Exposure; LLM10 is Improper Output Handling). VibeGuard’s `--all` report still uses the 2025 list.

---

## 2. What VibeGuard reports today

`src/owasp-agentic.js` defines three catalogs:

- `AGENTIC` (`:25-40`): ASI01–ASI10.
- `MCP` (`:42-57`): MCP01–MCP10.
- `LLM` (`:59-74`): LLM01–LLM10 labeled “2025”.

`coverageReport()` (`:230-270`) marks an item covered if at least one `CHECKS` entry maps to it. `CHECKS` statuses are hardcoded strings (`enforced`, `detected`, `monitored`, `advisory`). The default framework selection is Agentic + MCP (`:231`), producing 20/20 and 100%.

Observed:

```text
$ vibeguard owasp-coverage
Overall: 20/20 controls mapped (100%)

$ vibeguard owasp-coverage --all
Overall: 28/30 controls mapped
```

This is **mapping coverage**, not control effectiveness. For example, MCP07 (authentication/authorization) is marked under a check, but F-12 shows there is no identity/authentication. MCP06 is labeled “Intent Flow Subversion” while the current OWASP beta calls it “Prompt Injection via Contextual Payloads”. The coverage report does not test whether a control is enabled, configured or bypassable.

---

## 3. OWASP Agentic AI Top 10 2026 assessment

Official item names (OWASP Agentic Top 10 2026):

1. ASI01: Agent Goal Hijack
2. ASI02: Tool Misuse and Exploitation
3. ASI03: Identity & Privilege Abuse
4. ASI04: Agentic Supply Chain Vulnerabilities
5. ASI05: Unexpected Code Execution (RCE)
6. ASI06: Memory & Context Poisoning
7. ASI07: Insecure Inter-Agent Communication
8. ASI08: Cascading Failures
9. ASI09: Human-Agent Trust Exploitation
10. ASI10: Rogue Agents

| ID | VibeGuard mechanism | Honest status | Evidence / gap |
|---|---|---|---|
| ASI01 | Prompt firewall, tool-description scan, skill scan | **Partial** | F-08/F-09/F-10: pattern bypasses and false positives |
| ASI02 | Policy tool rules/capabilities, shell guard | **Partial** | F-05/F-11/F-15: default allow, shell egress, Windows gaps |
| ASI03 | Secret/PII scans, path deny, vault/env lock | **Partial** | F-06/F-07: symlink and DLP bypass; no agent identity |
| ASI04 | MCP audit, skill scan, supply firewall, package checks | **Partial** | F-01 plugin RCE, F-16 unpinned installer, F-13 vulnerable deps |
| ASI05 | vm/process sandbox, code scan rules | **Not effective** | F-02: sandbox escape; vm is not a boundary |
| ASI06 | Tool-definition scan, result injection, skill scan | **Partial** | F-03/F-08: resource/prompt paths and pattern bypasses |
| ASI07 | No inter-agent authentication; local stdio only | **Absent** | F-12/F-23: no identity, no remote auth |
| ASI08 | Rate limit, timeouts, behavior patterns | **Partial** | F-17/F-18: no kill switch, proxy DoS |
| ASI09 | ApprovalRequired blocks, audit | **Partial** | F-21: no human approval/reversibility workflow |
| ASI10 | Agent monitor, risk score | **Advisory only** | F-18/F-20: no enforcement; score manipulable |

The catalog names in `src/owasp-agentic.js:25-40` are close but abbreviate ASI05/ASI06; that is cosmetic. The substantive issue is the status claims.

---

## 4. OWASP MCP Top 10 2025 (beta) assessment

Official list and VibeGuard mapping:

| ID | Official 2025 item | VibeGuard implementation | Honest status |
|---|---|---|---|
| MCP01 | Token Mismanagement & Secret Exposure | Secret scanner, MCP config secret checks, result scrub | **Partial** — F-07 DLP bypass; no token lifecycle |
| MCP02 | Privilege Escalation via Scope Creep | Tool rules, capability gates, path scope | **Partial** — F-05/F-06/F-11 |
| MCP03 | Tool Poisoning | Definition scan + pin | **Partial** — F-08/F-27 |
| MCP04 | Software Supply Chain Attacks & Dependency Tampering | MCP audit, skill scan, package/CVE checks | **Partial** — F-01/F-13/F-16/F-25 |
| MCP05 | Command Injection & Execution | Shell guard, sandbox | **Partial** — F-02/F-11/F-15 |
| MCP06 | Prompt Injection via Contextual Payloads | Prompt/tool/skill scans, result injection | **Partial** — **catalog name is wrong**; F-03/F-09 |
| MCP07 | Insufficient Authentication & Authorization | None (local stdio, no token/identity) | **Absent** — F-12 |
| MCP08 | Lack of Audit and Telemetry | JSONL hash chain, monitor | **Partial** — F-04/F-19; no central telemetry |
| MCP09 | Shadow MCP Servers | Duplicate config detection in `agentic.js`/`mcp-audit` | **Partial** — config discovery gap F-16 |
| MCP10 | Context Injection & Over-Sharing | Result scrub, tool definition scan | **Partial** — F-03; no memory/context isolation |

`src/owasp-agentic.js:51` currently says `MCP06: Intent Flow Subversion`. That is not the current official beta label. This is a concrete catalog error that makes the report non-authoritative.

---

## 5. OWASP AISVS 1.01 assessment

AISVS 1.01 has **213 active chapter requirements** (plus Appendix C), three verification levels, and 12 chapters. VibeGuard has no AISVS identifiers, mapping or tests (`rg AISVS src` returns no matches).

The most relevant chapters are:

- **C9: Orchestration and Agentic Action**
- **C10: MCP Security**
- **C11: Adversarial Robustness**
- **C12: Monitoring and Logging**
- C7/C8 for input/output, memory and RAG (where applicable).

### 5.1 C9 requirements

| AISVS requirement | Requirement (abridged) | VibeGuard status | Evidence |
|---|---|---|---|
| C9.1.1 | Per-tool quotas and timeouts (CPU, memory, disk, egress, time) enforced by runtime | **Partial** | `maxCallsPerMinute`, `maxArgumentBytes`, sandbox timeout; no per-tool quotas or MCP call timeout |
| C9.1.2 | Per-execution budgets (recursion, tokens, spend) | **Absent** | No token/spend/recursion budget |
| C9.1.3 | Swarm-level kill switch | **Absent** | F-18 |
| C9.2.1 | Block privileged/irreversible actions until explicit human approval | **Partial** | `approvalRequired` blocks; no approval UI/record (F-21) |
| C9.2.2 | Approval displays canonical complete parameters | **Absent** | No approval workflow |
| C9.2.3 | Reversibility classification | **Absent** | No action classification |
| C9.2.4 | Enforce reversibility classes | **Absent** | No enforcement |
| C9.2.5 | Self-modification boundaries enforced by runtime | **Partial** | Skill scanner detects self-modification; no runtime boundary |
| C9.2.8 | Approvals cryptographically bound to parameters/identity/nonce | **Absent** | No approvals or keys |
| C9.2.10/11 | Multi-step/action-chain approval boundaries | **Absent** | No action chain model |

### 5.2 C10 requirements

| AISVS requirement | Requirement (abridged) | VibeGuard status | Evidence |
|---|---|---|---|
| C10.2.1 | MCP server validates access tokens per request | **Absent** | F-12 |
| C10.2.2 | Validate issuer/audience/expiry/scope (OAuth 2.1) | **Absent** | No OAuth |
| C10.2.4 | `tools/list` scoped to requester’s authorized scopes | **Absent** | Proxy filters poisoning, not authorization |
| C10.2.5 | Authorization on every tool invocation incl. argument values | **Partial** | Policy checks args, but no principal/token |
| C10.2.7 | Only accept tokens issued for this server; no token passthrough | **Not applicable / absent** | No token handling |
| C10.2.8 | `requestState` integrity and single use | **Not applicable / absent** | No OAuth state |
| C10.3.1 | Authenticated encrypted HTTP for remote MCP | **Absent** | Stdio-only proxy (F-23) |
| C10.3.2 | Stdio only in controlled local environments | **Partial** | Stdio used; no environment/consent control |
| C10.3.3 | Validate Origin and Host on HTTP transports | **Not applicable** | No HTTP transport |
| C10.3.5 | Sender-constrained tokens (mTLS/DPoP) | **Absent** | No token layer |
| C10.4.1 | Validate tools/list and tools/call responses against declared schemas | **Absent** | F-22 |
| C10.4.2 | Screen responses for indirect prompt injection before model context | **Partial** | Only tools/call; weak patterns; F-03/F-09 |
| C10.4.3 | Reject unrecognized/oversized parameters | **Partial** | `maxArgumentBytes`; no unknown-param/schema rejection |
| C10.4.4 | Strict schema validation on all servers | **Absent** | No schema validator |
| C10.4.5 | Max payload size on all transports | **Absent** | Unbounded line buffer; F-17 |
| C10.4.6 | Signed tool responses with nonce/timestamp | **Absent** | No response signing |
| C10.4.7 | Explicit consent for local server installation | **Absent** | Proxy spawns server without UI consent |
| C10.4.8 | Snapshot tool definitions; re-approval on change | **Partial** | Pins + block, but no user approval (F-27) |
| C10.4.9 | Shared OAuth proxy identity isolation | **Not applicable** | No OAuth |
| C10.4.10 | Bind consent/authorization to endpoint; re-approve on change | **Absent** | No endpoint authorization |
| C10.4.13 | Resource bounds for schema processing | **Absent** | No schema depth/size limits |

### 5.3 C11/C12

- **C11 Adversarial Robustness:** no adversarial evaluation harness, no calibrated corpus for the new MCP/agent paths, no mutation/fuzzing of parsers. The existing benchmark is for code rules.
- **C12 Monitoring and Logging:** local hash-chained JSONL and a monitor exist, but no structured telemetry export, no central sink, no alert delivery, no kill switch, and the log is forgeable (F-04/F-18/F-19). This is **partial**.

### 5.4 AISVS conclusion

VibeGuard is **not AISVS 1.01 compliant** and should not imply that it is. At best it has partial alignment with a subset of C9/C10 controls. A credible claim requires:

- a versioned requirement-to-control matrix,
- evidence for every claimed requirement,
- test coverage and configuration prerequisites,
- explicit `not implemented/not tested/partial` statuses,
- a statement of the verification level and excluded chapters.

---

## 6. OWASP LLM Top 10 2026 (current) vs VibeGuard’s 2025 catalog

Current 2026 list (from the official OWASP GenAI page/PDF):

1. LLM01: Prompt Injection
2. LLM02: Sensitive Information Disclosure
3. LLM03: Excessive Agency
4. LLM04: Supply Chain
5. LLM05: Data and Model Poisoning
6. LLM06: Unbounded Consumption
7. LLM07: Misinformation
8. LLM08: Hidden Context Exposure
9. LLM09: Vector and Embedding Weaknesses
10. LLM10: Improper Output Handling

`src/owasp-agentic.js:61` labels its catalog “OWASP Top 10 for LLM Applications (2025)” and uses the 2025 ordering:

- LLM03 Supply Chain
- LLM04 Data and Model Poisoning
- LLM05 Improper Output Handling
- LLM06 Excessive Agency
- LLM07 System Prompt Leakage
- LLM08 Vector and Embedding Weaknesses
- LLM09 Misinformation
- LLM10 Unbounded Consumption

Consequences:

- `vibeguard owasp-coverage --all` maps findings to the wrong 2026 items.
- The “28/30” result is not a current OWASP LLM 2026 assessment.
- LLM07 Misinformation and LLM08 Hidden Context Exposure are not represented under their current IDs; vector/embedding weaknesses may be out of scope for VibeGuard but must be labeled.

Recommended action: rename/update the catalog, keep a historical 2025 map if needed, and clearly version every report.

---

## 7. Compliance framework mapping is not attestation

`src/compliance.js` maps scanner findings to SOC 2, PCI-DSS, HIPAA, GDPR, ISO 27001, NIST CSF/800-53, CIS, ASVS and EU AI Act controls. That is useful for reporting, but:

- It is a **finding-to-control hint**, not evidence that a control is implemented or operating.
- It does not test runtime enforcement, access control or audit integrity.
- The README’s compliance claims should not be presented as certification readiness without an independent assessment.

The same applies to “OWASP ASVS” badges: mapping a rule to a control does not satisfy the control.

---

## 8. Claims that should change now

| Current claim | Better claim |
|---|---|
| “OWASP Agentic AI + MCP Top 10 coverage: 20/20” | “Maps 20 of 20 items to at least one control; control effectiveness is being verified. Current status: partial.” |
| “MCP06 Intent Flow Subversion” | “MCP06:2025 Prompt Injection via Contextual Payloads” |
| “OWASP LLM Top 10 2025” (as current) | “OWASP LLM Top 10 2025 (historical); 2026 mapping pending” |
| “AISVS” (if added anywhere) | Do not claim until a versioned C9/C10 matrix and evidence exist |
| “100% offline” | “Offline by default; explicit network commands are …” |
| “Process-isolated sandbox” | “Separate Node process; not an OS sandbox (see limitations)” |
| “Tamper-proof audit” | “Hash-chained audit log; tamper-evident against accidental edits, not authenticated against a writer” |
| “Zero dependencies” | “One runtime dependency (MCP SDK) plus optional parser packages” |

These are not cosmetic. Each one changes a user’s risk decision.

---

## 9. Primary sources

- OWASP Agentic Top 10 2026: https://genai.owasp.org/download/52117/
- OWASP MCP Top 10 (beta, 2025): https://owasp.org/projects/mcp-top-10
- OWASP AISVS 1.01 release: https://github.com/OWASP/AISVS/releases
- AISVS 1.01 PDF: https://raw.githubusercontent.com/OWASP/AISVS/main/1.01/dist/AISVS-1.01.pdf
- AISVS C9: https://github.com/OWASP/AISVS/blob/main/1.01/en/0x10-C09-Orchestration-and-Agentic-Action.md
- AISVS C10: https://github.com/OWASP/AISVS/blob/main/1.01/en/0x10-C10-MCP-Security.md
- OWASP LLM Top 10 2026: https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
- OWASP LLM Top 10 2026 PDF: https://genai.owasp.org/download/56857/
