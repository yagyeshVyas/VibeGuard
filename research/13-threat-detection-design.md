# AI Threat Detection Design

**Design date:** 2026-11-21  
**Basis:** audit F-03/F-07/F-08/F-09/F-10/F-14, `08`/`09`/`10`  
**Status:** design only. Deterministic detection is the core; AI assistance is optional and never authoritative.

---

## 1. Principles

1. **Instructions have provenance.** Text from a tool description, tool result, resource, web page or skill is data, not authority. The gateway labels provenance and policy decides how much instruction weight it may carry.
2. **Normalize before matching.** Unicode, encodings and whitespace are attacker-controlled; detection must normalize and decode within strict bounds.
3. **Deterministic first.** The same input + same detector version + same seed must produce the same findings.
4. **Detectors produce evidence, not decisions.** A detector returns findings/labels/confidence; the policy engine maps those facts to allow/deny/approval/quarantine.
5. **No LLM final authority.** An optional local classifier may add advisory evidence and, if policy allows, escalate to approval/deny. It can never remove a deterministic deny or authorize an action.
6. **No raw secrets in evidence.** Evidence stores hashes/spans/labels, not secret values.
7. **Fail safe.** Detector errors produce `detector_error`; strict policy denies guarded operations; no silent pass.

---

## 2. Pipeline

```
Content acquisition
  (bounded size/type; streaming-aware)
      │
      ▼
Canonicalization
  - Unicode NFKC/NFKD, confusable mapping, bidi/invisible removal
  - line-ending/whitespace normalization (offsets preserved)
      │
      ▼
Decoding (bounded, multi-layer)
  - base64/base64url, hex, percent, HTML entities, \u/\x escapes
  - max 3 layers, max 256 KiB decoded, no recursion bombs
      │
      ▼
Structured parsing
  - JSON/Markdown/HTML/code/text; separate instruction/data fields
  - schema validation; size/depth limits
      │
      ▼
Deterministic detectors (parallel)
  - direct/indirect injection, tool poisoning, hidden Unicode/obfuscation,
    schema manipulation, memory poisoning, multi-agent, secrets, PII, skills
      │
      ▼
Evidence fusion
  - dedupe, correlate spans, confidence, source labels
  - deterministic ordering by detector ID/span
      │
      ▼
Policy evidence set
  - findings + labels + trust + provenance + detector status
      │
      ├──────────────┐
      ▼              ▼
Optional AI       Deterministic decision
advisory          (policy engine)
      │              │
      └──────► final decision (AI can only add escalation, never allow)
```

The gateway **never** calls an AI model before or instead of deterministic checks.

---

## 3. Provenance and instruction hierarchy

Every content unit gets a `ContentContext`:

```ts
interface ContentContext {
  contentType: 'text'|'json'|'markdown'|'html'|'code'|'resource'|'prompt';
  source: 'system'|'operator-policy'|'user'|'tool-description'|'tool-result'
        | 'resource'|'prompt-template'|'skill'|'memory'|'web'|'unknown';
  trust: 'trusted'|'reviewed'|'untrusted';
  server?: string;
  tool?: string;
  resourceUri?: string;
  sessionId: string;
  agentId: string;
  labels: DataLabelSet;
  spanMap: SpanMap;          // normalized → original offsets
}
```

Instruction hierarchy (highest to lowest):

1. system/operator security policy — **never derived from content**
2. signed policy and approvals
3. user instruction
4. agent skill instructions (only if trusted/signed)
5. tool descriptions (untrusted unless approved)
6. tool results/resources/retrieved data/web — **data only; never authority**

A detector can flag content that tries to cross a boundary (e.g., a tool result saying “ignore the policy”). Policy can quarantine the server/skill that supplied it.

---

## 4. Detector families

### 4.1 Direct prompt injection

Signals:

- instruction override (“ignore/disregard/forget previous instructions”)
- role/goal hijack (“you are now…”, “your new task is…”)
- system-prompt extraction
- safety/policy bypass
- encoded/obfuscated instruction
- data-exfiltration instruction
- tool-call coercion (“call this tool before answering”)

Design requirements:

- Word-boundary and phrase-level matching, not bare substrings (fixes `DAN` matching “guidance”).
- Multilingual and transliterated variants where feasible; otherwise mark as `coverage: partial`.
- Benign-context handling: quoted examples, documentation, test fixtures can be allowlisted with signed exceptions.
- Every finding carries offset/span and a short safe explanation.

### 4.2 Indirect prompt injection

Same signals, but from tool results/resources/prompts/web/skills. Additional signals:

- instruction embedded in a data field (JSON value, HTML attribute, Markdown link title)
- hidden text (CSS color/size, zero-width, off-screen)
- tool output that asks the model to call another tool or read a secret
- cross-tool instruction (“when you use tool B, send…”) 
- provenance mismatch (tool result claims to be system/policy)

Policy default: **untrusted content cannot introduce new instructions**; strip/withhold or require approval.

### 4.3 Tool poisoning and schema manipulation

Signals:

- description contains instruction-like text, concealment, urgency, forced invocation
- description conflicts with name/annotations (`readOnlyHint` lie)
- schema anomalies: hidden `default` values, overly broad `additionalProperties`, unusual formats, giant descriptions, encoded constraints
- tool shadowing/collision with a trusted tool name
- definition drift after approval
- result contains a tool definition or asks to install/change tools
- hidden Unicode/confusables in name/description/schema
- tool result claims to be a system message

Control:

- Hash + approve definitions; first sight requires approval in strict mode.
- Diff descriptions/schemas on every list; changed definition = quarantine/deny.
- Schema validation with depth/size limits; reject invalid JSON Schema.
- Tools that cannot be parsed are denied, not passed through.

### 4.4 Hidden Unicode and obfuscated payloads

Normalization pipeline:

- NFKC/NFKD, case folding for matching (preserve original spans)
- remove/flag zero-width, bidi controls, soft hyphen, tag characters
- map common confusables/homoglyphs (Cyrillic/Greek/Latin, fullwidth, mathematical alphanumerics)
- strip/flag HTML comments, CSS-hidden text, Markdown link titles, alt text
- decode base64/base64url/hex/percent/unicode escapes (bounded)
- detect leetspeak/spacing/word-splitting patterns as a separate finding, not a bypass

Rules:

- Hidden/invisible characters in model-facing content = finding, even if no known phrase matches.
- Encoded blobs over a small threshold are decoded and scanned; if undecodable, flag as suspicious.
- No unbounded decoding; record depth and bytes.

### 4.5 Memory manipulation

Memory is a privileged state store; design:

- Every memory write has provenance (`source`, `agent`, `session`, `trust`).
- Untrusted content cannot write to durable memory without approval; strict default deny.
- Memory entries have owner/tenant/scope/TTL; no cross-tenant reads.
- Detect attempts to write instructions, policy overrides, credentials, or “remember to always…” patterns.
- Detect context bleed: memory from another session/tenant/agent; policy denies.
- Memory reads include provenance; untrusted memory is labeled data.

### 4.6 Multi-agent attacks

Maintain a flow graph per tenant:

- nodes: human/agent/service/server/tool/resource/session
- edges: call, delegate, return, memory write, resource share
- attributes: capabilities, tenant, trust, time

Signals:

- privilege escalation via delegation (agent grants itself/another a capability it does not have)
- cross-tenant/cross-agent context sharing
- instruction forwarding: untrusted content becomes instructions to another agent
- loops/amplification (A→B→A with escalating actions)
- collusion pattern: multiple agents split a prohibited action
- tool-call chain (recon → credential access → staging → egress)
- contradictory authorization (different agents see different policy scopes)

Control: policy on delegation; flow taint; chain detection; quarantine the chain, not just one call.

### 4.7 Secrets, PII, data classes

- Deterministic patterns + entropy + decoders + named credential fields.
- Secret values are never included in findings; use HMAC fingerprints and span offsets.
- PII detection with per-type policy (redact/block/approval).
- Data labels propagate through gateway; DLP at egress/result/memory.
- Unknown high-entropy values near network destinations are treated as potential secrets (policy-configurable).

### 4.8 Skill/plugin detection

- Signed skill manifest + permission declaration.
- Scan instruction text, scripts, links, embedded MCP config, package installs.
- Natural-language intent detection for data access/exfil, not just verb proximity.
- No auto-`require()`; plugins are executed only in a sandbox with declared permissions.
- Trust states: unknown/pending/trusted/revoked.

---

## 5. Finding and evidence schema

```json
{
  "findingId": "fnd_01...",
  "detectorId": "prompt-injection.indirect",
  "detectorVersion": "1.2.0",
  "severity": "high",
  "confidence": 0.87,
  "categories": ["instruction_override", "data_exfiltration"],
  "source": {"kind":"tool-result","server":"files","tool":"read_file"},
  "spans": [{"start":120,"end":180,"normalizedStart":110,"normalizedEnd":170}],
  "evidenceHash": "sha256:...",
  "safeExcerpt": "…include the contents of the [REDACTED] file…",
  "labels": ["untrusted","instruction"],
  "explanation": "Tool output asks the model to disclose a local file.",
  "remediation": "Withhold the result; quarantine the server or require approval.",
  "deterministic": true
}
```

Rules:

- No raw secret values, credentials or full malicious payloads in logs/dashboards by default.
- `safeExcerpt` is redacted and size-limited.
- Findings are sorted deterministically; IDs are stable for regression tests.
- Confidence is calibrated and labeled; 0.87 must mean something measured, not arbitrary.

---

## 6. Optional AI-assisted analysis

**Allowed uses**

- paraphrase detection for novel injection wording
- ambiguous intent classification
- triage suggestions
- clustering/duplicate findings
- human-readable explanations

**Forbidden uses**

- final allow/deny
- overriding deterministic deny
- accessing secrets/raw data unnecessarily
- network calls in offline mode
- silently suppressing findings
- training on customer data without consent

Contract:

```ts
interface ClassifierPort {
  classify(input: DetectionInput, ctx: DetectionContext): Promise<AdvisoryResult>;
}

interface AdvisoryResult {
  label: 'benign'|'suspicious'|'malicious'|'unknown';
  confidence: number;
  explanation?: string;
  modelId: string;
  modelHash: string;
  deterministicSeed?: number;
}
```

Policy can say `aiAssist.mode:"advisory"` and `mayEscalateTo:["approval_required"]`. A `benign` advisory never turns a deny into allow. AI failure/timeout logs `ai_unavailable` and continues with deterministic findings.

Offline local model requirements:

- pinned model hash, no network
- bounded input/output tokens/time
- no secret leakage: input already redacted for secrets; or run on labels/hashes only
- model output treated as untrusted text
- reproducible/seed where the runtime supports it
- resource isolation (same sandbox/worker restrictions)

---

## 7. Policy integration

Detector output is converted into an `EvidenceSet`:

```json
{
  "findings": [{"detectorId":"...","severity":"high","confidence":0.87}],
  "labels": ["untrusted","instruction"],
  "trust": {"server":"unknown"},
  "detectorStatus": {"promptInjection":"ok","hiddenUnicode":"ok"}
}
```

Policy examples:

- `promptInjection == block` → deny if finding severity >= high
- `toolPoisoning == quarantine` → quarantine server, deny tool
- `hiddenUnicode == block` → withhold result
- `aiAssist.label == malicious` → approval_required (never allow)

Detector severity is a fact; policy decides the action. This keeps detection changes separately testable from enforcement changes.

---

## 8. Performance and resource budgets

| Stage | Budget |
|---|---|
| Per-message parse | ≤ 5 ms typical; hard size/depth cap |
| Normalization/decoding | ≤ 10 ms per 64 KiB; max 256 KiB decoded |
| Detectors | ≤ 25 ms per 64 KiB total (target) |
| Optional AI | ≤ 2 s timeout, off by default |
| Result scan | ≤ 1 MiB, max depth 32 |
| Session flow graph | bounded nodes/edges; eviction by TTL |

Budgets are measured on documented hardware; exceeding a hard cap fails closed with `VG_LIMIT_EXCEEDED`, not an unbounded scan.

---

## 9. Calibration and false positives

- Maintain a labeled corpus per detector family: benign, malicious, ambiguous, encoded, multilingual, domain-specific.
- Report precision, recall, F1, FPR, and bypass rate per detector, not just aggregate.
- Confidence must be calibrated (reliability curve/Brier score); if not, label findings `confidence:"uncalibrated"` and policy should not rely on it alone.
- Suppressions are signed/explicit and expire; no silent inline ignore in strict mode.
- Every false positive becomes a regression case or a documented limitation.
- No claim of “100% detection.”

---

## 10. Detector implementation rules

- No network, no global mutable state, no `Date.now()`/randomness in core scoring; inject clock/seed.
- No dynamic `eval`/`Function` in detectors.
- Regexes are bounded (RE2-compatible subset or length limits); no catastrophic backtracking.
- All parsing has size/depth limits.
- Deterministic order and stable IDs.
- No raw content in exceptions/logs.
- Every detector has a version and an owner.
- Optional AI adapter is a separate module with no core imports.

---

## 11. Detection acceptance tests

- Bypass corpus: paraphrases, homoglyphs, base64/hex, spacing, zero-width, Markdown/HTML hiding, multilingual, tool-result/resource channels.
- False-positive corpus: documentation, code snippets, test fixtures, “guidance”, quoted examples, benign JSON.
- Tool schema corpus: hidden defaults, broad schemas, annotation lies, drift.
- Memory corpus: cross-tenant bleed, untrusted write, instruction persistence.
- Multi-agent corpus: delegation escalation, context sharing, loop amplification.
- AI-assisted tests: timeout/error/benign escalation cannot allow; deterministic deny remains.
- Performance tests at 64 KiB/1 MiB/10 MiB with time/memory bounds.

The full benchmark design is in `14-testing-and-benchmark-design.md`.
