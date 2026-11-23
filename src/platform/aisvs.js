'use strict';

/*
 * AISVS-style control mapping. This is an internal readiness matrix, not a
 * certification and not a claim that every AISVS 1.01 requirement is met.
 * Statuses are derived from the independent verification evidence IDs.
 */

const CONTROLS = [
  { id: 'AISVS-GOV-01', title: 'AI security ownership and policy', status: 'partial', evidence: ['research/SECURITY_TEST_MATRIX.md'], note: 'Strict policy exists; no organizational governance evidence.' },
  { id: 'AISVS-INV-01', title: 'Agent/tool/model inventory', status: 'partial', evidence: ['src/mcp-audit.js'], note: 'Config discovery only; no complete registry.' },
  { id: 'AISVS-PI-01', title: 'Prompt injection resistance', status: 'partial', evidence: ['IV-PI-01..09'], note: 'Tested patterns; no precision corpus coverage beyond small corpus.' },
  { id: 'AISVS-TOOL-01', title: 'Tool definition integrity', status: 'partial', evidence: ['IV-TP-01..05'], note: 'Hash/pin and text scanning; no full schema provenance.' },
  { id: 'AISVS-AUTH-01', title: 'Caller authentication', status: 'partial', evidence: ['IV-AUTH-01..07'], note: 'HTTP/stdio token path; approval service now requires password-authenticated human sessions or human tokens plus signed approver proofs.' },
  { id: 'AISVS-AUTHZ-01', title: 'Least-privilege authorization', status: 'partial', evidence: ['IV-UA-01..07'], note: 'Strict policy/v2 library; legacy default allow.' },
  { id: 'AISVS-DATA-01', title: 'Secret/PII protection', status: 'partial', evidence: ['IV-SEC-01..08'], note: 'Pattern/entropy DLP; no universal coverage.' },
  { id: 'AISVS-SBX-01', title: 'Untrusted code isolation', status: 'not_verified', evidence: ['IV-SBX-01..06'], note: 'Linux namespace and Windows AppContainer verified; macOS VM requires a configured, verified guest image.' },
  { id: 'AISVS-LOG-01', title: 'Tamper-evident audit', status: 'partial', evidence: ['IV-AUD-01..07'], note: 'Signed logger/checkpoint; gateway strict uses it; external anchor absent.' },
  { id: 'AISVS-MON-01', title: 'Runtime monitoring/response', status: 'partial', evidence: ['IV-FO-08'], note: 'Kill-on-block added; no OS network/process monitor.' },
  { id: 'AISVS-SC-01', title: 'Supply-chain integrity', status: 'partial', evidence: ['IV-DEP-01..03'], note: 'Audit overrides; no provenance/signature.' },
  { id: 'AISVS-MA-01', title: 'Multi-agent isolation', status: 'not_implemented', evidence: ['IV-MA-01..03'], note: 'Library controls only, not wired.' },
  { id: 'AISVS-MEM-01', title: 'Memory/context integrity', status: 'not_implemented', evidence: ['IV-MEM-01..03'], note: 'No persistent memory path.' },
  { id: 'AISVS-EVAL-01', title: 'Adversarial evaluation', status: 'partial', evidence: ['test/corpus', 'research/REPRODUCIBLE_BENCHMARKS.md'], note: 'Small labeled corpus + local tests; no independent penetration test.' },
  { id: 'AISVS-IR-01', title: 'Incident response/forensics', status: 'partial', evidence: ['IV-FO-01..08'], note: 'Audit + kill switch; no incident workflow/SIEM.' },
];

function getAisvsReport() {
  const counts = { implemented: 0, partial: 0, not_implemented: 0, not_verified: 0 };
  for (const c of CONTROLS) counts[c.status] = (counts[c.status] || 0) + 1;
  return {
    framework: 'AISVS-style internal mapping (not certified AISVS 1.01 coverage)',
    generatedAt: new Date().toISOString(),
    counts,
    controls: CONTROLS,
  };
}

module.exports = { CONTROLS, getAisvsReport };
