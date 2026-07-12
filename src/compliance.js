'use strict';

/*
 * Compliance mapping module for VibeGuard.
 *
 * Maps findings to SOC2, PCI-DSS, HIPAA, GDPR, ISO 27001, and EU AI Act
 * control IDs using the CWE-based COMPLIANCE_MAP from rules-pack.js.
 *
 * Generates a compliance report showing which controls have findings
 * and which are satisfied (clean).
 */

const { COMPLIANCE_MAP } = require('./rules-pack');

const FRAMEWORKS = ['SOC2', 'PCI-DSS', 'HIPAA', 'GDPR', 'ISO27001', 'EUAIAct'];

const FRAMEWORK_NAMES = {
  SOC2: 'SOC 2 Type II',
  'PCI-DSS': 'PCI DSS v4.0',
  HIPAA: 'HIPAA Security Rule',
  GDPR: 'GDPR (Regulation 2016/679)',
  ISO27001: 'ISO/IEC 27001:2022',
  EUAIAct: 'EU AI Act (Regulation 2024/1689)',
};

function mapFindingsToCompliance(findings) {
  const report = {};

  for (const fw of FRAMEWORKS) {
    report[fw] = {
      name: FRAMEWORK_NAMES[fw],
      controls: {},
      summary: { total: 0, failing: 0, passing: 0 },
    };
  }

  for (const f of findings) {
    const cwe = f.cwe || extractCWE(f);
    if (!cwe) continue;

    for (const fw of FRAMEWORKS) {
      const map = COMPLIANCE_MAP[fw];
      if (!map || !map[cwe]) continue;

      for (const controlId of map[cwe]) {
        if (!report[fw].controls[controlId]) {
          report[fw].controls[controlId] = {
            id: controlId,
            status: 'fail',
            findings: [],
          };
          report[fw].summary.total++;
          report[fw].summary.failing++;
        }
        report[fw].controls[controlId].findings.push({
          ruleId: f.ruleId,
          file: f.file,
          line: f.line,
          severity: f.severity,
          title: f.title,
        });
      }
    }
  }

  return report;
}

function extractCWE(f) {
  if (!f.cwe) return null;
  const m = /CWE-(\d+)/.exec(f.cwe);
  return m ? `CWE-${m[1]}` : null;
}

function generateComplianceReport(findings, framework) {
  if (framework && !FRAMEWORKS.includes(framework)) {
    return { error: `Unknown framework: ${framework}. Available: ${FRAMEWORKS.join(', ')}` };
  }

  const report = mapFindingsToCompliance(findings);
  if (framework) {
    return report[framework];
  }
  return report;
}

function getControlDescription(framework, controlId) {
  const descriptions = {
    SOC2: {
      'CC6.1': 'The entity implements logical access controls',
      'CC6.3': 'The entity authorizes, modifies, and removes access',
      'CC6.7': 'The entity restricts access to information',
      'CC7.1': 'The entity detects security events',
      'CC7.2': 'The entity responds to security events',
      'CC7.3': 'The entity recovers from security events',
      'CC7.4': 'The entity detects deviations from established processes',
    },
    'PCI-DSS': {
      '3.1': 'Minimize storage of cardholder data',
      '3.34': 'Render PAN unreadable wherever stored',
      '4.1': 'Encrypt transmission of cardholder data',
      '6.5.1': 'Injection flaws',
      '6.5.3': 'Insecure cryptographic storage',
      '6.5.7': 'Cross-site scripting',
      '6.5.8': 'Improper access control',
      '6.5.9': 'Cross-site request forgery',
      '6.5.10': 'Broken authentication',
      '7.1': 'Limit access to system components',
      '8.2.1': 'Strong authentication',
    },
    HIPAA: {
      '164.312(a)(1)': 'Access control',
      '164.312(a)(2)(i)': 'Unique user identification',
      '164.312(a)(2)(iv)': 'Encryption and decryption',
      '164.312(b)': 'Audit controls',
      '164.312(d)': 'Person or entity authentication',
      '164.312(e)(1)': 'Transmission security',
      '164.312(e)(2)(ii)': 'Encryption',
    },
    GDPR: {
      'Art.5': 'Principles relating to processing of personal data',
      'Art.25': 'Data protection by design and by default',
      'Art.32': 'Security of processing',
    },
    ISO27001: {
      'A.9.4.1': 'Information access restriction',
      'A.9.4.3': 'Password management',
      'A.9.4.4': 'Use of privileged utility programs',
      'A.10.1.1': 'Policy on the use of cryptographic controls',
      'A.12.4.1': 'Event logging',
      'A.13.1.1': 'Network controls',
      'A.13.2.1': 'Information transfer policies',
      'A.14.2.5': 'Secure system engineering principles',
      'A.15.1.1': 'Supplier relationships policy',
    },
    EUAIAct: {
      'Art.15': 'Accuracy, robustness, and cybersecurity',
      'Art.27': 'Fundamental rights impact assessment',
    },
  };

  return (descriptions[framework] && descriptions[framework][controlId]) || 'No description available';
}

module.exports = {
  FRAMEWORKS,
  FRAMEWORK_NAMES,
  mapFindingsToCompliance,
  generateComplianceReport,
  getControlDescription,
};
