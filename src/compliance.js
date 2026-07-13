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

const FRAMEWORKS = ['SOC2', 'PCI-DSS', 'HIPAA', 'GDPR', 'ISO27001', 'EUAIAct', 'NISTCSF', 'ASVS', 'CIS', 'NIST800-53'];

const FRAMEWORK_NAMES = {
  SOC2: 'SOC 2 Type II',
  'PCI-DSS': 'PCI DSS v4.0',
  HIPAA: 'HIPAA Security Rule',
  GDPR: 'GDPR (Regulation 2016/679)',
  ISO27001: 'ISO/IEC 27001:2022',
  EUAIAct: 'EU AI Act (Regulation 2024/1689)',
  NISTCSF: 'NIST Cybersecurity Framework 2.0',
  ASVS: 'OWASP ASVS L1/L2/L3',
  CIS: 'CIS Controls v8',
  'NIST800-53': 'NIST SP 800-53 Rev. 5',
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
      '3.2': 'Sensitivity of stored cardholder data is minimized',
      '3.3': 'Sensitive authentication data is not retained after authorization',
      '4.2.1': 'Strong cryptography and security protocols are used to safeguard PAN during transmission',
      '6.2.4': 'Software engineering techniques address common coding vulnerabilities',
      '6.5.2': 'Software vulnerabilities are patched and managed',
      '6.5.3': 'Cryptographic keys used for encryption of stored cardholder data are secured',
      '6.5.5': 'Access control mechanisms are implemented for all system components',
      '7.2.1': 'Access control model is defined and implemented for all system components',
      '8.3.2': 'Strong authentication is implemented for all access to system components',
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
    NISTCSF: {
      'PR.AC-1': 'Identities and credentials are managed',
      'PR.AC-3': 'Access permissions are managed',
      'PR.AC-4': 'Access permissions and activity are verified',
      'PR.DS-1': 'Data-at-rest is protected',
      'PR.DS-2': 'Data-in-transit is protected',
      'PR.IP-1': 'Baseline configurations are maintained',
      'PR.IP-2': 'Software engineering practices are used',
      'DE.CM-1': 'Networks are monitored for security events',
      'AU-2': 'Audit events are logged',
    },
    ASVS: {
      'V4.1.1': 'Access control verifies authenticated users',
      'V4.1.3': 'Access control denies non-whitelisted resources',
      'V4.2.1': 'Secrets are not hardcoded',
      'V4.3.1': 'Data exposure is minimized',
      'V5.3.1': 'SQL injection is prevented',
      'V5.3.2': 'NoSQL injection is prevented',
      'V5.3.4': 'Untrusted input is escaped',
      'V5.3.5': 'XSS is prevented',
      'V6.1.1': 'Secrets are generated securely',
      'V6.2.1': 'Algorithms are current and strong',
      'V6.3.1': 'TLS is used for data in transit',
      'V7.1.1': 'Logs do not contain sensitive data',
      'V7.2.1': 'Logs are protected from tampering',
      'V8.3.1': 'SSRF is prevented',
      'V9.1.1': 'TLS certificate validation is enabled',
      'V12.1.1': 'Command injection is prevented',
      'V12.3.1': 'Path traversal is prevented',
      'V13.2.1': 'CSRF protection is in place',
      'V14.1.1': 'Build pipeline is secured',
      'V14.2.1': 'Dependencies are checked for known vulnerabilities',
    },
    CIS: {
      'CIS-3': 'Data protection measures are in place',
      'CIS-4': 'Secure configuration of hardware and software',
      'CIS-6': 'Access control management',
      'CIS-8': 'Audit log management',
      'CIS-12': 'Network monitoring and defense',
      'CIS-16': 'Application software security',
      'CIS-17': 'Incident response and management',
      'CIS-18': 'Penetration testing and red team exercises',
      'CIS-20': 'Security awareness and training',
    },
    'NIST800-53': {
      'AC-2': 'Account management',
      'AC-3': 'Access enforcement',
      'IA-2': 'Identification and authentication',
      'IA-5': 'Authenticator management',
      'AU-2': 'Event logging',
      'AU-3': 'Content of audit records',
      'SC-7': 'Boundary protection',
      'SC-8': 'Transmission confidentiality and integrity',
      'SC-12': 'Cryptographic key establishment',
      'SC-13': 'Cryptographic protection',
      'SI-10': 'Information input validation',
      'SA-11': 'Developer testing and evaluation',
      'CM-7': 'Least functionality',
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
