'use strict';

/*
 * VibeGuard Behavioral Analysis Engine.
 *
 * Analyzes AI agent behavior over time to detect:
 * - Anomalous access patterns (sudden access to secrets)
 * - Data gathering (collecting data from many sources before exfil)
 * - Slow exfiltration (small amounts over time)
 * - Privilege escalation attempts (progressive access to higher-risk resources)
 * - Trust building then exploit (innocent actions followed by attack)
 * - Resource exhaustion patterns (infinite loops, memory bombs)
 *
 * Builds a behavioral profile per session and flags suspicious patterns.
 * 100% local. Zero network. Zero dependencies.
 */

const MAX_EVENTS = 10000; // Per session

// Risk score per action type
const ACTION_RISK = {
  file_read: 1, file_write: 2, exec: 3, network: 2,
  secret_access: 10, env_access: 8, ai_api: 2,
  blocked: 5, tamper: 20,
};

// Suspicious patterns
const PATTERNS = {
  // Accessing secrets after many normal actions (trust building)
  TRUST_BUILDING: {
    detect: (events) => {
      if (events.length < 10) return false;
      const recent = events.slice(-5);
      const earlier = events.slice(0, -5);
      const earlierNormal = earlier.every(e => ACTION_RISK[e.type] <= 2);
      const recentDanger = recent.some(e => ACTION_RISK[e.type] >= 8);
      return earlierNormal && recentDanger;
    },
    severity: 'high',
    message: 'Trust building pattern: many normal actions followed by secret/env access',
  },
  // Data gathering: reading many files before a network request
  DATA_GATHERING: {
    detect: (events) => {
      const recent = events.slice(-15);
      const reads = recent.filter(e => e.type === 'file_read').length;
      const network = recent.filter(e => e.type === 'network').length;
      return reads >= 5 && network >= 1 && reads > network * 3;
    },
    severity: 'high',
    message: 'Data gathering pattern: many file reads before network request',
  },
  // Slow exfiltration: multiple small network requests over time
  SLOW_EXFIL: {
    detect: (events) => {
      const networkEvents = events.filter(e => e.type === 'network');
      if (networkEvents.length < 5) return false;
      const timeSpan = networkEvents[networkEvents.length - 1].timestamp - networkEvents[0].timestamp;
      return timeSpan > 30000 && networkEvents.length > 5; // 30s+ with 5+ requests
    },
    severity: 'high',
    message: 'Slow exfiltration pattern: multiple network requests over time',
  },
  // Privilege escalation: progressively higher risk actions
  PRIVILEGE_ESCALATION: {
    detect: (events) => {
      if (events.length < 5) return false;
      const recent = events.slice(-10);
      const risks = recent.map(e => ACTION_RISK[e.type] || 0);
      for (let i = 1; i < risks.length; i++) {
        if (risks[i] > risks[i - 1] + 2) return true; // Sudden jump in risk
      }
      return false;
    },
    severity: 'critical',
    message: 'Privilege escalation pattern: progressively higher-risk actions',
  },
  // Repeated blocked attempts (trying to bypass security)
  REPEATED_BLOCKS: {
    detect: (events) => {
      const blocks = events.filter(e => e.type === 'blocked');
      return blocks.length >= 3;
    },
    severity: 'critical',
    message: 'Repeated blocked attempts: AI is trying to bypass security controls',
  },
  // Tamper attempts
  TAMPER_DETECTED: {
    detect: (events) => events.some(e => e.type === 'tamper'),
    severity: 'critical',
    message: 'Tampering attempt detected: AI tried to disable or modify VibeGuard',
  },
  // Off-hours access (accessing secrets at unusual times)
  OFF_HOURS: {
    detect: (events) => {
      const secretAccess = events.filter(e => e.type === 'secret_access' || e.type === 'env_access');
      if (secretAccess.length === 0) return false;
      const hour = new Date(secretAccess[0].timestamp).getHours();
      return hour < 6 || hour > 22; // Before 6am or after 10pm
    },
    severity: 'medium',
    message: 'Off-hours secret access: accessing secrets at unusual times',
  },
  // Unusual frequency: too many actions in short time
  RAPID_FIRE: {
    detect: (events) => {
      if (events.length < 20) return false;
      const timeSpan = events[events.length - 1].timestamp - events[0].timestamp;
      return timeSpan < 5000 && events.length > 20; // 20+ events in 5s
    },
    severity: 'medium',
    message: 'Rapid-fire pattern: too many actions in short time (automated attack?)',
  },
};

function createSession() {
  return {
    events: [],
    startTime: Date.now(),
    riskScore: 0,
    patterns: [],
  };
}

function recordEvent(session, type, detail = {}) {
  const event = {
    type,
    detail,
    timestamp: Date.now(),
    risk: ACTION_RISK[type] || 0,
  };
  session.events.push(event);
  if (session.events.length > MAX_EVENTS) session.events.shift();
  session.riskScore += event.risk;
  return event;
}

function analyzeSession(session) {
  const detected = [];
  for (const [name, pattern] of Object.entries(PATTERNS)) {
    if (pattern.detect(session.events)) {
      detected.push({ pattern: name, severity: pattern.severity, message: pattern.message });
    }
  }

  // Calculate behavioral risk level
  const riskLevel = session.riskScore === 0 ? 'NONE' :
    session.riskScore < 20 ? 'LOW' :
    session.riskScore < 50 ? 'MEDIUM' :
    session.riskScore < 100 ? 'HIGH' : 'CRITICAL';

  // Check for blocked actions ratio
  const blockedCount = session.events.filter(e => e.type === 'blocked').length;
  const blockedRatio = session.events.length > 0 ? blockedCount / session.events.length : 0;

  return {
    totalEvents: session.events.length,
    riskScore: session.riskScore,
    riskLevel,
    blockedCount,
    blockedRatio: Math.round(blockedRatio * 100) + '%',
    patterns: detected,
    patternsCount: detected.length,
    sessionDuration: Date.now() - session.startTime,
    recommendation: detected.length === 0 ? 'No suspicious patterns detected' :
      detected.some(p => p.severity === 'critical') ? 'IMMEDIATE ACTION: Critical behavioral pattern detected. Terminate AI session.' :
      detected.some(p => p.severity === 'high') ? 'WARNING: Suspicious behavior pattern detected. Review AI session.' :
      'CAUTION: Minor behavioral anomaly detected. Monitor.',
  };
}

function renderBehaviorReport(analysis) {
  const C = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', cyan: '\x1b[36m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  const riskColor = { NONE: C.green, LOW: C.green, MEDIUM: C.yellow, HIGH: C.yellow, CRITICAL: C.red };
  const color = riskColor[analysis.riskLevel] || C.white;

  const lines = [
    `${C.bold}VibeGuard Behavioral Analysis${C.reset}`,
    `${C.dim}${'─'.repeat(60)}${C.reset}`,
    '',
    `  Risk Score:     ${color}${analysis.riskScore}${C.reset} (${color}${analysis.riskLevel}${C.reset})`,
    `  Total Events:   ${analysis.totalEvents}`,
    `  Blocked:        ${C.red}${analysis.blockedCount}${C.reset} (${analysis.blockedRatio})`,
    `  Patterns:       ${analysis.patternsCount}`,
    `  Duration:        ${analysis.sessionDuration}ms`,
    '',
  ];

  if (analysis.patterns.length > 0) {
    lines.push(`${C.bold}Detected Patterns${C.reset}`, '');
    for (const p of analysis.patterns) {
      const sc = p.severity === 'critical' ? C.red : p.severity === 'high' ? C.yellow : C.dim;
      lines.push(`  ${sc}[${p.severity}]${C.reset} ${p.pattern}`);
      lines.push(`    ${p.message}`);
      lines.push('');
    }
  }

  lines.push(`${C.bold}Recommendation${C.reset}`);
  lines.push(`  ${color}${analysis.recommendation}${C.reset}`);

  return lines.join('\n');
}

module.exports = { createSession, recordEvent, analyzeSession, renderBehaviorReport, PATTERNS, ACTION_RISK };