'use strict';

/*
 * Prompt tracing — link findings back to the AI prompt that generated them.
 *
 * Reads Cursor (.cursor/), Claude Code, and Windsurf session history files.
 * Scans for security-relevant behavior patterns in AI agent transcripts.
 *
 * Two capabilities:
 *   1. Trace a finding back to the AI prompt that likely generated the code
 *   2. Behavior analysis: detect blind approvals, high delegation, risky patterns
 */

const fs = require('fs');
const path = require('path');

const SESSION_DIRS = [
  '.cursor',
  '.cursor/projects',
  '.windsurf',
  '.claude',
  '.continue',
];

function findSessionFiles(root) {
  const files = [];
  for (const dir of SESSION_DIRS) {
    const absDir = path.join(root, dir);
    if (!fs.existsSync(absDir)) continue;
    try {
      walkAndCollect(absDir, files, /\.(?:json|jsonl|md|txt)$/i);
    } catch {}
  }
  return files;
}

function walkAndCollect(dir, out, extRe) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch { return; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walkAndCollect(full, out, extRe);
    else if (e.isFile() && extRe.test(e.name)) out.push(full);
  }
}

function parseSession(filepath) {
  const content = fs.readFileSync(filepath, 'utf8');
  const messages = [];

  // Try JSONL format (one JSON object per line)
  if (filepath.endsWith('.jsonl')) {
    for (const line of content.split('\n')) {
      try {
        const obj = JSON.parse(line);
        if (obj.role || obj.type || obj.message) messages.push(obj);
      } catch {}
    }
  }

  // Try JSON array
  if (messages.length === 0 && filepath.endsWith('.json')) {
    try {
      const arr = JSON.parse(content);
      if (Array.isArray(arr)) messages.push(...arr);
      else messages.push(arr);
    } catch {}
  }

  // Try markdown/text (split by user/assistant markers)
  if (messages.length === 0) {
    const parts = content.split(/^(?:User|Human|Assistant|AI|>>>)[:\s]/m);
    parts.forEach((p, i) => {
      if (p.trim()) messages.push({ role: i % 2 === 0 ? 'user' : 'assistant', content: p.trim() });
    });
  }

  return { file: filepath, messages };
}

const RISKY_BEHAVIORS = [
  {
    id: 'behavior.blind-approval',
    re: /(?:yes|ok|sure|go ahead|do it|approve|sounds good|perfect|great)\s*[!.?\s]*$/i,
    risk: 'medium',
    desc: 'Blind approval of AI suggestion without review',
  },
  {
    id: 'behavior.high-delegation',
    re: /(?:do\s+(?:all|everything|the\s+whole)|build\s+(?:the\s+entire|all)|write\s+(?:all|every|the\s+complete)|implement\s+(?:all|everything|the\s+entire))/i,
    risk: 'medium',
    desc: 'High delegation — asking AI to do everything at once reduces review quality',
  },
  {
    id: 'behavior.skip-tests',
    re: /(?:skip|don'?t\s+need|no\s+need\s+for)\s+(?:tests?|testing|validation)/i,
    risk: 'high',
    desc: 'Requesting code without tests',
  },
  {
    id: 'behavior.skip-auth',
    re: /(?:skip|don'?t\s+(?:need|worry\s+about)|no\s+need\s+for)\s+(?:auth|authentication|authorization|security)/i,
    risk: 'high',
    desc: 'Explicitly requesting to skip authentication/security',
  },
  {
    id: 'behavior.hardcode-secrets',
    re: /(?:just\s+)?(?:hardcode|hard-code|put\s+(?:the\s+)?(?:password|secret|token|key|api\s+key)\s+(?:directly\s+)?(?:in|here))/i,
    risk: 'high',
    desc: 'Asking AI to hardcode secrets',
  },
  {
    id: 'behavior.disable-security',
    re: /(?:disable|turn\s+off|remove|skip|bypass)\s+(?:security|validation|sanitization|escaping|CORS|helmet|CSRF)/i,
    risk: 'high',
    desc: 'Asking AI to disable security features',
  },
  {
    id: 'behavior.trust-input',
    re: /(?:trust\s+the\s+(?:user|client|input)|user\s+input\s+is\s+(?:safe|trusted|fine)|don'?t\s+validate)/i,
    risk: 'high',
    desc: 'Expressing trust in user/client input without validation',
  },
  {
    id: 'behavior.excessive-iter',
    re: /(?:again|redo|try\s+again|different\s+approach|start\s+over)/i,
    risk: 'low',
    desc: 'Excessive iteration on AI output — possible degradation of review quality',
    threshold: 10,
  },
];

function analyzeBehavior(messages) {
  const behaviors = [];
  let userMessages = 0;
  let approvals = 0;
  let iterations = 0;

  for (const msg of messages) {
    const role = msg.role || msg.type || '';
    const content = msg.content || msg.message || msg.text || '';
    if (typeof content !== 'string') continue;
    if (!/user|human/i.test(role)) continue;
    userMessages++;

    for (const b of RISKY_BEHAVIORS) {
      if (b.re.test(content)) {
        if (b.id === 'behavior.blind-approval') approvals++;
        if (b.id === 'behavior.excessive-iter') iterations++;
        if (b.id === 'behavior.excessive-iter' && iterations < (b.threshold || 10)) continue;
        behaviors.push({
          id: b.id,
          risk: b.risk,
          message: b.desc,
          snippet: content.slice(0, 200),
        });
      }
    }
  }

  const delegationRatio = userMessages > 0 ? approvals / userMessages : 0;
  const risk = delegationRatio > 0.6 ? 'high' : delegationRatio > 0.3 ? 'medium' : 'low';

  return {
    totalUserMessages: userMessages,
    approvals,
    iterations,
    delegationRatio: Math.round(delegationRatio * 100) / 100,
    risk,
    behaviors,
    recommendation:
      risk === 'high'
        ? 'High blind-approval ratio — review AI suggestions more carefully before accepting'
        : risk === 'medium'
        ? 'Moderate delegation — ensure each AI suggestion is reviewed'
        : 'Good review discipline — keep validating AI output',
  };
}

function traceFindingsToPrompts(findings, sessions) {
  const traces = [];
  for (const f of findings) {
    const matching = [];
    for (const session of sessions) {
      for (const msg of session.messages) {
        const content = msg.content || msg.message || '';
        if (typeof content !== 'string') continue;
        const snippet = f.snippet || '';
        if (snippet && content.includes(snippet.slice(0, 30))) {
          matching.push({ file: session.file, role: msg.role, snippet: content.slice(0, 200) });
        }
        const titleWords = (f.title || '').split(/\s+/).filter((w) => w.length > 4);
        if (titleWords.length > 0 && titleWords.every((w) => content.toLowerCase().includes(w.toLowerCase()))) {
          matching.push({ file: session.file, role: msg.role, snippet: content.slice(0, 200) });
        }
      }
    }
    if (matching.length > 0) {
      traces.push({ finding: f.ruleId, file: f.file, line: f.line, matches: matching });
    }
  }
  return traces;
}

function trace(root, findings) {
  const sessionFiles = findSessionFiles(root);
  if (sessionFiles.length === 0) {
    return { sessions: 0, behavior: null, traces: [] };
  }

  const sessions = sessionFiles.map(parseSession);
  const behavior = analyzeBehavior(sessions.flatMap((s) => s.messages));
  const traces = traceFindingsToPrompts(findings, sessions);

  return { sessions: sessions.length, behavior, traces };
}

module.exports = { trace, analyzeBehavior, findSessionFiles, parseSession, RISKY_BEHAVIORS };
