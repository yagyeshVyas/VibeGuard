'use strict';

/*
 * Opt-in live-key verification (`--verify-keys`).
 *
 * For a few providers, confirm whether a found key is ACTIVE by making a cheap,
 * read-only API call. This turns "looks like a secret" into "confirmed live
 * secret" — the difference between a warning and an emergency.
 *
 * SECURITY / PRIVACY: this sends the key to the provider that already owns it
 * (nowhere else). It is OFF by default and only runs on explicit --verify-keys.
 * Findings store a redacted snippet, so we re-read the file to get the raw value.
 */

const fs = require('fs');
const path = require('path');

// ruleId -> { extract regex, verify(key) -> Promise<'live'|'inactive'|'unknown'> }
const PROVIDERS = {
  'secret.openai-key': {
    extract: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{20,}\b/,
    async verify(key) {
      return probe('https://api.openai.com/v1/models', { authorization: `Bearer ${key}` });
    },
  },
  'secret.stripe-live-key': {
    extract: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/,
    async verify(key) {
      return probe('https://api.stripe.com/v1/balance', { authorization: `Bearer ${key}` });
    },
  },
};

async function probe(url, headers) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch(url, { headers, signal: controller.signal });
    clearTimeout(t);
    if (res.status === 200) return 'live';
    if (res.status === 401 || res.status === 403) return 'inactive';
    return 'unknown';
  } catch {
    clearTimeout(t);
    return 'unknown';
  }
}

function extractRaw(root, finding, re) {
  try {
    const lines = fs.readFileSync(path.join(root, finding.file), 'utf8').split(/\r?\n/);
    const line = lines[finding.line - 1] || '';
    const m = re.exec(line);
    return m ? m[0] : null;
  } catch {
    return null;
  }
}

// Annotate findings in place with a `verified` field. Returns the count of live keys.
async function verifyKeys(root, findings) {
  let liveCount = 0;
  const tasks = [];
  for (const f of findings) {
    const provider = PROVIDERS[f.ruleId];
    if (!provider) continue;
    const raw = extractRaw(root, f, provider.extract);
    if (!raw) {
      f.verified = 'unknown';
      continue;
    }
    tasks.push(
      provider.verify(raw).then((status) => {
        f.verified = status;
        if (status === 'live') {
          liveCount++;
          f.message = 'CONFIRMED LIVE — ' + f.message;
          f.severity = 'critical';
        }
      })
    );
  }
  await Promise.all(tasks);
  return liveCount;
}

module.exports = { verifyKeys, PROVIDERS };
