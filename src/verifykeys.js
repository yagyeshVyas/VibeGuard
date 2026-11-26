'use strict';

/*
 * Opt-in live-key verification (`--verify-keys`).
 *
 * For a set of providers, confirm whether a found key is ACTIVE by making a
 * cheap, read-only API call. This turns "looks like a secret" into "confirmed
 * live secret" — the difference between a warning and an emergency.
 *
 * SECURITY / PRIVACY: this sends the key to the provider that already owns it
 * (nowhere else). It is OFF by default and only runs on explicit --verify-keys.
 * Findings store a redacted snippet, so we re-read the file to get the raw value.
 *
 * Providers are grouped by the credential's own "who am I" endpoint: a 200 means
 * the credential is live, 401/403 means revoked/invalid. Anything else is
 * reported as unknown rather than guessed.
 */

const fs = require('fs');
const path = require('path');

async function probe(url, headers, opts = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch(url, {
      method: opts.method || 'GET',
      headers,
      body: opts.body,
      signal: controller.signal,
    });
    clearTimeout(t);
    if (opts.expectJson) {
      // Slack-style APIs answer 200 for both live and dead tokens.
      const data = await res.json().catch(() => null);
      if (!data) return res.status === 200 ? 'unknown' : res.status === 401 || res.status === 403 ? 'inactive' : 'unknown';
      if (data.ok === true) return 'live';
      if (data.ok === false) return 'inactive';
    }
    if (res.status === 200) return 'live';
    if (res.status === 401 || res.status === 403) return 'inactive';
    return 'unknown';
  } catch {
    clearTimeout(t);
    return 'unknown';
  }
}

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
  'secret.github-token': {
    extract: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/,
    async verify(key) {
      return probe('https://api.github.com/user', {
        authorization: `Bearer ${key}`,
        'user-agent': 'VibeGuard-verify',
        accept: 'application/vnd.github+json',
      });
    },
  },
  'secret.gitlab-token': {
    extract: /\bglpat-[A-Za-z0-9_-]{20,}\b/,
    async verify(key) {
      return probe('https://gitlab.com/api/v4/user', { 'private-token': key });
    },
  },
  'secret.gitlab-pat': {
    extract: /\bglpat-[A-Za-z0-9_-]{20,}\b/,
    async verify(key) {
      return probe('https://gitlab.com/api/v4/user', { 'private-token': key });
    },
  },
  'secret.slack-token': {
    extract: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
    async verify(key) {
      return probe('https://slack.com/api/auth.test', {
        authorization: `Bearer ${key}`,
        'content-type': 'application/x-www-form-urlencoded',
      }, { method: 'POST', body: '', expectJson: true });
    },
  },
  'secret.sendgrid-key': {
    extract: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/,
    async verify(key) {
      return probe('https://api.sendgrid.com/v3/scopes', { authorization: `Bearer ${key}` });
    },
  },
  'secret.mailgun-key': {
    extract: /\bkey-[a-z0-9]{32}\b/,
    async verify(key) {
      const auth = Buffer.from(`api:${key}`).toString('base64');
      return probe('https://api.mailgun.net/v3/domains?limit=1', { authorization: `Basic ${auth}` });
    },
  },
  'secret.npm-token': {
    extract: /\bnpm_[A-Za-z0-9]{36}\b/,
    async verify(key) {
      return probe('https://registry.npmjs.org/-/whoami', { authorization: `Bearer ${key}` });
    },
  },
  'secret.telegram-bot-token': {
    extract: /\b\d{8,10}:[A-Za-z0-9_-]{30,}\b/,
    async verify(key) {
      return probe(`https://api.telegram.org/bot${key}/getMe`, {});
    },
  },
  'secret.digitalocean-token': {
    extract: /\bdop_v1_[a-f0-9]{64}\b/,
    async verify(key) {
      return probe('https://api.digitalocean.com/v2/account', { authorization: `Bearer ${key}` });
    },
  },
  'secret.heroku-api-key': {
    extract: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/,
    async verify(key) {
      return probe('https://api.heroku.com/account', {
        authorization: `Bearer ${key}`,
        accept: 'application/vnd.heroku+json; version=3',
      });
    },
  },
};

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
    // Multiple rule ids can describe the same credential family (gitlab-token /
    // gitlab-pat); resolve through the provider table, then re-extract with it.
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

module.exports = { verifyKeys, PROVIDERS, probe };
