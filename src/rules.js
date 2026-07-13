'use strict';

/*
 * Detection rules for VibeGuard.
 *
 * Design goals (in order): low false positives, well-defined matches, clear fixes.
 * Every rule is deliberately narrow. We would rather MISS a fuzzy case than cry
 * wolf on a safe one — noise is what makes people uninstall a scanner.
 *
 * Two kinds of rules:
 *   - lineRules:   run per line of every scanned file. Return matches with a column.
 *   - projectRules: run once over the whole project (see scanner.js for wiring).
 *
 * Severity: 'critical' | 'high' | 'medium' | 'low'
 */

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// A line that is purely a comment (used to skip code-pattern rules, NOT secrets —
// a leaked key inside a comment is still a leaked key).
function isCommentLine(line) {
  const t = line.trim();
  return (
    t.startsWith('//') ||
    t.startsWith('#') ||
    t.startsWith('*') ||
    t.startsWith('/*')
  );
}

// Obvious placeholder / non-secret values. Keeps generic secret rule quiet on
// templates like `password = "your_password_here"` or env interpolation.
const PLACEHOLDER_RE =
  /^(x{3,}|changeme|your[_-]?|example|placeholder|dummy|test|sample|\.\.\.|<|\{\{|\$\{|process\.env|import\.meta|os\.environ|todo|none|null|undefined|redacted|\*{3,})/i;

function looksLikePlaceholder(value) {
  if (!value) return true;
  const v = value.trim();
  if (v.length < 6) return true;
  if (PLACEHOLDER_RE.test(v)) return true;
  // Contains an env-var reference anywhere.
  if (/\$\{|process\.env|import\.meta\.env|os\.environ/.test(v)) return true;
  return false;
}

// BaaS keys that are DESIGNED to be public. Never flag these as secrets.
// Firebase web apiKey (AIza...) and Supabase / PostgREST anon keys.
function isPublicBaaSKey(fullLine, value) {
  // Firebase browser API key.
  if (/AIza[0-9A-Za-z\-_]{20,}/.test(value)) return true;
  // Named as an anon / public / publishable key on the same line.
  if (/\b(anon|public|publishable|NEXT_PUBLIC|VITE_|REACT_APP_)\w*\s*[:=]/i.test(fullLine)) {
    return true;
  }
  // Supabase anon key naming.
  if (/supabase\w*anon|anon\w*key/i.test(fullLine)) return true;
  return false;
}

// Build a fix-prompt-friendly one-liner.
function makeFinding(rule, opts) {
  // Confidence derivation:
  //   - If opts or rule explicitly sets confidence, keep it (taint=high, etc.).
  //   - Rules with a filter() function are multi-signal => medium.
  //   - Bare regex rules with no filter => low.
  let conf = opts.confidence || rule.confidence;
  if (!conf) {
    conf = typeof rule.filter === 'function' ? 'medium' : 'low';
  }
  return {
    ruleId: opts.ruleId || rule.id,
    severity: opts.severity || rule.severity,
    confidence: conf,
    title: opts.title || rule.title,
    message: opts.message || rule.message,
    fix: opts.fix || rule.fix,
    file: opts.file,
    line: opts.line,
    column: opts.column,
    snippet: opts.snippet,
  };
}

// Compiling a fresh global RegExp per call was the scanner's hot path — with
// hundreds of rules run against every line it meant millions of RegExp
// recompilations (≈64% of total scan time). Memoize the global-flag clone per
// source regex so each rule's regex is compiled once, not once per line.
// Extract a lowercase literal substring that MUST appear in any line the regex
// can match, so the scanner can cheaply `line.includes(lit)` and skip the rule
// entirely when it's absent. Provably safe (never causes a false negative):
//   - bails on alternation (`|`) — a literal in one branch isn't mandatory;
//   - only trusts depth-0 literals (outside any group, which could be optional);
//   - drops any char made optional by `?`, `*`, or `{0,...}`.
// Lowercasing is safe for case-sensitive rules too: it can only make the filter
// *less* aggressive (never skip a line the real regex would have matched).
function requiredLiteral(source) {
  if (source.includes('|')) return null;
  let best = '';
  let cur = '';
  let depth = 0;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (c === '\\') { cur = ''; i++; continue; } // escape → separator
    if (c === '(') { depth++; cur = ''; continue; }
    if (c === ')') { depth--; cur = ''; continue; }
    if (c === '[') { // char class → skip to matching ]
      cur = '';
      i++;
      while (i < source.length && source[i] !== ']') { if (source[i] === '\\') i++; i++; }
      continue;
    }
    if (depth > 0) { cur = ''; continue; }
    if (/[a-zA-Z0-9]/.test(c)) {
      const next = source[i + 1];
      if (next === '?' || next === '*') { cur = ''; continue; } // optional char
      if (next === '{' && /^\{0\b/.test(source.slice(i + 1))) { cur = ''; continue; }
      cur += c.toLowerCase();
      if (cur.length > best.length) best = cur;
    } else {
      cur = '';
    }
  }
  return best.length >= 4 ? best : null;
}

const GLOBAL_RE_CACHE = new WeakMap();
function globalOf(re) {
  let g = GLOBAL_RE_CACHE.get(re);
  if (!g) {
    g = re.flags.includes('g') ? re : new RegExp(re.source, re.flags + 'g');
    GLOBAL_RE_CACHE.set(re, g);
  }
  return g;
}

// Scan a single line with a global regex, yielding one match object per hit.
function* matchAll(re, line) {
  const g = globalOf(re);
  g.lastIndex = 0; // reset — cached instances are reused across lines
  let m;
  while ((m = g.exec(line)) !== null) {
    yield { index: m.index, match: m[0], groups: m };
    if (m.index === g.lastIndex) g.lastIndex++; // avoid zero-width loop
  }
}

// ---------------------------------------------------------------------------
// Secret rules (severity: critical)
// ---------------------------------------------------------------------------

const secretRules = [
  {
    id: 'secret.github-token',
    severity: 'critical',
    confidence: 'high',
    title: 'GitHub token',
    re: /\bgh[posur]_[A-Za-z0-9]{36,}\b/,
    message: 'Hardcoded GitHub token (personal access / OAuth / app token).',
    fix: 'Remove it, load from an environment variable, and revoke it in GitHub settings.',
  },
  {
    id: 'secret.slack-token',
    severity: 'critical',
    confidence: 'high',
    title: 'Slack token',
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
    message: 'Hardcoded Slack token.',
    fix: 'Remove it, load from an environment variable, and rotate it in the Slack app settings.',
  },
  {
    id: 'secret.gitlab-token',
    severity: 'critical',
    confidence: 'high',
    title: 'GitLab personal access token',
    re: /\bglpat-[A-Za-z0-9_\-]{20,}\b/,
    message: 'Hardcoded GitLab personal access token.',
    fix: 'Remove it, load from an environment variable, and revoke it in GitLab.',
  },
  {
    id: 'secret.twilio-key',
    severity: 'critical',
    confidence: 'high',
    title: 'Twilio API key',
    re: /\bSK[0-9a-f]{32}\b/,
    message: 'Hardcoded Twilio API key.',
    fix: 'Remove it, load from an environment variable, and rotate it in the Twilio console.',
  },
  {
    id: 'secret.sendgrid-key',
    severity: 'critical',
    confidence: 'high',
    title: 'SendGrid API key',
    re: /\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b/,
    message: 'Hardcoded SendGrid API key.',
    fix: 'Remove it, load from an environment variable, and rotate it in SendGrid.',
  },
  {
    id: 'secret.mailgun-key',
    severity: 'critical',
    confidence: 'high',
    title: 'Mailgun API key',
    re: /\bkey-[0-9a-f]{32}\b/,
    message: 'Hardcoded Mailgun API key.',
    fix: 'Remove it, load from an environment variable, and rotate it in Mailgun.',
  },
  {
    id: 'secret.telegram-bot-token',
    severity: 'critical',
    confidence: 'high',
    title: 'Telegram bot token',
    re: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/,
    message: 'Hardcoded Telegram bot token.',
    fix: 'Remove it, load from an environment variable, and revoke it via BotFather.',
  },
  {
    id: 'secret.npm-token',
    severity: 'critical',
    confidence: 'high',
    title: 'npm access token',
    re: /\bnpm_[A-Za-z0-9]{36}\b/,
    message: 'Hardcoded npm access token (also flagged in .npmrc).',
    fix: 'Remove it, use an environment variable / CI secret, and revoke it on npmjs.com.',
  },
  {
    id: 'secret.resend-key',
    severity: 'critical',
    confidence: 'high',
    title: 'Resend API key',
    re: /\bre_[A-Za-z0-9]{20,}\b/,
    message: 'Hardcoded Resend API key.',
    fix: 'Remove it, load from an environment variable, and rotate it in Resend.',
    filter(line) {
      // Avoid matching words like "re_export" / "re_run" — require it look like a token.
      return !/\bre_(?:export|run|try|use|new|set|get|map|do)\b/i.test(line);
    },
  },
  {
    id: 'secret.connection-string',
    severity: 'critical',
    confidence: 'high',
    title: 'Connection string with embedded credentials',
    re: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|amqps?):\/\/[^\s:@/]+:[^\s:@/]+@/,
    message: 'A database/broker connection string embeds a username and password.',
    fix: 'Load the connection string from an environment variable; never commit credentials.',
    filter(line, m) {
      // Ignore obvious placeholders like user:pass@ / user:password@host.
      return !/:\/\/(?:user|username|root|admin):(?:pass|password|changeme|xxx+|\.\.\.)@/i.test(m.match);
    },
  },
  {
    id: 'secret.public-llm-key',
    severity: 'critical',
    confidence: 'high',
    title: 'AI/secret key exposed to the browser via a public env prefix',
    // NEXT_PUBLIC_/VITE_/EXPO_PUBLIC_ on an LLM provider key or anything named *SECRET*.
    re: /\b(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|PUBLIC_)[A-Z0-9_]*(?:OPENAI|ANTHROPIC|GROQ|MISTRAL|COHERE|GEMINI|HUGGINGFACE|REPLICATE|TOGETHER|OPENROUTER|PERPLEXITY|DEEPSEEK)[A-Z0-9_]*|\b(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_)[A-Z0-9_]*SECRET[A-Z0-9_]*/i,
    message: 'A public env prefix exposes an AI provider key or a secret to the browser bundle — anyone can read it.',
    fix: 'Move this to a server-only env var (no NEXT_PUBLIC_/VITE_/EXPO_PUBLIC_ prefix) and rotate the key.',
  },
  {
    id: 'secret.anthropic-key',
    severity: 'critical',
    title: 'Anthropic API key',
    // Must be checked before the OpenAI rule (sk- prefix overlap).
    re: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/,
    message: 'Hardcoded Anthropic API key.',
    fix: 'Move the key to an environment variable (e.g. process.env.ANTHROPIC_API_KEY) and rotate the exposed key immediately.',
  },
  {
    id: 'secret.openai-key',
    severity: 'critical',
    title: 'OpenAI API key',
    // sk- or sk-proj-, but NOT sk-ant- (Anthropic) and NOT sk_live_ (Stripe uses _).
    re: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{20,}\b/,
    message: 'Hardcoded OpenAI API key.',
    fix: 'Move the key to an environment variable (e.g. process.env.OPENAI_API_KEY) and rotate the exposed key immediately.',
  },
  {
    id: 'secret.stripe-live-key',
    severity: 'critical',
    title: 'Stripe live secret key',
    re: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/,
    message: 'Hardcoded Stripe LIVE secret key. This can move real money.',
    fix: 'Remove the key, load it from process.env.STRIPE_SECRET_KEY, and roll it in the Stripe dashboard now.',
  },
  {
    id: 'secret.aws-access-key',
    severity: 'critical',
    title: 'AWS access key id',
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
    message: 'Hardcoded AWS access key id.',
    fix: 'Remove it, use an IAM role or environment variables, and deactivate/rotate the key in AWS IAM.',
  },
  {
    id: 'secret.private-key',
    severity: 'critical',
    title: 'Private key block',
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
    message: 'Private key material committed in source.',
    fix: 'Delete the key from the repo, store it in a secrets manager, and treat it as compromised (rotate it).',
  },
  {
    id: 'secret.generic-credential',
    severity: 'critical',
    title: 'Hardcoded credential',
    // key = "value" style. We post-filter for placeholders and public BaaS keys.
    re: /\b(password|passwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*['"]([^'"]{6,})['"]/i,
    message: 'Looks like a hardcoded credential.',
    fix: 'Load this from an environment variable instead of embedding it in code, and rotate it if it was ever real.',
    filter(line, m) {
      const value = m.groups[2];
      if (looksLikePlaceholder(value)) return false;
      if (isPublicBaaSKey(line, value)) return false;
      return true;
    },
  },
];

// ---------------------------------------------------------------------------
// Code rules
// ---------------------------------------------------------------------------

const codeRules = [
  {
    id: 'code.eval',
    severity: 'high',
    title: 'eval() usage',
    re: /\beval\s*\(/,
    skipComments: true,
    skipInString: true, // an eval() inside a quoted string is text, not a call
    message: 'eval() executes arbitrary code and is a common injection vector.',
    fix: 'Remove eval(). Use JSON.parse for data, a lookup object for dynamic dispatch, or a real parser.',
  },
  {
    id: 'code.command-injection',
    severity: 'high',
    title: 'Shell command built from variables',
    // exec/execSync/spawn(...) whose argument uses a template with ${...} or string + concat.
    re: /\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+|[A-Za-z_$][\w$]*\s*\+)/,
    skipComments: true,
    message: 'Shell command is assembled from variables — command injection risk.',
    fix: 'Pass arguments as an array (execFile("cmd", [arg1, arg2])) instead of interpolating into a shell string. Validate/allowlist inputs.',
  },
  {
    id: 'code.sql-injection',
    severity: 'high',
    title: 'SQL built by string concatenation',
    // Candidate detection: a SQL verb followed later on the line by either a
    // template interpolation (${) or a string+concat. The filter below then
    // confirms the string is REAL SQL (verb+clause), not English prose like
    // "FROM: " + email or "Delete from list: " + item.
    re: /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[\s\S]*?(?:`[^`]*\$\{|['"]\s*\+|\+\s*['"])/i,
    skipComments: true,
    fileFilter: /\.(?:js|ts|jsx|tsx|rb|php)$/,
    message: 'SQL query is built by string concatenation/interpolation — SQL injection risk.',
    fix: 'Use parameterized queries / prepared statements (e.g. db.query("... WHERE id = $1", [id])) instead of building the string.',
    filter(line) {
      // Require a genuine SQL statement shape. Each verb must pair with the
      // clause it always has in real queries, which prose almost never does.
      const isSql =
        /\bSELECT\b[\s\S]*\bFROM\b/i.test(line) ||
        /\bINSERT\s+INTO\b[\s\S]*(?:\bVALUES\b|\()/i.test(line) ||
        /\bUPDATE\b[\s\S]*\bSET\b/i.test(line) ||
        /\bDELETE\s+FROM\b[\s\S]*\bWHERE\b/i.test(line);
      if (!isSql) return false;
      // And the interpolation must land in a value position (after WHERE/SET/
      // VALUES/LIKE/IN/an operator), which is where injection actually happens.
      const injects =
        /(?:WHERE|SET|VALUES|LIKE|IN|=|<|>)[^;]*?(?:`[^`]*\$\{|['"]\s*\+|\+\s*['"])/i.test(
          line
        );
      return injects;
    },
  },
  {
    id: 'code.cors-wildcard',
    severity: 'medium',
    title: 'CORS allows any origin',
    re: /(?:origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"])/i,
    skipComments: true,
    message: 'CORS is set to "*", allowing any website to call this API.',
    fix: 'Restrict origin to an explicit allowlist of your own domains instead of "*".',
  },
  {
    id: 'code.insecure-http',
    severity: 'low',
    title: 'Plain http:// URL',
    // External http URLs only — localhost / loopback are fine for dev.
    re: /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[A-Za-z0-9.-]+/,
    skipComments: false,
    message: 'Plain http:// URL — traffic is unencrypted and can be intercepted.',
    fix: 'Use https:// for external URLs.',
    filter(line) {
      // Skip XML namespaces / schema URLs which are identifiers, not requests.
      return !/xmlns|w3\.org|schemas?\.|\.dtd|\.xsd/i.test(line);
    },
  },
];

// ---------------------------------------------------------------------------
// Auth / access-control rules (Phase 2)
// ---------------------------------------------------------------------------

const WEAK_SECRET_RE = /^(?:secret|secretkey|keyboard cat|changeme|change[_-]?me|password|passwd|123456|test|dev|mysecret|supersecret|topsecret|shhh+|admin|token|jwt|s3cr3t)$/i;

const authRules = [
  {
    id: 'auth.weak-session-secret',
    severity: 'high',
    confidence: 'high',
    title: 'Hardcoded / weak session secret',
    // session({ secret: '...' }) or cookieSession({ secret: '...' }) with a string literal.
    re: /(?:session|cookieSession|cookie-session)\s*\(\s*\{[\s\S]{0,200}?secret\s*:\s*['"]([^'"]+)['"]/i,
    skipComments: true,
    message: 'Session secret is a hardcoded string literal — sessions can be forged.',
    fix: 'Load the session secret from an environment variable and use a long random value (openssl rand -hex 32).',
    filter(line, m) {
      const v = m.groups[1];
      // A hardcoded literal here is always wrong (should be env). We still show
      // the weak-value note when it is also short/obvious.
      return !looksLikePlaceholder(v) || WEAK_SECRET_RE.test(v.trim()) || v.length < 16;
    },
  },
  {
    id: 'auth.hardcoded-jwt-secret',
    severity: 'high',
    confidence: 'high',
    title: 'Hardcoded JWT secret',
    // jwt.sign(payload, 'literal-secret', ...) / jwt.verify(token, 'literal')
    re: /\bjwt\.(?:sign|verify)\s*\([^,)]+,\s*['"]([^'"]{3,})['"]/i,
    skipComments: true,
    message: 'JWT secret is hardcoded in source — anyone with the code can mint valid tokens.',
    fix: 'Move the JWT secret to an environment variable (process.env.JWT_SECRET) and rotate it.',
    filter(line, m) {
      return !looksLikePlaceholder(m.groups[1]);
    },
  },
  {
    id: 'auth.idor-direct-object-ref',
    severity: 'high',
    confidence: 'low', // heuristic — presented as "review", not a verdict
    title: 'Possible IDOR — request id used in query without an ownership check',
    // A lookup/mutation call that passes req.params/query/body.<id> straight in.
    re: /\b(?:findById|findByPk|findOne|findUnique|deleteOne|updateOne|update|delete|get|query)\s*\([^)]*\breq\.(?:params|query|body)\.([A-Za-z_$][\w$]*)/,
    skipComments: true,
    message:
      'A record id from the request is used directly in a data lookup. Confirm the record belongs to the current user (an IDOR lets users read/modify others’ data).',
    fix: 'Scope the query to the authenticated user, e.g. Model.findOne({ id, ownerId: req.user.id }), or verify ownership after loading.',
    filter(line, m) {
      // Skip if an ownership/tenant signal is already on the line.
      if (/req\.user|userId|owner|tenant|req\.session\.user|accountId/i.test(line)) return false;
      // Only flag when the field looks like an identifier.
      const field = m.groups[1];
      return /(^id$|Id$|uuid|_id|pk$|slug$|key$)/.test(field) || /findById|findByPk/.test(line);
    },
  },
  {
    id: 'auth.missing-route-auth',
    severity: 'medium',
    confidence: 'low',
    title: 'Mutating route with an inline handler and no visible auth middleware',
    // app.post('/x', (req,res)=>...) — handler directly after the path, no middleware arg.
    re: /\bapp\.(?:post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]\s*,\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)/i,
    skipComments: true,
    message:
      'This route mutates data but has no middleware between the path and the handler. Confirm authentication/authorization is enforced (inside the handler or via a global guard).',
    fix: 'Add an auth middleware (e.g. app.post("/x", requireAuth, handler)) or verify req.user inside the handler before mutating.',
    filter(line, m) {
      const routePath = (m.groups[1] || '').toLowerCase();
      // Public endpoints legitimately have no auth.
      if (/login|signin|sign-in|signup|sign-up|register|logout|webhook|health|healthz|ping|public|oauth|callback|csp-report/.test(routePath)) {
        return false;
      }
      return true;
    },
  },
  {
    id: 'supabase.service-role-public',
    severity: 'critical',
    confidence: 'high',
    title: 'Supabase service_role key exposed to the browser',
    // NEXT_PUBLIC_/VITE_/REACT_APP_ prefix on a service-role key ships it to the
    // client, where it BYPASSES row-level security entirely.
    re: /\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_)[A-Z0-9_]*SERVICE_ROLE[A-Z0-9_]*/i,
    skipComments: false,
    message:
      'A Supabase service_role key is exposed to the browser via a public env prefix. The service role bypasses row-level security — anyone can read/write all data.',
    fix: 'Never expose the service_role key client-side. Use the anon key in the browser (with RLS), and keep service_role server-only (no NEXT_PUBLIC_/VITE_ prefix).',
  },
  {
    id: 'upload.path-traversal',
    severity: 'high',
    confidence: 'medium',
    title: 'User-controlled value used in a filesystem path',
    // path.join/resolve or fs.* with req.body/params/query inside.
    re: /(?:path\.(?:join|resolve)|fs\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|unlinkSync|sendFile))\s*\([^)]*\breq\.(?:body|params|query)\.[A-Za-z_$][\w$]*/,
    skipComments: true,
    message:
      'A request value is used to build a filesystem path — path traversal (../../) can read or overwrite arbitrary files.',
    fix: 'Sanitize with path.basename(), resolve against a fixed base dir, and reject any resolved path that escapes it.',
  },
];

// ---------------------------------------------------------------------------
// Web / crypto / backdoor rules (breadth pack)
// ---------------------------------------------------------------------------

const webRules = [
  {
    id: 'web.open-redirect',
    severity: 'medium',
    confidence: 'high',
    title: 'Open redirect from user input',
    re: /\bres\.(?:redirect|location)\s*\(\s*(?:[^)]*,\s*)?[^)]*\breq\.(?:query|params|body|headers)\.[A-Za-z_$][\w$]*/,
    skipComments: true,
    message: 'A redirect target comes straight from the request — open redirect (used for phishing).',
    fix: 'Redirect only to an allowlist of internal paths; reject absolute/off-site URLs from user input.',
  },
  {
    id: 'web.ssrf',
    severity: 'high',
    confidence: 'medium',
    title: 'Possible SSRF — outbound request to a user-supplied URL',
    re: /\b(?:fetch|got|superagent)\s*\(\s*[^)]*\breq\.(?:query|params|body|headers)\.|axios(?:\.(?:get|post|put|delete))?\s*\(\s*[^)]*\breq\.(?:query|params|body|headers)\.|https?\.get\s*\(\s*[^)]*\breq\.(?:query|params|body|headers)\./,
    skipComments: true,
    message: 'An outbound request targets a URL built from user input — server-side request forgery (SSRF).',
    fix: 'Allowlist permitted hosts/schemes; block internal/metadata IPs (169.254.169.254, localhost, private ranges).',
  },
  {
    id: 'auth.jwt-alg-none',
    severity: 'critical',
    confidence: 'high',
    title: 'JWT verification accepts the "none" algorithm',
    re: /algorithms?\s*:\s*\[[^\]]*['"]none['"]|['"]alg['"]\s*:\s*['"]none['"]|\.verify\([^)]*none/i,
    skipComments: true,
    message: 'JWT config allows the "none" algorithm — tokens can be forged with no signature.',
    fix: 'Pin an explicit algorithm allowlist (e.g. algorithms: ["HS256"]) and never accept "none".',
  },
  {
    id: 'crypto.weak-hash',
    severity: 'medium',
    confidence: 'medium',
    title: 'Weak hash for credentials',
    // md5/sha1 are unsuitable for passwords/tokens.
    re: /createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)|\b(?:md5|sha1)\s*\(/i,
    skipComments: true,
    message: 'MD5/SHA-1 is used — unsafe for passwords or security tokens (fast to brute-force / broken).',
    fix: 'For passwords use bcrypt/scrypt/argon2. For integrity use SHA-256+. (Ignore if this hash is non-security, e.g. a cache key.)',
  },
  {
    id: 'crypto.insecure-random',
    severity: 'medium',
    confidence: 'low',
    title: 'Insecure randomness for a secret/token',
    // Math.random() used to build something security-sensitive on the same line.
    re: /\b(?:token|secret|otp|nonce|salt|session|password|apikey|api_key|reset|verify)\w*\s*[:=][^;\n]*Math\.random\s*\(|Math\.random\s*\([^;\n]*(?:token|secret|otp|nonce|salt|session|password)/i,
    skipComments: true,
    message: 'Math.random() is not cryptographically secure — predictable tokens/secrets can be guessed.',
    fix: 'Use crypto.randomBytes()/crypto.randomUUID() (Node) or crypto.getRandomValues() (browser) for anything secret.',
  },
  {
    id: 'backdoor.hardcoded-comparison',
    severity: 'high',
    confidence: 'low',
    title: 'Credential compared to a hardcoded literal (possible backdoor / weak check)',
    // e.g. if (password === 'letmein') / token == "backdoor"
    re: /\b(?:password|passwd|pass|token|apikey|api_key|secret|auth|role|isAdmin|admin)\b\s*===?\s*['"][^'"]{2,}['"]/i,
    skipComments: true,
    message:
      'A credential/role is compared against a hardcoded string. This is a common backdoor or a check that should hit a real store — verify it is intentional.',
    fix: 'Compare against hashed values in your data store (constant-time compare for secrets). Remove any hardcoded bypass.',
    filter(line) {
      // Skip obvious test/enum comparisons and env-driven values.
      if (/process\.env|test|expect\(|assert|describe\(|it\(/i.test(line)) return false;
      // role/isAdmin compared to 'admin'/'user' is often legit RBAC — require a
      // secret-ish left side OR a suspicious literal for those.
      if (/\b(?:role|isAdmin|admin)\b/i.test(line) && !/(letmein|backdoor|god|secret|bypass|master|root)/i.test(line)) {
        return false;
      }
      return true;
    },
  },
];

// ---------------------------------------------------------------------------
// PII / sensitive-data leak rules
// ---------------------------------------------------------------------------
// These are the "data leak" checks vibe coders expect: secrets/PII written to
// logs, or personal data returned to the client. Heuristic and property-access
// oriented to keep false positives down; most are "review" confidence.

// Fields that are secrets/credentials — high value if they leak.
const SECRET_FIELD = 'password|passwd|pwd|passwordhash|password_hash|secret|token|apikey|api_key|access_token|refresh_token|private_key|session_secret';
// Personal data — sensitive but noisier, so lower confidence.
const PII_FIELD = 'ssn|social_security|creditcard|credit_card|card_number|cardnumber|cvv|cvc|passport|dob|date_of_birth|bank_account|routing_number';

// Functions that deliberately shape/redact data. If a value passes through one,
// the leak warning is suppressed. Teams can extend this list via a config file
// (.vibeguardrc.json { "shapingFunctions": ["toDTO", ...] }) — see configure().
const BASE_SHAPING = [
  'redact', 'omit', 'pick', 'sanitize', 'scrub', 'mask', 'obfuscate',
  'toSafe\\w*', 'toPublic\\w*', 'serialize\\w*', 'toJSON', 'select', 'only', 'except',
];
let extraShaping = [];

function buildRedactRe() {
  return new RegExp('\\b(?:' + [...BASE_SHAPING, ...extraShaping].join('|') + ')\\s*\\(', 'i');
}
// Reassigned by configure(); closures below read the current value.
let REDACT_RE = buildRedactRe();

// Called by the scanner with the project's config (or resets to defaults).
function configure(cfg) {
  const fns = (cfg && Array.isArray(cfg.shapingFunctions) ? cfg.shapingFunctions : [])
    .filter((s) => typeof s === 'string' && /^[\w\\*]+$/.test(s));
  extraShaping = fns;
  REDACT_RE = buildRedactRe();
}

function isRedacted(line) {
  return REDACT_RE.test(line);
}
function notRedacted(line) {
  return !REDACT_RE.test(line);
}

// Extract the balanced argument string of a call whose opening '(' is at
// openIdx. Skips parens inside string literals. Returns null if the call spans
// multiple lines (unbalanced on this line) — we don't try to analyze those.
function balancedArgs(line, openIdx) {
  let depth = 0;
  let quote = null;
  for (let i = openIdx; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === '\\') i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') quote = c;
    else if (c === '(') depth++;
    else if (c === ')') {
      depth--;
      if (depth === 0) return line.slice(openIdx + 1, i);
    }
  }
  return null;
}

// Filter factory: from the sink opener match, pull the FULL balanced argument
// expression (handles nested calls like console.log(fn(x).password)), then keep
// the finding only if a sensitive field appears AND the args aren't redacted.
function leakFilter(fieldRe) {
  return (line, hit) => {
    const open = hit.index + hit.match.length - 1; // index of '(' in the opener
    const args = balancedArgs(line, open);
    if (args == null) return false; // multi-line call — skip
    if (!fieldRe.test(args)) return false;
    if (isRedacted(args)) return false;
    return true;
  };
}

const LOG_SINK = /\b(?:console\.(?:log|info|debug|warn|error)|logger\.\w+|log\.\w+|print|println|fmt\.Print\w*|System\.out\.print\w*)\s*\(/i;
const RES_SINK = /\bres\.(?:json|send|write|end)\s*\(/i;

const piiRules = [
  {
    id: 'pii.secret-in-log',
    severity: 'high',
    confidence: 'medium',
    title: 'Secret written to logs',
    re: LOG_SINK,
    skipComments: true,
    message: 'A secret/credential is written to logs. Logs get shipped to files, consoles, and log aggregators — this leaks it.',
    fix: 'Never log secrets. Redact the field or log only a non-sensitive identifier.',
    filter: leakFilter(new RegExp(`\\.(?:${SECRET_FIELD})\\b`, 'i')),
  },
  {
    id: 'pii.personal-data-in-log',
    severity: 'medium',
    confidence: 'low',
    title: 'Personal data written to logs',
    re: LOG_SINK,
    skipComments: true,
    message: 'Personal data (PII) is written to logs. Confirm this is intended and compliant — logs are often less protected than your DB.',
    fix: 'Avoid logging PII, or redact/hash it. Log a user id instead of the raw personal field.',
    filter: leakFilter(new RegExp(`\\.(?:email|phone|${PII_FIELD})\\b`, 'i')),
  },
  {
    id: 'pii.secret-in-response',
    severity: 'high',
    confidence: 'medium',
    title: 'Secret/credential sent in an HTTP response',
    re: RES_SINK,
    skipComments: true,
    message: 'A secret/credential field is included in an HTTP response body — it will be sent to the client.',
    fix: 'Strip secret fields before responding (select only safe fields, or delete password/token from the object).',
    filter: leakFilter(new RegExp(`\\b(?:${SECRET_FIELD})\\b`, 'i')),
  },
  {
    id: 'pii.request-body-echoed',
    severity: 'medium',
    confidence: 'low',
    title: 'Raw request body returned to the client',
    re: /\bres\.(?:json|send)\s*\(\s*req\.body\s*\)/i,
    skipComments: true,
    message: 'The raw request body is echoed back in the response. Combined with mass-assignment this can reflect or expose unintended fields.',
    fix: 'Return an explicit, allowlisted object rather than echoing req.body.',
  },
];

// ---------------------------------------------------------------------------
// Robustness pack: input validation, injection, error handling, transport
// ---------------------------------------------------------------------------

const robustnessRules = [
  {
    id: 'validation.mass-assignment',
    severity: 'high',
    confidence: 'medium',
    title: 'Mass assignment from the request body',
    // new Model(req.body) / Model.create(req.body) / Object.assign(x, req.body)
    re: /\b(?:new\s+[A-Z]\w*|(?:\w+\.)?(?:create|insertOne|insert|save|build|update|updateOne|findOneAndUpdate))\s*\(\s*req\.body\s*[),]|Object\.assign\s*\([^,]+,\s*req\.body\s*\)/,
    skipComments: true,
    message: 'The whole request body is written to a model/record. An attacker can set fields you did not intend (role, isAdmin, balance) — mass assignment.',
    fix: 'Pick an explicit allowlist of fields from req.body instead of passing it whole.',
  },
  {
    id: 'injection.nosql',
    severity: 'high',
    confidence: 'medium',
    title: 'NoSQL query built from the request',
    // Model.find(req.body) / passing req.* straight as a query, or $where operator.
    re: /\.(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|count|countDocuments)\s*\(\s*(?:req\.(?:body|query|params)\s*[)\],]|\{[^}]*req\.(?:body|query|params)\.|\{[^}]*\$where)|\$where\s*:/,
    skipComments: true,
    message: 'A database query object comes directly from the request — NoSQL/operator injection (e.g. { "$gt": "" } bypasses checks).',
    fix: 'Build the query explicitly from validated scalar fields; never pass req.body/query straight into find().',
  },
  {
    id: 'error.detail-to-client',
    severity: 'medium',
    confidence: 'medium',
    title: 'Error detail / stack trace sent to the client',
    re: /\bres\.(?:json|send|write|end|status\s*\(\s*\d+\s*\)\s*\.(?:json|send))\s*\([^)]*\b(?:err|error|e|ex)\.(?:stack|message|sqlMessage|detail)\b|\bres\.(?:json|send)\s*\(\s*(?:err|error|ex)\s*\)/,
    skipComments: true,
    message: 'An error object/stack is returned in the response. Stack traces leak file paths, library versions, and query internals to attackers.',
    fix: 'Return a generic error message + status code to the client; log the full error server-side only.',
  },
  {
    id: 'error.empty-catch',
    severity: 'low',
    confidence: 'low',
    title: 'Empty catch block swallows errors',
    re: /catch\s*(?:\([^)]*\))?\s*\{\s*\}/,
    skipComments: true,
    message: 'An error is caught and silently ignored. Failures (including security failures) become invisible.',
    fix: 'At minimum log the error; handle it explicitly or rethrow.',
  },
  {
    id: 'net.tls-verification-disabled',
    severity: 'high',
    confidence: 'high',
    title: 'TLS certificate verification disabled',
    re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0|strictSSL\s*:\s*false|verify\s*=\s*False/,
    skipComments: true,
    message: 'TLS certificate validation is turned off. Traffic can be silently intercepted (man-in-the-middle).',
    fix: 'Remove rejectUnauthorized:false / NODE_TLS_REJECT_UNAUTHORIZED=0. Trust a proper CA instead.',
  },
  {
    id: 'cookie.insecure-flags',
    severity: 'medium',
    confidence: 'low',
    title: 'Cookie set without HttpOnly/Secure',
    re: /\bres\.cookie\s*\(/,
    skipComments: true,
    message: 'A cookie is set without HttpOnly and/or Secure — exposed to theft via XSS or over plain HTTP.',
    fix: 'Set { httpOnly: true, secure: true, sameSite: "lax" } on cookies (unless JS must read it).',
    filter(line, hit) {
      const open = hit.index + hit.match.length - 1;
      const args = balancedArgs(line, open);
      if (args == null) return false;
      // Flag if HttpOnly is not present in the options.
      return !/httponly/i.test(args);
    },
  },
  {
    id: 'upload.filename-path-traversal',
    severity: 'high',
    confidence: 'medium',
    title: 'Upload filename used to build a path',
    re: /(?:path\.(?:join|resolve)|fs\.\w+|createWriteStream)\s*\([^)]*\.(?:originalname|originalName|filename|name)\b/,
    skipComments: true,
    message: 'An uploaded file name is used to build a filesystem path. A crafted name (../../) overwrites arbitrary files.',
    fix: 'Generate a random server-side filename (e.g. crypto.randomUUID()); never trust the client filename.',
    filter(line) {
      // Require an upload/file context on the line to avoid generic .name FPs.
      return /file|upload|multer|req\.file|\.originalname/i.test(line);
    },
  },
];

// ---------------------------------------------------------------------------
// Framework-aware pack (Prisma / React / Express reflected XSS)
// ---------------------------------------------------------------------------

const frameworkRules = [
  {
    id: 'prisma.raw-unsafe',
    severity: 'high',
    confidence: 'high',
    title: 'Prisma raw query built dynamically',
    // $queryRawUnsafe / $executeRawUnsafe with a template ${} or string concat.
    re: /\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+|[A-Za-z_$][\w$]*\s*\+|[^)]*\+\s*[A-Za-z_$])/,
    skipComments: true,
    message: 'Prisma $queryRawUnsafe/$executeRawUnsafe is built from a dynamic string — SQL injection (the "Unsafe" variants do not parameterize).',
    fix: 'Use $queryRaw`...${x}...` (tagged template, parameterized) or Prisma.sql with placeholders — not the Unsafe variants with concatenation.',
  },
  {
    id: 'react.dangerous-html',
    severity: 'medium',
    confidence: 'medium',
    title: 'dangerouslySetInnerHTML with dynamic content',
    // __html set to something other than a string literal.
    re: /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*(?!['"`])/,
    skipComments: true,
    message: 'dangerouslySetInnerHTML renders raw HTML from a dynamic value — stored/reflected XSS if any part is user-controlled.',
    fix: 'Render text as children (React escapes it) or sanitize with DOMPurify before setting __html.',
  },
  {
    id: 'xss.reflected-response',
    severity: 'medium',
    confidence: 'low',
    title: 'User input reflected in an HTML response',
    // res.send/write/end that interpolates req.* (res.json is safe — escaped/typed).
    re: /\bres\.(?:send|write|end)\s*\(\s*(?:`[^`]*\$\{[^}]*\breq\.(?:query|params|body)|['"][^'"]*['"]\s*\+[^)]*\breq\.(?:query|params|body)|[^)]*\breq\.(?:query|params|body)\.[A-Za-z_$][\w$]*\s*\+)/,
    skipComments: true,
    message: 'User input is concatenated into an HTML/text response — reflected XSS. res.send renders HTML; the browser will execute injected <script>.',
    fix: 'Escape/encode the value for HTML context, or return JSON (res.json) and render safely on the client.',
  },
];

// ---------------------------------------------------------------------------
// AI / LLM / MCP security pack
// ---------------------------------------------------------------------------

const aiRules = [
  {
    id: 'ai.browser-api-key',
    severity: 'critical',
    confidence: 'high',
    title: 'AI SDK configured to run in the browser',
    re: /dangerouslyAllowBrowser\s*:\s*true/,
    skipComments: true,
    message: 'dangerouslyAllowBrowser: true ships your AI provider API key to the browser, where anyone can steal it.',
    fix: 'Call the AI provider from a server route/edge function; never expose the API key client-side.',
  },
  {
    id: 'ai.disabled-sandbox',
    severity: 'high',
    confidence: 'high',
    title: 'AI agent sandbox / permission check disabled',
    re: /dangerouslyDisableSandbox\s*:\s*true|dangerouslySkipPermissions|--dangerously-skip-permissions|bypassPermissions\s*:\s*true/,
    skipComments: true,
    message: 'A sandbox or permission gate for an AI agent/tool is disabled — the model can run unrestricted actions.',
    fix: 'Keep the sandbox/permission checks on; allowlist only the specific tools/paths the agent needs.',
  },
  {
    id: 'ai.eval-llm-output',
    severity: 'high',
    confidence: 'medium',
    title: 'Executing LLM output as code',
    re: /\b(?:eval|Function)\s*\(\s*[^)]*(?:completion|response|llmOutput|aiResponse|message\.content|choices\[0\]|\.text\b|generatedCode)/i,
    skipComments: true,
    message: 'Model output is executed as code (eval/Function). A prompt-injected response becomes remote code execution.',
    fix: 'Never execute model output. Parse structured data, or run it in a strict sandbox with no host access.',
  },
  {
    id: 'ai.prompt-injection-marker',
    severity: 'medium',
    confidence: 'low',
    title: 'Prompt-injection phrase in code / tool description',
    re: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|disregard\s+(?:the\s+)?(?:above|previous)|jailbreak\s+mode|\bDAN\s+mode\b|you\s+are\s+now\s+(?:in\s+)?developer\s+mode/i,
    skipComments: false,
    message: 'A classic prompt-injection phrase appears here (e.g. in an MCP tool description or system prompt). If this text can reach an LLM, it can hijack it.',
    fix: 'Remove untrusted instruction text; treat tool descriptions and external content as data, not instructions.',
  },
];

// ---------------------------------------------------------------------------
// Advanced injection pack (prototype pollution, ReDoS, XXE, CRLF)
// ---------------------------------------------------------------------------

const injectionRules = [
  {
    id: 'injection.prototype-pollution',
    severity: 'high',
    confidence: 'medium',
    title: 'Prototype pollution via deep merge of request data',
    re: /\b(?:_\.)?(?:merge|mergeWith|defaultsDeep|extend|set|setWith)\s*\([^)]*\breq\.(?:body|query|params)\b|deepmerge\s*\([^)]*\breq\.(?:body|query|params)\b|Object\.assign\s*\([^)]*\breq\.(?:body|query|params)\b/i,
    skipComments: true,
    message: 'A deep-merge/set of request data can set __proto__/constructor keys — prototype pollution.',
    fix: 'Validate keys, freeze prototypes, or use a merge that ignores __proto__/prototype/constructor.',
  },
  {
    id: 'injection.redos-user-regex',
    severity: 'high',
    confidence: 'high',
    title: 'RegExp built from user input (ReDoS)',
    re: /new\s+RegExp\s*\(\s*[^)]*\breq\.(?:body|query|params)\b/,
    skipComments: true,
    message: 'A RegExp is constructed from user input — a crafted pattern causes catastrophic backtracking (ReDoS) and can DoS the process.',
    fix: 'Do not build regexes from user input; use a fixed pattern or escape and length-limit the input.',
  },
  {
    id: 'injection.xxe',
    severity: 'high',
    confidence: 'medium',
    title: 'XML parser with external entities enabled',
    re: /noent\s*:\s*true|resolveExternalEntities\s*:\s*true|expandEntities\s*:\s*true|XMLParser\([^)]*processEntities\s*:\s*true/i,
    skipComments: true,
    message: 'XML external entity expansion is enabled — XXE lets attackers read files and reach internal services.',
    fix: 'Disable external entity resolution (noent/resolveExternalEntities/expandEntities = false).',
  },
  {
    id: 'injection.crlf',
    severity: 'medium',
    confidence: 'low',
    title: 'User input written to a response header',
    re: /\bres\.(?:setHeader|writeHead|header)\s*\([^)]*\breq\.(?:body|query|params|headers)\b/,
    skipComments: true,
    message: 'User input is used in a response header — CRLF injection can split headers or set arbitrary cookies.',
    fix: 'Validate/strip \\r and \\n from any user value used in a header.',
  },
];

// Import extended rule packs
const pack = require('./rules-pack');
const cveVersionRules = pack.allCveVersionRules || pack.cveVersionRules;
const COMPLIANCE_MAP = pack.COMPLIANCE_MAP;

const lineRules = [
  ...secretRules, ...codeRules, ...authRules, ...webRules, ...piiRules,
  ...robustnessRules, ...frameworkRules, ...aiRules, ...injectionRules,
  ...pack.allLineRules,
];

// ---------------------------------------------------------------------------
// File-level rules (need whole-file context, run once per file)
// ---------------------------------------------------------------------------

// Shannon entropy in bits/char — high for random secrets, low for words.
function shannonEntropy(s) {
  const freq = Object.create(null);
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  let e = 0;
  const n = s.length;
  for (const k in freq) {
    const p = freq[k] / n;
    e -= p * Math.log2(p);
  }
  return e;
}

// Files that are full of high-entropy strings that are NOT secrets.
const ENTROPY_SKIP_FILE = /(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|poetry\.lock|composer\.lock|\.min\.js|\.map|\.lock)$/i;
// Prefixes already covered by specific secret rules (avoid double-reporting) or
// known-public tokens.
const ENTROPY_SKIP_PREFIX = /^(?:sk-|sk_live_|sk_test_|rk_live_|pk_live_|pk_test_|AKIA|ASIA|AIza|eyJ|ghp_|gho_|xox[baprs]-)/;

const fileRules = [
  {
    id: 'secret.high-entropy',
    severity: 'high',
    confidence: 'medium',
    title: 'High-entropy string (possible hardcoded secret)',
    run(content, lines, relPath) {
      if (ENTROPY_SKIP_FILE.test(relPath || '')) return [];
      const out = [];
      const strRe = /['"`]([A-Za-z0-9+/=_\-]{24,120})['"`]/g;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 2000) continue;
        let m;
        strRe.lastIndex = 0;
        while ((m = strRe.exec(line)) !== null) {
          const val = m[1];
          if (ENTROPY_SKIP_PREFIX.test(val)) continue;
          if (looksLikePlaceholder(val)) continue;
          if (isPublicBaaSKey(line, val)) continue;
          // UUID — structured, not a secret.
          if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(val)) continue;
          // Pure-hex of checksum lengths (md5/sha1/sha256) — usually a hash, not a secret.
          if (/^[0-9a-f]+$/i.test(val) && [32, 40, 64].includes(val.length)) continue;
          // Must have digit+letter mix (avoids long English identifiers / base64 words).
          if (!/[0-9]/.test(val) || !/[A-Za-z]/.test(val)) continue;
          if (shannonEntropy(val) < 4.0) continue;
          out.push({
            line: i + 1,
            column: (m.index || 0) + 1,
            snippet: (val.slice(0, 4) + '****' + val.slice(-2)),
            message:
              'A long, high-entropy string is hardcoded here — it looks like a secret/token/key. If it is one, move it to an environment variable and rotate it.',
            fix: 'If this is a credential, load it from process.env and rotate it. If it is not (e.g. a public id), you can ignore this finding.',
          });
        }
      }
      return out;
    },
  },
  {
    id: 'pii.full-record-response',
    severity: 'medium',
    confidence: 'low',
    title: 'Full database record may be returned to the client',
    run(content, lines, relPath) {
      const ext = (relPath || '').toLowerCase();
      if (!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/.test(ext)) return [];
      const out = [];
      const findRe = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?[\w.$]*\.(?:find|findAll|findMany|findById|findOne|findByPk|findUnique|findFirst)\s*\(/;
      const selectRe = /\.select\s*\(|attributes\s*:|\bselect\s*:/i;

      // A .map()/serializer callback that picks explicit fields (object literal,
      // no spread of the record) is treated as SAFE shaping. A spread `...` or a
      // raw passthrough (u => u) keeps the whole record -> still unsafe.
      const selectsFields = (cb) => {
        if (/\.\.\./.test(cb)) return false; // spread copies everything
        if (/\{[^}]*:[^}]*\}/.test(cb)) return true; // explicit { field: ... }
        if (REDACT_RE.test(cb)) return true; // redact/omit/pick/serialize inside
        return false; // e.g. u => u, u => u.toJSON()
      };

      // Pass 1: seed unsafe vars from unfiltered finds.
      const unsafe = new Set();
      // Sanitized vars: once a value passes through a shaping fn (redact/omit/…),
      // it is trusted forever after — even if it was unsafe before. Sanitized
      // always wins over unsafe.
      const sanitized = new Set();
      for (const line of lines) {
        const m = findRe.exec(line);
        if (m && !selectRe.test(line)) unsafe.add(m[1]);
      }

      // Assignment shape helpers.
      const mapRe = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\.(?:map|reduce)\s*\((.*)$/;
      const filterRe = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\.(?:filter|slice|concat|sort)\s*\(/; // shape-preserving
      const aliasRe = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*;?\s*$/;
      // Y = { ...X, ... } -> Y carries all of X's fields.
      const spreadRe = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\{[^}]*\.\.\.([A-Za-z_$][\w$]*)/;
      // Y = redact(X) / omit(X, ...) / toDTO(X) -> Y is sanitized.
      const shapeAssignRe = new RegExp(
        '(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*(?:await\\s+)?(?:' +
          [...BASE_SHAPING, ...extraShaping].join('|') +
          ')\\s*\\(',
        'i'
      );

      for (let pass = 0; pass < 4; pass++) {
        for (const line of lines) {
          // Sanitizing assignment wins.
          let m = shapeAssignRe.exec(line);
          if (m) {
            sanitized.add(m[1]);
            unsafe.delete(m[1]);
            continue;
          }
          // map/reduce: safe only if the callback selects fields.
          m = mapRe.exec(line);
          if (m && unsafe.has(m[2]) && !selectsFields(m[3]) && !sanitized.has(m[1])) {
            unsafe.add(m[1]);
            continue;
          }
          // filter/slice/concat/sort: shape-preserving -> stays unsafe.
          m = filterRe.exec(line);
          if (m && unsafe.has(m[2]) && !sanitized.has(m[1])) {
            unsafe.add(m[1]);
            continue;
          }
          // object spread of an unsafe var -> unsafe (unless line also shapes it).
          m = spreadRe.exec(line);
          if (m && unsafe.has(m[2]) && !isRedacted(line) && !sanitized.has(m[1])) {
            unsafe.add(m[1]);
            continue;
          }
          // plain alias.
          m = aliasRe.exec(line);
          if (m && unsafe.has(m[2]) && !sanitized.has(m[1])) unsafe.add(m[1]);
        }
      }
      // Sanitized always wins.
      for (const s of sanitized) unsafe.delete(s);

      const flag = (i, name, why) =>
        out.push({
          line: i + 1,
          column: 1,
          snippet: lines[i].trim().slice(0, 120),
          message: `${why} — this can leak fields like password hashes, tokens, or other users' data.`,
          fix: 'Select only the fields the client needs (or delete sensitive fields / use a serializer) before responding.',
        });

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (isRedacted(line)) continue; // line shapes the data -> trust it
        // res.json(varFromUnfilteredRecord)
        let rm = /\bres\.(?:json|send)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/.exec(line);
        if (rm && unsafe.has(rm[1]) && !sanitized.has(rm[1])) {
          flag(i, rm[1], `"${rm[1]}" comes from an unfiltered DB lookup and is sent straight to the client`);
          continue;
        }
        // res.json(await Model.find...()) inline, no field selection
        if (/\bres\.(?:json|send)\s*\(\s*(?:await\s+)?[\w.$]*\.(?:find|findAll|findMany|findById|findOne|findByPk|findUnique|findFirst)\s*\(/i.test(line) && !selectRe.test(line)) {
          flag(i, 'record', 'An unfiltered DB record is returned inline in the response');
          continue;
        }
        // res.json({ ...unsafeVar }) inline spread of a full record
        rm = /\bres\.(?:json|send)\s*\(\s*\{[^}]*\.\.\.([A-Za-z_$][\w$]*)/.exec(line);
        if (rm && unsafe.has(rm[1])) {
          flag(i, rm[1], `"${rm[1]}" is spread into the response object, carrying all of its fields to the client`);
          continue;
        }
        // res.json(unsafeVar.map(cb)) where the map does not select fields
        rm = /\bres\.(?:json|send)\s*\(\s*([A-Za-z_$][\w$]*)\.map\s*\((.*)$/.exec(line);
        if (rm && unsafe.has(rm[1]) && !selectsFields(rm[2])) {
          flag(i, rm[1], `"${rm[1]}" records are mapped without selecting fields and returned to the client`);
        }
      }
      return out;
    },
  },
  {
    id: 'package.hygiene',
    severity: 'medium',
    confidence: 'high',
    title: 'package.json supply-chain hygiene',
    run(content, lines, relPath) {
      if ((relPath || '') !== 'package.json') return [];
      let pkg;
      try {
        pkg = JSON.parse(content);
      } catch {
        return [];
      }
      const out = [];
      const findLoc = (needle) => {
        for (let i = 0; i < lines.length; i++) {
          const c = lines[i].indexOf(needle);
          if (c !== -1) return { line: i + 1, column: c + 1 };
        }
        return { line: 1, column: 1 };
      };
      const deps = Object.assign({}, pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies);
      for (const [name, ver] of Object.entries(deps)) {
        if (typeof ver !== 'string') continue;
        if (ver === '*' || ver === 'latest' || ver === '' || /^[x*]/.test(ver)) {
          const loc = findLoc(`"${name}"`);
          out.push({
            line: loc.line,
            column: loc.column,
            confidence: 'high',
            snippet: `"${name}": "${ver}"`,
            message: `Dependency "${name}" is unpinned ("${ver}"). Any future (possibly malicious) version can be installed — supply-chain risk.`,
            fix: `Pin "${name}" to a specific version range (e.g. ^1.2.3) and commit a lockfile.`,
          });
        }
      }
      // Dangerous install scripts.
      const scripts = pkg.scripts || {};
      for (const hook of ['preinstall', 'postinstall', 'install', 'prepare']) {
        const s = scripts[hook];
        if (s && /curl|wget|\|\s*(?:sh|bash)|sudo|npx\s+\S+@|eval\s/i.test(s)) {
          const loc = findLoc(`"${hook}"`);
          out.push({
            line: loc.line,
            column: loc.column,
            severity: 'high',
            confidence: 'medium',
            snippet: `"${hook}": ${JSON.stringify(s).slice(0, 80)}`,
            message: `The "${hook}" script runs a network/shell command on install — a common malware and supply-chain vector.`,
            fix: `Review the "${hook}" script; avoid piping remote scripts to a shell during install.`,
          });
        }
      }
      return out;
    },
  },
  {
    id: 'ratelimit.missing-on-auth',
    severity: 'medium',
    confidence: 'low',
    title: 'Auth endpoint without visible rate limiting',
    run(content, lines) {
      const authRouteRe = /\bapp\.(?:post|put)\s*\(\s*['"]([^'"]*(?:login|signin|sign-in|auth|register|signup|sign-up|password|reset|token|otp)[^'"]*)['"]/i;
      const hasRateLimit = /rate[-\s]?limit|ratelimit|express-rate-limit|slow[-\s]?down|slowDown|\blimiter\b|throttle|express-brute|bruteforce/i.test(content);
      if (hasRateLimit) return [];
      const out = [];
      for (let i = 0; i < lines.length; i++) {
        const m = authRouteRe.exec(lines[i]);
        if (m) {
          out.push({
            line: i + 1,
            column: 1,
            snippet: lines[i].trim().slice(0, 120),
            message:
              'This authentication endpoint has no rate limiting in this file — it is exposed to brute-force / credential-stuffing.',
            fix: 'Add a rate limiter (e.g. express-rate-limit) to login/auth routes, e.g. app.post("/login", loginLimiter, handler).',
          });
        }
      }
      return out;
    },
  },
  {
    id: 'upload.unrestricted-multer',
    severity: 'medium',
    confidence: 'low',
    title: 'File upload without type/size restrictions',
    run(content, lines) {
      if (!/\bmulter\s*\(/.test(content) && !/require\(['"]multer['"]\)/.test(content)) {
        return [];
      }
      // If limits or a fileFilter are configured anywhere in the file, assume guarded.
      if (/fileFilter|limits\s*:/.test(content)) return [];
      const out = [];
      for (let i = 0; i < lines.length; i++) {
        if (/\bmulter\s*\(/.test(lines[i])) {
          out.push({
            line: i + 1,
            column: 1,
            snippet: lines[i].trim().slice(0, 120),
            message:
              'multer is configured without fileFilter or size limits — accepts any file type and size (upload abuse, storage exhaustion).',
            fix: 'Add limits (e.g. { limits: { fileSize: 5*1024*1024 } }) and a fileFilter that allowlists expected MIME types.',
          });
        }
      }
      return out;
    },
  },
  {
    id: 'iac.dockerfile',
    severity: 'medium',
    confidence: 'high',
    title: 'Dockerfile hardening',
    run(content, lines, relPath) {
      const base = (relPath || '').split('/').pop() || '';
      if (!/^dockerfile$/i.test(base) && !/\.dockerfile$/i.test(base)) return [];
      const out = [];
      let hasUser = false;
      for (let i = 0; i < lines.length; i++) {
        const l = lines[i];
        if (/^\s*USER\s+\S+/i.test(l) && !/^\s*USER\s+root\b/i.test(l)) hasUser = true;
        if (/^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|CREDENTIAL)\w*\s*[=\s]/i.test(l)) {
          out.push({ line: i + 1, column: 1, severity: 'high', snippet: l.trim().slice(0, 100), message: 'A secret is baked into the image via ENV/ARG — it is readable in every image layer.', fix: 'Pass secrets at runtime (docker secrets / --env-file / mounted files), never via ENV/ARG in the Dockerfile.' });
        }
        if (/^\s*ADD\s+https?:\/\//i.test(l)) {
          out.push({ line: i + 1, column: 1, severity: 'medium', snippet: l.trim().slice(0, 100), message: 'ADD fetches a remote URL — no checksum verification, and it auto-extracts archives.', fix: 'Use curl/wget with a pinned checksum, or COPY a vendored file.' });
        }
        const from = /^\s*FROM\s+([^\s]+)/i.exec(l);
        if (from && (/:latest$/i.test(from[1]) || !/[:@]/.test(from[1]))) {
          out.push({ line: i + 1, column: 1, severity: 'low', snippet: l.trim().slice(0, 100), message: 'Base image is untagged or :latest — builds are not reproducible and can pull a changed/compromised image.', fix: 'Pin the base image to a specific version and ideally a digest (image@sha256:...).' });
        }
      }
      if (!hasUser) out.push({ line: 1, column: 1, severity: 'medium', snippet: base, message: 'No non-root USER directive — the container runs as root, widening the blast radius of any compromise.', fix: 'Add a non-root user (RUN adduser ... && USER appuser).' });
      return out;
    },
  },
  {
    id: 'iac.github-actions',
    severity: 'medium',
    confidence: 'medium',
    title: 'GitHub Actions workflow hardening',
    run(content, lines, relPath) {
      if (!/\.github\/workflows\/.+\.(?:yml|yaml)$/.test(relPath || '')) return [];
      const out = [];
      for (let i = 0; i < lines.length; i++) {
        const l = lines[i];
        if (/\$\{\{\s*github\.(?:event|head_ref|pull_request)[^}]*\}\}/.test(l) && !/\benv\s*:/.test(l)) {
          out.push({ line: i + 1, column: 1, severity: 'high', confidence: 'medium', snippet: l.trim().slice(0, 100), message: 'Untrusted github.event/head_ref data is interpolated directly — script injection into the runner.', fix: 'Pass it through an env: var and reference "$VAR" in the script instead of inlining ${{ }}.' });
        }
        if (/permissions:\s*write-all/i.test(l)) {
          out.push({ line: i + 1, column: 1, severity: 'medium', snippet: l.trim().slice(0, 100), message: 'permissions: write-all grants the token full write access to the repo.', fix: 'Set least-privilege permissions per job (e.g. contents: read).' });
        }
        const uses = /^\s*-?\s*uses:\s*([\w.\-]+\/[\w.\-]+)@([\w.\-]+)\s*$/.exec(l);
        if (uses && !/^[0-9a-f]{40}$/.test(uses[2])) {
          out.push({ line: i + 1, column: 1, severity: 'low', snippet: l.trim().slice(0, 100), message: `Action ${uses[1]} is pinned to a tag/branch (@${uses[2]}), not a commit SHA — a moved tag can inject malicious code.`, fix: 'Pin third-party actions to a full commit SHA.' });
        }
      }
      return out;
    },
  },
  {
    id: 'iac.terraform',
    severity: 'high',
    confidence: 'high',
    title: 'Terraform misconfiguration',
    run(content, lines, relPath) {
      if (!/\.(?:tf|hcl)$/.test(relPath || '')) return [];
      const out = [];
      for (let i = 0; i < lines.length; i++) {
        const l = lines[i];
        if (/cidr_blocks?\s*=\s*\[?\s*"0\.0\.0\.0\/0"/.test(l)) {
          out.push({ line: i + 1, column: 1, severity: 'high', snippet: l.trim().slice(0, 100), message: 'Security group / firewall allows 0.0.0.0/0 — open to the entire internet.', fix: 'Restrict ingress to specific IP ranges; never expose admin ports (22/3389/db) to 0.0.0.0/0.' });
        }
        if (/acl\s*=\s*"public-read(?:-write)?"/.test(l)) {
          out.push({ line: i + 1, column: 1, severity: 'high', snippet: l.trim().slice(0, 100), message: 'A storage bucket ACL is public — objects are world-readable/writable.', fix: 'Use private ACLs and grant access via IAM policies / signed URLs.' });
        }
        if (/"(?:Action|Resource)"\s*:\s*"\*"|actions?\s*=\s*\[\s*"\*"\s*\]/.test(l)) {
          out.push({ line: i + 1, column: 1, severity: 'medium', confidence: 'medium', snippet: l.trim().slice(0, 100), message: 'IAM policy uses a wildcard "*" for Action/Resource — over-broad privileges.', fix: 'Scope IAM policies to the specific actions and resources needed.' });
        }
      }
      return out;
    },
  },
  {
    id: 'nextjs.missing-security-headers',
    severity: 'low',
    confidence: 'low',
    title: 'Next.js config without security headers',
    run(content, lines, relPath) {
      if (!/^next\.config\.(?:js|mjs|ts|cjs)$/.test(relPath || '')) return [];
      const hasHeadersFn = /headers\s*\(/.test(content) || /async\s+headers/.test(content);
      const hasSecHeader =
        /Strict-Transport-Security|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Permissions-Policy/i.test(
          content
        );
      if (hasHeadersFn && hasSecHeader) return [];
      return [
        {
          line: 1,
          column: 1,
          snippet: relPath,
          message:
            'No security response headers configured in next.config. Deployed pages ship without CSP / HSTS / X-Frame-Options / X-Content-Type-Options.',
          fix: 'Add an async headers() returning Content-Security-Policy, Strict-Transport-Security, X-Frame-Options=DENY, X-Content-Type-Options=nosniff, and Referrer-Policy.',
        },
      ];
    },
  },
  {
    id: 'cve.known-vulnerable-version',
    severity: 'high',
    confidence: 'high',
    title: 'Known vulnerable dependency version',
    run(content, lines, relPath) {
      if ((relPath || '') !== 'package.json') return [];
      let pkg;
      try { pkg = JSON.parse(content); } catch { return []; }
      const deps = Object.assign({}, pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies);
      const out = [];
      for (const cveRule of cveVersionRules) {
        const ver = deps[cveRule.pkg];
        if (!ver || typeof ver !== 'string') continue;
        const cleanVer = ver.replace(/^[^0-9]*/, '');
        const parts = cleanVer.split('.').map(Number);
        const major = parts[0] || 0;
        const minor = parts[1] || 0;
        const patch = parts[2] || 0;
        let isVulnerable = false;
        for (const vuln of cveRule.vuln) {
          if (vuln === '*') { isVulnerable = true; break; }
          const m = /^<(\d+)\.(\d+)(?:\.(\d+))?$/.exec(vuln);
          if (m) {
            const vMaj = parseInt(m[1], 10);
            const vMin = parseInt(m[2], 10);
            const vPat = parseInt(m[3] || '0', 10);
            if (major < vMaj || (major === vMaj && minor < vMin) || (major === vMaj && minor === vMin && patch < vPat)) {
              isVulnerable = true; break;
            }
          }
        }
        if (isVulnerable) {
          const loc = { line: 1, column: 1 };
          for (let i = 0; i < lines.length; i++) {
            const idx = lines[i].indexOf(`"${cveRule.pkg}"`);
            if (idx !== -1) { loc.line = i + 1; loc.column = idx + 1; break; }
          }
          out.push({
            line: loc.line,
            column: loc.column,
            severity: cveRule.severity,
            snippet: `"${cveRule.pkg}": "${ver}"`,
            message: `${cveRule.title}. Installed: ${ver}. ${cveRule.cve}.`,
            fix: cveRule.fix,
            title: cveRule.title,
          });
        }
      }
      return out;
    },
  },
];

// ---------------------------------------------------------------------------
// Cross-file rules (need ALL file contents at once — see scanner.js)
// ---------------------------------------------------------------------------

// Escape a string for use inside a RegExp.
function reEscape(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const crossFileRules = [
  {
    id: 'supabase.rls-missing',
    severity: 'high',
    confidence: 'low',
    title: 'SQL table created without row-level security enabled',
    // Aggregates across EVERY .sql file: a table may be created in schema.sql and
    // have RLS enabled in a separate migration. Only flag tables that are never
    // RLS-enabled anywhere in the project.
    run(files) {
      const sql = files.filter((f) => /\.sql$/i.test(f.rel));
      if (sql.length === 0) return [];

      const rlsTables = new Set();
      const creates = [];
      const createRe = /create\s+table\s+(?:if\s+not\s+exists\s+)?["'`]?([A-Za-z0-9_.]+)["'`]?/gi;
      const rlsRe = /alter\s+table\s+(?:public\.)?["'`]?([A-Za-z0-9_.]+)["'`]?\s+enable\s+row\s+level\s+security/gi;

      for (const f of sql) {
        let m;
        rlsRe.lastIndex = 0;
        while ((m = rlsRe.exec(f.content)) !== null) {
          rlsTables.add(m[1].replace(/^public\./i, '').toLowerCase());
        }
        for (let i = 0; i < f.lines.length; i++) {
          createRe.lastIndex = 0;
          const cm = createRe.exec(f.lines[i]);
          if (cm) creates.push({ table: cm[1].replace(/^public\./i, ''), file: f.rel, line: i + 1 });
        }
      }

      const out = [];
      for (const c of creates) {
        if (rlsTables.has(c.table.toLowerCase())) continue;
        out.push({
          file: c.file,
          line: c.line,
          column: 1,
          snippet: `create table ${c.table}`,
          message: `Table "${c.table}" is created but row-level security is never enabled for it anywhere in the project. Without RLS, Supabase exposes the whole table to any anon-key client.`,
          fix: `Add: ALTER TABLE ${c.table} ENABLE ROW LEVEL SECURITY; and define policies scoped to auth.uid().`,
        });
      }
      return out;
    },
  },
];

// Flat registry of every rule (for `vibeguard rules` / `explain`). File/cross
// rules carry dynamic messages, so message/fix may be empty there — title covers it.
function allRules() {
  const out = [];
  const add = (r) => out.push({
    id: r.id,
    category: (r.id || '').split('.')[0],
    severity: r.severity,
    confidence: r.confidence || 'high',
    title: r.title || r.id,
    message: r.message || '',
    fix: r.fix || '',
  });
  for (const r of lineRules) add(r);
  for (const r of fileRules) add(r);
  for (const r of crossFileRules) add(r);
  // Rules that live in other modules (not line/file/cross) — list by id for docs.
  for (const id of [
    'ast.eval-dynamic', 'ast.command-injection', 'ast.function-constructor',
    'ast.mass-assignment', 'ast.nosql-injection', 'ast.path-traversal', 'ast.ssrf',
    'taint.command-injection', 'taint.sql-injection', 'taint.code-injection',
    'taint.path-traversal', 'taint.ssrf', 'taint.open-redirect',
    'taint.interprocedural', 'taint.cross-file',
    'dep.npm-vulnerability', 'dep.pip-vulnerability',
    'package.no-lockfile', 'project.env-not-ignored', 'project.env-exposed',
    'url.no-https', 'url.missing-content-security-policy', 'url.insecure-cookie', 'url.version-leak',
    'history.secret', 'doctor.hook-injection', 'doctor.base-url-hijack', 'doctor.mcp-suspicious',
  ]) out.push({ id, category: id.split('.')[0], severity: '-', confidence: '-', title: id, message: '', fix: '' });
  return out;
}

module.exports = {
  SEVERITY_ORDER,
  allRules,
  lineRules,
  fileRules,
  crossFileRules,
  secretRules,
  codeRules,
  authRules,
  webRules,
  piiRules,
  makeFinding,
  matchAll,
  requiredLiteral,
  isCommentLine,
  looksLikePlaceholder,
  isPublicBaaSKey,
  configure,
  isRedacted,
  COMPLIANCE_MAP,
};
