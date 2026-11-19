'use strict';

/*
 * VibeGuard 2026 detection pack — the classes AI code generators get wrong.
 *
 * Separate from rules.js/rules-pack.js because this file targets the *evidence*
 * from 2025-2026 research on AI-written applications:
 *   - Veracode GenAI report: 45% of generated samples shipped an OWASP Top-10
 *     flaw; crypto (CWE-327) and log injection (CWE-117) were the worst classes.
 *   - CSA / CodeRabbit: 1.91x IDOR, 1.82x insecure deserialization, 2.74x more
 *     security issues in AI-co-authored PRs; 15/15 vibe-coded apps lacked CSRF.
 *   - GitGuardian 2026: Claude-assisted commits leak secrets at 3.2% vs 1.5%.
 *   - USENIX'25: 19.7% of LLM-recommended packages do not exist (slopsquatting).
 *
 * Precision contract: every rule either requires two independent signals or
 * matches a construct that is unambiguously wrong in production code. Rules that
 * would page on framework boilerplate are left out rather than shipped noisy.
 */

// --- small helpers ---------------------------------------------------------

const REQ = /\b(?:req|request|ctx|c|event|input|params|searchParams|query|body)\b/;

// A value derived from the request, in the forms generators actually emit.
const REQ_DERIVED =
  '(?:req\\.(?:body|query|params|headers|cookies)|request\\.(?:body|query|params|form|args|json|GET|POST|data)|' +
  'ctx\\.(?:body|query|params)|c\\.req\\.(?:query|param|json|body)|event\\.(?:body|queryStringParameters|pathParameters)|' +
  'searchParams\\.get\\(|params\\.(?:id|slug|uuid|key|token)|formData\\.get\\()';

const isComment = (l) => /^\s*(?:\/\/|#|\*|\/\*)/.test(l);
const has = (s, re) => re.test(s);

function idxOf(lines, line) {
  return lines ? lines.indexOf(line) : -1;
}

function makeLineRule(o) {
  return o;
}

// ---------------------------------------------------------------------------
// 1. Authorization: IDOR, missing authz, privilege from client
// ---------------------------------------------------------------------------

const authz2026 = [
  makeLineRule({
    id: 'authz2026.orm-fetch-by-param-id-no-owner',
    severity: 'high',
    confidence: 'medium',
    title: 'Object fetched by request id with no ownership filter (IDOR)',
    re: new RegExp(
      `(?:findUnique|findFirst|findOne|findById|findByIdAndUpdate|findByIdAndDelete|findOneAndUpdate|findOneAndDelete|` +
        `first|single|maybeSingle)\\s*\\(\\s*\\{[^}]{0,160}?${REQ_DERIVED}`,
      'i'
    ),
    filter(line) {
      // The query must select by id AND not constrain by an owner/tenant column.
      const selectsById = /\b(?:id|uuid|slug|key|token)\b\s*:?\s*(?:params|req\.|searchParams|\(\s*\))/i.test(line) ||
        /\.eq\(\s*['"](id|uuid)['"]/i.test(line);
      if (!selectsById) return false;
      const ownerScoped = /(?:userId|user_id|ownerId|owner_id|tenantId|tenant_id|orgId|org_id|accountId|account_id|authorId|author_id|workspaceId|teamId|customerId|auth\.uid\(\))/i.test(line);
      return !ownerScoped;
    },
    skipComments: true,
    message:
      'A record is fetched by an id that came straight from the request, with no owner/tenant predicate on the same query. Any authenticated user can read any row by changing the id (IDOR / BOLA).',
    fix: 'Add an ownership constraint to the same query — e.g. where: { id: params.id, userId: session.user.id } — or enforce it in a policy (RLS, Prisma extension, scoped repository).',
    cwe: 'CWE-639', owasp: 'A01:2025 Broken Access Control',
  }),

  makeLineRule({
    id: 'authz2026.orm-mutation-by-param-id-no-owner',
    severity: 'high',
    confidence: 'medium',
    title: 'Object updated/deleted by request id with no ownership filter',
    re: new RegExp(
      `\\.(?:update|updateMany|delete|deleteMany|upsert)\\s*\\(\\s*\\{[^}]{0,200}?where\\s*:\\s*\\{[^}]{0,120}?${REQ_DERIVED}`,
      'i'
    ),
    filter(line) {
      if (!/\bwhere\b/.test(line)) return false;
      return !/(?:userId|user_id|ownerId|owner_id|tenantId|tenant_id|orgId|org_id|authorId|accountId|workspaceId|teamId)/i.test(line);
    },
    skipComments: true,
    message:
      'A write is scoped only by a request-supplied id. Without an owner/tenant predicate the caller can update or delete another user\'s record (IDOR → privilege abuse / data loss).',
    fix: 'Constrain the write with the caller identity too: where: { id, userId: session.user.id }. Prefer a repository that cannot issue an unscoped write.',
    cwe: 'CWE-639', owasp: 'A01:2025 Broken Access Control',
  }),

  makeLineRule({
    id: 'authz2026.supabase-eq-id-no-user-filter',
    severity: 'high',
    confidence: 'medium',
    title: 'Supabase query filtered only by request id (RLS must cover it)',
    re: /\.eq\(\s*['"](?:id|uuid)['"]\s*,\s*[^)]*(?:params|req\.|searchParams|\bid\b)[^)]*\)/i,
    filter(line) {
      return !/(?:user_id|userId|owner_id|ownerId|tenant_id|tenantId|org_id|auth\.uid)/i.test(line);
    },
    skipComments: true,
    message:
      'Supabase row fetch/delete is filtered only by the id from the request. If the table\'s RLS policy is permissive or missing, any anon-key client can read/modify every row. RLS presence is not RLS correctness.',
    fix: 'Filter by the member column too (.eq("user_id", user.id)) and make sure the policy itself says auth.uid() = user_id for SELECT/UPDATE/DELETE.',
    cwe: 'CWE-639', owasp: 'A01:2025 Broken Access Control',
  }),

  makeLineRule({
    id: 'authz2026.mass-assignment-privileged-field',
    severity: 'high',
    confidence: 'medium',
    title: 'Request body spread into a write — privilege fields reachable',
    re: new RegExp(`(?:data|values|setRepr|document)\\s*:\\s*(?:\\.\\.\\.)?\\s*${REQ_DERIVED}`, 'i'),
    filter(line, hit, lines) { const idx = idxOf(lines, line);
    // Only when a privileged field exists nearby (the model or payload).
      const ctx = lines.slice(Math.max(0, idx - 4), idx + 6).join('\n') + line;
      return /(?:role|isAdmin|is_admin|admin|plan|credits|balance|verified|isVerified|tier|permissions|ownerId|price)\b/.test(ctx);
    },
    skipComments: true,
    message:
      'The whole request body is written to a record. Generators do this as `prisma.user.update({ data: req.body })`; a caller can then set role/isAdmin/credits/plan fields the UI never exposes (mass assignment).',
    fix: 'Destructure an explicit allowlist: const { name, bio } = body; then write only those. Never spread req.body into create/update.',
    cwe: 'CWE-915', owasp: 'A01:2025 Broken Access Control',
  }),

  makeLineRule({
    id: 'authz2026.admin-flag-from-request',
    severity: 'critical',
    confidence: 'high',
    title: 'Privilege flag taken from the request',
    re: new RegExp(`\\b(?:isAdmin|is_admin|role|permissions|isSuperuser|isStaff)\\b\\s*[:=]\\s*${REQ_DERIVED}`, 'i'),
    skipComments: true,
    message:
      'A privileged field is assigned straight from the request. A caller sets role/isAdmin themselves — vertical privilege escalation, regardless of auth.',
    fix: 'Never accept role/permission fields from clients. Resolve them server-side from the session or an allowlist.',
    cwe: 'CWE-269', owasp: 'A01:2025 Broken Access Control',
  }),

  makeLineRule({
    id: 'authz2026.authorization-header-trusted',
    severity: 'high',
    confidence: 'medium',
    title: 'Identity taken from a client-controlled header',
    re: /(?:headers?\.(?:get\()?\s*['"]?x-(?:user|userid|user-id|role|admin|tenant|account))|(?:req\.headers\[['"]x-user)/i,
    skipComments: true,
    message:
      'The request\'s own `x-user-id` / `x-role` header is trusted for identity. Headers are client-controlled unless a trusted proxy strips and rewrites them — impersonation.',
    fix: 'Derive identity from the verified session/JWT. If a gateway sets the header, strip inbound copies and verify the signature.',
    cwe: 'CWE-290', owasp: 'A07:2025 Authentication Failures',
  }),

  makeLineRule({
    id: 'authz2026.check-then-act-role',
    severity: 'medium',
    confidence: 'medium',
    title: 'Role check via assignment instead of comparison',
    re: /if\s*\(\s*[\w.]+\s*===\s*['"]admin['"]\s*\)\s*\{?|\brole\s*=\s*['"]admin['"]\s*(?:\)|;)/,
    filter(line) {
      return /\bif\s*\(|\brole\s*=/.test(line);
    },
    skipComments: true,
    message:
      'A role check looks like an assignment or has no trusted source. `if (user.role = "admin")` is always truthy in JS and grants admin to everyone.',
    fix: 'Compare, never assign: if (user?.role === "admin"). Put the check in one middleware and test it.',
    cwe: 'CWE-697', owasp: 'A01:2025 Broken Access Control',
  }),
];

// Next.js-specific: middleware-only auth, matchers, server actions.
const nextjs2026 = [
  {
    id: 'nextjs2026.middleware-matcher-excludes-api',
    severity: 'high',
    confidence: 'medium',
    title: 'Next.js middleware matcher excludes /api — those routes are unguarded',
    match(content) {
      const m = /matcher\s*:\s*\[([\s\S]{0,500}?)\]/.exec(content);
      if (!m) return [];
      const patterns = [...m[1].matchAll(/['"]([^'"]+)['"]/g)].map((x) => x[1]);
      const index = m.index + m[1].indexOf(patterns[0] || '');
      // `/((?!api|_next).*)` style negative lookaheads deliberately skip /api.
      const skipsApi = patterns.some((p) => /\(\?!.*\bapi\b/.test(p));
      if (!skipsApi) return [];
      return [{ index: Math.max(0, index), match: patterns.join(' ') }];
    },
    message:
      'The middleware matcher excludes /api. If auth lives only in middleware.ts, every app/api/*/route.ts is public — and middleware auth can be bypassed via x-middleware-subrequest (CVE-2025-29927) on unpatched Next versions.',
    fix: 'Guard each route handler/Server Action with the session check itself, and add an explicit per-route or per-middleware API guard. Upgrade next past the CVE-2025-29927 fix.',
    cwe: 'CWE-288', owasp: 'A01:2025 Broken Access Control',
  },
  {
    id: 'nextjs2026.server-action-no-auth',
    severity: 'high',
    confidence: 'medium',
    title: 'Server Action exported without an auth check',
    run(content, lines, relPath) {
      if (!/['"]use server['"]/.test(content)) return [];
      const re = /export\s+(?:async\s+)?function\s+(\w+)\s*\(/g;
      const out = [];
      let m;
      while ((m = re.exec(content)) !== null) {
        const lineIdx = content.slice(0, m.index).split('\n').length - 1;
        // Window: the function body, approximated to the next export or 60 lines.
        const window = lines.slice(lineIdx, Math.min(lines.length, lineIdx + 60)).join('\n');
        if (/\bauth\s*\(|\bgetServerSession\b|\bgetSession\b|\bcurrentUser\b|\brequire(?:User|Auth|Session)\b|\bverifySession\b|\bassertAuth\b/.test(window)) continue;
        // Only flag when the action does something privileged.
        if (!/(?:prisma|db|supabase|firebase|knex|drizzle|\.(?:create|update|delete|insert|save)\b|fetch\s*\(|fs\.)/.test(window)) continue;
        out.push({
          line: lineIdx + 1,
          column: 1,
          snippet: m[0].slice(0, 120),
          message: `Server Action ${m[1]}() is callable from any page by any visitor and performs a privileged operation with no session check. A Server Action is a public RPC endpoint, not a form handler.`,
          fix: `Start ${m[1]}() with the session check (e.g. const session = await auth(); if (!session) throw new Error("UNAUTHORIZED")), and authorize the specific object it mutates.`,
        });
        if (out.length >= 8) break;
      }
      return out;
    },
    severity: 'high',
    confidence: 'medium',
    titleCheck: true,
  },
  makeLineRule({
    id: 'nextjs2026.public-env-secret',
    severity: 'critical',
    confidence: 'high',
    title: 'Secret-looking value under a public env prefix — shipped to the browser',
    re: /\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC|NUXT_PUBLIC)_[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|CREDENTIAL|DB_|DATABASE|OPENAI|ANTHROPIC|STRIPE_SECRET|AWS_SECRET|JWT_SECRET|API_KEY|TOKEN)[A-Z0-9_]*\b/i,
    filter(line) {
      // NEXT_PUBLIC_SITE_URL, VITE_ANON_KEY etc. are meant to be public.
      if (/(?:SITE_URL|PUBLIC_KEY|ANON_KEY|POSTHOG|GOOGLE_ANALYTICS|GA_ID|SENTRY_DSN|STRIPE_PUBLISHABLE|PUBLISHABLE)/i.test(line)) return false;
      return true;
    },
    skipComments: true,
    message:
      'A name under a public/browser env prefix holds a private credential. Next/Vite/Expo inline these into the client bundle — the value is readable by every visitor (and by any AI agent that later scrapes the bundle).',
    fix: 'Drop the public prefix for server-only secrets, keep them only in server components/route handlers, and rotate the exposed value.',
    cwe: 'CWE-200', owasp: 'A02:2025 Security Misconfiguration',
  }),
  makeLineRule({
    id: 'nextjs2026.server-only-missing-service-role',
    severity: 'high',
    confidence: 'medium',
    title: 'Service-role/admin client created outside a server-only module',
    re: /(?:createClient|initializeApp|admin\.initializeApp)\s*\([^)]*(?:SERVICE_ROLE|service_role|ADMIN_KEY|SERVICE_KEY)/i,
    filter(line) {
      return !/['"]use server['"]|server-only|process\.env\.SUPABASE_SERVICE_ROLE/i.test(line);
    },
    skipComments: true,
    message:
      'A service-role/admin Supabase or Firebase client is created here. If this module can be imported by a client component, the key ships to the browser and RLS no longer protects anything.',
    fix: 'Move this into a server-only module (import "server-only") or a route handler, use the anon key on the client, and keep RLS enabled.',
    cwe: 'CWE-798', owasp: 'A02:2025 Security Misconfiguration',
  }),
  makeLineRule({
    id: 'nextjs2026.redirect-user-input',
    severity: 'medium',
    confidence: 'medium',
    title: 'Redirect target from request input (open redirect)',
    re: /\bredirect\s*\(\s*(?:searchParams\.get|params\.|req\.|request\.|ctx\.|c\.req\.|next\b|returnTo\b|callbackUrl\b)/i,
    skipComments: true,
    message:
      'The redirect target comes from the request (?next=, callbackUrl). Attackers use the trusted domain for phishing and token leakage.',
    fix: 'Allowlist internal paths: only accept a leading "/" and no "//"/scheme, or map an enum of known destinations.',
    cwe: 'CWE-601', owasp: 'A01:2025 Broken Access Control',
  }),
  {
    id: 'nextjs2026.config-no-security-headers',
    severity: 'medium',
    confidence: 'medium',
    title: 'next.config has no headers() block (CSP/HSTS/frame protection)',
    match(content, ctx) {
      const rel = ((ctx && ctx.relPath) || '').replace(/\\/g, '/');
      if (!/(?:^|\/)next\.config\.(?:js|mjs|ts)$/.test(rel)) return [];
      if (!/module\.exports|export\s+default/.test(content)) return [];
      if (/\bheaders\s*(?:\(\s*\)|:)\s*(?:async\s*)?\(?\s*\)?\s*(?:=>|\{)/.test(content)) return [];
      const idx = content.indexOf('module.exports');
      return [{ index: Math.max(0, idx), match: 'next.config' }];
    },
    message:
      'next.config defines no headers(), so the app ships without a Content-Security-Policy, HSTS, X-Frame-Options or Referrer-Policy by default — the exact gap found in AI-built apps.',
    fix: 'Add headers() returning Content-Security-Policy, Strict-Transport-Security, X-Frame-Options: DENY, Referrer-Policy: strict-origin-when-cross-origin.',
        cwe: 'CWE-693', owasp: 'A02:2025 Security Misconfiguration',
  },
];

// ---------------------------------------------------------------------------
// 2. Supabase / Firebase — correctness, not presence
// ---------------------------------------------------------------------------

const supabase2026 = [
  makeLineRule({
    id: 'supabase2026.rls-policy-using-true',
    severity: 'critical',
    confidence: 'high',
    title: 'RLS policy allows every row (USING (true))',
    re: /using\s*\(\s*true\s*\)/i,
    fileFilter: /\.(sql|ts|js)$/i,
    skipComments: true,
    message:
      'A row-level security policy allows all rows. RLS is enabled, so the Supabase dashboard shows "protected" — but any client with the anon key reads and writes everything.',
    fix: 'Scope the policy to the owner: using (auth.uid() = user_id) with check (auth.uid() = user_id). Run the Supabase security advisor after the change.',
    cwe: 'CWE-284', owasp: 'A01:2025 Broken Access Control',
  }),
  makeLineRule({
    id: 'supabase2026.security-definer-no-search-path',
    severity: 'medium',
    confidence: 'medium',
    title: 'SECURITY DEFINER function without a pinned search_path',
    re: /security\s+definer/i,
    filter(line, hit, lines) { const idx = idxOf(lines, line);
    if (!lines) return true;
      // The function's own body only: stop at the next CREATE FUNCTION, so a
      // later safe function cannot mask this one.
      const window = [];
      for (let i = Math.max(0, idx); i < Math.min(lines.length, idx + 20); i++) {
        if (i > idx && /create\s+(?:or\s+replace\s+)?function/i.test(lines[i])) break;
        window.push(lines[i]);
      }
      return !/set\s+search_path/i.test(window.join('\n'));
    },
    fileFilter: /\.sql$/i,
    skipComments: true,
    message:
      'A SECURITY DEFINER function runs with its owner\'s privileges. Without `set search_path = \'\'` an attacker who can create objects in an earlier schema shadows tables/functions it calls (CVE-2018-1058 class).',
    fix: 'Add `set search_path = \'\'` (or a fixed schema) to the function body and fully qualify every referenced object.',
    cwe: 'CWE-269', owasp: 'A01:2025 Broken Access Control',
  }),
  makeLineRule({
    id: 'supabase2026.grant-all-to-anon',
    severity: 'critical',
    confidence: 'high',
    title: 'GRANT ALL to anon/authenticated',
    re: /grant\s+all\s+(?:privileges\s+)?on\s+[a-z_."]+?\s+to\s+(?:anon|authenticated)\b/i,
    fileFilter: /\.sql$/i,
    skipComments: true,
    message:
      'ALL privileges are granted to anon/authenticated. Even with RLS enabled, this hands DDL/DML power and defeats least privilege; anonymous callers can often truncate or drop.',
    fix: 'Grant the minimum verbs per table (select/insert/update/delete) only to authenticated, and scope RLS policies per row.',
    cwe: 'CWE-269', owasp: 'A01:2025 Broken Access Control',
  }),
  makeLineRule({
    id: 'supabase2026.select-star-exposed',
    severity: 'medium',
    confidence: 'medium',
    title: 'select("*") from a table plus a response — column leak',
    re: /\.from\(\s*['"][\w]+['"]\s*\)\s*\.select\(\s*['"]\*['"]\s*\)/i,
    filter(line, hit, lines) { const idx = idxOf(lines, line);
    const ctx = lines ? lines.slice(Math.max(0, (idx) - 2), (idx) + 6).join('\n') : line;
      // Only when the rows then go back to the caller / client.
      return /res\.(?:json|send)|Response\.json|return\s+data|NextResponse\.json|\.map\(|serialize/i.test(ctx);
    },
    skipComments: true,
    message:
      'select("*") returns every column and the rows are sent to the caller — password_hash, api_key, reset_token and internal notes included. AI-generated schemas usually carry those columns.',
    fix: 'Select the fields the UI needs explicitly: .select("id, title, created_at"). Never return auth/secret columns to the client.',
    cwe: 'CWE-200', owasp: 'A01:2025 Broken Access Control',
  }),
  {
    id: 'supabase2026.service-role-in-client',
    severity: 'critical',
    confidence: 'high',
    title: 'service_role key referenced from client-side code',
    match(content, ctx) {
      const relPath = (ctx && ctx.relPath) || '';
      if (!/\.(?:tsx|jsx|ts|js)$/.test(relPath)) return [];
      const client = /['"]use client['"]/.test(content) || /(?:^|\/)components?\//.test(relPath) || /\.(?:tsx|jsx)$/.test(relPath);
      if (!client) return [];
      const idx = content.search(/(?:SUPABASE_SERVICE_ROLE|service_role|SERVICE_ROLE_KEY)/);
      if (idx < 0) return [];
      // Server-only marker in the same file makes it safe.
      if (/server-only|['"]use server['"]/.test(content)) return [];
      return [{ index: idx, match: 'service_role' }];
    },
    message:
      'A service_role key is used in a file that can be (or is) part of the client bundle. service_role bypasses RLS entirely — shipping it means the whole database is public.',
    fix: 'Never reference service_role outside server-only modules/route handlers. Use the anon key on the client and enforce RLS policies.',
    cwe: 'CWE-798', owasp: 'A02:2025 Security Misconfiguration',
  },
];

const firebase2026 = [
  makeLineRule({
    id: 'firebase2026.rules-allow-true',
    severity: 'critical',
    confidence: 'high',
    title: 'Firestore/Storage rules allow everyone',
    re: /allow\s+(?:read|write|read\s*,\s*write|write\s*,\s*read)\s*:\s*if\s*(?:true|\btrue\b)/i,
    fileFilter: /(?:firestore\.rules|storage\.rules|database\.rules)$/i,
    skipComments: true,
    message:
      'A Firebase rules file allows unauthenticated read/write. Anyone with the public config (which is in every client) can read, write and delete the collection.',
    fix: 'Scope rules to the owner: allow read, write: if request.auth != null && request.auth.uid == resource.data.userId.',
    cwe: 'CWE-284', owasp: 'A01:2025 Broken Access Control',
  }),
  makeLineRule({
    id: 'firebase2026.rules-auth-only-write',
    severity: 'medium',
    confidence: 'medium',
    title: 'Firebase write allowed for any authenticated user',
    re: /allow\s+write\s*:\s*if\s*request\.auth\s*!=\s*null\s*;/i,
    fileFilter: /(?:firestore|storage|database)\.rules$/i,
    skipComments: true,
    message:
      'Any signed-in user can write any document. "Logged in" is not "owns this row" — a second account can overwrite the first user\'s data.',
    fix: 'Compare identity to the record: request.auth.uid == resource.data.userId (and a separate create rule checking request.resource.data.userId).',
    cwe: 'CWE-284', owasp: 'A01:2025 Broken Access Control',
  }),
];

// ---------------------------------------------------------------------------
// 3. Auth: JWT, cookies, sessions, CSRF
// ---------------------------------------------------------------------------

const jwt2026 = [
  makeLineRule({
    id: 'jwt2026.decode-used-for-identity',
    severity: 'high',
    confidence: 'high',
    title: 'JWT decoded (not verified) and used as identity',
    re: /\bjwt(?:Decode|_decode|\s*)\.decode\s*\(|\bjwtDecode\s*\(|\batob\s*\(\s*\w+\.split\(['"]\.['"]\)\s*\[\s*1\s*\]/i,
    filter(line, hit, lines) { const idx = idxOf(lines, line);
    const ctx = lines ? lines.slice(idx, (idx) + 8).join('\n') : line;
      return /\b(?:userId|user_id|sub|role|email|admin|uid|identity|owner)\b/i.test(ctx);
    },
    skipComments: true,
    message:
      'A JWT is decoded without verifying its signature, then its claims are trusted. Anyone can forge `{"sub":"1","role":"admin"}` in base64 — full account takeover.',
    fix: 'Use jwt.verify(token, secret, { algorithms: ["HS256"] }) (or the framework session helper) and only trust verified claims.',
    cwe: 'CWE-347', owasp: 'A07:2025 Authentication Failures',
  }),
  makeLineRule({
    id: 'jwt2026.alg-none',
    severity: 'critical',
    confidence: 'high',
    title: 'JWT accepts the "none" algorithm',
    re: /algorithms?\s*:\s*\[?\s*['"]none['"]/i,
    skipComments: true,
    message:
      'The verifier accepts `alg: none`. An attacker strips the signature and the token is accepted as valid.',
    fix: 'Pin the expected algorithm (e.g. ["RS256"]) and reject everything else.',
    cwe: 'CWE-347', owasp: 'A07:2025 Authentication Failures',
  }),
  makeLineRule({
    id: 'jwt2026.weak-fallback-secret',
    severity: 'high',
    confidence: 'high',
    title: 'Session/JWT secret falls back to a literal',
    re: /(?:JWT_SECRET|NEXTAUTH_SECRET|SESSION_SECRET|AUTH_SECRET)\b[^;\n]{0,40}?\|\|\s*['"][^'"]{3,}['"]/i,
    skipComments: true,
    message:
      'The signing secret falls back to a hardcoded string. If the env var is missing in production (it usually is on first deploy), every token is forgeable with a value that is in the repo.',
    fix: 'Fail closed: if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET missing"). Generate 32+ random bytes.',
    cwe: 'CWE-798', owasp: 'A07:2025 Authentication Failures',
  }),
  makeLineRule({
    id: 'jwt2026.no-expiry',
    severity: 'medium',
    confidence: 'medium',
    title: 'JWT signed without an expiry',
    re: /\bjwt\.sign\s*\(\s*[^;]{0,200}\)\s*;/,
    filter(line) {
      return !/(?:expiresIn|exp\s*:)/.test(line);
    },
    skipComments: true,
    message:
      'A token is signed with no expiry. A leaked token stays valid forever; "logout" cannot revoke it.',
    fix: 'Add { expiresIn: "15m" } and a refresh flow, or use the framework session (which rotates).',
    cwe: 'CWE-613', owasp: 'A07:2025 Authentication Failures',
  }),
  makeLineRule({
    id: 'jwt2026.token-in-localstorage',
    severity: 'medium',
    confidence: 'medium',
    title: 'Session token stored in localStorage',
    re: /localStorage\.(?:setItem|getItem)\s*\(\s*['"](?:token|access_token|jwt|auth|session)['"]/i,
    skipComments: true,
    message:
      'An auth token is kept in localStorage, readable by any XSS. httpOnly cookies are not readable by script and are the right default.',
    fix: 'Set the session in an httpOnly, Secure, SameSite=Lax cookie server-side; keep localStorage for non-sensitive UI state only.',
    cwe: 'CWE-1004', owasp: 'A07:2025 Authentication Failures',
  }),
  makeLineRule({
    id: 'jwt2026.cookie-insecure',
    severity: 'medium',
    confidence: 'high',
    title: 'Session cookie without httpOnly/secure/sameSite',
    re: /cookie\s*:\s*\{|setCookie\s*\(|res\.cookie\s*\(/,
    filter(line) {
      // Must look like session/auth cookie context.
      if (!/(?:session|token|auth|jwt|sid)/i.test(line)) return false;
      return !/httpOnly\s*:\s*true/i.test(line) || !/secure\s*:\s*true/i.test(line);
    },
    skipComments: true,
    message:
      'A session-shaped cookie is set without the full httpOnly + secure + sameSite flags. Script-readable session cookies turn any XSS into account takeover; missing Secure leaks them over HTTP.',
    fix: 'cookies().set("session", v, { httpOnly: true, secure: true, sameSite: "lax", path: "/" }) — or the equivalent in your framework.',
    cwe: 'CWE-1004', owasp: 'A07:2025 Authentication Failures',
  }),
  makeLineRule({
    id: 'jwt2026.csrf-missing-state-route',
    severity: 'medium',
    confidence: 'low',
    title: 'Cookie-authenticated write route with no CSRF/origin check',
    re: /\b(?:app|router|server)\.(?:post|put|patch|delete)\s*\(/i,
    filter(line, hit, lines) { const idx = idxOf(lines, line);
    if (!lines) return false;
      
      const ctx = lines.slice(idx, Math.min(lines.length, idx + 25)).join('\n');
      const cookieAuth = /(?:req\.cookies|getSession|auth\(\)|session|cookie)/i.test(ctx);
      const writes = /(?:\.(?:create|update|delete|insert|save)|writeFile|sendMail|transfer)/i.test(ctx);
      const csrf = /(?:csrf|origin\s*!==|origin\s*===|x-csrf|sameSite\s*:\s*['"]strict|verifyOrigin)/i.test(ctx);
      return cookieAuth && writes && !csrf;
    },
    skipComments: true,
    message:
      'A cookie-authenticated state-changing route has no CSRF token and no Origin/Referer check. Another site can submit the request with the victim\'s cookies (CWE-352); 15/15 vibe-coded apps tested in the 2026 CSA note shipped without CSRF protection.',
    fix: 'Use SameSite=Lax/Strict cookies plus a double-submit CSRF token, or verify Origin on every unsafe method; use the framework\'s built-in CSRF helper.',
    cwe: 'CWE-352', owasp: 'A01:2025 Broken Access Control',
  }),
];

// ---------------------------------------------------------------------------
// 4. LLM output handling / agent safety / cost
// ---------------------------------------------------------------------------

const llm2026 = [
  makeLineRule({
    id: 'llm2026.output-to-exec',
    severity: 'critical',
    confidence: 'high',
    title: 'Model output reaches eval/exec (improper output handling)',
    re: /(?:eval|new\s+Function|exec|execSync|vm\.runIn\w+)\s*\(\s*(?:await\s+)?[\w.]*(?:completion|response|output|content|message|choices|answer|result|llm|ai)[\w.['"]{0,60}/i,
    skipComments: true,
    message:
      'Text returned by an LLM is executed as code. Prompt injection becomes RCE — the model (or a web page it read) controls the command (OWASP LLM05).',
    fix: 'Never execute model output. Map output to a fixed enum of actions, validate with a JSON schema, and parameterize any downstream call.',
    cwe: 'CWE-95', owasp: 'LLM05 Improper Output Handling',
  }),
  makeLineRule({
    id: 'llm2026.output-to-sql',
    severity: 'critical',
    confidence: 'medium',
    title: 'Model output interpolated into SQL',
    re: /(?:query|raw|execute|executeRawUnsafe|queryRawUnsafe)\s*\(\s*`[^`]*\$\{[^}]*(?:completion|response|answer|output|llm|choices|message)/i,
    skipComments: true,
    message:
      'SQL is built from model output. A prompt-injected response (or bad hallucination) runs arbitrary SQL (OWASP LLM05).',
    fix: 'Model output must never become SQL text. Map it to parameters or a fixed query chosen by a validated enum.',
    cwe: 'CWE-89', owasp: 'LLM05 Improper Output Handling',
  }),
  makeLineRule({
    id: 'llm2026.system-prompt-from-request',
    severity: 'high',
    confidence: 'high',
    title: 'System prompt built from request/user data',
    re: /role\s*:\s*['"]system['"]\s*,\s*content\s*:\s*(?:`[^`]*\$\{|[^,\n]*\+|[^,\n]*\breq\.)/i,
    skipComments: true,
    message:
      'A system message includes request data. The system slot is the trust boundary; injecting untrusted text there lets user content rewrite the instructions (OWASP LLM01).',
    fix: 'Keep the system prompt static; pass user content in the user/assistant role inside explicit delimiters, and never concatenate tool output into system.',
    cwe: 'CWE-1427', owasp: 'LLM01 Prompt Injection',
  }),
  makeLineRule({
    id: 'llm2026.tool-result-into-system',
    severity: 'high',
    confidence: 'medium',
    title: 'Tool/function result fed back into a system message',
    re: /(?:role\s*:\s*['"]system['"]|systemPrompt\s*[:=]|system_prompt\s*=)[^;\n]{0,120}(?:toolResult|tool_result|functionResult|toolOutput|result\.content|output\.content)/i,
    skipComments: true,
    message:
      'Tool output is inserted into the system prompt. Tool results are attacker-influenced (a web page, an email, a file) — this is the indirect prompt-injection path that turns a read-only tool into an instruction channel.',
    fix: 'Keep tool results in the tool role, label them as untrusted data, and require an explicit policy check before the model can act on them.',
    cwe: 'CWE-1427', owasp: 'LLM01 Prompt Injection',
  }),
  makeLineRule({
    id: 'llm2026.llm-call-no-max-tokens',
    severity: 'medium',
    confidence: 'medium',
    title: 'LLM call with no max_tokens / budget (cost blowup)',
    re: /(?:messages\.create|chat\.completions\.create|generateText|generateContent|completions\.create|responses\.create)\s*\(/,
    filter(line, hit, lines) { const idx = idxOf(lines, line);
    if (!lines) return false;
      
      const ctx = lines.slice(idx, Math.min(lines.length, idx + 15)).join('\n');
      if (/(?:max_tokens|maxTokens|maxOutputTokens|max_completion_tokens|max_output_tokens|budget)/.test(ctx)) return false;
      // Streaming calls need the cap too; a call with no cap is the signal.
      return true;
    },
    skipComments: true,
    message:
      'A paid model call has no output cap and no timeout. One user prompt (or an injected loop) can run up an unbounded bill (OWASP LLM10).',
    fix: 'Always pass max_tokens/maxOutputTokens, a timeout/AbortController, and a per-user rate limit on the route.',
    cwe: 'CWE-770', owasp: 'LLM10 Unbounded Consumption',
  }),
  makeLineRule({
    id: 'llm2026.agent-loop-no-cap',
    severity: 'medium',
    confidence: 'medium',
    title: 'Agent loop with no iteration/cost cap',
    re: /while\s*\(\s*(?:true|1|!?\s*(?:done|finished|complete))\s*\)|for\s*\(\s*;\s*;\s*\)/,
    filter(line, hit, lines) { const idx = idxOf(lines, line);
    if (!lines) return false;
      
      const ctx = lines.slice(idx, Math.min(lines.length, idx + 40)).join('\n');
      const agent = /(?:tool_calls|toolCalls|tools\s*:|generateText|chat\.completions|messages\.create|agent\.run|callModel|llm\()/i.test(ctx);
      const capped = /(?:maxIterations|max_steps|maxSteps|maxTurns|step\s*<\s*\d|COST_LIMIT|tokenBudget|break\b)/i.test(ctx);
      return agent && !capped;
    },
    skipComments: true,
    message:
      'An agent loop calls a model/tool until `done`, with no step, token or cost ceiling. A tool that returns a "not finished" response spins forever — unbounded spend and a stuck worker (OWASP LLM06/LLM10).',
    fix: 'Add maxIterations (e.g. 8), a token budget, a wall-clock timeout, and a hard stop that surfaces to the user.',
    cwe: 'CWE-834', owasp: 'LLM06 Excessive Agency',
  }),
  makeLineRule({
    id: 'llm2026.tool-schema-raw-command',
    severity: 'high',
    confidence: 'medium',
    title: 'Tool schema accepts a raw command/shell string',
    re: /(?:command|shell|cmd|script|exec)\s*:\s*\{\s*type\s*:\s*['"]string['"]/i,
    filter(line, hit, lines) { const idx = idxOf(lines, line);
    if (!lines) return false;
      
      const ctx = lines.slice(Math.max(0, idx - 8), Math.min(lines.length, idx + 20)).join('\n');
      return /(?:description|name)\s*:/.test(ctx); // it is a tool schema, not a config
    },
    skipComments: true,
    message:
      'A tool exposes a free-form command/shell string to the model. The model is a confused deputy: injected text (a file, a web page) can dictate that command (OWASP Agentic ASI02/ASI05).',
    fix: 'Expose typed, enumerated actions (e.g. { op: "list" | "read", path }) instead of a shell string; sandbox the executor and require confirmation for destructive ops.',
    cwe: 'CWE-78', owasp: 'LLM06 Excessive Agency',
  }),
  makeLineRule({
    id: 'llm2026.memory-write-from-untrusted',
    severity: 'medium',
    confidence: 'medium',
    title: 'Unscreened tool/web output written to agent memory',
    re: /(?:memory|memories|vectorstore|vectorStore|index)\.(?:save|addDocuments|upsert|insert|add)\s*\(/i,
    filter(line) {
      return /(?:toolResult|tool_result|webpage|scrape|html|response\.text|content|toolOutput)/i.test(line);
    },
    skipComments: true,
    message:
      'Raw tool/web content is persisted to long-term memory. Poisoned content survives the session and steers every later answer (memory poisoning, OWASP Agentic ASI06).',
    fix: 'Sanitize and label provenance before persisting; keep agent-written memory out of the trusted instruction channel; expire it.',
    cwe: 'CWE-349', owasp: 'LLM04 Data and Model Poisoning',
  }),
  makeLineRule({
    id: 'llm2026.permission-bypass',
    severity: 'high',
    confidence: 'high',
    title: 'Agent permission/sandbox bypass enabled',
    re: /(?:dangerously[-_ ]?skip[-_ ]?permissions|--dangerously-skip-permissions|bypassPermissions|autoApproveAll|allowAllTools|dangerouslyAllowAll|skipPermissions\s*:\s*true)/i,
    skipComments: false,
    message:
      'An agent is configured to skip human approval or sandbox controls. Every prompt injection now executes without a human gate (OWASP Agentic ASI10).',
    fix: 'Remove the bypass in shared code/config; scope tools and require confirmation for write/deploy/delete actions.',
    cwe: 'CWE-250', owasp: 'LLM06 Excessive Agency',
  }),
  makeLineRule({
    id: 'llm2026.rag-no-tenant-filter',
    severity: 'medium',
    confidence: 'medium',
    title: 'Vector search without a tenant/user filter',
    re: /(?:similaritySearch|similarity_search|asRetriever|vectorSearch|retrieve)\s*\(/i,
    filter(line) {
      return !/(?:filter|where|namespace|userId|user_id|tenant|orgId|metadata)/i.test(line);
    },
    skipComments: true,
    message:
      'Retrieval runs against the whole index with no tenant predicate. One customer\'s documents (and system prompt fragments) surface in another customer\'s answer (OWASP LLM08).',
    fix: 'Pass a metadata filter with the caller\'s tenant id and use per-tenant namespaces where the vector store supports them.',
    cwe: 'CWE-284', owasp: 'LLM08 Vector and Embedding Weaknesses',
  }),
];

// ---------------------------------------------------------------------------
// 5. Crypto (CWE-327 — AI code's worst class after log injection)
// ---------------------------------------------------------------------------

const crypto2026 = [
  makeLineRule({
    id: 'crypto2026.weak-hash-for-password',
    severity: 'high',
    confidence: 'high',
    title: 'MD5/SHA-1 used for passwords',
    re: /createHash\s*\(\s*['"](?:md5|sha1)['"]|hashlib\.(?:md5|sha1)\s*\(|MessageDigest\.getInstance\(\s*['"](?:MD5|SHA-?1)['"]/i,
    filter(line) {
      return /(?:password|passwd|pwd|secret|token)/i.test(line);
    },
    skipComments: true,
    message:
      'A fast, broken hash is used for password material. GPU cracking recovers passwords at billions/sec; nobody should ship md5/sha1 for credentials.',
    fix: 'Use bcrypt/argon2/scrypt (cost 10-12 for bcrypt) or the framework auth provider — never createHash for passwords.',
    cwe: 'CWE-327', owasp: 'A02:2025 Cryptographic Failures',
  }),
  makeLineRule({
    id: 'crypto2026.math-random-token',
    severity: 'high',
    confidence: 'high',
    title: 'Math.random()/random.random() for a token or OTP',
    re: /(?:Math\.random\(\)|random\.random\(\)|new\s+Random\(\))/i,
    filter(line) {
      // Security-relevant name either side of the PRNG call: `otp = Math.random…`
      // or `Math.random(…).toString(36)` assigned to `token`. Requiring both the
      // PRNG and a security word on the same line keeps paint jitter out.
      const securityWord = /\b(?:token|otp|one[- ]?time|code|password|secret|nonce|session|reset|api[_-]?key|salt|csrf|verification)\b/i;
      if (!securityWord.test(line)) return false;
      if (/(?:uuid|test|mock|seed|jitter|retry|delay|animation|styling|color|theme)/i.test(line)) return false;
      return true;
    },
    skipComments: true,
    message:
      'A predictor is used to generate a security token/OTP. Math.random() is seedable and observed output predicts the next value.',
    fix: 'Use crypto.randomBytes(32) / crypto.randomUUID() (or secrets.token_urlsafe in Python) for anything security-relevant.',
    cwe: 'CWE-338', owasp: 'A02:2025 Cryptographic Failures',
  }),
  makeLineRule({
    id: 'crypto2026.ecb-mode',
    severity: 'high',
    confidence: 'high',
    title: 'AES-ECB mode',
    re: /aes-\d+-ecb|createCipheriv\s*\(\s*['"]aes-[^'"]*-ecb/i,
    skipComments: true,
    message:
      'ECB encrypts identical plaintext blocks identically — patterns survive encryption (and it is unauthenticated).',
    fix: 'Use aes-256-gcm (or chacha20-poly1305) with a random 12-byte IV and authenticate the tag.',
    cwe: 'CWE-327', owasp: 'A02:2025 Cryptographic Failures',
  }),
  makeLineRule({
    id: 'crypto2026.static-iv',
    severity: 'high',
    confidence: 'medium',
    title: 'Static IV/nonce in encryption',
    re: /createCipheriv\s*\([^;]{0,200}(?:iv|nonce)\s*[:=]\s*(?:Buffer\.from\(\s*['"][^'"]+['"]|['"][A-Za-z0-9+/=]{8,}['"]|Buffer\.alloc\s*\(\s*\d+\s*\))/i,
    skipComments: true,
    message:
      'A hardcoded/zero IV is reused for every message. Reuse breaks confidentiality (identifiable ciphertexts, keystream reuse) even with a strong cipher.',
    fix: 'Generate a fresh random IV per encryption (crypto.randomBytes(12) for GCM) and store it next to the ciphertext.',
    cwe: 'CWE-329', owasp: 'A02:2025 Cryptographic Failures',
  }),
  makeLineRule({
    id: 'crypto2026.timing-unsafe-compare',
    severity: 'medium',
    confidence: 'medium',
    title: 'Secret compared with === / == (timing leak)',
    re: /(?:password|api[_-]?key|token|secret|signature|hmac)\w*\s*(?:===?|!==?)\s*(?:req\.|request\.|body\.|query\.|headers|params\.|['"])/i,
    skipComments: true,
    message:
      'A secret is compared with a normal equality operator, which short-circuits on the first differing byte — a timing oracle for tokens/API keys.',
    fix: 'Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) with equal lengths (or hmac.compare_digest in Python).',
    cwe: 'CWE-208', owasp: 'A02:2025 Cryptographic Failures',
  }),
  makeLineRule({
    id: 'crypto2026.jwt-alg-verify-disabled',
    severity: 'high',
    confidence: 'high',
    title: 'Signature verification disabled',
    re: /verify\s*:\s*false|verify_signature\s*:\s*false|jwt\.verify\([^)]*\{\s*algorithms\s*:\s*\[\s*\]/i,
    skipComments: true,
    message:
      'Signature/verification is explicitly disabled. The token or webhook is accepted from anyone.',
    fix: 'Enable verification with a pinned algorithm and key, and verify webhook signatures with the provider\'s SDK.',
    cwe: 'CWE-347', owasp: 'A07:2025 Authentication Failures',
  }),
];

// ---------------------------------------------------------------------------
// 6. Log injection / PII in logs (CWE-117 — 88% failure in Veracode)
// ---------------------------------------------------------------------------

const leak2026 = [
  makeLineRule({
    id: 'leak2026.log-injection-request-interpolation',
    severity: 'medium',
    confidence: 'medium',
    title: 'Request data interpolated into a log line (log injection)',
    re: /\b(?:console\.(?:log|info|warn|error|debug)|logger\.(?:info|warn|error|debug)|log\.(?:info|warn|error)|print\s*\(|logging\.(?:info|warning|error|debug)\s*\()/i,
    filter(line) {
      // Two signals: a log/print call and a request-derived value on the line.
      const requestData = /\b(?:req\.(?:body|query|params|headers|cookies)|request\.(?:body|query|params|form|json|headers)|ctx\.(?:body|query|params)|searchParams\.get\(|params\.|\bbody\.)/i;
      if (!requestData.test(line)) return false;
      if (/(?:sanitize|escape|redact|\[REDACTED\]|JSON\.stringify\([^)]*req)/i.test(line)) return false;
      return true;
    },
    skipComments: true,
    message:
      'Raw request data is interpolated into a log message. Newlines let an attacker forge log entries, and the value usually carries secrets/PII (CWE-117, the most-failed class in the 2025 Veracode GenAI report).',
    fix: 'Log structured fields (logger.info({ userId, route }, "msg")) with an encoder, or JSON.stringify the values; never concatenate raw input.',
    cwe: 'CWE-117', owasp: 'A09:2025 Security Logging and Alerting Failures',
  }),
  makeLineRule({
    id: 'leak2026.logs-auth-header',
    severity: 'high',
    confidence: 'high',
    title: 'Authorization header / token logged',
    re: /(?:console\.(?:log|info|warn|error)|logger\.\w+|log\.\w+|print\s*\(|logging\.\w+\s*\()\s*\([^;\n]{0,120}(?:authorization|bearer|api[_-]?key|access[_-]?token|refresh[_-]?token|req\.headers|request\.headers)/i,
    skipComments: true,
    message:
      'A credential is written to logs. Logs are copied to observability vendors, bug reports and AI agents — one line can leak a live token (GitGuardian 2026: AI-assisted commits leak at 3.2% vs 1.5%).',
    fix: 'Never log headers/tokens. Log an identifier (userId, requestId) and redact the rest; add a log scrubber at the transport.',
    cwe: 'CWE-532', owasp: 'A09:2025 Security Logging and Alerting Failures',
  }),
  makeLineRule({
    id: 'leak2026.error-stack-to-client',
    severity: 'high',
    confidence: 'high',
    title: 'Stack trace / error internals returned to the client',
    re: /(?:res|response|reply)\.(?:json|send|status\([^)]*\)\.json)\s*\(\s*\{[^}]{0,200}(?:e\.stack|err\.stack|error\.stack|\.stack\b|e\.message\s*,\s*e\.stack)/i,
    skipComments: true,
    message:
      'A raw error with stack/message goes to the client. It exposes file paths, SQL and internal library versions — the reconnaissance step of most exploits.',
    fix: 'Return a generic message plus an error id; log the detail server-side.',
    cwe: 'CWE-209', owasp: 'A02:2025 Security Misconfiguration',
  }),
  makeLineRule({
    id: 'leak2026.debug-endpoint',
    severity: 'high',
    confidence: 'high',
    title: 'Debug/admin endpoint exposed in app code',
    re: /(?:app|router|server)\.(?:get|post|all)\s*\(\s*['"]\/(?:debug|__debug|dev|__dev|admin\/debug|_test)[^'"]*['"]/i,
    skipComments: true,
    message:
      'A debug/dev endpoint is registered unconditionally. These return env, DB state or arbitrary query results in production.',
    fix: 'Register it only under a NODE_ENV check and an admin guard, or move it out of the deployed app.',
    cwe: 'CWE-489', owasp: 'A05:2025 Security Misconfiguration',
  }),
];

// ---------------------------------------------------------------------------
// 7. Secrets: formats generators leak that regex packs miss
// ---------------------------------------------------------------------------

// Narrow, well-prefixed, high-entropy providers. Kept here (not in rules-pack)
// because they postdate most rule sets: DeepSeek/OpenRouter/Groq/HF/pscale etc.
const secretRe = (prefix, minLen, label, fix) => ({
  id: `secret2026.${label}`,
  severity: 'critical',
  confidence: 'high',
  title: `${label.replace(/-/g, ' ')} leaked`,
  re: new RegExp(`['"\`](${prefix}[A-Za-z0-9_-]{${minLen},})['"\`]`),
  skipComments: false,
  message: `A ${label.replace(/-/g, ' ')} is hardcoded in tracked code. Secret scanning in CI cannot stop the push that already happened — rotate and move it to an env var.`,
  fix: `${fix || 'Rotate the key now, remove it from the file, move it to .env (gitignored) and use the AI tool credentials store for local runs.'}`,
  cwe: 'CWE-798', owasp: 'A02:2025 Security Misconfiguration',
});

const secret2026 = [
  secretRe('sk-or-v1-', 32, 'openrouter-key'),
  secretRe('gsk_', 32, 'groq-key'),
  secretRe('hf_', 24, 'huggingface-token'),
  secretRe('nvapi-', 20, 'nvidia-api-key'),
  secretRe('r8_', 20, 'replicate-token'),
  secretRe('pscale_tkn_', 16, 'planetscale-token'),
  secretRe('vercel_', 20, 'vercel-token'),
  secretRe('shpat_', 24, 'shopify-admin-token'),
  secretRe('sbp_', 20, 'supabase-access-token'),
  secretRe('github_pat_', 20, 'github-fine-grained-pat'),
  secretRe('rzp_live_', 12, 'razorpay-live-key'),
  secretRe('dop_v1_', 24, 'digitalocean-token'),
  {
    id: 'secret2026.supabase-service-role-jwt',
    severity: 'critical',
    confidence: 'high',
    title: 'Supabase service_role JWT',
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    filter(line, hit) {
      const tok = (hit && hit.match) || '';
      const parts = tok.split('.');
      if (parts.length !== 3) return false;
      try {
        const payload = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
        return /"role"\s*:\s*"service_role"/.test(payload);
      } catch {
        return false;
      }
    },
    skipComments: false,
    message:
      'A Supabase JWT with role=service_role is in the source. It bypasses every RLS policy — the anon key is public by design, this key is not.',
    fix: 'Rotate the JWT secret (this invalidates the key), keep service_role only in server env vars, and access it through a server-only client.',
    cwe: 'CWE-798', owasp: 'A02:2025 Security Misconfiguration',
  },
  {
    id: 'secret2026.private-key-block',
    severity: 'critical',
    confidence: 'high',
    title: 'Private key committed',
    re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/,
    filter(line, hit, lines) { const idx = idxOf(lines, line);
    // Fixtures/tests are common; keep them but at lower noise if obviously fake.
      const ctx = lines ? lines.slice(idx, (idx) + 4).join('\n') : line;
      return !/(?:BEGIN PRIVATE KEY-----\\n'|test|fixture|dummy|example|placeholder)/i.test(ctx);
    },
    skipComments: false,
    message:
      'A private key is committed. Anything signed or encrypted with it is compromised until rotated — historical copies survive in forks and caches.',
    fix: 'Revoke/rotate the key pair, remove it from the working tree and git history (git filter-repo), and load keys from a secret manager.',
    cwe: 'CWE-798', owasp: 'A02:2025 Security Misconfiguration',
  },
];

// ---------------------------------------------------------------------------
// 8. Supply chain / CI / containers / IaC
// ---------------------------------------------------------------------------

const supply2026 = [
  {
    id: 'supply2026.postinstall-network-shell',
    severity: 'critical',
    confidence: 'high',
    title: 'Install script downloads and executes code',
    run(content, lines, relPath) {
      if (!/package\.json$/.test(relPath || '')) return [];
      let pkg;
      try { pkg = JSON.parse(content); } catch { return []; }
      const scripts = pkg.scripts || {};
      const risky = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'];
      const out = [];
      const re = /(?:curl|wget|Invoke-WebRequest|iwr|iex|powershell|bash\s+-c|sh\s+-c|node\s+-e|base64\s+(?:-d|--decode)|eval\b|child_process|process\.env)/i;
      for (const name of risky) {
        const cmd = scripts[name];
        if (typeof cmd !== 'string' || !re.test(cmd)) continue;
        const idx = content.indexOf(cmd);
        out.push({
          line: idx >= 0 ? content.slice(0, idx).split('\n').length : 1,
          column: 1,
          snippet: `${name}: ${cmd.slice(0, 100)}`,
          message: `The "${name}" script downloads/executes code or touches the environment at install time. This is how npm supply-chain malware (postinstall RCE) runs on every deploy, and it is invisible to a code review of dependencies.`,
          fix: 'Remove network/shell work from install scripts. If a build step is required, make it explicit (npm run build) and pin it in CI after review.',
        });
      }
      return out;
    },
  },
  makeLineRule({
    id: 'supply2026.unpinned-npx-install',
    severity: 'medium',
    confidence: 'medium',
    title: 'Unpinned npx/uvx auto-install (MCP/server bootstrap)',
    re: /\b(?:npx|uvx|bunx)\s+(?:-y|--yes)\s+(?:@?[\w./-]+)(?:\s|['"`]|$)/,
    filter(line) {
      // A pinned version (pkg@1.2.3) is the safe form.
      const m = /(?:npx|uvx|bunx)\s+(?:-y|--yes)\s+([@\w./-]+)/.exec(line);
      if (!m) return false;
      const spec = m[1];
      if (/vibeguard/i.test(spec)) return false; // documented self-invocation
      return !/@\d+\.\d+/.test(spec);
    },
    skipComments: true,
    message:
      'An unpinned package is fetched and run at startup. The registry version can change (or be hijacked) after review — a rug pull, not a reproducible bootstrap.',
    fix: 'Pin the exact version (npx -y package@1.4.2) and record it in the config; update deliberately.',
    cwe: 'CWE-829', owasp: 'A06:2025 Vulnerable and Outdated Components',
  }),
  {
    id: 'supply2026.dependency-confusion-scoped-private',
    severity: 'medium',
    confidence: 'low',
    title: 'Scoped dependency could be claimed on public npm',
    run(content, lines, relPath) {
      if (!/package\.json$/.test(relPath || '')) return [];
      let pkg;
      try { pkg = JSON.parse(content); } catch { return []; }
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      const names = Object.keys(deps);
      // Only scopes that no registry config pins to a private feed.
      const npmrc = (() => {
        // A sibling .npmrc is not visible here; treat as unknown.
        return '';
      })();
      const out = [];
      for (const name of names) {
        const m = /^@([\w.-]+)\/([\w.-]+)$/.exec(name);
        if (!m) continue;
        const scope = m[1];
        // The project's own package name scope is internal by definition (it is
        // published); everything else scoped is a private-name candidate.
        const own = pkg.name && pkg.name.startsWith(`@${scope}/`);
        if (own) continue;
        const idx = content.indexOf(`"${name}"`);
        out.push({
          line: idx >= 0 ? content.slice(0, idx).split('\n').length : 1,
          column: 1,
          snippet: name,
          message: `Dependency ${name} is a scoped private name with no registry pin visible here. If the scope is unclaimed on public npm, an attacker can publish it and npm may prefer the public version (dependency confusion).`,
          fix: `Pin scopes to the private registry in .npmrc (@${scope}:registry=https://your-registry/) and use --ignore-scripts in CI installs.`,
        });
      }
      return out.slice(0, 20);
    },
  },
  {
    id: 'supply2026.lockfile-no-integrity',
    severity: 'medium',
    confidence: 'medium',
    title: 'Lockfile has no integrity hashes',
    run(content, lines, relPath) {
      if (!/(?:package-lock\.json|npm-shrinkwrap\.json)$/.test(relPath || '')) return [];
      // v1 lockfiles can legitimately lack integrity in old projects; a v2/v3
      // lockfile without any integrity means tampering/proxy stripping.
      const version = (/"lockfileVersion"\s*:\s*(\d)/.exec(content) || [])[1];
      if (!version || Number(version) < 2) return [];
      const hasIntegrity = /"integrity"\s*:/.test(content);
      if (hasIntegrity) return [];
      return [{ line: 1, column: 1, snippet: `lockfileVersion ${version}, 0 integrity fields` }];
    },
    message:
      'A modern npm lockfile has zero `integrity` fields. Installs cannot verify tarball contents, so a registry/proxy compromise or a mutated package goes unnoticed.',
    fix: 'Regenerate the lockfile with npm install (it writes integrity normally), commit it, and pin the registry over HTTPS.',
    cwe: 'CWE-829',
  },
  makeLineRule({
    id: 'supply2026.npmrc-http-registry',
    severity: 'high',
    confidence: 'high',
    title: '.npmrc uses an insecure/overridden registry',
    re: /^\s*(?:registry|@[\w-]+:registry)\s*=\s*http:/i,
    fileFilter: /(?:\.npmrc|\.yarnrc(?:\.yml)?)$/i,
    message:
      'Packages are fetched over plain HTTP. A network attacker can replace any tarball with malware (install scripts run on deploy).',
    fix: 'Use https:// (or a pinned internal registry over TLS); set strict-ssl=true and never commit auth tokens.',
    cwe: 'CWE-319', owasp: 'A06:2025 Vulnerable and Outdated Components',
  }),
  makeLineRule({
    id: 'supply2026.npmrc-auth-token-committed',
    severity: 'critical',
    confidence: 'high',
    title: 'npm auth token committed in .npmrc',
    re: /(?:_authToken|_auth|_password)\s*=\s*[A-Za-z0-9+/=_-]{8,}/i,
    fileFilter: /(?:\.npmrc|\.yarnrc(?:\.yml)?)$/i,
    message:
      'A registry auth token is committed. Anyone with the repo (including every AI agent that reads it) can publish/read under your account.',
    fix: 'Remove it, rotate the token, and use ${NPM_TOKEN} expansion in .npmrc with the token only in CI secrets.',
    cwe: 'CWE-798', owasp: 'A06:2025 Vulnerable and Outdated Components',
  }),
  makeLineRule({
    id: 'supply2026.ci-unpinned-action',
    severity: 'medium',
    confidence: 'medium',
    title: 'Third-party GitHub Action pinned to a branch/tag',
    re: /uses\s*:\s*([\w.-]+\/[\w.-]+)@(?:main|master|latest|HEAD)\b/i,
    fileFilter: /\.github\/workflows\/.*\.ya?ml$/i,
    message:
      'An action is pinned to a mutable ref. If the action repo is compromised or its maintainer retags, the next workflow run executes attacker code with your repository secrets.',
    fix: 'Pin third-party actions to a full commit SHA (with the version in a comment) and enable Dependabot for actions.',
    cwe: 'CWE-829', owasp: 'A06:2025 Vulnerable and Outdated Components',
  }),
  makeLineRule({
    id: 'supply2026.ci-user-input-in-run',
    severity: 'critical',
    confidence: 'high',
    title: 'Pull request text interpolated into a shell step (script injection)',
    re: /\$\{\{\s*github\.event\.(?:pull_request|issue|discussion)\.(?:title|body|head\.ref|head\.label|message|comment\.body)/i,
    fileFilter: /\.github\/workflows\/.*\.ya?ml$/i,
    skipComments: false,
    message:
      'A PR title/body/branch name is interpolated into a workflow `run:` step. The shell executes the attacker\'s text with your token — arbitrary code in CI (script injection).',
    fix: 'Pass untrusted values through env: and reference "$GITHUB_EVENT_PATH" / "${{ env.TITLE }}"; never inline them into the script.',
    cwe: 'CWE-78', owasp: 'A03:2025 Injection',
  }),
];

const container2026 = [
  makeLineRule({
    id: 'container2026.docker-secret-in-env-or-arg',
    severity: 'high',
    confidence: 'medium',
    title: 'Secret baked into image via ENV/ARG',
    re: /^\s*(?:ENV|ARG)\s+[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY|API_KEY|CREDENTIAL)[A-Z0-9_]*\s*[=\s]+\S+/i,
    fileFilter: /(?:Dockerfile|\.dockerfile)$/i,
    filter(line) {
      return !/\$\{/ .test(line); // ARG with a runtime-provided value is not baked
    },
    message:
      'A secret is written into an image layer. Anyone who pulls the image (or the registry cache) reads it, and `docker history` shows it.',
    fix: 'Use build secrets (BuildKit --mount=type=secret) or runtime env injection; never ENV/ARG a credential.',
    cwe: 'CWE-798', owasp: 'A02:2025 Security Misconfiguration',
  }),
  makeLineRule({
    id: 'container2026.docker-published-db-port',
    severity: 'medium',
    confidence: 'high',
    title: 'Database port published to the host',
    re: /^\s*-\s*["']?(?:5432|3306|6379|27017|5433|1433|9200):/m,
    fileFilter: /(?:docker-compose|compose)\.ya?ml$/i,
    skipComments: true,
    message:
      'A database port is mapped to the host without a bind address. Any process (or network, on a cloud VM without a firewall) reaches the DB; the generated password is often "postgres".',
    fix: 'Remove the ports mapping (services talk over the compose network) or bind to 127.0.0.1: "127.0.0.1:5432:5432".',
    cwe: 'CWE-284', owasp: 'A05:2025 Security Misconfiguration',
  }),
  makeLineRule({
    id: 'container2026.container-runs-as-root',
    severity: 'medium',
    confidence: 'low',
    title: 'Container has no non-root USER',
    re: /^\s*FROM\s+\S+/i,
    fileFilter: /(?:Dockerfile|\.dockerfile)$/i,
    filter(line, hit, lines) {
      if (!lines) return false;
      return !lines.some((l) => /^\s*USER\s+(?!root\b)\S+/i.test(l));
    },
    message:
      'The image never switches to a non-root user. A container escape or app RCE starts with root inside the container and escalates host mounts.',
    fix: 'Create a non-root user in the Dockerfile (RUN adduser --system app) and add USER app before the entrypoint.',
    cwe: 'CWE-250',
  }),
  makeLineRule({
    id: 'container2026.compose-privileged',
    severity: 'high',
    confidence: 'high',
    title: 'Compose service runs privileged / mounts docker.sock',
    re: /privileged\s*:\s*true|\/var\/run\/docker\.sock/i,
    fileFilter: /(?:docker-compose|compose)\.ya?ml$/i,
    skipComments: true,
    message:
      'A service is privileged or holds the Docker socket. That is root on the host — any RCE in the app owns the machine.',
    fix: 'Drop privileged; replace docker.sock access with a scoped API proxy; mount only the directories needed.',
    cwe: 'CWE-250', owasp: 'A05:2025 Security Misconfiguration',
  }),
];

// Terraform: the open-cidr rule needs a few lines of context (port + cidr blocks).
const cloud2026 = [
  {
    id: 'cloud2026.terraform-open-admin-ports',
    severity: 'high',
    confidence: 'medium',
    title: 'Terraform security group open to the world on an admin port',
    run(content, lines, relPath) {
      if (!/\.(tf|hcl)$/.test(relPath || '')) return [];
      const out = [];
      const cidrRe = /0\.0\.0\.0\/0/g;
      let m;
      while ((m = cidrRe.exec(content)) !== null) {
        const idx = content.slice(0, m.index).split('\n').length - 1;
        const ctx = lines.slice(Math.max(0, idx - 6), idx + 4).join('\n');
        const adminPort = /\b(?:22|3389|5432|3306|6379|27017|9200|2375|2376)\b/.test(ctx);
        const httpPort = /\b(?:80|443)\b/.test(ctx);
        if (!adminPort || httpPort) continue;
        out.push({
          line: idx + 1,
          column: 1,
          snippet: '0.0.0.0/0 on an administrative port',
          message:
            'A security group admits 0.0.0.0/0 on an administrative port (SSH/DB/Redis/K8s API). AI-generated Terraform copies the quickstart allow-all and ships a database to the internet.',
          fix: 'Restrict to a bastion/VPN CIDR (var.admin_cidr), or remove the public ingress and use SSM/session-manager.',
        });
        if (out.length >= 5) break;
      }
      return out;
    },
  },
  makeLineRule({
    id: 'cloud2026.terraform-public-bucket',
    severity: 'high',
    confidence: 'medium',
    title: 'Terraform S3 bucket publicly readable',
    re: /acl\s*=\s*["']public-read(?:-write)?["']|block_public_acls\s*=\s*false/i,
    fileFilter: /\.tf$/i,
    skipComments: true,
    message:
      'The bucket is public. Every object (uploads, backups, user files) is world-readable, and public-write buckets are used to host malware.',
    fix: 'Keep ACLs private (block_public_acls = true, ignore_public_acls = false) and serve files through signed URLs or CloudFront.',
    cwe: 'CWE-284', owasp: 'A05:2025 Security Misconfiguration',
  }),
  makeLineRule({
    id: 'cloud2026.aws-wildcard-iam',
    severity: 'high',
    confidence: 'medium',
    title: 'IAM policy with wildcard Action and Resource',
    re: /Action\s*[:=]\s*["']\*["'][\s\S]{0,120}?Resource\s*[:=]\s*["']\*["']|Resource\s*[:=]\s*["']\*["'][\s\S]{0,120}?Action\s*[:=]\s*["']\*["']/,
    fileFilter: /\.(tf|json|ya?ml)$/i,
    skipComments: true,
    message:
      'An IAM policy grants * on *. Any RCE or leaked credential with this role owns the whole account (delete backups, exfiltrate everything).',
    fix: 'Scope actions and resources to what the service uses; add a condition (aws:SourceAccount / SourceArn) for cross-service access.',
    cwe: 'CWE-269', owasp: 'A01:2025 Broken Access Control',
  }),
];

// ---------------------------------------------------------------------------
// 9. Web-app basics generators still miss
// ---------------------------------------------------------------------------

const api2026 = [
  makeLineRule({
    id: 'api2026.cors-wildcard-credentials',
    severity: 'high',
    confidence: 'high',
    title: 'CORS allows every origin with credentials',
    re: /origin\s*:\s*(?:true|['"]\*['"]|\([^)]*\)\s*=>\s*[^,\n]*)\s*,\s*credentials\s*:\s*true|Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"][\s\S]{0,80}Allow-Credentials['"]?\s*[,:]\s*['"]true/i,
    skipComments: true,
    message:
      'Any website can send credentialed requests to this API and read the response. With session cookies, that is a full cross-site account takeover.',
    fix: 'Allowlist origins from config and never combine "*" (or reflected Origin) with credentials:true.',
    cwe: 'CWE-942', owasp: 'A05:2025 Security Misconfiguration',
  }),
  makeLineRule({
    id: 'api2026.graphql-introspection-prod',
    severity: 'low',
    confidence: 'medium',
    title: 'GraphQL introspection/playground enabled unconditionally',
    re: /introspection\s*:\s*true|playground\s*:\s*true/i,
    skipComments: true,
    message:
      'Introspection/playground is enabled without an environment check, exposing the whole schema and mutation surface in production.',
    fix: 'Enable only when NODE_ENV !== "production", or gate behind admin auth.',
    cwe: 'CWE-200', owasp: 'A05:2025 Security Misconfiguration',
  }),
  makeLineRule({
    id: 'api2026.postmessage-no-origin',
    severity: 'medium',
    confidence: 'medium',
    title: 'message listener without origin check',
    re: /addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:async\s*)?(?:\(|function)/,
    filter(line, hit, lines) { const idx = idxOf(lines, line);
    if (!lines) return false;
      
      const ctx = lines.slice(idx, Math.min(lines.length, idx + 12)).join('\n');
      return !/(?:event|e|evt)\.origin|origin\s*!==|origin\s*===|allowedOrigin/i.test(ctx);
    },
    skipComments: true,
    message:
      'A postMessage handler does not verify event.origin. Any embedded/open page can send it messages and drive privileged actions.',
    fix: 'Check e.origin against an allowlist at the top of the handler (and validate the payload shape).',
    cwe: 'CWE-346', owasp: 'A01:2025 Broken Access Control',
  }),
  makeLineRule({
    id: 'api2026.upload-unrestricted',
    severity: 'medium',
    confidence: 'medium',
    title: 'File upload without size/type limits',
    re: /multer\s*\(\s*\{|busboy\s*\(|formidable\s*\(|formData\s*\(\s*\)/,
    filter(line, hit, lines) { const idx = idxOf(lines, line);
    const ctx = lines ? lines.slice(idx, (idx) + 12).join('\n') : line;
      return !/(?:limits|fileSize|maxFileSize|mimetype|mimeType|allowedTypes|accept)/i.test(ctx);
    },
    skipComments: true,
    message:
      'An upload handler has no size or MIME allowlist. Attackers upload multi-GB files (disk/cost DoS), .html/.svg (stored XSS) or polyglots.',
    fix: 'Set limits.fileSize, allowlist MIME + extension, store outside the web root with a random name, and serve with Content-Disposition/Content-Type set.',
    cwe: 'CWE-434', owasp: 'A04:2025 Insecure Design',
  }),
  makeLineRule({
    id: 'api2026.ssrf-metadata-url',
    severity: 'critical',
    confidence: 'high',
    title: 'Outbound fetch to a user-controllable URL (SSRF)',
    re: /(?:fetch|axios(?:\.get|\.post)?|got|requests\.(?:get|post)|http\.get)\s*\(\s*(?:req\.|request\.|ctx\.|body\.|params\.|searchParams|query\.)/i,
    skipComments: true,
    message:
      'A URL taken from the request is fetched directly. The server\'s network position lets the caller hit 169.254.169.254 (cloud credentials), localhost admin ports and internal services.',
    fix: 'Parse with new URL(), allowlist schemes/hosts, block private/link-local ranges after DNS resolution, and disable redirects.',
    cwe: 'CWE-918', owasp: 'A01:2025 Broken Access Control',
  }),
  makeLineRule({
    id: 'api2026.raw-sql-unsafe',
    severity: 'critical',
    confidence: 'high',
    title: 'Unsafe raw SQL API (queryRawUnsafe / executeRawUnsafe / sql.raw)',
    re: /\$(?:query|execute)RawUnsafe\s*\(|\bsql\.raw\s*\(|\bknex\.raw\s*\(\s*[`'"].*\$\{/i,
    skipComments: true,
    message:
      'An explicitly-unsafe raw API is used. These bypass parameterization by design — any interpolated value is SQL injection.',
    fix: 'Use the tagged-template form ($queryRaw`...${value}`) or parameterized calls; never build the string yourself.',
    cwe: 'CWE-89', owasp: 'A03:2025 Injection',
  }),
  makeLineRule({
    id: 'api2026.header-injection',
    severity: 'high',
    confidence: 'medium',
    title: 'Request data written into a response header',
    re: /(?:res|response|reply)\.(?:setHeader|header|set)\s*\(\s*[^,)]+,\s*[^)]*(?:req\.|request\.|ctx\.|searchParams|params\.)/i,
    skipComments: true,
    message:
      'Request data is used as a response header value. CR/LF in the value splits the response and can set arbitrary headers/cookies (CWE-113).',
    fix: 'Validate/strip \\r and \\n, or map the value to an enum before setting the header.',
    cwe: 'CWE-113', owasp: 'A03:2025 Injection',
  }),
  makeLineRule({
    id: 'api2026.dangerously-set-innerhtml-llm',
    severity: 'high',
    confidence: 'high',
    title: 'LLM output rendered as raw HTML',
    re: /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*[^}]{0,80}(?:completion|response\.|message\.content|output|answer|llm)/i,
    skipComments: true,
    message:
      'Model output is injected as HTML. Prompt injection becomes stored XSS in the user\'s session (OWASP LLM05).',
    fix: 'Render as text ({content}) or sanitize with DOMPurify before dangerous HTML; prefer markdown with a sanitizer.',
    cwe: 'CWE-79', owasp: 'LLM05 Improper Output Handling',
  }),
  makeLineRule({
    id: 'api2026.react-markdown-rehype-raw',
    severity: 'medium',
    confidence: 'medium',
    title: 'ReactMarkdown with rehype-raw and no sanitizer',
    re: /rehypePlugins\s*=\s*\{\s*\[[^\]]*rehypeRaw/i,
    filter(line) {
      return !/rehypeSanitize|rehype-sanitize|DOMPurify|sanitize-html/i.test(line);
    },
    skipComments: true,
    message:
      'Markdown is rendered with raw HTML enabled and no sanitizer — any markdown source (user comment, model output, scraped page) can inject script.',
    fix: 'Add rehype-sanitize AFTER rehype-raw (sanitize the result) or drop rehype-raw entirely.',
    cwe: 'CWE-79', owasp: 'A03:2025 Injection',
  }),
];

// ---------------------------------------------------------------------------
// 10. Deserialization / prototype pollution / template injection
// ---------------------------------------------------------------------------

const deser2026 = [
  makeLineRule({
    id: 'deser2026.pickle-loads-user',
    severity: 'critical',
    confidence: 'high',
    title: 'pickle.loads on request data',
    re: /pickle\.loads?\s*\(\s*(?:request\.|req\.|body|data|payload|base64)/i,
    filter(line) {
      return !/(?:test|fixture|trusted)/i.test(line);
    },
    skipComments: true,
    message:
      'pickle deserializes arbitrary Python objects — request data executes code on load (RCE).',
    fix: 'Use JSON (or a signed, versioned format). If pickle is unavoidable, verify an HMAC over the payload with a server-side key first.',
    cwe: 'CWE-502', owasp: 'A08:2025 Software and Data Integrity Failures',
  }),
  makeLineRule({
    id: 'deser2026.unsafe-yaml-load',
    severity: 'high',
    confidence: 'medium',
    title: 'yaml.load without SafeLoader',
    re: /yaml\.load\s*\(\s*(?!.*Loader\s*=\s*(?:yaml\.)?SafeLoader)/,
    skipComments: true,
    message:
      'yaml.load with the default loader can construct arbitrary Python objects (RCE) from untrusted YAML.',
    fix: 'Use yaml.safe_load() / Loader=yaml.SafeLoader.',
    cwe: 'CWE-502', owasp: 'A08:2025 Software and Data Integrity Failures',
  }),
  makeLineRule({
    id: 'deser2026.node-serialize',
    severity: 'critical',
    confidence: 'high',
    title: 'node-serialize / unserialize on input',
    re: /(?:node-serialize|unserialize)\s*\(/i,
    filter(line) {
      return /serialize\.unserialize|node-serialize|require\(\s*['"]node-serialize/.test(line) || !/^\s*\/\//.test(line);
    },
    skipComments: true,
    message:
      'The node-serialize package evaluates serialized functions — a well-known RCE. Untrusted input there is instant code execution.',
    fix: 'Remove node-serialize; use JSON plus a schema validator (zod) and explicit class hydration.',
    cwe: 'CWE-502', owasp: 'A08:2025 Software and Data Integrity Failures',
  }),
  makeLineRule({
    id: 'deser2026.proto-pollution-merge',
    severity: 'high',
    confidence: 'medium',
    title: 'Deep merge of request body (prototype pollution)',
    re: /(?:lodash\.)?_\.merge\s*\(|(?:Object\.assign|merge|defaultsDeep|set|unflatten)\s*\([^)]*(?:req\.body|request\.json|body\b)/i,
    filter(line) {
      return !/(?:Object\.freeze|Object\.create\(null\))/.test(line);
    },
    skipComments: true,
    message:
      'Request data is deep-merged into an object. `{"__proto__":{"isAdmin":true}}` pollutes Object.prototype for the whole process (CWE-1321).',
    fix: 'Merge only schema-validated keys, reject __proto__/constructor/prototype, and use Object.create(null) for maps.',
    cwe: 'CWE-1321', owasp: 'A03:2025 Injection',
  }),
  makeLineRule({
    id: 'deser2026.template-injection',
    severity: 'high',
    confidence: 'medium',
    title: 'Template engine compiled from request data (SSTI)',
    re: /\.(?:render|compile)\s*\([^;]*(?:req\.|request\.|body\.|query\.|params\.|searchParams)/i,
    fileFilter: /\.(?:js|ts|mjs|cjs|py)$/i,
    filter(line, hit, lines) {
      // Only when a template engine is actually in play (imported in this file).
      const ctx = (lines || []).join('\n');
      return /\b(?:ejs|pug|handlebars|nunjucks|liquid|twig|jinja2?|mustache)\b/i.test(ctx);
    },
    skipComments: true,
    message:
      'A template string built from request data is compiled server-side. Template engines can read the filesystem / execute helpers (SSTI → RCE).',
    fix: 'Keep templates static; pass user data only as context values, never as the template source.',
    cwe: 'CWE-1336', owasp: 'A03:2025 Injection',
  }),
];

module.exports = {
  lineRules: [
    ...authz2026, ...nextjs2026.filter((r) => r.re), ...supabase2026.filter((r) => r.re),
    ...firebase2026, ...jwt2026, ...llm2026, ...crypto2026, ...leak2026,
    ...secret2026, ...supply2026.filter((r) => r.re), ...container2026,
    ...cloud2026.filter((r) => r.re), ...api2026, ...deser2026,
  ],
  fileRules: [
    ...nextjs2026.filter((r) => !r.re),
    ...supabase2026.filter((r) => !r.re),
    ...supply2026.filter((r) => !r.re),
    ...cloud2026.filter((r) => !r.re),
  ],
  crossFileRules: [],
};
