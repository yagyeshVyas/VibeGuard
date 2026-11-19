'use strict';

/*
 * Framework-aware entrypoint extraction.
 *
 * A scanner that only greps for sinks cannot tell an attacker-reachable bug from
 * dead code, and cannot answer the only question that matters at review time:
 * "which HTTP endpoint / RPC / server action can be abused, and is it guarded?"
 *
 * This module turns a project into a list of ENTRYPOINTS (every place an
 * untrusted caller can enter the program) with the facts needed to grade it:
 *   - the handler's extent in the file (line window, derived by brace matching)
 *   - the auth guards actually executed in that window (or inherited from a
 *     router mount / decorator / middleware chain)
 *   - whether it mutates state, reads an object id, and whether it filters by an
 *     owner/tenant column (the IDOR signal)
 *
 * Zero dependencies, text-based: runs even when acorn is unavailable. The AST
 * pass is precision on top, not a prerequisite. Frameworks are detected by file
 * convention first (Next.js, Supabase edge, pages/api), then by call shape
 * (Express, Fastify, Hono, tRPC, FastAPI/Flask, Gin/Echo, Rails).
 *
 * Output is consumed by src/surface.js (risk merge with scanner findings) and by
 * `vibeguard attack-surface`.
 */

const path = require('path');

// ---------------------------------------------------------------------------
// Guard vocabulary — calls that prove an identity check ran inside the handler.
// Deliberately narrow: a guard must be CALLED, not imported, in the body window.
// ---------------------------------------------------------------------------
const GUARD_RE = new RegExp(
  [
    '\\bauth\\s*\\(', // NextAuth / Auth.js
    '\\bgetServerSession\\s*\\(',
    '\\bgetSession\\s*\\(',
    '\\bgetUser\\s*\\(', // supabase.auth.getUser()
    '\\brequireUser\\b', '\\brequireAuth\\b', '\\brequireLogin\\b',
    '\\brequireSession\\b', '\\brequireRole\\b', '\\brequirePermission\\b',
    '\\bwithAuth\\b', '\\bwithApiAuthRequired\\b', '\\bwithPageAuthRequired\\b',
    '\\bcurrentUser\\s*\\(', '\\bclerkMiddleware\\b', '\\bprotect\\s*\\(',
    '\\bensureAuth\\b', '\\bensureAuthenticated\\b', '\\bassertAuth\\b',
    '\\bassertAuthenticated\\b', '\\bcheckAuth\\b', '\\bcheckPermission\\b',
    '\\bisAuthenticated\\b', '\\bisLoggedIn\\b', '\\bisLoggedInMiddleware\\b',
    '\\bensureLoggedIn\\b', '\\brequireLoggedIn\\b', '\\bisAdmin\\b',
    '\\bisAdminUserMiddleware\\b', '\\bcheckSession\\b', '\\bhasPermission\\b',
    '\\bauthenticate\\b', '\\bauthorize\\b',
    '\\bverifyToken\\b', '\\bverifyJwt\\b', '\\bverifyJWT\\b', '\\bjwt\\.verify\\b',
    '\\bgetToken\\b', '\\bgetAuth\\s*\\(', '\\bvalidateSession\\b',
    '\\bverifySession\\b', '\\bgetCurrentUser\\b', '\\bgetLoggedInUser\\b',
    '\\bhasRole\\b', '\\bcan\\s*\\(', '\\bability\\.can\\b',
    '\\bisAuthorized\\b', '\\bdenyAll\\b', '\\bisAdminUser\\b',
    '\\bblockUnauthorized\\b', '\\brequireValidToken\\b',
    '\\bDepends\\s*\\(\\s*get_current_user', '\\bbefore_action\\b.*authenticate',
  ].join('|')
);

// Calls that prove the OPPOSITE: the route is explicitly public.
const PUBLIC_RE = /\bpublicProcedure\b|\bpublicRoute\b|\ballowAnonymous\b|\bskipAuth\b/;

// Data-mutating work.
const WRITE_RE = new RegExp(
  [
    '\\.(?:create|createMany|update|updateMany|upsert|delete|deleteMany|save|insert|insertOne|insertMany|destroy|bulkCreate|findOneAndUpdate|findOneAndDelete|findByIdAndUpdate|findByIdAndDelete)\\s*\\(',
    '\\bsave\\s*\\(\\s*\\)',
    '\\.(?:set|increment|decrement|push|splice)\\s*\\(', // doc/array mutation on a loaded record
    '\\bwriteFile(?:Sync)?\\s*\\(', '\\bappendFile(?:Sync)?\\s*\\(', '\\bunlink(?:Sync)?\\s*\\(',
    '\\brm(?:Sync)?\\s*\\(', '\\bmkdir(?:Sync)?\\s*\\(',
    '\\bexec(?:Sync)?\\s*\\(', '\\bspawn(?:Sync)?\\s*\\(',
    '\\bfetch\\s*\\(', '\\baxios\\.(?:post|put|patch|delete)\\b',
    '\\b(?:insert\\s+into|update\\s+\\w+\\s+set|delete\\s+from|drop\\s+table|alter\\s+table)\\b',
    '\\bbenchmark\\.invoke\\b', '\\bqueue\\.add\\b', '\\bsendMail\\b', '\\bsendEmail\\b',
  ].join('|'),
  'i'
);

// Reads of an object identifier straight from the request.
const ID_PARAM_RE = new RegExp(
  [
    '\\bparams\\s*\\.\\s*(id|uuid|slug|key|token|userId|user_id)\\b',
    '\\bparams\\s*\\[\\s*[\'"](id|uuid|slug|key|token|userId|user_id)[\'"]\\s*\\]',
    '\\breq\\.params\\.(id|uuid|slug|key|token|userId|user_id)\\b',
    '\\bsearchParams\\.get\\(\\s*[\'"](id|uuid|slug|key|token|userId|user_id)[\'"]\\s*\\)',
    '\\bquery\\.(id|uuid|slug|key|token|userId|user_id)\\b',
    '\\breq\\.query\\.(id|uuid|slug|key|token|userId|user_id)\\b',
    '\\brequest\\.query\\.(id|uuid|slug|key|token|userId|user_id)\\b',
    '\\bc\\.req\\.param\\(\\s*[\'"](id|uuid|slug|key|token)[\'"]\\s*\\)',
    '\\bctx\\.params\\.(id|uuid|slug|key|token)\\b',
    '\\{\\s*(id|uuid|slug|key|token|userId|user_id)\\s*\\}[\\s\\S]{0,30}?=\\s*req\\.params',
    '\\bfrom\\s+[\\w.]+\\s+where\\s+id\\s*=\\s*\\$?\\d',
  ].join('|'),
  'i'
);

// An ownership / tenant predicate near the object fetch.
const OWNER_RE = new RegExp(
  [
    '\\b(userId|user_id|ownerId|owner_id|tenantId|tenant_id|orgId|org_id|accountId|account_id|authorId|author_id|workspaceId|workspace_id|customerId|customer_id|teamId|team_id)\\b',
    '\\bauth\\.uid\\(\\)', '\\bcurrentUser\\(\\)\\.id', '\\bsession\\.user\\.id',
    '\\bctx\\.user\\.(?:id|userId)', '\\breq\\.user\\.(?:id|userId)',
  ].join('|')
);

// Rate-limit presence (login/chat/OTP endpoints without it are brute-forceable).
const RATELIMIT_RE = /\b(?:rateLimit|rateLimiter|rate_limit|ratelimit|limiter|throttle|express-rate-limit|upstash\/ratelimit|slowDown)\b/i;

const ENTRYPOINT_FILE_RULES = [
  { re: /(?:^|\/)app\/.*\/route\.(?:js|jsx|ts|tsx|mjs)$/, framework: 'next-app' },
  { re: /(?:^|\/)pages\/api\/.*\.(?:js|jsx|ts|tsx)$/, framework: 'next-pages' },
  { re: /(?:^|\/)middleware\.(?:js|ts)$/, framework: 'next-middleware' },
  { re: /(?:^|\/)supabase\/functions\/[^/]+\/(?:index|main)\.(?:ts|js)$/, framework: 'supabase-edge' },
  { re: /(?:^|\/)netlify\/functions\/.*\.(?:js|ts)$/, framework: 'netlify' },
  // Serverless: only a real api/ or vercel api/ directory — not test folders.
  { re: /(?:^|\/)(?:src\/)?api\/[^/]+\.(?:js|ts)$/, framework: 'serverless' },
];

function frameworkOfFile(rel) {
  const p = String(rel || '').replace(/\\/g, '/');
  if (isFixtureLike(p)) return null;
  for (const r of ENTRYPOINT_FILE_RULES) {
    if (r.re.test(p)) return r.framework;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Body windowing
// ---------------------------------------------------------------------------

// Find the line index (0-based) where the `{` opening a block that starts at or
// after `startIdx` opens, then return the matching close line by counting braces
// while skipping strings/template literals/comments. Falls back to a bounded
// window when braces are unbalanced (JSX, broken code).
function braceWindow(lines, startIdx, maxLines = 200) {
  let depth = 0;
  let opened = false;
  let start = startIdx;
  let end = Math.min(lines.length - 1, startIdx + 40);
  let inBlockComment = false;

  for (let i = startIdx; i < lines.length && i <= startIdx + maxLines; i++) {
    const line = lines[i];
    let quote = null;
    for (let j = 0; j < line.length; j++) {
      const ch = line[j];
      const nx = line[j + 1];
      if (inBlockComment) {
        if (ch === '*' && nx === '/') { inBlockComment = false; j++; }
        continue;
      }
      if (quote) {
        if (ch === '\\') { j++; continue; }
        if (ch === quote) quote = null;
        continue;
      }
      if (ch === '/' && nx === '/') break; // line comment
      if (ch === '/' && nx === '*') { inBlockComment = true; j++; continue; }
      if (ch === "'" || ch === '"' || ch === '`') { quote = ch; continue; }
      if (ch === '{') { depth++; opened = true; }
      else if (ch === '}') {
        depth--;
        if (opened && depth === 0) { end = i; i = lines.length; break; }
      }
    }
    if (opened && depth === 0) { end = i; break; }
  }
  if (!opened) end = startIdx; // one-liner handler: the registration line IS the body
  return { start, end };
}

function bodyText(lines, start, end) {
  return lines.slice(start, end + 1).join('\n');
}

// Does the query that reads the request id also constrain an owner/tenant column
// with the CALLER's identity? The identity reference is required — a bare
// `userId` identifier is usually the request parameter itself, not a filter.
const CALLER_IDENTITY_RE =
  /req\.user\b|req\.session|res\.locals|auth\.uid\(\)|session\.user|user\.id\b|ctx\.user|currentUser\(|getServerSession|getSession\(|jwt\.verify|verifyToken/i;
const OWNER_COLUMN_RE =
  /(userId|user_id|ownerId|owner_id|tenantId|tenant_id|orgId|org_id|accountId|account_id|authorId|author_id|workspaceId|teamId|customerId|profileId)/i;

function ownerCheck(lines, start, end, idMatchLine) {
  // Strip comments across the WHOLE window first — a multi-line comment can
  // start before the id line and end after it, so line-local stripping lies.
  const cleaned = stripComments(lines.slice(start, end + 1).join('\n')).split('\n');
  const idRel = Math.max(0, Math.min(cleaned.length - 1, idMatchLine - start));
  for (let i = Math.max(0, idRel - 4); i <= Math.min(cleaned.length - 1, idRel + 4); i++) {
    const window = cleaned.slice(i, i + 3).join('\n');
    if (OWNER_COLUMN_RE.test(window) && CALLER_IDENTITY_RE.test(window)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Auth inference
// ---------------------------------------------------------------------------

function guardsIn(text, callsOnly) {
  const out = [];
  const re = new RegExp(GUARD_RE.source, 'g');
  let m;
  while ((m = re.exec(text)) !== null) {
    if (callsOnly) {
      const after = text.slice(m.index + m[0].length, m.index + m[0].length + 3);
      if (!/^\s*\(/.test(after)) continue; // `user.isAdmin ? …` is not a guard call
    }
    out.push(m[0].replace(/\(.*$/, '').trim());
    if (out.length > 40) break;
  }
  return [...new Set(out)];
}

// Strip comments before trust decisions — a commented-out guard is not a guard.
function stripComments(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1')
    .replace(/(^|\s)#[^\n]*/g, '$1');
}

// Common auth middleware names used in mount chains: router.use(requireAuth).
const MOUNT_AUTH_RE = new RegExp(GUARD_RE.source, 'i');

// ---------------------------------------------------------------------------
// Per-framework extractors
// ---------------------------------------------------------------------------

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'];

// folder path -> route path for Next App Router.
function nextAppPath(rel) {
  const idx = rel.lastIndexOf('/app/');
  const tail = idx >= 0 ? rel.slice(idx + 5) : rel.replace(/^app\//, '');
  const parts = tail.split('/').slice(0, -1); // drop route.ts
  const segs = [];
  for (const p of parts) {
    if (/^\(.*\)$/.test(p)) continue; // route group
    if (/^@/.test(p)) continue; // parallel route slot
    if (p === 'page' || p === 'layout') continue;
    segs.push(p.replace(/^\[\[?(\.\.\.)?([^\]]+)\]\]?$/, (_, rest, name) => (rest ? '*' : ':' + name)));
  }
  return '/' + segs.join('/');
}

function extractNextApp(file, out) {
  const { rel, content, lines } = file;
  const routePath = nextAppPath(rel);
  const base = path.basename(rel);
  if (base === 'middleware.ts' || base === 'middleware.js') return;

  // Exported route handlers: export (async) function GET(...) / export const GET = ...
  const fnRe = /\bexport\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s*\(/g;
  const constRe = /\bexport\s+const\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s*=/g;
  const hits = [];
  let m;
  while ((m = fnRe.exec(content)) !== null) hits.push({ method: m[1], index: m.index });
  while ((m = constRe.exec(content)) !== null) hits.push({ method: m[1], index: m.index });
  for (const h of hits) {
    const line = content.slice(0, h.index).split('\n').length - 1;
    const { start, end } = braceWindow(lines, line);
    out.push(finishEntrypoint(file, {
      kind: 'http', framework: 'next-app', method: h.method, path: routePath,
      line: line + 1, start, end,
    }));
  }
}

function extractNextPages(file, out, expressLike) {
  const { rel, content, lines } = file;
  const routePath = (() => {
    const idx = rel.lastIndexOf('/pages/api');
    let tail = idx >= 0 ? rel.slice(idx + 10) : rel;
    tail = tail.replace(/\.(?:js|jsx|ts|tsx)$/, '');
    if (tail.endsWith('/index')) tail = tail.slice(0, -6);
    tail = tail.replace(/\[\[?\.\.\.([^\]]+)\]\]?/g, '*').replace(/\[([^\]]+)\]/g, ':$1');
    return '/api' + tail;
  })();

  const def = /\bexport\s+default\s+(?:async\s+)?(?:function\s*\w*\s*\(|\([^)]*\)\s*=>|\w+\s*=>|\w+\b)/.exec(content);
  let line = def ? content.slice(0, def.index).split('\n').length - 1 : 0;
  let { start, end } = def ? braceWindow(lines, line) : { start: 0, end: lines.length - 1 };
  const body = bodyText(lines, start, end);
  const methods = [];
  const methodSwitch = /\breq(?:uest)?\.method\s*===?\s*['"](GET|POST|PUT|PATCH|DELETE)['"]/g;
  let mm;
  while ((mm = methodSwitch.exec(body)) !== null) methods.push(mm[1]);
  if (methods.length === 0) methods.push('*');
  for (const method of methods) {
    out.push(finishEntrypoint(file, {
      kind: 'http', framework: 'next-pages', method, path: routePath,
      line: line + 1, start, end,
    }));
  }
}

function extractExpressLike(file, out, matches) {
  const { rel, lines } = file;
  for (const h of matches) {
    const { start, end } = braceWindow(lines, h.line);
    out.push(finishEntrypoint(file, {
      kind: 'http', framework: h.framework, method: h.method, path: h.path,
      line: h.line + 1, start, end,
    }));
  }
}

// Server Actions: a 'use server' file makes every exported async function a
// remotely-callable endpoint. This is the most under-scanned attack surface in
// Next.js apps because nothing in the file looks like a route.
function extractServerActions(file, out) {
  const { content, lines } = file;
  if (!/['"]use server['"]/.test(content)) return;
  const re = /\bexport\s+(?:async\s+)?function\s+(\w+)\s*\(/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    if (insideString(content, m.index) || !plausibleStart(content, m.index)) continue;
    const line = content.slice(0, m.index).split('\n').length - 1;
    const { start, end } = braceWindow(lines, line);
    out.push(finishEntrypoint(file, {
      kind: 'server-action', framework: 'next-app', method: 'ACTION', path: m[1],
      line: line + 1, start, end,
    }));
  }
  // export const action = async (…) => …
  const cre = /\bexport\s+const\s+(\w+)\s*=\s*async\b/g;
  while ((m = cre.exec(content)) !== null) {
    if (insideString(content, m.index) || !plausibleStart(content, m.index)) continue;
    const line = content.slice(0, m.index).split('\n').length - 1;
    const { start, end } = braceWindow(lines, line);
    out.push(finishEntrypoint(file, {
      kind: 'server-action', framework: 'next-app', method: 'ACTION', path: m[1],
      line: line + 1, start, end,
    }));
  }
}

function extractTrpc(file, out) {
  const { content, lines } = file;
  if (!/(?:createTRPCRouter|\bt\.router|initTRPC|(?:public|protected|private)Procedure\s*[.(])/.test(content)) return;
  // procedure entries: name: publicProcedure.protectedProcedure.query|mutation
  const re = /(\w+)\s*:\s*(public|protected|private)Procedure\b([\s\S]{0,200}?)\.(query|mutation)\s*\(/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    if (insideString(content, m.index) || !plausibleStart(content, m.index)) continue;
    const line = content.slice(0, m.index).split('\n').length - 1;
    const { start, end } = braceWindow(lines, line);
    out.push(finishEntrypoint(file, {
      kind: 'trpc', framework: 'trpc', method: m[4] === 'mutation' ? 'MUTATION' : 'QUERY',
      path: m[1], line: line + 1, start, end,
      explicitAuth: m[2] === 'public' ? 'none' : 'enforced',
    }));
  }
}

function extractFastify(file, out) {
  const { content, lines } = file;
  const re = /\b(?:fastify|app|server|router)\.(get|post|put|patch|delete|options|head)\s*\(\s*['"`]([^'"`]+)['"`]/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    const line = content.slice(0, m.index).split('\n').length - 1;
    const { start, end } = braceWindow(lines, line);
    out.push(finishEntrypoint(file, {
      kind: 'http', framework: 'fastify', method: m[1].toUpperCase(), path: m[2],
      line: line + 1, start, end,
    }));
  }
  const routeRe = /\b(?:fastify|app|server)\.route\s*\(\s*\{([\s\S]{0,600}?)\}\s*\)/g;
  while ((m = routeRe.exec(content)) !== null) {
    const block = m[1];
    const url = /url\s*:\s*['"`]([^'"`]+)['"`]/.exec(block);
    const method = /method\s*:\s*['"`]([A-Za-z]+)['"`]/.exec(block);
    if (!url) continue;
    const line = content.slice(0, m.index).split('\n').length - 1;
    const { start, end } = braceWindow(lines, line);
    out.push(finishEntrypoint(file, {
      kind: 'http', framework: 'fastify', method: (method ? method[1] : 'GET').toUpperCase(),
      path: url[1], line: line + 1, start, end,
    }));
  }
}

function extractHono(file, out) {
  const { content, lines } = file;
  if (!/\b(?:hono|app|router)\b/.test(content)) return;
  const re = /\b(?:app|router|api)\.(get|post|put|patch|delete|all|on)\s*\(\s*['"`]([^'"`]+)['"`]/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    const line = content.slice(0, m.index).split('\n').length - 1;
    const { start, end } = braceWindow(lines, line);
    out.push(finishEntrypoint(file, {
      kind: 'http', framework: 'hono', method: m[1] === 'all' || m[1] === 'on' ? '*' : m[1].toUpperCase(),
      path: m[2], line: line + 1, start, end,
    }));
  }
}

function extractNest(file, out) {
  const { content, lines } = file;
  if (!/\.(?:ts|js)$/i.test(file.rel)) return;
  const ctrl = /@Controller\s*\(\s*['"`]?([^'"`)]*)['"`]?\s*\)/.exec(content);
  if (!ctrl) return;
  const base = '/' + String(ctrl[1]).replace(/^\/+/, '');
  const clsGuard = /@UseGuards\s*\(([^)]*)\)/.exec(content);
  const re = /@(Get|Post|Put|Patch|Delete)\s*\(\s*(?:['"`]([^'"`]*)['"`])?\s*\)/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    const line = content.slice(0, m.index).split('\n').length - 1;
    const { start, end } = braceWindow(lines, line);
    out.push(finishEntrypoint(file, {
      kind: 'http', framework: 'nestjs', method: m[1].toUpperCase(),
      path: (base + '/' + (m[2] || '')).replace(/\/+$/, '') || '/',
      line: line + 1, start, end,
      classGuard: clsGuard ? clsGuard[1].trim() : null,
    }));
  }
}

function extractPy(file, out) {
  const { content, lines } = file;
  if (!/\.py$/i.test(file.rel)) return; // Python route syntax appears in JS example strings
  const frameworks = [
    { re: /@(?:app|router|api)\.(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]/g, framework: 'fastapi' },
    { re: /@(?:app|bp|blueprint)\.route\s*\(\s*['"]([^'"]+)['"](?:\s*,\s*methods\s*=\s*\[([^\]]*)\])?/g, framework: 'flask' },
  ];
  for (const fw of frameworks) {
    let m;
    fw.re.lastIndex = 0;
    while ((m = fw.re.exec(content)) !== null) {
      const line = content.slice(0, m.index).split('\n').length - 1;
      // Python body = following indented lines.
      let end = line;
      const indent = (lines[line + 1] || '').match(/^(\s*)/)[1].length;
      for (let i = line + 1; i < lines.length; i++) {
        const l = lines[i];
        if (l.trim() === '') { end = i; continue; }
        const ind = l.match(/^(\s*)/)[1].length;
        if (ind <= indent) break;
        end = i;
      }
      const methods = m[2]
        ? m[2].split(',').map((s) => s.trim().replace(/['"]/g, '').toUpperCase()).filter(Boolean)
        : [fw.framework === 'flask' ? 'GET' : (m[1] || 'GET').toUpperCase()];
      for (const method of methods) {
        out.push(finishEntrypoint(file, {
          kind: 'http', framework: fw.framework, method,
          path: m[2] !== undefined || fw.framework === 'fastapi' ? m[1] : m[1],
          line: line + 1, start: line, end,
        }));
      }
    }
  }
  // Django urlpatterns: path('users/<int:pk>/', view)
  const dj = /\bpath\s*\(\s*['"]([^'"]+)['"]\s*,\s*([\w.]+)/g;
  let m;
  while ((m = dj.exec(content)) !== null) {
    if (insideString(content, m.index)) continue;
    const line = content.slice(0, m.index).split('\n').length - 1;
    out.push(finishEntrypoint(file, {
      kind: 'http', framework: 'django', method: '*',
      path: '/' + m[1].replace(/<[^>]+>/g, (x) => (x.includes('slug') ? ':slug' : ':id')).replace(/^\/+/, ''),
      line: line + 1, start: line, end: Math.min(lines.length - 1, line),
    }));
  }
}

function extractGo(file, out) {
  const { content, lines } = file;
  if (!/\.go$/i.test(file.rel)) return;
  const re = /\b(?:r|router|e|app|g|mux|http)\w*\.(GET|POST|PUT|PATCH|DELETE)\s*\(\s*"([^"]+)"/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    const line = content.slice(0, m.index).split('\n').length - 1;
    const { start, end } = braceWindow(lines, line);
    out.push(finishEntrypoint(file, {
      kind: 'http', framework: 'go', method: m[1], path: m[2], line: line + 1, start, end,
    }));
  }
  const hf = /\bhttp\.HandleFunc\s*\(\s*"([^"]+)"/g;
  while ((m = hf.exec(content)) !== null) {
    const line = content.slice(0, m.index).split('\n').length - 1;
    const { start, end } = braceWindow(lines, line);
    out.push(finishEntrypoint(file, {
      kind: 'http', framework: 'go', method: '*', path: m[1], line: line + 1, start, end,
    }));
  }
}

function extractSupabaseEdge(file, out) {
  const { content, lines } = file;
  const m = /Deno\.serve\s*\(\s*(?:async\s*)?(?:\(|function)/.exec(content);
  if (!m) return;
  const relParts = file.rel.split('/');
  const idx = relParts.indexOf('functions');
  const name = idx >= 0 ? relParts[idx + 1] : path.basename(path.dirname(file.rel));
  const line = content.slice(0, m.index).split('\n').length - 1;
  const { start, end } = braceWindow(lines, line);
  out.push(finishEntrypoint(file, {
    kind: 'edge-function', framework: 'supabase-edge', method: '*', path: '/' + name,
    line: line + 1, start, end,
  }));
}

function extractRails(file, out) {
  if (!/\.rb$/i.test(file.rel)) return; // `get 'x'` would otherwise match English text in any string
  const { content, lines } = file;
  const re = /\b(get|post|put|patch|delete)\s+['"]([^'"]+)['"]/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    const line = content.slice(0, m.index).split('\n').length - 1;
    out.push(finishEntrypoint(file, {
      kind: 'http', framework: 'rails', method: m[1].toUpperCase(), path: m[2],
      line: line + 1, start: line, end: line,
    }));
  }
}

function extractMcpTools(file, out) {
  const { content, lines } = file;
  const re = /\b(?:server|mcp|toolServer)\.(?:tool|registerTool)\s*\(\s*['"`]([^'"`]+)['"`]/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    if (insideString(content, m.index) || !plausibleStart(content, m.index)) continue;
    const line = content.slice(0, m.index).split('\n').length - 1;
    const { start, end } = braceWindow(lines, line);
    out.push(finishEntrypoint(file, {
      kind: 'mcp-tool', framework: 'mcp', method: 'TOOL', path: m[1],
      line: line + 1, start, end,
    }));
  }
}

// Express routes need their line indices; collected by a scan pass so mounting
// can be resolved before finalizing.
function collectExpressRoutes(files) {
  const routes = []; // {file, line, method, path}
  const mounts = []; // {file, line, base, ident, middleware}
  const imports = new Map(); // rel -> Map(ident -> rel)
  for (const f of files) {
    const map = new Map();
    const reqRe = /\b(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['"](\.{1,2}\/[^'"]+)['"]\s*\)/g;
    let m;
    while ((m = reqRe.exec(f.content)) !== null) map.set(m[1], m[2]);
    const impRe = /\bimport\s+(\w+)\s+from\s+['"](\.{1,2}\/[^'"]+)['"]/g;
    while ((m = impRe.exec(f.content)) !== null) map.set(m[1], m[2]);
    imports.set(f.rel, map);
  }
  const resolve = (fromRel, spec) => {
    const dir = fromRel.includes('/') ? fromRel.slice(0, fromRel.lastIndexOf('/')) : '';
    const base = path.posix.normalize((dir + '/' + spec).replace(/^\/+/, ''));
    const known = files.map((x) => x.rel);
    const cands = [base, base + '.js', base + '.ts', base + '.mjs', base + '/index.js', base + '/index.ts'];
    return cands.find((c) => known.includes(c)) || null;
  };

  for (const f of files) {
    const routeRe = /\b(app|router|server|api)\.(get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]\s*,/g;
    let m;
    while ((m = routeRe.exec(f.content)) !== null) {
      routes.push({
        file: f.rel,
        line: f.content.slice(0, m.index).split('\n').length - 1,
        method: m[2] === 'all' ? '*' : m[2].toUpperCase(),
        path: m[3],
      });
    }
    const mountRe = /\b(app|server)\.use\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*([^)]+(?:\)[^)]*)?)\)/g;
    while ((m = mountRe.exec(f.content)) !== null) {
      const rawArgs = m[3].trim();
      // `require('./routes/users')` style mounts: take the specifier directly.
      const reqSpec = /^(?:require\s*\(\s*['"]([^'"]+)['"]\s*\)|(\w+))$/.exec(rawArgs);
      const specInline = /require\s*\(\s*['"]([^'"]+)['"]\s*\)\s*$/.exec(rawArgs);
      mounts.push({
        file: f.rel,
        base: m[2],
        spec: (specInline && specInline[1]) || (reqSpec && reqSpec[1]) || null,
        ident: !specInline && reqSpec && reqSpec[2] ? reqSpec[2] : null,
        middleware: rawArgs.replace(/require\s*\([^)]*\)/, '').replace(/^,|,$/g, ''),
      });
    }
  }

  // Resolve mounts to router files.
  const mountByRel = new Map(); // rel -> [{base, middleware}]
  for (const mo of mounts) {
    let target = null;
    if (mo.spec) target = resolve(mo.file, mo.spec);
    else if (mo.ident) {
      const spec = (imports.get(mo.file) || new Map()).get(mo.ident);
      if (spec) target = resolve(mo.file, spec);
    }
    if (!target) continue;
    if (!mountByRel.has(target)) mountByRel.set(target, []);
    mountByRel.get(target).push({ base: mo.base.replace(/\/$/, ''), middleware: mo.middleware });
  }
  return { routes, mountByRel, imports, resolve };
}

// Is the character offset inside a quoted string on this line? Prevents reading
// example/demo code strings (e.g. this project's own rule database) as routes.
function insideString(text, idx) {
  const lineStart = text.lastIndexOf('\n', idx) + 1;
  const lineEnd = text.indexOf('\n', idx);
  const line = text.slice(lineStart, lineEnd === -1 ? undefined : lineEnd);
  const rel = idx - lineStart;
  let quote = null;
  for (let i = 0; i < rel && i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = null;
    } else if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch;
    }
  }
  return quote !== null;
}

// Is the match at a plausible statement boundary? Rejects hits inside regex
// literals and escaped example text (`/\bapp\.post\(.../`) while accepting real
// calls after a newline, `;`, `{`, `}`, `,`, `(` or `)`.
function plausibleStart(text, idx) {
  let i = idx - 1;
  while (i >= 0 && (text[i] === ' ' || text[i] === '\t' || text[i] === '\r')) i--;
  if (i < 0) return true;
  return ['\n', ';', '{', '}', ',', '(', ')'].includes(text[i]);
}

// ---------------------------------------------------------------------------
// Handler resolution (Express-style: the route is registered by reference)
// ---------------------------------------------------------------------------

const TEST_FILE = /(?:^|\/)(?:test|tests|__tests__|__mocks__|spec|specs|e2e|apitest|fixtures)\//i;
const TEST_NAME = /\.(?:test|spec|e2e)\.(?:[cm]?[jt]sx?)$/i;
// Not-deployed code that lives inside the repo: challenge fixtures, code-fix
// snippets, examples and demos. They contain real route registrations but never
// run in production, and counting them inflates the attack surface by 3x.
const FIXTURE_FILE = /(?:^|\/)(?:data\/static|static\/codefixes|codefixes?|fixtures?|examples?|samples?)\//i;
function isTestLike(rel) {
  const p = String(rel || '');
  return TEST_FILE.test(p) || TEST_NAME.test(p);
}
function isFixtureLike(rel) {
  const p = String(rel || '');
  return isTestLike(p) || FIXTURE_FILE.test(p) || /codefix/i.test(p);
}

// Extract the argument list of a call whose `(` is at openIdx. Returns the raw
// argument text and where the call ends. Handles quotes, escapes and nesting.
function callArgs(content, openIdx) {
  let depth = 0;
  let quote = null;
  let i = openIdx;
  const start = openIdx + 1;
  for (; i < content.length; i++) {
    const ch = content[i];
    if (quote) {
      if (ch === '\\') { i++; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') { quote = ch; continue; }
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) break;
    }
  }
  return { argsText: content.slice(start, i), end: i };
}

function splitArgs(argsText) {
  const out = [];
  let depth = 0;
  let quote = null;
  let cur = '';
  for (let i = 0; i < argsText.length; i++) {
    const ch = argsText[i];
    if (quote) {
      cur += ch;
      if (ch === '\\') { cur += argsText[i + 1] || ''; i++; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') { quote = ch; cur += ch; continue; }
    if ('([{'.includes(ch)) depth++;
    if (')]}'.includes(ch)) depth--;
    if (ch === ',' && depth === 0) { out.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

// Find a function/method definition inside one file, by name (and optional
// member). Prefers an AST range (exact), falls back to brace matching.
const PARSE_CACHE = new Map();

function parsedFile(file) {
  if (!file) return null;
  const key = `${file.rel}:${file.content.length}`;
  if (PARSE_CACHE.has(key)) return PARSE_CACHE.get(key);
  let tree = null;
  try {
    tree = require('./ast').parseSource(file.content, file.rel);
  } catch {
    tree = null;
  }
  PARSE_CACHE.set(key, tree);
  return tree;
}

function isFunctionNode(n) {
  return (
    n &&
    (n.type === 'FunctionDeclaration' ||
      n.type === 'FunctionExpression' ||
      n.type === 'ArrowFunctionExpression')
  );
}

// Depth-first search for a handler definition. Cheap on the files that hold
// route tables (they are small); bounded by node count.
function findInTree(root, ident, member) {
  let found = null;
  const visit = (node) => {
    if (!node || found) return;
    if (Array.isArray(node)) {
      for (const n of node) visit(n);
      return;
    }
    if (typeof node !== 'object') return;

    if (node.type === 'AssignmentExpression' && node.left && node.left.type === 'MemberExpression') {
      const left = node.left;
      const prop = left.property && left.property.name;
      if (member && prop === member && isFunctionNode(node.right)) {
        found = node.right;
        return;
      }
      if (!member && left.object && left.object.name === 'exports' && prop === ident && isFunctionNode(node.right)) {
        found = node.right;
        return;
      }
    }
    if (node.type === 'VariableDeclarator' && !member && node.id && node.id.name === ident && isFunctionNode(node.init)) {
      found = node.init;
      return;
    }
    if (node.type === 'FunctionDeclaration' && !member && node.id && node.id.name === ident) {
      found = node;
      return;
    }
    if (node.type === 'MethodDefinition' && member && isFunctionNode(node.value)) {
      const key = node.key && (node.key.name || node.key.value);
      if (key === member) {
        found = node.value;
        return;
      }
    }
    if (node.type === 'Property' && member && isFunctionNode(node.value)) {
      const key = node.key && (node.key.name || node.key.value);
      if (key === member) {
        found = node.value;
        return;
      }
    }
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'range' || key === 'start' || key === 'end' || key === 'type') continue;
      visit(node[key]);
    }
  };
  visit(root);
  return found;
}

function findDefinition(file, ident, member) {
  if (!file) return null;

  const tree = parsedFile(file);
  if (tree) {
    const node = findInTree(tree, ident, member);
    if (node && node.loc) {
      return { rel: file.rel, start: node.loc.start.line - 1, end: node.loc.end.line - 1 };
    }
  }

  // Fallback: text patterns + brace matching.
  const { content, lines } = file;
  const patterns = [];
  if (member) {
    patterns.push(new RegExp(`this\\.${member}\\s*=\\s*(?:async\\s*)?(?:function\\s*)?\\(`, 'g'));
    patterns.push(new RegExp(`(?:^|\\n)\\s*(?:async\\s+)?${member}\\s*\\([^)]*\\)\\s*\\{`, 'g'));
    patterns.push(new RegExp(`exports\\.${member}\\s*=\\s*(?:async\\s*)?(?:function\\s*)?\\(`, 'g'));
  } else {
    patterns.push(new RegExp(`(?:^|\\n)\\s*(?:async\\s+)?function\\s+${ident}\\s*\\(`, 'g'));
    patterns.push(new RegExp(`(?:const|let|var)\\s+${ident}\\s*=\\s*(?:async\\s*)?(?:function\\s*)?\\(`, 'g'));
  }
  for (const re of patterns) {
    re.lastIndex = 0;
    const m = re.exec(content);
    if (!m) continue;
    const index = m.index + (m[0].startsWith('\n') ? 1 : 0);
    const line = content.slice(0, index).split('\n').length - 1;
    const { start, end } = braceWindow(lines, line);
    return { rel: file.rel, start, end };
  }
  return null;
}

// Range of the inline handler passed to `app.<method>('<path>', …)` — precise
// AST bounds instead of brace guessing, which over-attributed findings from
// unrelated code in big server files.
function findRouteCallRange(file, method, path, nearLine) {
  const tree = parsedFile(file);
  if (!tree) return null;
  let found = null;
  const wanted = String(method).toLowerCase();
  const visit = (node) => {
    if (!node || found) return;
    if (Array.isArray(node)) {
      for (const n of node) visit(n);
      return;
    }
    if (typeof node !== 'object') return;
    if (node.type === 'CallExpression' && node.callee && node.callee.type === 'MemberExpression') {
      const prop = node.callee.property && node.callee.property.name;
      const args = node.arguments || [];
      const first = args[0];
      const firstVal =
        first && first.type === 'Literal' ? String(first.value)
        : first && first.type === 'TemplateLiteral' && first.expressions.length === 0 ? first.quasis[0].value.cooked
        : null;
      if (
        prop === wanted &&
        firstVal === path &&
        node.loc &&
        Math.abs(node.loc.start.line - 1 - nearLine) <= 3
      ) {
        const fn = [...args].reverse().find((a) => isFunctionNode(a));
        if (fn && fn.loc) found = fn;
        return;
      }
    }
    for (const key of Object.keys(node)) {
      if (key === 'loc' || key === 'range' || key === 'start' || key === 'end' || key === 'type') continue;
      visit(node[key]);
    }
  };
  visit(tree);
  return found ? { start: found.loc.start.line - 1, end: found.loc.end.line - 1 } : null;
}

function resolveHandlerExpr(ctx, fromRel, expr) {
  if (!ctx || !expr) return null;
  const cleaned = String(expr).replace(/^(?:await\s+)/, '').trim();
  const simple = /^([A-Za-z_$][\w$]*)(?:\.([A-Za-z_$][\w$]*))?$/.exec(cleaned);
  if (!simple) return null; // inline arrow/function — the registration window covers it
  const ident = simple[1];
  const member = simple[2] || null;

  const here = ctx.filesByRel.get(fromRel);
  const local = findDefinition(here, ident, member);
  if (local) return local;

  // `const allocationsHandler = new AllocationsHandler(db)` — the handler is a
  // method on an instance of an imported class.
  if (member && here) {
    const instantiate = new RegExp(`(?:const|let|var)\\s+${ident}\\s*=\\s*new\\s+([A-Za-z_$][\\w$]*)\\s*\\(`, 'g');
    const im = instantiate.exec(here.content);
    if (im) {
      const classSpec = (ctx.imports.get(fromRel) || new Map()).get(im[1]);
      if (classSpec) {
        const target = ctx.resolve(fromRel, classSpec);
        if (target) {
          const found = findDefinition(ctx.filesByRel.get(target), im[1], member);
          if (found) return found;
        }
      }
    }
  }

  const spec = (ctx.imports.get(fromRel) || new Map()).get(ident);
  if (!spec) return null;
  const target = ctx.resolve(fromRel, spec);
  if (!target) return null;
  return findDefinition(ctx.filesByRel.get(target), ident, member);
}

// ---------------------------------------------------------------------------
// Finalize: attach auth, ownership, writer facts to an entrypoint
// ---------------------------------------------------------------------------

function finishEntrypoint(file, e, ctx) {
  // Analyse the resolved handler body when we have one; otherwise the window
  // from the registration line (inline handlers, Next.js exports).
  let bodyFile = file;
  let start = Math.max(0, e.start);
  let end = Math.min(file.lines.length - 1, e.end);
  if (e.handler) {
    const resolved = ctx && ctx.filesByRel.get(e.handler.rel);
    if (resolved) {
      bodyFile = resolved;
      start = Math.max(0, e.handler.start);
      end = Math.min(resolved.lines.length - 1, e.handler.end);
    }
  }
  const lines = bodyFile.lines;
  const rel = file.rel;
  const raw = bodyText(lines, start, end);
  const body = stripComments(raw);
  const explicit = e.explicitAuth || null;

  // Guards can be: inherited from a mount, a class decorator, an explicit
  // public/protected qualifier, a middleware argument on the registration line,
  // or a call inside the handler body.
  const guardArgs = guardsIn(e.middlewareText || '');
  const guards = [...new Set([...guardArgs, ...guardsIn(body, true)])];
  const inherited = e.inheritedAuth || null;
  const isPublic = PUBLIC_RE.test(body);

  let auth;
  if (inherited === 'enforced' || (e.classGuard && e.classGuard.length > 0)) auth = 'enforced';
  else if (explicit === 'enforced') auth = 'enforced';
  else if (explicit === 'none' || isPublic) auth = 'none';
  else if (guards.length > 0) auth = 'enforced';
  else if (e.handlerUnresolved) auth = 'unknown';
  else auth = 'none';

  const stateChanging =
    !['GET', 'HEAD', 'OPTIONS'].includes(String(e.method).toUpperCase()) ||
    e.kind === 'server-action' || e.kind === 'mcp-tool';

  // Where does the request id enter this handler?
  const idRe = new RegExp(ID_PARAM_RE.source, 'i');
  const idMatch = idRe.exec(body);
  const idLine = idMatch ? start + body.slice(0, idMatch.index).split('\n').length - 1 : -1;
  // Alternatives carry different capture groups; take the first that matched.
  const idParam = idMatch ? (idMatch.slice(1).find(Boolean) || 'id') : null;

  // Ownership: an owner/tenant column constrains the same query. When it does
  // not, an identity-shaped id param (userId/accountId/…) with no session
  // reference is the classic IDOR shape.
  let ownership = 'n/a';
  if (idParam) {
    const near = ownerCheck(lines, start, end, idLine);
    if (near) ownership = 'scoped';
    else {
      const idVar = idParam.replace(/[^\w$]/g, '');
      const queryNearById =
        new RegExp(
          `(?:DAO\\.|\\.query\\(|\\bfind\\w*\\(|where\\s*:|\\beq\\(|\\b(?:get|set|load|fetch|delete|update|remove)[A-Z]\\w*\\s*\\()[\\s\\S]{0,200}?\\b${idVar}\\b`,
          'i'
        ).test(body) ||
        new RegExp(`\\b${idVar}\\b[\\s\\S]{0,120}?(?:DAO\\.|\\.query\\(|\\bfind\\w*\\()`, 'i').test(body);
      const identityShaped = /^(?:userId|user_id|accountId|account_id|customerId|customer_id|memberId|uid|ownerId|owner_id|profile)$/i.test(idParam);
      const sessionRef = /req\.session|res\.locals|req\.user\b|session\.user|user\.id|auth\(\)|getServerSession|getSession|getUser|currentUser|ctx\.user/i.test(body);
      // A handler that reads an object id from the request and never touches
      // the caller's identity is the shape of IDOR; with a session reference
      // present, only the identity-shaped params (userId/accountId/…) count.
      if (queryNearById && (!sessionRef || identityShaped)) ownership = 'missing';
    }
  }

  const writes = WRITE_RE.test(body);
  const rateLimited = RATELIMIT_RE.test(body);
  // Login / OTP / auth endpoints are brute-forceable when unthrottled.
  const sensitive =
    /\b(login|signin|sign_in|otp|verify|reset|forgot|register|signup|sign_up|token|password)\b/i.test(
      String(e.path)
    );

  return {
    id: `${e.kind}:${rel}:${e.line}:${e.method}:${e.path}`,
    kind: e.kind,
    framework: e.framework,
    method: e.method,
    path: e.path,
    file: rel,
    line: e.line,
    bodyFile: bodyFile.rel,
    startLine: start + 1,
    endLine: end + 1,
    guards,
    auth,
    stateChanging,
    writes,
    readsObjectId: !!idParam,
    idParam,
    ownership,
    rateLimited,
    sensitive,
    snippet: (lines[e.line - 1] || '').trim().slice(0, 160),
  };
}

// ---------------------------------------------------------------------------
// Public extraction
// ---------------------------------------------------------------------------

function extractEntrypoints(files) {
  const out = [];
  const { mountByRel, imports, resolve } = collectExpressRoutes(files);
  const ctx = { filesByRel: new Map(files.map((f) => [f.rel, f])), imports, resolve };
  let middleware = null;

  for (const file of files) {
    const rel = file.rel;
    if (isFixtureLike(rel)) continue; // tests and in-repo codefix/example fixtures aren't deployed endpoints
    const fw = frameworkOfFile(rel);

    // HTTP route files with conventions
    if (fw === 'next-app') {
      if (/\/route\.(js|jsx|ts|tsx|mjs)$/.test(rel)) extractNextApp(file, out);
      else if (/\/middleware\.(js|ts)$/.test(rel)) middleware = readNextMiddleware(file);
    }
    if (fw === 'next-pages' || fw === 'netlify' || fw === 'serverless') {
      extractNextPages(file, out);
    }
    if (fw === 'supabase-edge') extractSupabaseEdge(file, out);

    // Executor-level detection — one file can hold several of these. Express and
    // Fastify share `.get('/x', h)` syntax, so a file is classified by the
    // framework it actually imports to avoid emitting both. Only real code
    // files: tutorials/templates often contain example `app.get(...)` snippets
    // that are not endpoints of this program.
    const ext = path.extname(rel).toLowerCase();
    const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.go', '.rb', '.php', '.java', '.kt', '.cs', '.rs']);
    if (!CODE_EXT.has(ext)) continue;
    const contentText = file.content;
    const isFastify = /\bfastify\b/i.test(contentText);
    const isHono = /\bfrom\s+['"]hono['"]|require\(\s*['"]hono['"]\s*\)/i.test(contentText);
    const isExpressLike = /require\(\s*['"]express['"]\s*\)|from\s+['"]express['"]|express\.Router|\.use\s*\(\s*['"]\//i.test(contentText);

    extractServerActions(file, out);
    extractTrpc(file, out);
    extractNest(file, out);
    if (isFastify) extractFastify(file, out);
    if (isHono) extractHono(file, out);
    extractPy(file, out);
    extractGo(file, out);
    extractRails(file, out);
    extractMcpTools(file, out);

    // Express-family (also catches bare `app.get` files with no express import).
    // Handler references (`profileHandler.displayProfile`, `isLoggedIn`) are
    // resolved to their definitions so auth/IDOR analysis sees the real body.
    const routesHere = [];
    if (!isFastify && !isHono) {
      const routeRe = /\b(app|router|server|api)\.(get|post|put|patch|delete|all)\s*\(/g;
      let m;
      while ((m = routeRe.exec(contentText)) !== null) {
        if (insideString(contentText, m.index) || !plausibleStart(contentText, m.index)) continue;
        const parenIdx = m.index + m[0].lastIndexOf('(');
        const { argsText } = callArgs(contentText, parenIdx);
        const args = splitArgs(argsText);
        const rawPath = (args[0] || '').trim();
        if (!/^['"`]/.test(rawPath)) continue; // dynamic path expression
        const pathText = rawPath.replace(/^['"`]/, '').replace(/['"`]$/, '');
        if (pathText.includes('${')) continue; // template parameter, not a literal route
        routesHere.push({
          line: contentText.slice(0, m.index).split('\n').length - 1,
          method: m[2] === 'all' ? '*' : m[2].toUpperCase(),
          path: pathText,
          args,
        });
      }
    }
    // Prefix-scoped auth: `app.use('/api/BasketItems', security.isAuthorized())`
    // guards every route registered under that prefix after this line.
    const prefixGuards = [];
    {
      const useRe = /\b(app|server)\.use\s*\(\s*['"]([^'"]+)['"]\s*,/g;
      let um;
      while ((um = useRe.exec(contentText)) !== null) {
        const parenIdx = um.index + um[0].lastIndexOf('(');
        const { argsText } = callArgs(contentText, parenIdx);
        if (GUARD_RE.test(argsText) || /isAuthorized|denyAll|requireAuth|isLoggedIn/i.test(argsText)) {
          prefixGuards.push({
            base: um[2],
            line: contentText.slice(0, um.index).split('\n').length - 1,
          });
        }
      }
    }

    // Chained `app.route('/path').get(handler).put(handler)` — Express style used
    // by larger apps to group methods. Each chained verb is its own endpoint.
    {
      const routeChainRe = /\b(app|router)\.route\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
      let rm;
      while ((rm = routeChainRe.exec(contentText)) !== null) {
        const chainStart = rm.index + rm[0].length;
        const chainText = contentText.slice(chainStart, chainStart + 1500);
        const verbRe = /\.(get|post|put|patch|delete|all)\s*\(/g;
        let vm;
        while ((vm = verbRe.exec(chainText)) !== null) {
          const abs = chainStart + vm.index;
          const paren = vm.index + vm[0].lastIndexOf('(');
          const { argsText } = callArgs(chainText, paren);
          routesHere.push({
            line: contentText.slice(0, abs).split('\n').length - 1,
            method: vm[1] === 'all' ? '*' : vm[1].toUpperCase(),
            path: rm[2],
            args: [`'${rm[2]}'`, ...splitArgs(argsText)],
          });
        }
      }
    }

    // Attach router mount prefixes + auth middleware inherited from app.use().
    const mountInfo = mountByRel.get(rel) || [];
    const inherited = mountInfo.some((mo) => MOUNT_AUTH_RE.test(mo.middleware))
      ? 'enforced'
      : null;
    // router.use(authFn) before a route line also guards it.
    const useAuthLine = (() => {
      let best = -1;
      const useRe = /\b(?:router|app)\.use\s*\(\s*([^)]*)\)/g;
      let um;
      while ((um = useRe.exec(file.content)) !== null) {
        if (MOUNT_AUTH_RE.test(um[1])) {
          const ln = file.content.slice(0, um.index).split('\n').length - 1;
          if (ln >= 0 && (best === -1 || ln < best)) best = ln;
        }
      }
      return best;
    })();

    for (const r of routesHere) {
      const prefix = mountInfo.length ? mountInfo[0].base : '';
      const fullPath = prefix + r.path;
      const prefixGuard = prefixGuards.find((pg) => fullPath.startsWith(pg.base) && pg.line <= r.line);
      const localInherited =
        inherited || (prefixGuard ? 'enforced' : null) || (useAuthLine >= 0 && useAuthLine <= r.line ? 'enforced' : null);
      const middlewareText = r.args.slice(1, -1).join(',');
      const handlerExpr = (r.args[r.args.length - 1] || '').trim();
      let handler = null;
      let handlerUnresolved = false;
      let bodyWindow;
      if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?$/.test(handlerExpr)) {
        handler = resolveHandlerExpr(ctx, rel, handlerExpr);
        if (!handler) {
          // The body is elsewhere and we could not follow it. Keep the analysis
          // window on the registration line only — expanding braces here would
          // pull unrelated code (and other routes' guards) into this endpoint.
          handlerUnresolved = true;
          bodyWindow = { start: r.line, end: r.line };
        }
      } else {
        const methodToken = r.method === '*' ? 'all' : String(r.method).toLowerCase();
        bodyWindow =
          findRouteCallRange(file, methodToken, r.path, r.line) ||
          braceWindow(file.lines, r.line);
      }
      const { start, end } = handler ? { start: r.line, end: r.line } : bodyWindow;
      out.push(finishEntrypoint(file, {
        kind: 'http', framework: 'express', method: r.method, path: prefix + r.path,
        line: r.line + 1, start, end, inheritedAuth: localInherited,
        middlewareText, handler, handlerUnresolved,
      }, ctx));
    }
  }

  // Deduplicate by (kind,file,line,method,path).
  const seen = new Set();
  const unique = [];
  for (const e of out) {
    const key = `${e.kind}|${e.file}|${e.line}|${e.method}|${e.path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(e);
  }
  unique.sort((a, b) => (a.file === b.file ? a.line - b.line : a.file < b.file ? -1 : 1));

  const authCoverage = {
    total: unique.length,
    enforced: unique.filter((e) => e.auth === 'enforced').length,
    unprotected: unique.filter((e) => e.auth === 'none').length,
    unprotectedStateChanging: unique.filter((e) => e.auth === 'none' && e.stateChanging).length,
    idorCandidates: unique.filter((e) => e.ownership === 'missing').length,
    unthrottledSensitive: unique.filter((e) => e.sensitive && !e.rateLimited).length,
    coverage:
      unique.length > 0
        ? Math.round((unique.filter((e) => e.auth === 'enforced').length / unique.length) * 100)
        : 100,
  };

  return { entrypoints: unique, authCoverage, middleware };
}

function readNextMiddleware(file) {
  const matcher = /matcher\s*:\s*\[([\s\S]{0,400}?)\]/.exec(file.content);
  const patterns = matcher ? [...matcher[1].matchAll(/['"]([^'"]+)['"]/g)].map((m) => m[1]) : [];
  const hasAuth = MOUNT_AUTH_RE.test(file.content);
  // A matcher that excludes /api means middleware cannot be the only auth gate.
  const apiExcluded = patterns.some((p) => /api/i.test(p) && /\(\?!.*api/.test(p));
  return { file: file.rel, line: 1, patterns, hasAuth, apiExcluded };
}

module.exports = {
  extractEntrypoints,
  frameworkOfFile,
  nextAppPath,
  GUARD_RE,
  OWNER_RE,
  ID_PARAM_RE,
  WRITE_RE,
};
