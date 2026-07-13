"use client";

import { motion, AnimatePresence } from "framer-motion";
import { useState } from "react";

type Finding = { id: string; sev: "critical" | "high" | "medium" | "low"; msg: string; fix: string; line: number; snippet: string };

const RULES: { id: string; re: RegExp; sev: Finding["sev"]; msg: string; fix: string }[] = [
  { id: "secret.openai-key", re: /sk-proj-[A-Za-z0-9_-]{20,}/, sev: "critical", msg: "OpenAI API key exposed", fix: "Move to process.env.OPENAI_API_KEY" },
  { id: "secret.openai-key-legacy", re: /sk-[A-Za-z0-9]{48}/, sev: "critical", msg: "OpenAI API key (legacy format)", fix: "Move to process.env.OPENAI_API_KEY" },
  { id: "secret.stripe-key", re: /sk_live_[A-Za-z0-9]{16,}/, sev: "critical", msg: "Stripe secret key exposed", fix: "Move to process.env.STRIPE_SECRET_KEY" },
  { id: "secret.github-token", re: /gh[pousr]_[A-Za-z0-9]{36}/, sev: "critical", msg: "GitHub token exposed", fix: "Move to process.env.GITHUB_TOKEN" },
  { id: "secret.anthropic-key", re: /sk-ant-[A-Za-z0-9_-]{50,}/, sev: "critical", msg: "Anthropic API key exposed", fix: "Move to process.env.ANTHROPIC_API_KEY" },
  { id: "injection.eval", re: /\beval\s*\(/, sev: "high", msg: "eval() — code injection risk", fix: "Avoid eval(). Use JSON.parse() or a safe parser." },
  { id: "injection.sql-concat", re: /(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\+\s*(?:req\.|user|input|request)/i, sev: "high", msg: "SQL string concatenation — SQL injection", fix: "Use parameterized queries: db.query('SELECT ... WHERE id = ?', [id])" },
  { id: "injection.sql-template", re: /(?:query|execute)\s*\(\s*`[^`]*\$\{[^}]*req/, sev: "high", msg: "SQL template literal with user input — SQL injection", fix: "Use parameterized queries instead of template literals" },
  { id: "injection.command", re: /(?:exec|spawn|execSync)\s*\(\s*[^)]*(?:req\.|user|input)/i, sev: "critical", msg: "Command injection — user input passed to exec()", fix: "Use execFile() with validated arguments, never exec() with user input." },
  { id: "xss.innerHTML", re: /innerHTML\s*=\s*[^;]*(?:req\.|user|input|request)/i, sev: "high", msg: "innerHTML with user data — XSS", fix: "Use textContent or sanitize with DOMPurify." },
  { id: "xss.dangerouslySetInnerHTML", re: /dangerouslySetInnerHTML/i, sev: "high", msg: "React dangerouslySetInnerHTML — XSS risk", fix: "Sanitize with DOMPurify before rendering." },
  { id: "crypto.tls-reject", re: /rejectUnauthorized\s*:\s*false/, sev: "high", msg: "TLS verification disabled — MITM risk", fix: "Remove rejectUnauthorized: false. Verify certificates." },
  { id: "auth.hardcoded-token", re: /(?:password|secret|token|apikey|api_key)\s*[:=]\s*['"][^'"]{8,}['"]/i, sev: "high", msg: "Hardcoded secret", fix: "Use environment variables: process.env.SECRET" },
  { id: "config.cors-wildcard", re: /origin\s*:\s*['"]\*['"]/, sev: "medium", msg: "CORS wildcard origin", fix: "Set origin to an allowlist of your domains." },
  { id: "ai.prompt-injection", re: /role\s*:\s*['"]system['"][^}]*\+/i, sev: "high", msg: "Prompt injection — user input in system role", fix: "Never concatenate user input into the system role." },
  { id: "ai.agent-loop", re: /while\s*\(\s*(?:true|1)\s*\)/, sev: "medium", msg: "Uncapped agent loop — infinite API spend", fix: "Add an iteration limit: for (let i = 0; i < MAX; i++)" },
  { id: "ai.llm-output-exec", re: /exec\s*\([^)]*completion/i, sev: "critical", msg: "LLM output passed to exec() — RCE", fix: "Never pass LLM output to exec(). Validate and sanitize." },
];

const sampleCode = `const apiKey = 'sk-proj-abc123def456ghi789jkl';
const stripeKey = 'sk_live_51H8xdeadbeef1234';

db.query(\`SELECT * FROM users WHERE id = \${req.body.id}\`);

element.innerHTML = req.body.comment;

eval(userInput);

exec(completion.choices[0].message.content);

while (true) { await agent.step(); }`;

const sevStyle: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: "#ff3860", bg: "rgba(255,56,96,0.08)", border: "#ff3860" },
  high: { color: "#ffb547", bg: "rgba(255,181,71,0.08)", border: "#ffb547" },
  medium: { color: "#00f0ff", bg: "rgba(0,240,255,0.08)", border: "#00f0ff" },
  low: { color: "#00ff9d", bg: "rgba(0,255,157,0.08)", border: "#00ff9d" },
};

export default function Playground() {
  const [code, setCode] = useState(sampleCode);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scanned, setScanned] = useState(false);
  const [scanning, setScanning] = useState(false);

  const runScan = () => {
    setScanning(true);
    setFindings([]);
    setTimeout(() => {
      const lines = code.split("\n");
      const results: Finding[] = [];
      const seen = new Set<string>();
      for (let i = 0; i < lines.length; i++) {
        for (const rule of RULES) {
          if (rule.re.test(lines[i])) {
            const key = `${rule.id}-${i}`;
            if (!seen.has(key)) {
              seen.add(key);
              results.push({ id: rule.id, sev: rule.sev, msg: rule.msg, fix: rule.fix, line: i + 1, snippet: lines[i].trim().slice(0, 120) });
            }
          }
        }
      }
      results.sort((a, b) => {
        const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
        return order[a.sev] - order[b.sev];
      });
      setFindings(results);
      setScanning(false);
      setScanned(true);
    }, 800);
  };

  return (
    <section id="playground" className="relative py-24 px-6 overflow-hidden">
      <div className="absolute inset-0 glow-cyan opacity-20" />
      <div className="relative max-w-5xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-12"
        >
          <div className="inline-flex items-center gap-2 mb-4">
            <span className="font-mono text-xs text-[#00f0ff]/40 tracking-widest">[ 05 ]</span>
            <span className="h-px w-12 bg-[#00f0ff]/20" />
          </div>
          <h2 className="font-tech text-3xl md:text-5xl font-bold text-white tracking-wide">
            CODE SECURITY <span className="text-cyan-gradient glow-text-cyan">PLAYGROUND</span>
          </h2>
          <p className="mt-4 font-body text-[#5a8a9a]">Paste your code and run a live scan. No data leaves your browser.</p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, scale: 0.97 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          className="hud-panel scanline-overlay overflow-hidden shadow-2xl"
        >
          {/* Editor bar */}
          <div className="flex items-center justify-between px-5 py-3 border-b border-[#00f0ff]/10 bg-[#050a14]">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-[#ff3860]/70" />
              <span className="w-3 h-3 rounded-full bg-[#ffb547]/70" />
              <span className="w-3 h-3 rounded-full bg-[#00ff9d]/70" />
              <span className="ml-3 font-mono text-xs text-[#4a7a8a]">playground.js</span>
            </div>
            <div className="flex items-center gap-3">
              <button onClick={() => setCode(sampleCode)} className="font-mono text-xs text-[#4a7a8a] hover:text-[#00f0ff] transition-colors">
                [RESET]
              </button>
              <button
                onClick={runScan}
                disabled={scanning}
                className="font-tech px-5 py-1.5 rounded-sm bg-[#00f0ff]/10 border border-[#00f0ff]/40 text-[#00f0ff] text-xs font-bold tracking-wider hover:bg-[#00f0ff]/20 hover:glow-box-cyan transition-all disabled:opacity-60 clip-hex-sm"
              >
                {scanning ? "SCANNING…" : "▶ SCAN CODE"}
              </button>
            </div>
          </div>

          {/* Textarea */}
          <textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            spellCheck={false}
            className="w-full min-h-[220px] bg-[#02040a] text-[#c8f0ff] font-mono text-sm p-5 outline-none resize-y placeholder:text-[#1a3040] crt-flicker"
            placeholder="// Paste your code here..."
          />

          {/* Results */}
          {scanned && (
            <div className="border-t border-[#00f0ff]/10 p-5 bg-[#050a14]">
              <div className="flex items-center justify-between mb-4">
                <span className="font-tech text-sm font-semibold text-white tracking-wide">
                  {findings.length === 0 ? "✓ NO ISSUES DETECTED — CLEAN CODE" : `${findings.length} FINDING${findings.length > 1 ? "S" : ""} DETECTED`}
                </span>
                {findings.length > 0 && (
                  <div className="flex gap-2">
                    {["critical", "high", "medium", "low"].map((s) => {
                      const count = findings.filter((f) => f.sev === s).length;
                      if (count === 0) return null;
                      return (
                        <span key={s} className="font-tech px-2 py-0.5 rounded text-xs font-bold tracking-wider" style={{ color: sevStyle[s].color, background: sevStyle[s].bg, border: `1px solid ${sevStyle[s].border}` }}>
                          {count} {s}
                        </span>
                      );
                    })}
                  </div>
                )}
              </div>
              <AnimatePresence>
                {findings.map((f, i) => (
                  <motion.div
                    key={`${f.id}-${f.line}`}
                    initial={{ opacity: 0, x: -16 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.06 }}
                    className="mb-2.5 p-3.5 border-l-2"
                    style={{ borderLeftColor: sevStyle[f.sev].border, background: sevStyle[f.sev].bg }}
                  >
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-tech text-xs font-bold uppercase tracking-wider" style={{ color: sevStyle[f.sev].color }}>{f.sev}</span>
                      <code className="text-xs text-[#5a8a9a] font-mono">{f.id}</code>
                      <span className="font-mono text-xs text-[#4a7a8a]">· line {f.line}</span>
                    </div>
                    <div className="mt-1.5 font-body text-sm text-[#c8f0ff]">{f.msg}</div>
                    <code className="mt-1 block text-xs text-[#5a8a9a] font-mono truncate">{f.snippet}</code>
                    <div className="mt-1.5 font-body text-xs text-[#00ff9d]">
                      <span className="font-mono font-bold">[FIX]</span> {f.fix}
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          )}
        </motion.div>
      </div>
    </section>
  );
}