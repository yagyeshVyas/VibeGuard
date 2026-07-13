"use client";

import { motion, AnimatePresence } from "framer-motion";
import { useState } from "react";

const vulns = [
  { title: "Leaked Stripe Key", sev: "critical", code: `const key = "sk_live_51H8x...";\n// anyone with devtools can issue refunds`, finding: "secret.stripe-live-key", fix: "Move to process.env.STRIPE_SECRET_KEY" },
  { title: "Supabase Database Open to World", sev: "high", code: `create table posts ( ... );\n-- no RLS — anyone can read/write all rows`, finding: "db.supabase-missing-rls", fix: "Enable Row Level Security with proper policies" },
  { title: "SQL Injection via Template Literal", sev: "high", code: `db.query(\`SELECT * FROM users\n  WHERE id = \${req.body.id}\`);`, finding: "taint.sql-injection", fix: "Use parameterized queries: db.query('SELECT ... WHERE id = ?', [id])" },
  { title: "Prompt Injection in System Prompt", sev: "high", code: `{ role: "system",\n  content: "You are " + req.body.prompt }`, finding: "ai.user-input-in-system-prompt", fix: "Never inject user input into the system role" },
  { title: "dangerouslySetInnerHTML with Request Data", sev: "high", code: `<div dangerouslySetInnerHTML=\n  {{__html: req.body.html}} />`, finding: "react.dangerous-html", fix: "Use textContent or sanitize with DOMPurify" },
  { title: "AI Agent Loop Without Iteration Cap", sev: "medium", code: `while (true) {\n  await agent.step();\n}`, finding: "ai.agent-loop-no-cap", fix: "Add an iteration limit to prevent infinite API spend" },
  { title: "Hardcoded JWT Secret", sev: "critical", code: `jwt.sign(payload, "mysecret123");\n// token forgery`, finding: "secret.hardcoded-jwt", fix: "Use environment variables: process.env.JWT_SECRET" },
  { title: "Shell Command from LLM Output", sev: "critical", code: `const completion = await openai\n  .chat.completions.create({...});\nexec(completion.choices[0]\n  .message.content);`, finding: "ai.llm-output-exec", fix: "Never pass LLM output to exec(). Validate and sanitize first." },
];

const sevStyle: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: "#ff3860", bg: "rgba(255,56,96,0.08)", border: "#ff3860" },
  high: { color: "#ffb547", bg: "rgba(255,181,71,0.08)", border: "#ffb547" },
  medium: { color: "#00f0ff", bg: "rgba(0,240,255,0.08)", border: "#00f0ff" },
};

export default function WhatItCatches() {
  const [active, setActive] = useState(0);
  const v = vulns[active];

  return (
    <section id="catches" className="relative py-24 px-6 overflow-hidden">
      <div className="absolute inset-0 glow-red opacity-15" />
      <div className="relative max-w-6xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-14"
        >
          <div className="inline-flex items-center gap-2 mb-4">
            <span className="font-mono text-xs text-[#00f0ff]/40 tracking-widest">[ 04 ]</span>
            <span className="h-px w-12 bg-[#00f0ff]/20" />
          </div>
          <h2 className="font-tech text-3xl md:text-5xl font-bold text-white tracking-wide">
            WHAT IT <span className="text-gold-gradient glow-text-gold">CATCHES</span>
          </h2>
          <p className="mt-4 font-body text-[#5a8a9a] max-w-2xl mx-auto">
            The holes AI coding tools leave behind — click any card to see the vulnerable code and the fix.
          </p>
        </motion.div>

        <div className="grid lg:grid-cols-2 gap-6">
          {/* List */}
          <div className="space-y-2">
            {vulns.map((item, i) => (
              <motion.button
                key={item.title}
                initial={{ opacity: 0, x: -20 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.05 }}
                onClick={() => setActive(i)}
                className={`w-full text-left px-5 py-4 hud-panel rounded-sm transition-all relative ${
                  active === i ? "border-[#00f0ff]/40 glow-box-cyan" : "hover:border-[#00f0ff]/20"
                }`}
              >
                <div className="flex items-center gap-3">
                  <span
                    className="font-tech px-2 py-0.5 rounded text-xs font-bold tracking-wider"
                    style={{ color: sevStyle[item.sev].color, background: sevStyle[item.sev].bg, border: `1px solid ${sevStyle[item.sev].border}` }}
                  >
                    {item.sev}
                  </span>
                  <span className={`font-body text-sm font-medium ${active === i ? "text-white" : "text-[#5a8a9a]"}`}>
                    {item.title}
                  </span>
                  {active === i && (
                    <motion.span layoutId="arrow-indicator" className="ml-auto text-[#00f0ff]">
                      ▶
                    </motion.span>
                  )}
                </div>
              </motion.button>
            ))}
          </div>

          {/* Code display */}
          <div>
            <AnimatePresence mode="wait">
              <motion.div
                key={active}
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="hud-panel scanline-overlay rounded-sm overflow-hidden shadow-2xl"
              >
                <div className="flex items-center justify-between px-5 py-3 border-b border-[#00f0ff]/10">
                  <span className="font-tech text-sm font-semibold text-white tracking-wide">{v.title}</span>
                  <span
                    className="font-tech px-2 py-0.5 rounded text-xs font-bold tracking-wider"
                    style={{ color: sevStyle[v.sev].color, background: sevStyle[v.sev].bg, border: `1px solid ${sevStyle[v.sev].border}` }}
                  >
                    {v.sev}
                  </span>
                </div>
                <div className="p-5">
                  <pre className="font-mono text-sm text-[#c8f0ff] bg-[#02040a] rounded p-4 overflow-x-auto border border-[#00f0ff]/10">
                    <code>{v.code}</code>
                  </pre>
                  <div className="mt-4 space-y-2">
                    <div className="flex items-start gap-2">
                      <span className="font-mono text-xs text-[#ff3860] font-bold mt-0.5">[FINDING]</span>
                      <code className="text-xs text-[#5a8a9a] font-mono">{v.finding}</code>
                    </div>
                    <div className="flex items-start gap-2">
                      <span className="font-mono text-xs text-[#00ff9d] font-bold mt-0.5">[FIX]</span>
                      <span className="font-body text-xs text-[#00ff9d]">{v.fix}</span>
                    </div>
                  </div>
                </div>
              </motion.div>
            </AnimatePresence>
          </div>
        </div>
      </div>
    </section>
  );
}