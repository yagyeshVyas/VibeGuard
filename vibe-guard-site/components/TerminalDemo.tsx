"use client";

import { motion } from "framer-motion";
import { useEffect, useRef, useState } from "react";

const scanLines: { text: string; cls: string; delay: number }[] = [
  { text: "$ npx @yagyeshvyas/vibeguard scan", cls: "text-[#c8f0ff]", delay: 0 },
  { text: "", cls: "", delay: 300 },
  { text: "VibeGuard security scan", cls: "text-white font-bold", delay: 400 },
  { text: "./my-app", cls: "text-[#4a6b7e]", delay: 500 },
  { text: "", cls: "", delay: 600 },
  { text: "CRITICAL  api/route.ts:3  [secret.openai-key]", cls: "text-[#ff3860] font-bold glow-text-red", delay: 800 },
  { text: "  OpenAI API key hardcoded in server code", cls: "text-[#7ea6bc]", delay: 950 },
  { text: "  fix: Move to environment variable.", cls: "text-[#00ff9d]", delay: 1100 },
  { text: "", cls: "", delay: 1200 },
  { text: "HIGH      db/query.ts:5   [taint.sql-injection]", cls: "text-[#ffb547] font-bold glow-text-gold", delay: 1400 },
  { text: "  User input flows into SQL query via template literal", cls: "text-[#7ea6bc]", delay: 1550 },
  { text: "  fix: Use parameterized queries / prepared statements.", cls: "text-[#00ff9d]", delay: 1700 },
  { text: "", cls: "", delay: 1800 },
  { text: "HIGH      app/page.jsx:8  [taint.xss-dom]", cls: "text-[#ffb547] font-bold glow-text-gold", delay: 2000 },
  { text: "  User input reaches innerHTML — DOM XSS", cls: "text-[#7ea6bc]", delay: 2150 },
  { text: "  fix: Use textContent instead of innerHTML.", cls: "text-[#00ff9d]", delay: 2300 },
  { text: "", cls: "", delay: 2400 },
  { text: "Grade D  (12 files)  1 critical  3 high  2 medium  1 low", cls: "text-white font-bold", delay: 2600 },
  { text: "", cls: "", delay: 2700 },
  { text: "Run vibeguard fix to auto-fix 4 issues", cls: "text-[#00f0ff]", delay: 2900 },
];

export default function TerminalDemo() {
  const [visible, setVisible] = useState(0);
  const [replayKey, setReplayKey] = useState(0);
  const sectionRef = useRef<HTMLDivElement>(null);
  const [started, setStarted] = useState(false);

  useEffect(() => {
    if (!started) return;
    setVisible(0);
    const timers = scanLines.map((_, i) =>
      setTimeout(() => setVisible((v) => Math.max(v, i + 1)), scanLines[i].delay)
    );
    const reset = setTimeout(() => setReplayKey((k) => k + 1), 6000);
    return () => {
      timers.forEach(clearTimeout);
      clearTimeout(reset);
    };
  }, [started, replayKey]);

  useEffect(() => {
    const obs = new IntersectionObserver(
      ([e]) => { if (e.isIntersecting) setStarted(true); },
      { threshold: 0.3 }
    );
    if (sectionRef.current) obs.observe(sectionRef.current);
    return () => obs.disconnect();
  }, []);

  return (
    <section ref={sectionRef} className="relative py-24 px-6 overflow-hidden">
      <div className="absolute inset-0 glow-green opacity-20" data-parallax="25" />
      <div className="relative max-w-4xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-10"
        >
          <div className="inline-flex items-center gap-2 mb-4">
            <span className="font-mono text-xs text-[#00f0ff]/40 tracking-widest">[ 02 ]</span>
            <span className="h-px w-12 bg-[#00f0ff]/20" data-rule-line />
          </div>
          <h2 className="font-display text-3xl md:text-4xl font-semibold text-white tracking-tight">
            SEE IT <span className="text-aurora-gradient glow-text-cyan">IN ACTION</span>
          </h2>
          <p className="mt-3 font-body text-[#7ea6bc]">A real scan of a test project with a planted Stripe key.</p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          className="glass-strong scanline-overlay overflow-hidden shadow-2xl shadow-[#00f0ff]/10"
          data-float-in
        >
          {/* Terminal title bar */}
          <div className="flex items-center gap-2 px-4 py-3 border-b border-[#00f0ff]/10 bg-[#050a14]">
            <span className="w-3 h-3 rounded-full bg-[#ff3860]/70" />
            <span className="w-3 h-3 rounded-full bg-[#ffb547]/70" />
            <span className="w-3 h-3 rounded-full bg-[#00ff9d]/70" />
            <span className="ml-3 font-mono text-xs text-[#4a6b7e]">vibeguard — scan — 120×40</span>
            <span className="ml-auto font-mono text-[10px] text-[#00f0ff]/30">REC ●</span>
          </div>

          {/* Terminal output */}
          <div className="relative p-6 font-mono text-sm bg-[#02040a] min-h-[420px] crt-flicker">
            {scanLines.slice(0, visible).map((line, i) => (
              <motion.div
                key={`${replayKey}-${i}`}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                className={`whitespace-pre ${line.cls}`}
              >
                {line.text || "\u00A0"}
              </motion.div>
            ))}
            {visible >= scanLines.length && (
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="inline-block w-2 h-4 bg-[#00ff9d] align-middle cursor-blink"
              />
            )}
          </div>
        </motion.div>
      </div>
    </section>
  );
}