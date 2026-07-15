"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import Shell from "@/components/Shell";
import ArcReactor from "@/components/ArcReactor";

const stats = [
  { num: "752", label: "Detection Rules" },
  { num: "82", label: "MCP Tools" },
  { num: "419", label: "Tests Passing" },
  { num: "89%", label: "F1 Benchmark" },
  { num: "18", label: "Languages" },
  { num: "$0", label: "Cost Forever" },
];

const timeline = [
  { phase: "v0.1.0", title: "Initial Release", desc: "Core scanner with secrets, injection, auth, config, PII rules. MCP server with 5 tools. Pre-commit hook. SARIF output. Zero runtime dependencies." },
  { phase: "v1.0.0", title: "Layered Protection Suite", desc: "699 rules, 75 MCP tools, AST taint analysis, cross-file taint tracking, auto-fix, daemon mode, shell guard, multi-client installer. 342 tests." },
  { phase: "v1.3.0", title: "Phase 0-4 Complete", desc: "752 rules, 82 MCP tools, 18 languages, 10 compliance frameworks, Python taint v2, firewall semantic classifier, local MITM proxy, plugin system v2, agentic fix contracts, C/C++/Dart/Scala/Elixir rules. 419 tests. F1 89.1%." },
];

export default function AboutPage() {
  return (
    <Shell>
      {/* Hero */}
      <section className="relative min-h-[70vh] flex items-center justify-center pt-32 pb-16 px-6 overflow-hidden">
        <div className="absolute inset-0 bg-hex-animated opacity-40" />
        <div className="absolute inset-0 glow-cyan" />

        <motion.div
          initial={{ opacity: 0, scale: 0.3 }}
          animate={{ opacity: 0.15, scale: 1 }}
          transition={{ duration: 1.5 }}
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2"
        >
          <ArcReactor size={500} />
        </motion.div>

        <div className="relative z-10 max-w-3xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            className="inline-flex items-center gap-2 px-4 py-1.5 glass clip-hex-sm mb-8"
          >
            <span className="w-2 h-2 rounded-full bg-[#00ff9d] animate-pulse" />
            <span className="font-mono text-xs text-[#00f0ff]/70 tracking-widest">CREATOR PROFILE</span>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="font-tech text-5xl md:text-7xl font-black tracking-tight"
          >
            <span className="text-white glow-text-cyan">YAGYESH</span>{" "}
            <span className="text-cyan-gradient glow-text-cyan">VYAS</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="mt-6 font-body text-lg md:text-xl text-[#5a8a9a] max-w-2xl mx-auto leading-relaxed"
          >
            Developer behind VibeGuard. Building security tools for the AI coding era.
            One person, zero dependencies, trusted by many.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.6 }}
            className="mt-10 flex flex-wrap items-center justify-center gap-4"
          >
            <a
              href="https://www.linkedin.com/in/yagyeshvyas"
              target="_blank"
              rel="noreferrer"
              className="font-tech px-7 py-3.5 rounded-sm bg-gradient-to-r from-[#00f0ff]/80 to-[#00ff9d]/80 text-[#02040a] text-sm font-bold tracking-wider hover:shadow-[#00f0ff]/40 hover:-translate-y-0.5 transition-all clip-hex-sm flex items-center gap-2"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 01-2.063-2.065 2.063 2.063 0 112.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z" />
              </svg>
              CONNECT ON LINKEDIN
            </a>
            <a
              href="https://github.com/yagyeshVyas"
              target="_blank"
              rel="noreferrer"
              className="btn-ghost font-display px-7 py-3.5 clip-notch text-sm font-bold tracking-wider"
            >
              GITHUB PROFILE
            </a>
          </motion.div>
        </div>
      </section>

      {/* Stats */}
      <section className="relative py-16 px-6">
        <div className="max-w-5xl mx-auto">
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-6">
            {stats.map((s, i) => (
              <motion.div
                key={s.label}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.08 }}
                className="glass rounded-sm p-5 text-center"
              >
                <div className="font-tech text-3xl font-black text-cyan-gradient glow-text-cyan">{s.num}</div>
                <div className="mt-2 font-mono text-xs text-[#4a7a8a] tracking-widest">{s.label}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Story */}
      <section className="relative py-24 px-6">
        <div className="absolute inset-0 glow-green opacity-15" />
        <div className="relative max-w-3xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-center mb-14"
          >
            <div className="inline-flex items-center gap-2 mb-4">
              <span className="font-mono text-xs text-[#00f0ff]/40 tracking-widest">[ STORY ]</span>
              <span className="h-px w-12 bg-[#00f0ff]/20" />
            </div>
            <h2 className="font-tech text-3xl md:text-5xl font-bold text-white tracking-wide">
              THE <span className="text-cyan-gradient glow-text-cyan">MISSION</span>
            </h2>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="glass-strong scanline-overlay rounded-sm p-8 space-y-6"
          >
            <p className="font-body text-lg text-[#c8f0ff] leading-relaxed">
              AI coding tools like Claude Code, Cursor, and Windsurf generate code at incredible speed —
              but they leave security holes behind. Leaked API keys. SQL injection. Prompt injection.
              Open databases. These are not theoretical risks; they are the default output.
            </p>
            <p className="font-body text-lg text-[#c8f0ff] leading-relaxed">
              VibeGuard catches those holes <span className="text-[#00ff9d] font-bold">before they ship</span>.
              It runs entirely on your machine — no telemetry, no cloud, no dependencies.
              752 rules, 82 MCP tools, AST-based taint analysis, local MITM proxy, semantic firewall. Free forever.
            </p>
            <p className="font-body text-lg text-[#c8f0ff] leading-relaxed">
              Built by <span className="text-[#00f0ff] font-bold">Yagyesh Vyas</span> — a developer who
              believes security tools should not require a budget, a team, or a PhD to use.
            </p>
          </motion.div>
        </div>
      </section>

      {/* Timeline */}
      <section className="relative py-24 px-6">
        <div className="relative max-w-3xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-center mb-14"
          >
            <div className="inline-flex items-center gap-2 mb-4">
              <span className="font-mono text-xs text-[#00f0ff]/40 tracking-widest">[ TIMELINE ]</span>
              <span className="h-px w-12 bg-[#00f0ff]/20" />
            </div>
            <h2 className="font-tech text-3xl md:text-5xl font-bold text-white tracking-wide">
              VERSION <span className="text-cyan-gradient glow-text-cyan">HISTORY</span>
            </h2>
          </motion.div>

          <div className="space-y-6">
            {timeline.map((t, i) => (
              <motion.div
                key={t.phase}
                initial={{ opacity: 0, x: -20 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.15 }}
                className="glass rounded-sm p-6 relative"
              >
                <div className="flex items-center gap-3 mb-3">
                  <span className="font-tech text-sm font-bold text-[#00f0ff] tracking-wider">{t.phase}</span>
                  <span className="h-px flex-1 bg-[#00f0ff]/20" />
                </div>
                <h3 className="font-tech text-lg font-bold text-white mb-2">{t.title}</h3>
                <p className="font-body text-sm text-[#5a8a9a] leading-relaxed">{t.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="relative py-20 px-6">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="max-w-3xl mx-auto text-center"
        >
          <div className="flex justify-center mb-6">
            <ArcReactor size={80} />
          </div>
          <h2 className="font-tech text-3xl font-bold text-white tracking-wide">
            SHIP SAFE CODE. <span className="text-cyan-gradient glow-text-cyan">SLEEP EASY.</span>
          </h2>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
            <Link href="/" className="btn-primary font-display px-7 py-3.5 clip-notch text-sm font-bold tracking-wider">
              BACK TO HOME
            </Link>
            <Link href="/playground" className="btn-ghost font-display px-7 py-3.5 clip-notch text-sm font-bold tracking-wider">
              TRY PLAYGROUND
            </Link>
          </div>
        </motion.div>
      </section>
    </Shell>
  );
}