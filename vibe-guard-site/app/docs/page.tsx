"use client";

import { motion } from "framer-motion";
import { useState } from "react";
import Link from "next/link";
import Shell from "@/components/Shell";

const sections = [
  {
    id: "install",
    title: "Installation",
    commands: [
      { cmd: "npx @yagyeshvyas/vibeguard scan", desc: "Run a one-time scan — no install needed" },
      { cmd: "npm install -g @yagyeshvyas/vibeguard", desc: "Install globally" },
      { cmd: "claude mcp add vibeguard -- npx @yagyeshvyas/vibeguard mcp", desc: "Wire into Claude Code" },
    ],
  },
  {
    id: "scan",
    title: "Scanning",
    commands: [
      { cmd: "vibeguard scan [dir]", desc: "Scan a project (auto-detects framework)" },
      { cmd: "vibeguard scan --fix", desc: "Scan + apply safe auto-fixes" },
      { cmd: "vibeguard scan --all", desc: "Show all findings including low-confidence" },
      { cmd: "vibeguard scan --min-confidence medium", desc: "Hide low-confidence hints" },
      { cmd: "vibeguard scan --output sarif", desc: "SARIF output for GitHub Code Scanning" },
    ],
  },
  {
    id: "auto",
    title: "Full Protection (auto)",
    commands: [
      { cmd: "vibeguard auto [dir]", desc: "Activates daemon + hooks + shell guard" },
      { cmd: "vibeguard auto --status", desc: "See what's active" },
      { cmd: "vibeguard auto --stop", desc: "Turn off, restore backups byte-for-byte" },
      { cmd: "vibeguard auto --ci", desc: "Pipeline mode, exit non-zero on critical" },
      { cmd: "vibeguard auto --fix", desc: "Apply safe auto-fixes during daemon mode" },
    ],
  },
  {
    id: "fix",
    title: "Auto-Fix",
    commands: [
      { cmd: "vibeguard fix [dir]", desc: "Auto-fix 43 rule types with snapshot + rollback" },
      { cmd: "vibeguard fix --verify", desc: "Show resolved / remaining / new issues" },
    ],
  },
  {
    id: "mcp",
    title: "MCP Server",
    commands: [
      { cmd: "vibeguard mcp", desc: "Start MCP server (75 tools)" },
      { cmd: "vibeguard install", desc: "Auto-detect and wire into all AI clients" },
    ],
  },
  {
    id: "hooks",
    title: "Hooks & Guard",
    commands: [
      { cmd: "vibeguard install-hook", desc: "Git pre-commit hook (blocks on critical)" },
      { cmd: "vibeguard install-hook-post", desc: "PostToolUse hook (auto-scan AI edits)" },
      { cmd: 'vibeguard guard "rm -rf /"', desc: "Check a shell command before running" },
      { cmd: "vibeguard pre-deploy [dir]", desc: "13-gate deployment check" },
    ],
  },
];

const languages = [
  "JavaScript", "TypeScript", "Python", "Go", "Java", "Ruby", "PHP",
  "C#", "Rust", "Kotlin", "Swift", "Bash", "SQL", "YAML",
];

const clients = [
  "Claude Code", "Cursor", "Windsurf", "Codex CLI", "Antigravity", "Gemini CLI",
  "Continue", "Cline", "Roo Code", "OpenHands", "Aider",
];

export default function DocsPage() {
  const [activeSection, setActiveSection] = useState("install");
  const [copiedCmd, setCopiedCmd] = useState("");

  const copyCmd = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(cmd);
    setTimeout(() => setCopiedCmd(""), 2000);
  };

  return (
    <Shell>
      {/* Hero */}
      <section className="relative pt-32 pb-12 px-6 text-center overflow-hidden">
        <div className="absolute inset-0 bg-hex-animated opacity-30" />
        <div className="absolute inset-0 glow-cyan" />
        <div className="relative z-10">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            className="inline-flex items-center gap-2 px-4 py-1.5 hud-panel clip-hex-sm mb-6"
          >
            <span className="w-2 h-2 rounded-full bg-[#00f0ff] animate-pulse" />
            <span className="font-mono text-xs text-[#00f0ff]/70 tracking-widest">TECHNICAL DOCUMENTATION</span>
          </motion.div>
          <motion.h1
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="font-tech text-4xl md:text-6xl font-black text-white tracking-tight"
          >
            <span className="glow-text-cyan">DOCUMENTATION</span>
          </motion.h1>
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.2 }}
            className="mt-4 font-body text-[#5a8a9a]"
          >
            Everything you need to run VibeGuard. By <span className="text-[#00f0ff] font-bold">Yagyesh Vyas</span>.
          </motion.p>
        </div>
      </section>

      {/* Content */}
      <section className="relative py-12 px-6">
        <div className="max-w-6xl mx-auto grid lg:grid-cols-[200px_1fr] gap-8">
          {/* Sidebar */}
          <aside className="lg:sticky lg:top-24 self-start">
            <div className="hud-panel rounded-sm p-4 space-y-1">
              <div className="font-mono text-xs text-[#4a7a8a] tracking-widest mb-3 px-2">SECTIONS</div>
              {sections.map((s) => (
                <button
                  key={s.id}
                  onClick={() => {
                    setActiveSection(s.id);
                    document.getElementById(s.id)?.scrollIntoView({ behavior: "smooth", block: "start" });
                  }}
                  className={`w-full text-left px-3 py-2 rounded-sm font-body text-sm transition-colors ${
                    activeSection === s.id
                      ? "text-[#00f0ff] bg-[#00f0ff]/10"
                      : "text-[#5a8a9a] hover:text-[#00f0ff] hover:bg-[#00f0ff]/5"
                  }`}
                >
                  {s.title}
                </button>
              ))}
            </div>
          </aside>

          {/* Main content */}
          <div className="space-y-16">
            {sections.map((section, si) => (
              <div key={section.id} id={section.id}>
                <motion.div
                  initial={{ opacity: 0, y: 30 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  className="mb-6"
                >
                  <div className="inline-flex items-center gap-2 mb-3">
                    <span className="font-mono text-xs text-[#00f0ff]/40 tracking-widest">[ {String(si + 1).padStart(2, "0")} ]</span>
                    <span className="h-px w-12 bg-[#00f0ff]/20" />
                  </div>
                  <h2 className="font-tech text-2xl md:text-3xl font-bold text-white tracking-wide">
                    {section.title.toUpperCase()}
                  </h2>
                </motion.div>

                <div className="space-y-3">
                  {section.commands.map((c, ci) => (
                    <motion.div
                      key={ci}
                      initial={{ opacity: 0, x: -16 }}
                      whileInView={{ opacity: 1, x: 0 }}
                      viewport={{ once: true }}
                      transition={{ delay: ci * 0.05 }}
                      className="hud-panel rounded-sm p-4 hover:border-[#00f0ff]/30 transition-colors group"
                    >
                      <div className="flex items-center justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <code className="font-mono text-sm text-[#00ff9d] break-all">{c.cmd}</code>
                          <p className="mt-1 font-body text-sm text-[#5a8a9a]">{c.desc}</p>
                        </div>
                        <button
                          onClick={() => copyCmd(c.cmd)}
                          className="font-mono text-xs text-[#4a7a8a] hover:text-[#00f0ff] transition-colors whitespace-nowrap"
                        >
                          {copiedCmd === c.cmd ? "[COPIED]" : "[COPY]"}
                        </button>
                      </div>
                    </motion.div>
                  ))}
                </div>
              </div>
            ))}

            {/* Languages */}
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
            >
              <h2 className="font-tech text-2xl md:text-3xl font-bold text-white tracking-wide mb-6">
                SUPPORTED LANGUAGES
              </h2>
              <div className="flex flex-wrap gap-3">
                {languages.map((l, i) => (
                  <motion.span
                    key={l}
                    initial={{ opacity: 0, scale: 0.8 }}
                    whileInView={{ opacity: 1, scale: 1 }}
                    viewport={{ once: true }}
                    transition={{ delay: i * 0.04 }}
                    className="hud-panel rounded-sm px-4 py-2 font-body text-sm text-[#c8f0ff] clip-hex-sm"
                  >
                    {l}
                  </motion.span>
                ))}
              </div>
            </motion.div>

            {/* AI Clients */}
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
            >
              <h2 className="font-tech text-2xl md:text-3xl font-bold text-white tracking-wide mb-6">
                AI CLIENTS SUPPORTED
              </h2>
              <div className="flex flex-wrap gap-3">
                {clients.map((c, i) => (
                  <motion.span
                    key={c}
                    initial={{ opacity: 0, scale: 0.8 }}
                    whileInView={{ opacity: 1, scale: 1 }}
                    viewport={{ once: true }}
                    transition={{ delay: i * 0.04 }}
                    className="hud-panel rounded-sm px-4 py-2 font-body text-sm text-[#00f0ff] hover:glow-box-cyan transition-all clip-hex-sm"
                  >
                    {c}
                  </motion.span>
                ))}
              </div>
            </motion.div>

            {/* CTA */}
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              className="hud-panel rounded-sm p-8 text-center scanline-overlay"
            >
              <p className="font-body text-[#5a8a9a] mb-4">Ready to start?</p>
              <div className="flex flex-wrap items-center justify-center gap-4">
                <Link href="/playground" className="font-tech px-7 py-3.5 rounded-sm bg-gradient-to-r from-[#00f0ff]/80 to-[#00ff9d]/80 text-[#02040a] text-sm font-bold tracking-wider hover:-translate-y-0.5 transition-all clip-hex-sm">
                  TRY PLAYGROUND
                </Link>
                <a href="https://github.com/yagyeshVyas/VibeGuard" target="_blank" rel="noreferrer" className="font-tech px-7 py-3.5 rounded-sm hud-panel text-[#00f0ff] text-sm font-bold tracking-wider hover:glow-box-cyan transition-all clip-hex-sm">
                  VIEW SOURCE
                </a>
              </div>
            </motion.div>
          </div>
        </div>
      </section>
    </Shell>
  );
}