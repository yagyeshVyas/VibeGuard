"use client";

import { useRef } from "react";
import type { MouseEvent } from "react";

const features = [
  { icon: "◈", title: "Secret Detection", desc: "50+ secret types — OpenAI, AWS, GitHub, Stripe, Slack, Firebase — plus entropy-based detection for unknown secrets.", glow: "cyan" },
  { icon: "⬡", title: "AI Security", desc: "Prompt injection detection, MCP tool analysis, agent guardrails, LLM output sink analysis, secure_prompt analysis.", glow: "green" },
  { icon: "⬢", title: "AST Taint Analysis", desc: "SQL injection, XSS, command injection, path traversal, prototype pollution. AST-based dataflow tracing.", glow: "gold" },
  { icon: "◆", title: "Cross-File Taint", desc: "Import/export graph taint tracking. Follows user input across modules to find injection paths.", glow: "red" },
  { icon: "⬟", title: "Supply Chain", desc: "CVE intel via OSV.dev, slopsquat detection, typosquat detection, postinstall script analysis.", glow: "cyan" },
  { icon: "⬣", title: "Compliance Mapping", desc: "SOC 2, PCI-DSS, HIPAA, GDPR, ISO 27001, EU AI Act. Maps findings to control IDs.", glow: "green" },
  { icon: "⬤", title: "MCP Server", desc: "82 MCP tools for Claude Code, Cursor, Windsurf, Codex, Gemini CLI, Continue, Cline, Roo Code, OpenHands, Aider, Copilot CLI, Amazon Q, Cody.", glow: "gold" },
  { icon: "✦", title: "Real-Time Hooks", desc: "PostToolUse hook auto-scans files after AI edits. Pre-commit hook blocks commits on critical findings.", glow: "red" },
  { icon: "◈", title: "Auto-Fix + Verify", desc: "43 auto-fixable rule types with snapshot + rollback. Verify mode shows resolved/remaining/new issues.", glow: "cyan" },
];

const glowMap: Record<string, string> = {
  cyan: "rgba(0,240,255,0.18)",
  green: "rgba(0,255,157,0.14)",
  gold: "rgba(255,181,71,0.12)",
  red: "rgba(255,56,96,0.12)",
};
const colorMap: Record<string, string> = {
  cyan: "#00f0ff",
  green: "#00ff9d",
  gold: "#ffb547",
  red: "#ff3860",
};

function GlassCard({ f }: { f: (typeof features)[number] }) {
  const cardRef = useRef<HTMLDivElement>(null);

  const onMove = (e: MouseEvent<HTMLDivElement>) => {
    const el = cardRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    el.style.setProperty("--mx", `${e.clientX - r.left}px`);
    el.style.setProperty("--my", `${e.clientY - r.top}px`);
  };

  return (
    <div
      ref={cardRef}
      onMouseMove={onMove}
      className="glass-gradient clip-notch p-7 group hover:-translate-y-2 transition-transform duration-300 h-full relative overflow-hidden"
      style={{ borderRadius: 6 }}
    >
      <span className="card-liquid-glow" />
      <div
        className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
        style={{ background: `radial-gradient(circle at center, ${glowMap[f.glow]}, transparent 70%)` }}
      />
      <span className="corner tl" style={{ borderColor: colorMap[f.glow] }} />
      <span className="corner tr" style={{ borderColor: colorMap[f.glow] }} />
      <span className="corner bl" style={{ borderColor: colorMap[f.glow] }} />
      <span className="corner br" style={{ borderColor: colorMap[f.glow] }} />
      <div className="relative">
        <div
          className="text-4xl mb-4 inline-block group-hover:scale-110 group-hover:-rotate-3 transition-transform duration-300 font-tech"
          style={{ color: colorMap[f.glow], textShadow: `0 0 14px ${glowMap[f.glow]}` }}
        >
          {f.icon}
        </div>
        <h3 className="font-display text-lg font-semibold text-white mb-2 tracking-wide">{f.title}</h3>
        <p className="font-body text-sm text-[#7ea6bc] leading-relaxed">{f.desc}</p>
      </div>
    </div>
  );
}

export default function Features() {
  return (
    <section id="features" className="relative py-28 px-6">
      <div className="absolute inset-0 bg-hex opacity-20" data-parallax="30" />
      <div className="relative max-w-7xl mx-auto">
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 mb-4">
            <span className="font-mono text-xs text-[#00f0ff]/50 tracking-widest">[ 03 ]</span>
            <span className="h-px w-12 bg-[#00f0ff]/20" data-rule-line />
          </div>
          <h2 className="font-display text-3xl md:text-5xl font-semibold text-white tracking-tight">
            EVERYTHING IT CATCHES,{" "}
            <span className="text-aurora-gradient glow-text-cyan">NOTHING IT MISSES</span>
          </h2>
          <p className="mt-4 font-body text-lg text-[#7ea6bc] max-w-2xl mx-auto">
            Nine detection engines running in 5 seconds, fully offline, on your machine.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((f) => (
            <GlassCard key={f.title} f={f} />
          ))}
        </div>
      </div>
    </section>
  );
}
