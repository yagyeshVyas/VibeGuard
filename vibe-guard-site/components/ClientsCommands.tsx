"use client";

import { motion } from "framer-motion";

const clients = [
  "Claude Code", "Cursor", "Windsurf", "Codex CLI", "Antigravity", "Gemini CLI",
  "Continue", "Cline", "Roo Code", "OpenHands", "Aider",
];

const commands = [
  { cmd: "vibeguard scan [dir]", desc: "Scan a project (auto-detects framework)" },
  { cmd: "vibeguard scan --fix", desc: "Scan + apply safe auto-fixes" },
  { cmd: "vibeguard scan --all", desc: "Show all findings including low-confidence" },
  { cmd: "vibeguard auto [dir]", desc: "Full protection (daemon + hooks + shell guard)" },
  { cmd: "vibeguard auto --stop", desc: "Turn off, restore backups" },
  { cmd: "vibeguard fix [dir]", desc: "Auto-fix 43 rule types" },
  { cmd: "vibeguard pre-deploy [dir]", desc: "13-gate deployment check" },
  { cmd: "vibeguard mcp", desc: "MCP server (for AI client integration)" },
  { cmd: 'vibeguard guard "command"', desc: "Check a shell command before running it" },
  { cmd: "vibeguard install-hook", desc: "Git pre-commit hook (blocks on critical)" },
];

export default function ClientsCommands() {
  return (
    <section id="commands" className="relative py-24 px-6">
      <div className="absolute inset-0 bg-hex opacity-15" data-parallax="20" />
      <div className="relative max-w-6xl mx-auto space-y-20">
        {/* AI Clients */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center"
        >
          <div className="inline-flex items-center gap-2 mb-4">
            <span className="font-mono text-xs text-[#00f0ff]/40 tracking-widest">[ 07 ]</span>
            <span className="h-px w-12 bg-[#00f0ff]/20" data-rule-line />
          </div>
          <h2 className="font-display text-3xl md:text-5xl font-semibold text-white tracking-tight">
            ONE COMMAND — <span className="text-aurora-gradient glow-text-cyan">ALL AI CLIENTS</span>
          </h2>
          <p className="mt-4 font-body text-[#7ea6bc]">
            <code className="font-mono text-[#00ff9d]">vibeguard install</code> auto-detects and wires MCP into every client you have:
          </p>
          <div className="mt-10 flex flex-wrap gap-3 justify-center">
            {clients.map((c, i) => (
              <motion.div
                key={c}
                initial={{ opacity: 0, scale: 0.8 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.05 }}
                whileHover={{ y: -4, scale: 1.05 }}
                className="glass rounded-sm px-5 py-3 font-body text-sm font-medium text-[#c8f0ff] hover:border-[#00f0ff]/40 hover:glow-box-cyan transition-all clip-hex-sm"
              >
                {c}
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Commands reference */}
        <motion.div initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}>
          <div className="text-center mb-10">
            <div className="inline-flex items-center gap-2 mb-4">
              <span className="font-mono text-xs text-[#00f0ff]/40 tracking-widest">[ 08 ]</span>
              <span className="h-px w-12 bg-[#00f0ff]/20" data-rule-line />
            </div>
            <h2 className="font-display text-3xl md:text-5xl font-semibold text-white tracking-tight">
              COMMAND <span className="text-aurora-gradient glow-text-cyan">REFERENCE</span>
            </h2>
          </div>
          <div className="glass rounded-sm overflow-hidden scanline-overlay">
            {commands.map((c, i) => (
              <motion.div
                key={c.cmd}
                initial={{ opacity: 0, x: -16 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.05 }}
                className={`flex flex-col md:flex-row md:items-center gap-1 md:gap-4 px-5 py-4 ${
                  i !== commands.length - 1 ? "border-b border-[#00f0ff]/10" : ""
                } hover:bg-[#00f0ff]/5 transition-colors group`}
              >
                <code className="font-mono text-sm text-[#00ff9d] whitespace-nowrap md:w-72">{c.cmd}</code>
                <span className="font-body text-sm text-[#7ea6bc]">{c.desc}</span>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  );
}