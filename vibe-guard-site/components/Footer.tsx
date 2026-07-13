"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import ArcReactor from "./ArcReactor";

export default function Footer() {
  return (
    <footer className="relative py-20 px-6 overflow-hidden">
      <div className="absolute inset-0 glow-cyan opacity-15" />
      <div className="relative max-w-4xl mx-auto text-center">
        {/* CTA with arc reactor */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="hud-panel rounded-sm p-10 mb-16 scanline-overlay"
        >
          <div className="flex justify-center mb-6">
            <ArcReactor size={80} />
          </div>
          <h2 className="font-tech text-3xl md:text-4xl font-bold text-white tracking-wide">
            SHIP SAFE CODE. <span className="text-cyan-gradient glow-text-cyan">SLEEP EASY.</span>
          </h2>
          <p className="mt-4 font-body text-[#5a8a9a]">Free forever. No ads. No tracking. No data collection.</p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
            <a
              href="https://www.npmjs.com/package/@yagyeshvyas/vibeguard"
              target="_blank"
              rel="noreferrer"
              className="font-tech px-8 py-3.5 rounded-sm bg-gradient-to-r from-[#00f0ff]/80 to-[#00ff9d]/80 text-[#02040a] text-sm font-bold tracking-wider shadow-lg shadow-[#00f0ff]/20 hover:shadow-[#00f0ff]/40 hover:-translate-y-0.5 transition-all clip-hex-sm"
            >
              GET STARTED — FREE
            </a>
            <a
              href="https://github.com/yagyeshVyas/VibeGuard"
              target="_blank"
              rel="noreferrer"
              className="font-tech px-8 py-3.5 rounded-sm hud-panel text-[#00f0ff] text-sm font-bold tracking-wider hover:glow-box-cyan transition-all clip-hex-sm"
            >
              STAR ON GITHUB
            </a>
          </div>
        </motion.div>

        {/* Creator section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="mb-10"
        >
          <p className="font-tech text-lg font-bold text-white tracking-wider mb-3">
            BUILT BY <span className="text-cyan-gradient glow-text-cyan">YAGYESH VYAS</span>
          </p>
          <a
            href="https://www.linkedin.com/in/yagyeshvyas"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 px-5 py-2.5 hud-panel rounded-sm hover:border-[#00f0ff]/40 hover:glow-box-cyan transition-all clip-hex-sm group"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" className="text-[#00f0ff]">
              <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 01-2.063-2.065 2.063 2.063 0 112.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z" />
            </svg>
            <span className="font-tech text-sm font-bold text-[#00f0ff] tracking-wider group-hover:text-white transition-colors">
              CONNECT ON LINKEDIN
            </span>
          </a>
        </motion.div>

        {/* Links */}
        <div className="flex flex-wrap items-center justify-center gap-6 mb-8">
          <Link href="/" className="font-mono text-xs text-[#4a7a8a] hover:text-[#00f0ff] transition-colors tracking-widest">HOME</Link>
          <Link href="/about" className="font-mono text-xs text-[#4a7a8a] hover:text-[#00f0ff] transition-colors tracking-widest">ABOUT</Link>
          <Link href="/playground" className="font-mono text-xs text-[#4a7a8a] hover:text-[#00f0ff] transition-colors tracking-widest">PLAYGROUND</Link>
          <Link href="/docs" className="font-mono text-xs text-[#4a7a8a] hover:text-[#00f0ff] transition-colors tracking-widest">DOCS</Link>
          <a href="https://github.com/yagyeshVyas/VibeGuard" target="_blank" rel="noreferrer" className="font-mono text-xs text-[#4a7a8a] hover:text-[#00f0ff] transition-colors tracking-widest">GITHUB</a>
          <a href="https://www.npmjs.com/package/@yagyeshvyas/vibeguard" target="_blank" rel="noreferrer" className="font-mono text-xs text-[#4a7a8a] hover:text-[#00f0ff] transition-colors tracking-widest">NPM</a>
          <a href="https://www.linkedin.com/in/yagyeshvyas" target="_blank" rel="noreferrer" className="font-mono text-xs text-[#4a7a8a] hover:text-[#00f0ff] transition-colors tracking-widest">LINKEDIN</a>
        </div>

        <div className="font-mono text-xs text-[#3a5a6a]">
          <p className="font-tech text-sm font-semibold text-[#5a8a9a] mb-2 tracking-wider">VIBEGUARD — BY YAGYESH VYAS</p>
          <p>MIT LICENSE · ZERO DEPENDENCIES · ZERO TELEMETRY · FREE FOREVER</p>
          <p className="mt-4 text-[10px]">&copy; 2026 YAGYESH VYAS. RELEASED UNDER THE MIT LICENSE.</p>
        </div>
      </div>
    </footer>
  );
}