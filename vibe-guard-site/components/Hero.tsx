"use client";

import { motion } from "framer-motion";
import { useEffect, useState } from "react";
import dynamic from "next/dynamic";
import ArcReactor from "./ArcReactor";

/* The 3D WebGL scene is client-only (WebGL + R3F). Dynamic + ssr:false
 * prevents any SSR/GL mismatch and keeps initial paint light.
 * The loading fallback shows a prominent arc-reactor echo while the
 * Three.js chunk downloads and WebGL context initializes. */
const Hero3DScene = dynamic(() => import("./Hero3DScene"), {
  ssr: false,
  loading: () => <HeroSceneFallback />,
});

function HeroSceneFallback() {
  return (
    <div className="absolute inset-0 flex items-center justify-center">
      <motion.div
        initial={{ opacity: 0, scale: 0.6 }}
        animate={{ opacity: 0.35, scale: 1 }}
        transition={{ duration: 0.8, ease: "easeOut" }}
        className="relative"
      >
        <ArcReactor size={420} />
      </motion.div>
    </div>
  );
}

const installCmd = "npx @yagyeshvyas/vibeguard scan";

export default function Hero() {
  const [copied, setCopied] = useState(false);
  const [typed, setTyped] = useState("");

  useEffect(() => {
    let i = 0;
    const t = setInterval(() => {
      if (i <= installCmd.length) {
        setTyped(installCmd.slice(0, i));
        i++;
      } else {
        clearInterval(t);
      }
    }, 50);
    return () => clearInterval(t);
  }, []);

  const copy = () => {
    navigator.clipboard.writeText(installCmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden pt-20 pb-12">
      {/* 3D WebGL hero — sits behind the content */}
      <div className="absolute inset-0 z-0 opacity-90">
        <Hero3DScene />
      </div>

      {/* Background layers */}
      <div className="absolute inset-0 bg-hex-animated opacity-30 z-[1] pointer-events-none" data-parallax="60" />
      <div className="absolute inset-0 glow-violet z-[1] pointer-events-none" style={{ top: "-10%" }} data-parallax="40" />

      {/* Faint arc reactor echo behind 3D core */}
      <motion.div
        initial={{ opacity: 0, scale: 0.3 }}
        animate={{ opacity: 0.12, scale: 1 }}
        transition={{ delay: 0.5, duration: 1.5, ease: "easeOut" }}
        className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-[1] pointer-events-none"
      >
        <ArcReactor size={640} />
      </motion.div>

      {/* Gradient vignette so text stays readable over 3D */}
      <div
        className="absolute inset-0 z-[2] pointer-events-none"
        style={{
          background:
            "radial-gradient(1100px 700px at 50% 45%, transparent 0%, rgba(3,5,12,0.55) 60%, rgba(3,5,12,0.9) 100%)",
        }}
      />

      {/* Floating orbs */}
      <motion.div
        animate={{ y: [0, -20, 0], x: [0, 10, 0] }}
        transition={{ duration: 7, repeat: Infinity, ease: "easeInOut" }}
        className="absolute top-1/4 left-10 w-24 h-24 rounded-full bg-[#00f0ff]/5 blur-2xl z-[1]"
      />
      <motion.div
        animate={{ y: [0, 15, 0], x: [0, -12, 0] }}
        transition={{ duration: 8, repeat: Infinity, ease: "easeInOut" }}
        className="absolute bottom-1/4 right-10 w-32 h-32 rounded-full bg-[#00ff9d]/5 blur-3xl z-[1]"
      />

      <div className="relative z-10 max-w-5xl mx-auto px-6 text-center">
        {/* Badge */}
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.3 }}
          className="inline-flex items-center gap-2 px-4 py-1.5 glass-gradient clip-hex-sm mb-10"
        >
          <span className="w-2 h-2 rounded-full bg-[#00ff9d] animate-pulse" />
          <span className="font-mono text-xs text-[#00f0ff]/80 tracking-widest">
            100% OFFLINE · ZERO DEPS · FREE FOREVER
          </span>
        </motion.div>

        {/* Headline */}
        <motion.h1
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4, duration: 0.7 }}
          className="font-display text-5xl md:text-7xl font-bold leading-[1.05] tracking-tight"
        >
          <span className="text-white glow-text-cyan">SCAN YOUR AI CODE</span>
          <br />
          <span className="text-aurora-gradient glow-text-cyan">BEFORE IT SHIPS.</span>
        </motion.h1>

        {/* Subheadline */}
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6, duration: 0.7 }}
          className="mt-6 font-body text-lg md:text-xl text-[#7ea6bc] max-w-2xl mx-auto leading-relaxed"
        >
          Catches leaked keys, open databases, and injection holes in 5 seconds.
          Built for the vibe-coding era — runs entirely on your machine.
        </motion.p>

        {/* Install command — glass terminal */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8, duration: 0.7 }}
          className="mt-10 max-w-xl mx-auto"
        >
          <div
            onClick={copy}
            className="glass-strong clip-notch px-5 py-4 flex items-center justify-between cursor-pointer hover:glow-box-cyan transition-all group scanline-overlay"
          >
            <code className="font-mono text-sm md:text-base text-[#00ff9d]">
              <span className="text-[#4a6b7e]">$ </span>
              {typed}
              <span className="cursor-blink" />
            </code>
            <span className="font-mono text-[10px] text-[#4a6b7e] group-hover:text-[#00f0ff] transition-colors">
              {copied ? "[COPIED]" : "[CLICK]"}
            </span>
          </div>
        </motion.div>

        {/* CTA buttons */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1.0, duration: 0.7 }}
          className="mt-8 flex flex-wrap items-center justify-center gap-4"
        >
          <a
            href="#playground"
            className="btn-primary font-display px-8 py-3.5 clip-notch text-sm font-bold tracking-wider"
          >
            ENGAGE PLAYGROUND
          </a>
          <a
            href="#features"
            className="btn-ghost font-display px-8 py-3.5 clip-notch text-sm font-bold tracking-wider"
          >
            VIEW FEATURES
          </a>
        </motion.div>

        {/* Trust row */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.2 }}
          className="mt-14 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 font-mono text-xs text-[#4a6b7e]"
        >
          {["752 RULES", "82 MCP TOOLS", "18 LANGUAGES", "15 AI CLIENTS", "0 DEPENDENCIES"].map((t, i) => (
            <span key={t} className="flex items-center gap-6">
              {i > 0 && <span className="text-[#0a2030]">/</span>}
              <span className="hover:text-[#00f0ff] transition-colors">{t}</span>
            </span>
          ))}
        </motion.div>

        {/* Built by */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.4 }}
          className="mt-6"
        >
          <a
            href="https://www.linkedin.com/in/yagyeshvyas"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 font-mono text-xs text-[#4a6b7e] hover:text-[#00f0ff] transition-colors group"
          >
            <span className="h-px w-6 bg-[#00f0ff]/20 group-hover:bg-[#00f0ff] transition-colors" />
            <span>BUILT BY</span>
            <span className="font-bold text-[#00f0ff]">YAGYESH VYAS</span>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" className="text-[#4a6b7e] group-hover:text-[#00f0ff] transition-colors">
              <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 01-2.063-2.065 2.063 2.063 0 112.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z" />
            </svg>
          </a>
        </motion.div>
      </div>

      {/* Scroll hint */}
      <motion.div
        animate={{ y: [0, 8, 0] }}
        transition={{ duration: 1.5, repeat: Infinity }}
        className="absolute bottom-8 left-1/2 -translate-x-1/2 text-[#00f0ff]/40 z-10"
      >
        <svg width="24" height="24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 5v14M6 13l6 6 6-6" />
        </svg>
      </motion.div>
    </section>
  );
}
