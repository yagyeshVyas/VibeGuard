"use client";

import { motion } from "framer-motion";
import Shell from "@/components/Shell";
import Playground from "@/components/Playground";
import ArcReactor from "@/components/ArcReactor";

export default function PlaygroundPage() {
  return (
    <Shell>
      {/* Page hero */}
      <section className="relative pt-32 pb-8 px-6 text-center overflow-hidden">
        <div className="absolute inset-0 bg-hex-animated opacity-30" />
        <div className="absolute inset-0 glow-cyan" />

        <motion.div
          initial={{ opacity: 0, scale: 0.3 }}
          animate={{ opacity: 0.1, scale: 1 }}
          transition={{ duration: 1.5 }}
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2"
        >
          <ArcReactor size={400} />
        </motion.div>

        <div className="relative z-10">
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            className="inline-flex items-center gap-2 px-4 py-1.5 hud-panel clip-hex-sm mb-6"
          >
            <span className="w-2 h-2 rounded-full bg-[#00ff9d] animate-pulse" />
            <span className="font-mono text-xs text-[#00f0ff]/70 tracking-widest">INTERACTIVE SCANNER</span>
          </motion.div>
          <motion.h1
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="font-tech text-4xl md:text-6xl font-black text-white tracking-tight"
          >
            <span className="glow-text-cyan">PLAYGROUND</span>
          </motion.h1>
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.2 }}
            className="mt-4 font-body text-[#5a8a9a]"
          >
            Paste your code and run a live scan. No data leaves your browser.
          </motion.p>
        </div>
      </section>

      <Playground />
    </Shell>
  );
}