"use client";

import { motion, AnimatePresence } from "framer-motion";
import { useEffect, useState } from "react";

const bootLines = [
  { text: "> INITIALIZING VIBEGUARD OS v1.0.0", delay: 100 },
  { text: "> Loading security kernel...", delay: 300 },
  { text: "> [OK] AST taint analysis engine", delay: 600 },
  { text: "> [OK] Secret detection module (50+ types)", delay: 900 },
  { text: "> [OK] AI security guardrails", delay: 1200 },
  { text: "> [OK] MCP server (75 tools)", delay: 1500 },
  { text: "> [OK] Shell guard interceptor", delay: 1800 },
  { text: "> [OK] Cross-file taint tracker", delay: 2100 },
  { text: "> Loading 699 detection rules...", delay: 2400 },
  { text: "> [OK] All systems online.", delay: 2700 },
  { text: "> WELCOME.", delay: 3000 },
];

export default function BootSequence({ onDone }: { onDone: () => void }) {
  const [visible, setVisible] = useState(0);
  const [hide, setHide] = useState(false);

  useEffect(() => {
    const timers = bootLines.map((l, i) =>
      setTimeout(() => setVisible(i + 1), l.delay)
    );
    const hideTimer = setTimeout(() => setHide(true), 3400);
    const doneTimer = setTimeout(onDone, 4000);
    return () => {
      timers.forEach(clearTimeout);
      clearTimeout(hideTimer);
      clearTimeout(doneTimer);
    };
  }, [onDone]);

  return (
    <AnimatePresence>
      {!hide && (
        <motion.div
          exit={{ opacity: 0 }}
          transition={{ duration: 0.6 }}
          className="fixed inset-0 z-[100] bg-[#02040a] flex items-center justify-center"
        >
          <div className="w-full max-w-2xl px-8">
            {/* Boot header */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="mb-6 flex items-center gap-3"
            >
              <div className="w-3 h-3 rounded-full bg-[#00f0ff] animate-pulse" />
              <span className="font-tech text-sm tracking-[0.3em] text-[#00f0ff]">
                VIBEGUARD // SECURITY PROTOCOL
              </span>
            </motion.div>

            {/* Boot lines */}
            <div className="font-mono text-sm space-y-1 min-h-[260px]">
              {bootLines.slice(0, visible).map((l, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  className={
                    l.text.includes("[OK]")
                      ? "text-[#00ff9d]"
                      : l.text.includes("WELCOME")
                      ? "text-[#00f0ff] font-bold text-lg glow-text-cyan"
                      : "text-[#4a7a8a]"
                  }
                >
                  {l.text}
                  {l.text.includes("WELCOME") && <span className="boot-cursor">_</span>}
                </motion.div>
              ))}
            </div>

            {/* Progress bar */}
            <div className="mt-8">
              <div className="h-0.5 bg-[#0a2030] rounded-full overflow-hidden">
                <motion.div
                  initial={{ width: "0%" }}
                  animate={{ width: "100%" }}
                  transition={{ duration: 3, ease: "easeInOut" }}
                  className="h-full bg-gradient-to-r from-[#00f0ff] to-[#00ff9d]"
                />
              </div>
              <div className="mt-2 flex justify-between font-mono text-xs text-[#4a7a8a]">
                <span>SYSTEM BOOT</span>
                <span>{Math.round((visible / bootLines.length) * 100)}%</span>
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}