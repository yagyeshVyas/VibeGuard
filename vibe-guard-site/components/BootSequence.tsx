"use client";

import { motion, AnimatePresence } from "framer-motion";
import { useEffect, useState } from "react";

/* === Cinematic boot → hero transition
 * Variable delays: [OK] lines stream fast, dramatic lines pause.
 * Exit: curtain wipe (scaleY 0 from top) + brief flash, reveals
 * the hero content already loaded underneath.
 * Skip: any user interaction (click / key / scroll / touch). === */

const bootLines = [
  { text: "> INITIALIZING VIBEGUARD OS v1.0.0", delay: 30, cls: "" },
  { text: "> Loading security kernel...", delay: 130, cls: "" },
  { text: "> [OK] AST taint analysis engine", delay: 240, cls: "ok" },
  { text: "> [OK] Secret detection module (50+ types)", delay: 320, cls: "ok" },
  { text: "> [OK] AI security guardrails", delay: 400, cls: "ok" },
  { text: "> [OK] MCP server (82 tools)", delay: 470, cls: "ok" },
  { text: "> [OK] Shell guard interceptor", delay: 540, cls: "ok" },
  { text: "> [OK] Cross-file taint tracker", delay: 610, cls: "ok" },
  { text: "> [OK] Local MITM proxy", delay: 680, cls: "ok" },
  { text: "> Loading 752 detection rules...", delay: 780, cls: "" },
  { text: "> [OK] All systems online.", delay: 920, cls: "ok" },
  { text: "> WELCOME.", delay: 1100, cls: "welcome" },
];

export default function BootSequence({ onDone }: { onDone: () => void }) {
  const [visible, setVisible] = useState(0);
  const [phase, setPhase] = useState<"boot" | "flash" | "done">("boot");

  const skip = () => {
    setVisible(bootLines.length);
    setPhase("flash");
  };

  useEffect(() => {
    const timers = bootLines.map((l, i) =>
      setTimeout(() => setVisible((v) => Math.max(v, i + 1)), l.delay)
    );

    // Phase transitions: boot → flash → done → onDone
    const flashTimer = setTimeout(() => setPhase("flash"), 1350);
    const doneTimer = setTimeout(() => {
      setPhase("done");
      onDone();
    }, 1650);

    // Skip on ANY user interaction
    window.addEventListener("click", skip);
    window.addEventListener("keydown", skip);
    window.addEventListener("wheel", skip, { passive: true });
    window.addEventListener("touchstart", skip, { passive: true });

    return () => {
      timers.forEach(clearTimeout);
      clearTimeout(flashTimer);
      clearTimeout(doneTimer);
      window.removeEventListener("click", skip);
      window.removeEventListener("keydown", skip);
      window.removeEventListener("wheel", skip);
      window.removeEventListener("touchstart", skip);
    };
  }, [onDone]);

  const exiting = phase === "flash" || phase === "done";

  return (
    <AnimatePresence>
      {!exiting || phase === "flash" ? (
        <motion.div
          key="boot"
          exit={{ scaleY: 0, opacity: 0 }}
          transition={{ duration: 0.5, ease: [0.4, 0, 0.2, 1] }}
          style={{ transformOrigin: "top" }}
          className="fixed inset-0 z-[100] bg-[#010307] flex items-center justify-center cursor-pointer"
          onClick={skip}
        >
          {/* Flash overlay — brief cyan flash before curtain wipe */}
          {phase === "flash" && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: [0, 0.3, 0] }}
              transition={{ duration: 0.3 }}
              className="absolute inset-0 z-[101] bg-[#00f0ff] pointer-events-none"
            />
          )}

          <div className="w-full max-w-2xl px-8 relative z-[102]">
            {/* Boot header */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="mb-6 flex items-center gap-3"
            >
              <div className="w-3 h-3 rounded-full bg-[#00f0ff] animate-pulse" />
              <span className="font-display text-sm tracking-[0.3em] text-[#00f0ff]">
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
                  transition={{ duration: 0.12 }}
                  className={
                    l.cls === "ok"
                      ? "text-[#00ff9d]"
                      : l.cls === "welcome"
                      ? "text-[#00f0ff] font-bold text-lg glow-text-cyan"
                      : "text-[#4a6b7e]"
                  }
                >
                  {l.text}
                  {l.cls === "welcome" && <span className="boot-cursor">_</span>}
                </motion.div>
              ))}
            </div>

            {/* Progress bar */}
            <div className="mt-8">
              <div className="h-0.5 bg-[#0a2030] rounded-full overflow-hidden">
                <motion.div
                  initial={{ width: "0%" }}
                  animate={{ width: "100%" }}
                  transition={{ duration: 1.2, ease: "easeInOut" }}
                  className="h-full bg-gradient-to-r from-[#00f0ff] to-[#00ff9d]"
                />
              </div>
              <div className="mt-2 flex justify-between font-mono text-xs text-[#4a6b7e]">
                <span>SYSTEM BOOT</span>
                <span className="tabular-nums">{Math.round((visible / bootLines.length) * 100)}%</span>
              </div>
            </div>

            {/* Skip hint */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.6 }}
              className="mt-6 flex justify-end"
            >
              <span className="font-mono text-xs text-[#00f0ff]/30 tracking-wider animate-pulse">
                [ CLICK / SCROLL TO SKIP ]
              </span>
            </motion.div>
          </div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
}
