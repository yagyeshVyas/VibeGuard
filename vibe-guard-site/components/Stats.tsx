"use client";

import { motion, useInView, useMotionValue, animate } from "framer-motion";
import { useEffect, useRef } from "react";

const stats = [
  { num: 699, label: "RULES", suffix: "" },
  { num: 75, label: "MCP TOOLS", suffix: "" },
  { num: 22, label: "CLI COMMANDS", suffix: "" },
  { num: 11, label: "AI CLIENTS", suffix: "" },
  { num: 0, label: "DEPENDENCIES", suffix: "" },
  { num: 0, label: "COST", suffix: "$" },
];

function Gauge({ target, label, suffix }: { target: number; label: string; suffix: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true });
  const mv = useMotionValue(0);
  const [display, setDisplay] = useState(0);

  useEffect(() => {
    if (inView) {
      const controls = animate(mv, target, {
        duration: 1.5,
        ease: "easeOut",
        onUpdate: (v) => setDisplay(Math.round(v)),
      });
      return controls.stop;
    }
  }, [inView, target, mv]);

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, scale: 0.7 }}
      whileInView={{ opacity: 1, scale: 1 }}
      viewport={{ once: true }}
      className="flex flex-col items-center group"
    >
      {/* Circular gauge */}
      <div className="relative w-24 h-24 mb-3">
        <svg className="absolute inset-0 spin-slow" width="96" height="96" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="46" fill="none" stroke="rgba(0,240,255,0.1)" strokeWidth="1" strokeDasharray="2 4" />
        </svg>
        <svg className="absolute inset-0" width="96" height="96" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="40" fill="none" stroke="rgba(0,240,255,0.08)" strokeWidth="3" />
          <motion.circle
            cx="50" cy="50" r="40"
            fill="none"
            stroke="#00f0ff"
            strokeWidth="3"
            strokeLinecap="round"
            strokeDasharray={251.2}
            initial={{ strokeDashoffset: 251.2 }}
            whileInView={{ strokeDashoffset: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 1.5, ease: "easeOut" }}
            transform="rotate(-90 50 50)"
            style={{ filter: "drop-shadow(0 0 4px rgba(0,240,255,0.6))" }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="font-tech text-2xl font-black text-[#00f0ff] glow-text-cyan">
            {suffix}{display}
          </span>
        </div>
      </div>
      <div className="font-mono text-xs text-[#4a7a8a] tracking-widest group-hover:text-[#00f0ff] transition-colors">
        {label}
      </div>
    </motion.div>
  );
}

// Need useState import fix
import { useState } from "react";

export default function Stats() {
  return (
    <section className="relative py-20 px-6">
      <div className="max-w-6xl mx-auto">
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-8">
          {stats.map((s, i) => (
            <motion.div
              key={s.label}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.08 }}
            >
              <Gauge target={s.num} label={s.label} suffix={s.suffix} />
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}