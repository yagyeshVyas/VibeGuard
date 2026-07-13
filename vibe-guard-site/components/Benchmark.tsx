"use client";

import { motion } from "framer-motion";

const data = [
  { category: "INJECTION", precision: 89.6, recall: 87.8, f1: 88.7, color: "#ff3860" },
  { category: "SECRETS", precision: 73.1, recall: 90.5, f1: 80.9, color: "#ffb547" },
  { category: "XSS", precision: 100.0, recall: 94.1, f1: 97.0, color: "#00f0ff" },
  { category: "PATH TRAVERSAL", precision: 90.0, recall: 90.0, f1: 90.0, color: "#00ff9d" },
  { category: "AI SAFETY", precision: 80.0, recall: 57.1, f1: 66.7, color: "#a855f7" },
];

const overall = { precision: 86.4, recall: 85.6, f1: 86.0 };

// Radar chart points (5 categories, 3 metrics each)
function radarPoints(cx: number, cy: number, radius: number, values: number[], sides: number) {
  const points = values.map((v, i) => {
    const angle = (i / sides) * Math.PI * 2 - Math.PI / 2;
    const r = (v / 100) * radius;
    return `${cx + r * Math.cos(angle)},${cy + r * Math.sin(angle)}`;
  });
  return points.join(" ");
}

export default function Benchmark() {
  const cx = 180, cy = 180, radius = 140;
  const f1Values = data.map((d) => d.f1);
  const precisionValues = data.map((d) => d.precision);
  const recallValues = data.map((d) => d.recall);

  return (
    <section id="benchmark" className="relative py-24 px-6 overflow-hidden">
      <div className="absolute inset-0 glow-green opacity-15" />
      <div className="relative max-w-5xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center mb-14"
        >
          <div className="inline-flex items-center gap-2 mb-4">
            <span className="font-mono text-xs text-[#00f0ff]/40 tracking-widest">[ 06 ]</span>
            <span className="h-px w-12 bg-[#00f0ff]/20" />
          </div>
          <h2 className="font-tech text-3xl md:text-5xl font-bold text-white tracking-wide">
            HONEST <span className="text-cyan-gradient glow-text-cyan">BENCHMARK</span>
          </h2>
          <p className="mt-4 font-body text-[#5a8a9a] max-w-2xl mx-auto">
            Measured against a curated corpus of 121 files. Run <code className="font-mono text-[#00ff9d]">npm run benchmark</code> to reproduce.
          </p>
        </motion.div>

        <div className="grid lg:grid-cols-2 gap-8 items-center">
          {/* Radar chart */}
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            className="hud-panel rounded-sm p-6 flex items-center justify-center scanline-overlay"
          >
            <svg width={360} height={360} viewBox="0 0 360 360">
              {/* Grid rings */}
              {[0.25, 0.5, 0.75, 1].map((r, i) => (
                <polygon
                  key={i}
                  points={radarPoints(cx, cy, radius * r, Array(5).fill(100), 5)}
                  fill="none"
                  stroke="rgba(0,240,255,0.1)"
                  strokeWidth="1"
                />
              ))}
              {/* Grid spokes */}
              {data.map((_, i) => {
                const angle = (i / 5) * Math.PI * 2 - Math.PI / 2;
                return (
                  <line
                    key={i}
                    x1={cx} y1={cy}
                    x2={cx + radius * Math.cos(angle)}
                    y2={cy + radius * Math.sin(angle)}
                    stroke="rgba(0,240,255,0.08)"
                    strokeWidth="1"
                  />
                );
              })}
              {/* Data areas */}
              <motion.polygon
                points={radarPoints(cx, cy, radius, precisionValues, 5)}
                fill="rgba(0,240,255,0.08)"
                stroke="#00f0ff"
                strokeWidth="2"
                initial={{ opacity: 0, scale: 0 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                transition={{ duration: 1 }}
                style={{ transformOrigin: "180px 180px" }}
              />
              <motion.polygon
                points={radarPoints(cx, cy, radius, recallValues, 5)}
                fill="rgba(0,255,157,0.08)"
                stroke="#00ff9d"
                strokeWidth="2"
                initial={{ opacity: 0, scale: 0 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                transition={{ duration: 1, delay: 0.2 }}
                style={{ transformOrigin: "180px 180px" }}
              />
              <motion.polygon
                points={radarPoints(cx, cy, radius, f1Values, 5)}
                fill="rgba(255,181,71,0.06)"
                stroke="#ffb547"
                strokeWidth="2"
                initial={{ opacity: 0, scale: 0 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                transition={{ duration: 1, delay: 0.4 }}
                style={{ transformOrigin: "180px 180px" }}
              />
              {/* Labels */}
              {data.map((d, i) => {
                const angle = (i / 5) * Math.PI * 2 - Math.PI / 2;
                const lr = radius + 22;
                return (
                  <text
                    key={i}
                    x={cx + lr * Math.cos(angle)}
                    y={cy + lr * Math.sin(angle)}
                    fill="#4a7a8a"
                    fontSize="10"
                    fontFamily="Orbitron"
                    fontWeight="700"
                    textAnchor="middle"
                    dominantBaseline="middle"
                  >
                    {d.category}
                  </text>
                );
              })}
            </svg>
          </motion.div>

          {/* Overall + bars */}
          <div>
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              className="hud-panel rounded-sm p-6 mb-6 text-center"
            >
              <div className="font-tech text-6xl font-black text-cyan-gradient glow-text-cyan">{overall.f1}%</div>
              <div className="mt-2 font-mono text-xs uppercase tracking-widest text-[#4a7a8a]">Overall F1 Score</div>
              <div className="mt-4 flex justify-center gap-8">
                <div>
                  <div className="font-tech text-2xl font-bold text-white">{overall.precision}%</div>
                  <div className="font-mono text-xs text-[#4a7a8a] uppercase">Precision</div>
                </div>
                <div>
                  <div className="font-tech text-2xl font-bold text-white">{overall.recall}%</div>
                  <div className="font-mono text-xs text-[#4a7a8a] uppercase">Recall</div>
                </div>
              </div>
              {/* Legend */}
              <div className="mt-4 flex justify-center gap-4">
                <span className="font-mono text-xs text-[#00f0ff]">● PRECISION</span>
                <span className="font-mono text-xs text-[#00ff9d]">● RECALL</span>
                <span className="font-mono text-xs text-[#ffb547]">● F1</span>
              </div>
            </motion.div>

            <div className="space-y-2.5">
              {data.map((d, i) => (
                <motion.div
                  key={d.category}
                  initial={{ opacity: 0, x: -16 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.08 }}
                  className="hud-panel rounded-sm p-3.5"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-tech text-xs font-bold text-white tracking-wider">{d.category}</span>
                    <span className="font-tech text-sm font-bold" style={{ color: d.color }}>{d.f1}%</span>
                  </div>
                  <div className="flex gap-1">
                    {[{ v: d.precision, c: "#00f0ff" }, { v: d.recall, c: "#00ff9d" }, { v: d.f1, c: "#ffb547" }].map((m, j) => (
                      <div key={j} className="flex-1 h-1.5 rounded-full bg-[#0a2030] overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          whileInView={{ width: `${m.v}%` }}
                          viewport={{ once: true }}
                          transition={{ duration: 1, ease: "easeOut", delay: i * 0.08 + 0.2 }}
                          className="h-full rounded-full"
                          style={{ background: m.c }}
                        />
                      </div>
                    ))}
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </div>

        <p className="mt-8 text-center font-body text-sm text-[#5a8a9a]">
          86.0% F1 means it misses ~14% of real issues. Read per-category details in{" "}
          <code className="font-mono text-[#00ff9d]">test/benchmark/benchmark-results.md</code> before relying on it.
        </p>
      </div>
    </section>
  );
}