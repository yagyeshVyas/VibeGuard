"use client";

import { motion } from "framer-motion";

export default function ArcReactor({ size = 120 }: { size?: number }) {
  return (
    <div
      className="relative flex items-center justify-center"
      style={{ width: size, height: size }}
    >
      {/* Outer rotating ring with segments */}
      <svg
        className="absolute spin-slow"
        width={size}
        height={size}
        viewBox="0 0 200 200"
      >
        <circle
          cx="100" cy="100" r="92"
          fill="none"
          stroke="rgba(0,240,255,0.2)"
          strokeWidth="2"
          strokeDasharray="4 8"
        />
      </svg>

      {/* Second ring — dashed, reverse */}
      <svg
        className="absolute spin-reverse-slow"
        width={size * 0.85}
        height={size * 0.85}
        viewBox="0 0 200 200"
      >
        <circle
          cx="100" cy="100" r="90"
          fill="none"
          stroke="rgba(0,240,255,0.3)"
          strokeWidth="1.5"
          strokeDasharray="20 6 4 6"
        />
      </svg>

      {/* Third ring — segmented arcs */}
      <svg
        className="absolute spin-medium"
        width={size * 0.72}
        height={size * 0.72}
        viewBox="0 0 200 200"
      >
        {[0, 60, 120, 180, 240, 300].map((angle) => (
          <path
            key={angle}
            d={`M 100 20 A 80 80 0 0 1 ${100 + 70 * Math.cos((angle + 30) * Math.PI / 180)} ${100 + 70 * Math.sin((angle + 30) * Math.PI / 180)}`}
            fill="none"
            stroke="rgba(0,240,255,0.5)"
            strokeWidth="3"
            strokeLinecap="round"
          />
        ))}
      </svg>

      {/* Inner core glow */}
      <motion.div
        animate={{ scale: [1, 1.08, 1], opacity: [0.8, 1, 0.8] }}
        transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
        className="absolute rounded-full"
        style={{
          width: size * 0.45,
          height: size * 0.45,
          background: "radial-gradient(circle, rgba(0,240,255,0.4) 0%, rgba(0,240,255,0.1) 60%, transparent 70%)",
          filter: "blur(8px)",
        }}
      />

      {/* Center triangle (Iron Man style) */}
      <svg
        className="absolute"
        width={size * 0.5}
        height={size * 0.5}
        viewBox="0 0 100 100"
      >
        <polygon
          points="50,15 85,80 15,80"
          fill="none"
          stroke="rgba(0,240,255,0.8)"
          strokeWidth="2"
        />
        <polygon
          points="50,30 70,68 30,68"
          fill="rgba(0,240,255,0.06)"
          stroke="rgba(0,240,255,0.4)"
          strokeWidth="1"
        />
      </svg>

      {/* Pulsing rings */}
      <div
        className="absolute rounded-full border pulse-ring"
        style={{ width: size * 0.5, height: size * 0.5, borderColor: "rgba(0,240,255,0.4)" }}
      />
      <div
        className="absolute rounded-full border pulse-ring"
        style={{ width: size * 0.5, height: size * 0.5, borderColor: "rgba(0,240,255,0.3)", animationDelay: "1s" }}
      />
    </div>
  );
}