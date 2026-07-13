"use client";

import { motion } from "framer-motion";
import { useEffect, useState } from "react";

export default function HudReadout() {
  const [time, setTime] = useState("");
  const [coords, setCoords] = useState({ x: 0, y: 0 });
  const [scan, setScan] = useState(0);

  useEffect(() => {
    const tick = () => {
      const d = new Date();
      setTime(
        `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}:${String(d.getUTCSeconds()).padStart(2, "0")} UTC`
      );
      setScan((s) => (s + 1) % 1000);
    };
    tick();
    const interval = setInterval(tick, 1000);
    const onMove = (e: MouseEvent) => {
      setCoords({ x: Math.round((e.clientX / window.innerWidth) * 100), y: Math.round((e.clientY / window.innerHeight) * 100) });
    };
    window.addEventListener("mousemove", onMove);
    return () => {
      clearInterval(interval);
      window.removeEventListener("mousemove", onMove);
    };
  }, []);

  return (
    <>
      {/* Top-left HUD readout */}
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: 0.5 }}
        className="fixed top-20 left-4 z-30 hidden lg:block pointer-events-none"
      >
        <div className="font-mono text-[10px] text-[#00f0ff]/40 space-y-0.5">
          <div>SYS://VIBEGUARD.v1.0</div>
          <div>STATUS: <span className="text-[#00ff9d]">ONLINE</span></div>
          <div>RULES: 699 ACTIVE</div>
          <div>SCAN#: {String(scan).padStart(4, "0")}</div>
        </div>
      </motion.div>

      {/* Top-right HUD readout */}
      <motion.div
        initial={{ opacity: 0, x: 20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: 0.5 }}
        className="fixed top-20 right-4 z-30 hidden lg:block pointer-events-none text-right"
      >
        <div className="font-mono text-[10px] text-[#00f0ff]/40 space-y-0.5">
          <div>{time}</div>
          <div>X:{String(coords.x).padStart(3, "0")} Y:{String(coords.y).padStart(3, "0")}</div>
          <div>LAT: 38.9°N LON: 77.0°W</div>
          <div>PWR: <span className="text-[#00ff9d]">100%</span></div>
        </div>
      </motion.div>

      {/* Left edge vertical data streams */}
      <div className="fixed left-0 top-0 bottom-0 w-1 z-20 pointer-events-none hidden md:block">
        {[20, 45, 70].map((left, i) => (
          <div
            key={i}
            className="data-stream"
            style={{ left: `${left}px`, height: "60%", animationDelay: `${i * 0.8}s` }}
          />
        ))}
      </div>

      {/* Right edge vertical data streams */}
      <div className="fixed right-0 top-0 bottom-0 w-1 z-20 pointer-events-none hidden md:block">
        {[10, 35, 80].map((right, i) => (
          <div
            key={i}
            className="data-stream"
            style={{ right: `${right}px`, height: "60%", animationDelay: `${i * 0.6 + 0.3}s` }}
          />
        ))}
      </div>
    </>
  );
}