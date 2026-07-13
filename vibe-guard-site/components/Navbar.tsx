"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";

export default function Navbar() {
  const [open, setOpen] = useState(false);
  const pathname = usePathname();

  const links = [
    { href: "/", label: "Home" },
    { href: "/about", label: "About" },
    { href: "/playground", label: "Playground" },
    { href: "/docs", label: "Docs" },
  ];

  return (
    <motion.nav
      initial={{ y: -80, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.6, ease: "easeOut", delay: 0.2 }}
      className="fixed top-0 left-0 right-0 z-50 hud-panel"
    >
      <div className="max-w-7xl mx-auto px-6 py-3.5 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-3 group">
          {/* Mini arc reactor logo */}
          <div className="relative w-9 h-9 flex items-center justify-center">
            <svg className="absolute spin-slow" width="36" height="36" viewBox="0 0 100 100">
              <circle cx="50" cy="50" r="46" fill="none" stroke="rgba(0,240,255,0.3)" strokeWidth="2" strokeDasharray="4 6" />
            </svg>
            <svg className="absolute spin-reverse-slow" width="28" height="28" viewBox="0 0 100 100">
              <circle cx="50" cy="50" r="44" fill="none" stroke="rgba(0,240,255,0.5)" strokeWidth="2" strokeDasharray="16 4" />
            </svg>
            <div className="w-3 h-3 rounded-full bg-[#00f0ff] glow-box-cyan" />
          </div>
          <span className="font-tech text-lg font-bold tracking-wider text-white">
            VIBE<span className="text-[#00f0ff]">GUARD</span>
          </span>
        </Link>

        <div className="hidden md:flex items-center gap-6">
          {links.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className={`font-body text-sm font-medium tracking-wide relative group transition-colors ${
                pathname === l.href ? "text-[#00f0ff]" : "text-[#4a7a8a] hover:text-[#00f0ff]"
              }`}
            >
              {l.label.toUpperCase()}
              <span className={`absolute -bottom-1 left-0 h-px bg-[#00f0ff] transition-all ${
                pathname === l.href ? "w-full" : "w-0 group-hover:w-full"
              }`} />
            </Link>
          ))}
          <a
            href="https://github.com/yagyeshVyas/VibeGuard"
            target="_blank"
            rel="noreferrer"
            className="font-body text-sm font-medium text-[#4a7a8a] hover:text-[#00f0ff] transition-colors tracking-wide"
          >
            GITHUB
          </a>
          <Link
            href="/playground"
            className="font-tech px-5 py-2 rounded-sm bg-[#00f0ff]/10 border border-[#00f0ff]/40 text-[#00f0ff] text-xs font-bold tracking-wider hover:bg-[#00f0ff]/20 hover:glow-box-cyan transition-all clip-hex-sm"
          >
            INITIALIZE
          </Link>
        </div>

        <button
          className="md:hidden text-[#00f0ff]"
          onClick={() => setOpen(!open)}
          aria-label="Toggle menu"
        >
          <svg width="24" height="24" fill="none" stroke="currentColor" strokeWidth="2">
            {open ? <path d="M6 6l12 12M6 18L18 6" /> : <path d="M4 7h16M4 12h16M4 17h16" />}
          </svg>
        </button>
      </div>

      {open && (
        <motion.div
          initial={{ height: 0, opacity: 0 }}
          animate={{ height: "auto", opacity: 1 }}
          className="md:hidden hud-panel border-t border-[#00f0ff]/10"
        >
          <div className="px-6 py-4 flex flex-col gap-3">
            {links.map((l) => (
              <Link
                key={l.href}
                href={l.href}
                className={`font-body text-sm ${
                  pathname === l.href ? "text-[#00f0ff]" : "text-[#4a7a8a] hover:text-[#00f0ff]"
                }`}
                onClick={() => setOpen(false)}
              >
                {l.label.toUpperCase()}
              </Link>
            ))}
          </div>
        </motion.div>
      )}
    </motion.nav>
  );
}