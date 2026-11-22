import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "VibeGuard — Free Security Scanner for AI-Coded Apps",
  description:
    "Scan your AI-generated app for leaked keys, open databases, and injection holes in 5 seconds. Offline by default, free forever. 861 rules, 93 MCP tools, 18 languages, real-time MCP firewall, agent risk scoring, AST taint analysis, local MITM proxy.",
  keywords: [
    "AI security scanner",
    "vibe coding security",
    "secret detection",
    "prompt injection",
    "SQL injection",
    "MCP",
    "Claude Code",
    "Cursor",
    "static analysis",
  ],
  openGraph: {
    title: "VibeGuard — Free Security Scanner for AI-Coded Apps",
    description:
      "Scan your AI-generated app for leaked keys, open databases, and injection holes in 5 seconds. Offline by default, free forever.",
    type: "website",
  },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div id="boot-root" />
        {children}
      </body>
    </html>
  );
}