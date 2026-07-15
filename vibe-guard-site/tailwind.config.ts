import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        obsidian: "#010307",
        ink: "#03050c",
        ink2: "#060a16",
        panel: "#0a1020",
        panel2: "#11151f",
        edge: "#1c2230",
        accent: "#00f0ff",
        accent2: "#00ff9d",
        violet: "#7c5cff",
        danger: "#ff3860",
        warn: "#ffb547",
        ok: "#00ff9d",
        fg: "#d6f4ff",
        "fg-dim": "#7ea6bc",
        "fg-mute": "#4a6b7e",
      },
      fontFamily: {
        tech: ["Space Grotesk", "Orbitron", "system-ui", "sans-serif"],
        display: ["Space Grotesk", "system-ui", "sans-serif"],
        branded: ["Orbitron", "Space Grotesk", "system-ui", "sans-serif"],
        sans: ["Rajdhani", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
      keyframes: {
        float: {
          "0%,100%": { transform: "translateY(0)" },
          "50%": { transform: "translateY(-8px)" },
        },
        pulseGlow: {
          "0%,100%": { opacity: "0.4" },
          "50%": { opacity: "0.9" },
        },
        gridMove: {
          "0%": { backgroundPosition: "0 0" },
          "100%": { backgroundPosition: "40px 40px" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
      },
      animation: {
        float: "float 5s ease-in-out infinite",
        pulseGlow: "pulseGlow 3s ease-in-out infinite",
        gridMove: "gridMove 6s linear infinite",
        shimmer: "shimmer 2.5s linear infinite",
      },
      backdropBlur: {
        xs: "2px",
      },
    },
  },
  plugins: [],
};
export default config;
