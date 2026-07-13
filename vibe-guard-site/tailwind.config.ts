import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        ink: "#050608",
        panel: "#0b0e14",
        panel2: "#11151f",
        edge: "#1c2230",
        accent: "#3b82f6",
        accent2: "#22c55e",
        danger: "#ef4444",
        warn: "#f97316",
        ok: "#22c55e",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
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
    },
  },
  plugins: [],
};
export default config;