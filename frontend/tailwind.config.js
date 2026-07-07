/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // surface scale (Modern Dark — slate based, avoid pure black)
        bg: "#0B1120",
        surface: "#0F172A",
        "surface-2": "#141d2e",
        "surface-3": "#1E293B",
        border: "#233145",
        "border-strong": "#334155",
        fg: "#F8FAFC",
        muted: "#94A3B8",
        faint: "#64748B",
        accent: "#22C55E", // run / active
        "accent-dim": "#16A34A",
        // severity semantic
        critical: "#EF4444",
        high: "#F97316",
        medium: "#EAB308",
        low: "#3B82F6",
        info: "#64748B",
      },
      fontFamily: {
        mono: ["'Fira Code'", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
        sans: ["'Fira Sans'", "ui-sans-serif", "system-ui", "sans-serif"],
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(34,197,94,0.25), 0 8px 30px -10px rgba(34,197,94,0.25)",
        card: "0 1px 0 0 rgba(255,255,255,0.03) inset, 0 10px 30px -18px rgba(0,0,0,0.7)",
      },
      keyframes: {
        "pulse-dot": { "0%,100%": { opacity: "1" }, "50%": { opacity: "0.35" } },
        "fade-in": { from: { opacity: "0", transform: "translateY(4px)" }, to: { opacity: "1", transform: "none" } },
      },
      animation: {
        "pulse-dot": "pulse-dot 1.4s ease-in-out infinite",
        "fade-in": "fade-in 0.25s ease-out both",
      },
    },
  },
  plugins: [],
};
