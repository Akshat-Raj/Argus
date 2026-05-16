import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        ink: "#0a0a0a",
        "ink-2": "#141414",
        "ink-3": "#1c1c1c",
        line: "#262626",
        "line-2": "#2e2e2e",
        paper: "#f5f3ee",
        "paper-2": "#ebe7df",
        mute: "#8a8580",
        "mute-2": "#6a655e",
        brass: "#b08d57",
        "brass-2": "#d4b483",
        ok: "#9bb89b",
        err: "#c08a8a",
      },
      fontFamily: {
        serif: ['"Instrument Serif"', '"Times New Roman"', "serif"],
        sans: ['"Inter Tight"', "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "monospace"],
      },
      maxWidth: {
        container: "1360px",
      },
    },
  },
  plugins: [],
};
export default config;
