/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "#0a0a0c",
        card: "#121216",
        primary: "#3b82f6",
        malicious: "#ef4444",
        benign: "#10b981",
        warning: "#f59e0b",
      },
    },
  },
  plugins: [],
};
