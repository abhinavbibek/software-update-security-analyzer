/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        inter: ["Inter", "sans-serif"],
      },
      colors: {
        bg: "#071025",
        card: "#0d1326",
        panel: "#0a1425",
        accent: "#1a2640",
        primary: "#6366f1",
        primaryLight: "#818cf8",
        emerald: "#34d399",
      },
      boxShadow: {
        card: "0 4px 18px rgba(0,0,0,0.35)",
        cardHover: "0 6px 25px rgba(0,0,0,0.50)",
      },
    },
  },
  plugins: [],
};
