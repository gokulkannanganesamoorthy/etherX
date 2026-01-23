/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"Share Tech Mono"', 'monospace'],
        sans: ['"Share Tech Mono"', 'monospace'],
      },
      colors: {
        'neon-green': '#00ff41',
        'neon-red': '#ff003c',
        'terminal-black': '#050505',
        'terminal-dim': '#0d110d',
      },
      boxShadow: {
        neon: '0 0 10px rgba(0, 255, 65, 0.5), 0 0 20px rgba(0, 255, 65, 0.3)',
        'neon-red':
          '0 0 10px rgba(255, 0, 60, 0.5), 0 0 20px rgba(255, 0, 60, 0.3)',
      },
      animation: {
        scan: 'scan 8s linear infinite',
        glitch: 'glitch 1s linear infinite',
      },
      keyframes: {
        scan: {
          '0%': { backgroundPosition: '0% 0%' },
          '100%': { backgroundPosition: '0% 100%' },
        },
      },
    },
  },
  plugins: [],
};
