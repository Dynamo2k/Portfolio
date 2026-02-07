/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  theme: {
    extend: {
      colors: {
        'bg-primary': '#0d0d0d',
        'bg-secondary': '#1a1a1a',
        'bg-elevated': '#262626',
        'bg-hover': '#303030',
        'bg-input': '#1f1f1f',
        'accent-primary': '#00ff9f',
        'accent-secondary': '#00d4ff',
        'accent-purple': '#a78bfa',
        'accent-orange': '#ff6b35',
        'success': '#10b981',
        'warning': '#f59e0b',
        'danger': '#ef4444',
        'info': '#3b82f6',
        'text-primary': '#e8e8e8',
        'text-secondary': '#a0a0a0',
        'text-muted': '#6e6e6e',
        'text-heading': '#ffffff',
        'border-subtle': '#2a2a2a',
        'border-medium': '#3a3a3a',
        'border-strong': '#4a4a4a',
        'border-accent': '#00ff9f',
        'offensive': '#ff6b6b',
        'defensive': '#4dabf7',
        'forensics': '#be4bdb',
        'development': '#51cf66',
        'research': '#ff922b',
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      maxWidth: {
        'content': '1400px',
      },
    },
  },
  plugins: [],
};
