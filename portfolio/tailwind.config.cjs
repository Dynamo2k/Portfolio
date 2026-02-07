/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  theme: {
    extend: {
      colors: {
        'bg-primary': '#0A0E27',
        'bg-secondary': '#1A1F3A',
        'bg-elevated': '#242B4A',
        'accent-primary': '#00D9FF',
        'accent-secondary': '#7B68EE',
        'accent-teal': '#14B8A6',
        'success': '#10B981',
        'warning': '#F59E0B',
        'danger': '#DC2626',
        'info': '#3B82F6',
        'text-primary': '#E5E7EB',
        'text-secondary': '#9CA3AF',
        'text-muted': '#6B7280',
        'offensive': '#DC2626',
        'defensive': '#3B82F6',
        'forensics': '#7B68EE',
        'development': '#10B981',
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
      maxWidth: {
        'content': '1200px',
      },
    },
  },
  plugins: [],
};
