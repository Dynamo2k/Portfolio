export const themes = {
  matte: {
    name: 'Matte Black',
    colors: {
      'bg-primary': '#0d0d0d',
      'bg-secondary': '#1a1a1a',
      'bg-elevated': '#262626',
      'bg-hover': '#303030',
      'bg-input': '#1f1f1f',
      'accent-primary': '#00ff9f',
      'accent-secondary': '#00d4ff',
      'text-primary': '#e8e8e8',
      'text-secondary': '#a0a0a0',
      'text-muted': '#6e6e6e',
      'text-heading': '#ffffff',
      'border-subtle': '#2a2a2a',
      'border-medium': '#3a3a3a',
      'border-strong': '#4a4a4a',
    }
  }
};

export type ThemeName = keyof typeof themes;
