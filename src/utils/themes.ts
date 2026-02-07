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
  },
  jet: {
    name: 'Jet Black',
    colors: {
      'bg-primary': '#000000',
      'bg-secondary': '#0a0a0a',
      'bg-elevated': '#1a1a1a',
      'bg-hover': '#242424',
      'bg-input': '#111111',
      'accent-primary': '#00ff9f',
      'accent-secondary': '#00d4ff',
      'text-primary': '#ffffff',
      'text-secondary': '#b0b0b0',
      'text-muted': '#707070',
      'text-heading': '#ffffff',
      'border-subtle': '#1f1f1f',
      'border-medium': '#2f2f2f',
      'border-strong': '#3f3f3f',
    }
  },
  light: {
    name: 'Light Mode',
    colors: {
      'bg-primary': '#ffffff',
      'bg-secondary': '#f5f5f5',
      'bg-elevated': '#e8e8e8',
      'bg-hover': '#d0d0d0',
      'bg-input': '#f0f0f0',
      'accent-primary': '#00b386',
      'accent-secondary': '#0096cc',
      'text-primary': '#1a1a1a',
      'text-secondary': '#4a4a4a',
      'text-muted': '#777777',
      'text-heading': '#000000',
      'border-subtle': '#e0e0e0',
      'border-medium': '#cccccc',
      'border-strong': '#aaaaaa',
    }
  }
};

export type ThemeName = keyof typeof themes;
