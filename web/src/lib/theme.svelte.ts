const KEY = 'vigordns_theme';
type Theme = 'light' | 'dark';

function initial(): Theme {
  try {
    const saved = localStorage.getItem(KEY);
    if (saved === 'light' || saved === 'dark') return saved;
  } catch {
    /* storage unavailable */
  }
  return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

class ThemeState {
  current = $state<Theme>(initial());

  constructor() {
    this.apply();
  }

  private apply() {
    document.documentElement.dataset.theme = this.current;
  }

  toggle = () => {
    this.current = this.current === 'dark' ? 'light' : 'dark';
    this.apply();
    try {
      localStorage.setItem(KEY, this.current);
    } catch {
      /* ignore */
    }
  };
}

export const theme = new ThemeState();
