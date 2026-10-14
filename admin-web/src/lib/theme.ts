// Dark/light theming.
//
// HeroUI resolves every token from `data-theme` on the root element
// (`.dark, [data-theme=dark], :host(.dark)`), so switching is one attribute
// and no React re-render is needed. The choice is persisted because a console
// that flips back to dark on every reload is worse than no toggle at all.

export type Theme = 'dark' | 'light'

const KEY = 'admin-panel-theme'

export function currentTheme(): Theme {
  return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark'
}

export function applyTheme(theme: Theme): void {
  document.documentElement.setAttribute('data-theme', theme)
  // color-scheme drives native form controls, scrollbars and the caret.
  document.documentElement.style.colorScheme = theme
  try {
    localStorage.setItem(KEY, theme)
  } catch {
    // Private browsing or a locked-down profile: the theme still applies for
    // this session, it just will not be remembered.
  }
}

export function initTheme(): Theme {
  let stored: string | null = null
  try {
    stored = localStorage.getItem(KEY)
  } catch {
    stored = null
  }
  const theme: Theme = stored === 'light' || stored === 'dark' ? stored : 'dark'
  applyTheme(theme)
  return theme
}

export function toggleTheme(): Theme {
  const next: Theme = currentTheme() === 'dark' ? 'light' : 'dark'
  applyTheme(next)
  return next
}