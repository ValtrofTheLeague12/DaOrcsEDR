import { useEffect, useState } from 'react'
import Icon from './Icon'
import { currentTheme, initTheme, toggleTheme, type Theme } from '../lib/theme'

export default function ThemeToggle({ className = '' }: { className?: string }) {
  const [theme, setTheme] = useState<Theme>('dark')

  useEffect(() => {
    // initTheme re-applies whatever was persisted; index.html ships dark as
    // the no-flash default for first paint.
    setTheme(initTheme())
  }, [])

  const next = theme === 'dark' ? 'light' : 'dark'

  return (
    <button
      onClick={() => setTheme(toggleTheme())}
      title={`Switch to ${next} theme`}
      aria-label={`Switch to ${next} theme`}
      className={`btn-ghost ${className}`}
    >
      <Icon name={theme === 'dark' ? 'moon' : 'sun'} size={14} />
      <span className="capitalize">{theme}</span>
    </button>
  )
}

export { currentTheme }