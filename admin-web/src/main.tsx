import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import { initTheme } from './lib/theme'
import './styles.css'

// Applied before the first render so there is no flash of the wrong theme.
// index.html ships data-theme="dark" for exactly this reason.
initTheme()

// Vite fires this when a lazy panel's chunk cannot be fetched - the normal
// case after a rebuild replaced the hashed filenames while this tab was open.
// Without it the rejected import reaches PanelBoundary and the operator sees
// "This panel failed to open" for a page that exists in the new build. Reload
// once; the five-second guard keeps a genuinely broken deploy from looping.
window.addEventListener('vite:preloadError', (event) => {
  event.preventDefault()
  try {
    const key = 'ia:stale-chunk'
    const last = Number(sessionStorage.getItem(key) || 0)
    if (Date.now() - last < 5000) return
    sessionStorage.setItem(key, String(Date.now()))
  } catch {
    // Private mode may deny sessionStorage; reloading is still the right move.
  }
  window.location.reload()
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)