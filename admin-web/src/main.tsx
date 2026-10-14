import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import { initTheme } from './lib/theme'
import './styles.css'

// Applied before the first render so there is no flash of the wrong theme.
// index.html ships data-theme="dark" for exactly this reason.
initTheme()

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)