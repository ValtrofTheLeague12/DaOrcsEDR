import { useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { auth } from '../api'
import Icon from '../components/Icon'

// Modern, but deliberately not a marketing page. This is an operator console
// in front of malware analysis, so the page says what it protects and where the
// token comes from instead of decorating the box.

type Phase = 'idle' | 'submitting' | 'error'

export default function Login({ onOk }: { onOk: () => void }) {
  const [value, setValue] = useState('')
  const [phase, setPhase] = useState<Phase>('idle')
  const [error, setError] = useState<string | null>(null)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const token = value.trim()
    if (!token) {
      setError('Enter the panel token.')
      setPhase('error')
      return
    }
    setPhase('submitting')
    setError(null)
    try {
      await auth.login(token)
      onOk()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed.')
      setPhase('error')
      setValue('')
    }
  }

  return (
    <>
      <div className="ambient" aria-hidden />
      <div className="auth-shell relative z-10">
        <div className="w-full max-w-[23rem]">
        <div className="mb-7 text-center">
          <span className="mx-auto mb-4 flex h-11 w-11 items-center justify-center rounded-xl bg-accent/15 text-accent shadow-[0_8px_30px_-12px_var(--accent)]">
            <Icon name="stats" size={20} />
          </span>
          <h1 className="text-lg font-semibold tracking-tight">Admin Console</h1>
          <p className="mt-1 text-xs text-default-500">
            Static analyzer orchestration
          </p>
        </div>

        <form onSubmit={submit} noValidate className="auth-card p-6">
          <h2 className="text-sm font-semibold">Sign in</h2>
          <p className="mt-1 text-xs text-default-500">
            Enter the panel token to continue.
          </p>

          {phase === 'error' && error && (
            <div className="mt-4">
              <Alert status="danger">
                <Alert.Description>{error}</Alert.Description>
              </Alert>
            </div>
          )}

          <label className="mt-5 flex flex-col gap-1.5">
            <span className="text-xs font-medium text-default-600">Token</span>
            <input
              type="password"
              value={value}
              autoFocus
              autoComplete="current-password"
              spellCheck={false}
              onChange={(e) => {
                setValue(e.target.value)
                if (phase === 'error') setPhase('idle')
              }}
              placeholder="ADMIN_PANEL_TOKEN"
              className="field font-mono"
            />
          </label>

          <button
            type="submit"
            disabled={phase === 'submitting'}
            className="btn-primary mt-4 w-full justify-center"
          >
            {phase === 'submitting' ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <p className="mt-5 text-center text-[11px] leading-relaxed text-default-400">
          The token is <code className="font-mono">ADMIN_PANEL_TOKEN</code> in{' '}
          <code className="font-mono">.env</code>. With it unset the panel is open
          to anything on loopback, which is the default.
        </p>
        </div>
      </div>
    </>
  )
}