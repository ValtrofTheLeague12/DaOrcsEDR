import { useEffect, useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import { api } from '../api'
import type { CTISettings } from '../types'

export default function ThreatIntelligenceApis() {
  const [settings, setSettings] = useState<CTISettings | null>(null)
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    api.ctiSettings()
      .then((result) => { if (!cancelled) setSettings(result) })
      .catch((exc: unknown) => {
        if (!cancelled) setError(exc instanceof Error ? exc.message : String(exc))
      })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])

  const saveKey = async (providerId: string) => {
    const key = drafts[providerId]?.trim()
    if (!key || busy) return
    setBusy(providerId)
    setError(null)
    setMessage(null)
    try {
      setSettings(await api.saveCtiSettings({ [providerId]: key }))
      setDrafts((current) => ({ ...current, [providerId]: '' }))
      setMessage('API key saved securely for analyzer runs started from this panel.')
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc))
    } finally {
      setBusy(null)
    }
  }

  const clearKey = async (providerId: string) => {
    if (busy) return
    setBusy(providerId)
    setError(null)
    setMessage(null)
    try {
      setSettings(await api.saveCtiSettings({ [providerId]: null }))
      setDrafts((current) => ({ ...current, [providerId]: '' }))
      setMessage('Saved API key removed. Analyzer runs may still use an environment-provided key.')
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="threat-page">
      <header className="threat-header">
        <div>
          <p className="eyebrow">Static analyzer integrations</p>
          <h1 className="page-title mt-1">Threat Intelligence API Configuration</h1>
          <p className="mt-2 max-w-3xl text-xs leading-relaxed text-default-500">
            Configure the intelligence providers used by static analysis. Keys
            are stored outside the repository and used for runs started from
            this panel. Saved values are never sent back to the browser.
          </p>
        </div>
        {loading && <Chip size="sm" variant="soft">Loading status…</Chip>}
      </header>

      {error && (
        <Alert status="danger">
          <Alert.Title>API configuration failed</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}
      {message && (
        <Alert status="success">
          <Alert.Description>{message}</Alert.Description>
        </Alert>
      )}

      {settings && (
        <section className="threat-api-section" aria-label="Provider API keys">
          <div className="threat-api-grid">
            {settings.providers.map((provider) => (
              <Card className="threat-api-card" key={provider.id}>
                <Card.Header className="threat-api-card-header">
                  <div>
                    <Card.Title>{provider.name}</Card.Title>
                    <p className="threat-api-env">{provider.env}</p>
                  </div>
                  <Chip
                    size="sm"
                    variant="soft"
                    color={provider.configured ? 'success' : 'warning'}
                  >
                    {provider.configured ? 'Saved' : 'Not saved'}
                  </Chip>
                </Card.Header>
                <Card.Content className="threat-api-card-content">
                  <p>{provider.description}</p>
                  <span className="threat-api-requirement">
                    {provider.optional ? 'Optional · improves quota' : 'Key required for authenticated lookups'}
                  </span>
                  <label className="threat-api-input-label" htmlFor={`cti-key-${provider.id}`}>
                    API key
                  </label>
                  <input
                    id={`cti-key-${provider.id}`}
                    type="password"
                    autoComplete="new-password"
                    spellCheck={false}
                    value={drafts[provider.id] ?? ''}
                    onChange={(event) => setDrafts((current) => ({
                      ...current,
                      [provider.id]: event.target.value,
                    }))}
                    placeholder={provider.configured ? 'Saved · enter a new key to replace' : 'Paste API key'}
                  />
                  <div className="threat-api-actions">
                    <button
                      type="button"
                      className="artifact-action"
                      disabled={busy !== null || !drafts[provider.id]?.trim()}
                      onClick={() => void saveKey(provider.id)}
                    >
                      {busy === provider.id ? 'Saving…' : 'Save key'}
                    </button>
                    {provider.configured && (
                      <button
                        type="button"
                        className="artifact-action threat-api-clear"
                        disabled={busy !== null}
                        onClick={() => void clearKey(provider.id)}
                      >
                        Clear
                      </button>
                    )}
                  </div>
                </Card.Content>
              </Card>
            ))}
          </div>
        </section>
      )}
    </div>
  )
}
