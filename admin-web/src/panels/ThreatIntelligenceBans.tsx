import { Fragment, useEffect, useMemo, useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { Chip } from '@heroui/react/chip'
import { api, usePoll, type UserCredentialCheck } from '../api'
import Icon from '../components/Icon'
import Loading from '../components/Loading'

/** The stored digest prefixes cti_auth accepts. */
function isBcryptDigest(value: string | null | undefined): boolean {
  return typeof value === 'string' && value.length === 60 && /^\$2[aby]\$/.test(value)
}

function decisionLabel(decision: boolean | null | undefined): string {
  if (decision === true) return 'allow'
  if (decision === false) return 'block'
  return 'unset'
}

function formatCreated(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

export default function AvailableUsers() {
  const { data, error, loading, refresh, mutate } = usePoll(
    () => api.threatIntelligenceUsers(),
    60_000,
  )
  const [saving, setSaving] = useState<Set<number>>(new Set())
  const [err, setErr] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const [output, setOutput] = useState<string[]>([
    'Ready. Allow or block a user to see the result here.',
  ])

  // Credential inspection is per row and lives entirely on this page. The
  // candidate password is held only while the operator is typing and is
  // cleared as soon as the request finishes.
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const [testing, setTesting] = useState<Set<number>>(new Set())
  const [passwords, setPasswords] = useState<Record<number, string>>({})
  const [testIps, setTestIps] = useState<Record<number, string>>({})
  const [checks, setChecks] = useState<Record<number, UserCredentialCheck>>({})
  const [checkErrors, setCheckErrors] = useState<Record<number, string>>({})

  const appendOutput = (message: string) => {
    const stamp = new Date().toISOString().slice(11, 19)
    setOutput((current) => [...current, `[${stamp}] ${message}`].slice(-200))
  }

  useEffect(() => {
    // A refresh clears a previous toggle failure, but not the success line: the
    // optimistic patch below also updates `data`, and clearing the message here
    // would hide the confirmation in the same render that showed the new state.
    setErr(null)
  }, [data])

  const users = useMemo(() => data?.users ?? [], [data?.users])
  const allowedCount = users.filter((u) => u.allowed).length
  const blockedCount = users.filter((u) => !u.allowed).length

  const isSaving = (id: number) => saving.has(id)
  const isTesting = (id: number) => testing.has(id)

  const toggleUser = async (id: number) => {
    if (isSaving(id)) return
    setSaving((current) => new Set([...current, id]))
    setErr(null)
    setMsg(null)
    const target = users.find((user) => user.id_user === id)
    const label = target ? `${target.username} (#${id})` : `#${id}`
    const action = target?.allowed ? 'Block' : 'Allow'
    appendOutput(`${action}: sending request for ${label}…`)
    try {
      const result = await api.toggleUserDecision(id)
      // The response is the new authority for this row. Patch it in place so
      // the Decision text, Status chip and Allow/Block button flip on the same
      // frame as the confirmation, then re-read the list to pick up anything
      // else the write changed (an ip_list row created for a user with none).
      mutate((current) =>
        current
          ? {
              users: current.users.map((user) =>
                user.id_user === result.id_user
                  ? {
                      ...user,
                      decision: result.decision,
                      allowed: result.allowed,
                    }
                  : user,
              ),
            }
          : current,
      )
      const message = `${result.id_user} is now ${result.allowed ? 'allowed' : 'blocked'}.`
      setMsg(message)
      appendOutput(message)
      void refresh()
    } catch (exc) {
      const message = exc instanceof Error ? exc.message : String(exc)
      setErr(message)
      appendOutput(`${action} failed for ${label} — ${message}`)
    } finally {
      setSaving((current) => {
        const next = new Set(current)
        next.delete(id)
        return next
      })
    }
  }

  const toggleCredentials = (id: number) => {
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  const verifyCredentials = async (id: number) => {
    if (isTesting(id)) return
    const candidate = passwords[id] ?? ''
    if (!candidate) {
      setCheckErrors((current) => ({
        ...current,
        [id]: 'Enter the password you want to test.',
      }))
      return
    }
    const testIp = testIps[id] ?? ''
    setTesting((current) => new Set([...current, id]))
    // The candidate is used once and dropped before the request leaves the
    // page: it is never logged, persisted, or kept in state afterwards.
    setPasswords((current) => ({ ...current, [id]: '' }))
    setCheckErrors((current) => {
      const next = { ...current }
      delete next[id]
      return next
    })
    setChecks((current) => {
      const next = { ...current }
      delete next[id]
      return next
    })
    setErr(null)
    setMsg(null)
    try {
      const result = await api.verifyUserCredentials(id, candidate, testIp)
      setChecks((current) => ({ ...current, [id]: result }))
      appendOutput(
        `Credential check for ${result.username} (#${id}): ${
          result.allowed ? 'login would be allowed' : 'login would be refused'
        }.`,
      )
    } catch (exc) {
      const message = exc instanceof Error ? exc.message : String(exc)
      setCheckErrors((current) => ({ ...current, [id]: message }))
      appendOutput(`Credential check failed for #${id} — ${message}`)
    } finally {
      setTesting((current) => {
        const next = new Set(current)
        next.delete(id)
        return next
      })
    }
  }

  if (loading) return <Loading label="Loading users…" />

  return (
    <div className="threat-page">
      <header className="threat-header">
        <div>
          <p className="eyebrow">Threat Intelligence · Access control</p>
          <h1 className="page-title mt-1">Available Users</h1>
          <p className="mt-2 max-w-3xl text-xs leading-relaxed text-default-500">
            Users registered in the CTI server database and their allow/block
            status. Toggle a user to grant or revoke access to the website, or
            open Credentials to inspect the stored digest and test a password
            against the login gate.
          </p>
        </div>
        <button
          type="button"
          className="artifact-action"
          onClick={() => void refresh()}
          disabled={loading}
        >
          <Icon name="refresh" size={13} />
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </header>

      {error && (
        <Alert status="danger">
          <Alert.Title>Users could not be loaded</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}
      {err && (
        <Alert status="danger">
          <Alert.Title>Toggle failed</Alert.Title>
          <Alert.Description>{err}</Alert.Description>
        </Alert>
      )}
      {msg && (
        <Alert status="success">
          <Alert.Description>{msg}</Alert.Description>
        </Alert>
      )}

      <section className="threat-ban-section" aria-label="Available users">
        <div className="threat-ban-heading">
          <div>
            <h3>Available Users</h3>
            <p>
              {users.length} registered user(s).{' '}
              <strong>{allowedCount} allowed</strong>,{' '}
              <strong>{blockedCount} blocked</strong>.
            </p>
          </div>
          <div className="threat-catalog-counts">
            <Chip size="sm" variant="soft" color="success">
              {allowedCount} allowed
            </Chip>
            <Chip size="sm" variant="soft" color="danger">
              {blockedCount} blocked
            </Chip>
          </div>
        </div>

        <div
          className="threat-subsection threat-ban-output-section"
          aria-label="User access output"
        >
          <div className="threat-subsection-heading">
            <div>
              <p className="eyebrow">Access control log</p>
              <h3>Allow and block activity</h3>
              <p>
                Every Allow, Block and credential check is logged here with the
                user it changed, so a failed action does not disappear when the
                alert clears.
              </p>
            </div>
            <div className="threat-ban-output-actions">
              <Chip
                size="sm"
                variant="soft"
                color={saving.size > 0 ? 'accent' : 'default'}
              >
                {saving.size > 0 ? 'Saving…' : `${users.length} users`}
              </Chip>
              <button
                type="button"
                className="artifact-action"
                onClick={() => setOutput(['Output cleared.'])}
                disabled={saving.size > 0}
              >
                Clear
              </button>
            </div>
          </div>
          <div className="threat-ban-output" aria-label="Allow and block output">
            <pre aria-live="polite">{output.join('\n')}</pre>
          </div>
        </div>

        {users.length === 0 ? (
          <p className="threat-ban-empty">
            No users found. Create a user in the CTI server to get started.
          </p>
        ) : (
          <div className="threat-ban-table-wrap">
            <table className="threat-ban-table">
              <thead>
                <tr>
                  <th style={{ width: 60 }}>ID</th>
                  <th>Username</th>
                  <th>IP address</th>
                  <th>Decision</th>
                  <th>Status</th>
                  <th style={{ width: 220 }}></th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => {
                  const open = expanded.has(user.id_user)
                  const check = checks[user.id_user]
                  const checkError = checkErrors[user.id_user]
                  const digestValid = isBcryptDigest(user.password)
                  return (
                    <Fragment key={user.id_user}>
                      <tr
                        className={`threat-ban-row${!user.allowed ? ' blocked' : ''}`}
                      >
                        <td>
                          <span className="threat-ban-muted">{user.id_user}</span>
                        </td>
                        <td>
                          <span
                            className="threat-ban-name"
                            title={user.username}
                          >
                            {user.username}
                          </span>
                        </td>
                        <td>
                          <span className="threat-ban-muted">
                            {user.ip_address ?? '—'}
                          </span>
                        </td>
                        <td>
                          <span className="threat-ban-muted">
                            {user.decision === true
                              ? 'allow'
                              : user.decision === false
                                ? 'block'
                                : 'block (default)'}
                          </span>
                        </td>
                        <td>
                          <Chip
                            size="sm"
                            variant="soft"
                            color={user.allowed ? 'success' : 'danger'}
                          >
                            {user.allowed ? 'Allowed' : 'Blocked'}
                          </Chip>
                        </td>
                        <td>
                          <div className="threat-ban-actions">
                            <button
                              type="button"
                              className="artifact-action"
                              aria-expanded={open}
                              aria-controls={`credentials-${user.id_user}`}
                              onClick={() => toggleCredentials(user.id_user)}
                            >
                              <Icon name="user" size={12} />
                              {open ? 'Hide' : 'Credentials'}
                            </button>
                            <button
                              type="button"
                              className={`artifact-action threat-ban-button ${
                                user.allowed
                                  ? 'artifact-action-danger'
                                  : 'threat-ban-allow'
                              }`}
                              disabled={isSaving(user.id_user)}
                              onClick={() => toggleUser(user.id_user)}
                            >
                              {isSaving(user.id_user)
                                ? 'Toggling…'
                                : user.allowed
                                  ? 'Block'
                                  : 'Allow'}
                            </button>
                          </div>
                        </td>
                      </tr>
                      {open && (
                        <tr className="threat-ban-detail-row">
                          <td colSpan={6}>
                            <div
                              className="threat-cred"
                              id={`credentials-${user.id_user}`}
                            >
                              <div className="threat-cred-grid">
                                <div className="threat-cred-item">
                                  <span className="threat-cred-label">
                                    Username
                                  </span>
                                  <code className="threat-cred-value">
                                    {user.username}
                                  </code>
                                </div>
                                <div className="threat-cred-item">
                                  <span className="threat-cred-label">
                                    Pepper
                                  </span>
                                  <code className="threat-cred-value">
                                    {user.unique_peper || '—'}
                                  </code>
                                </div>
                                <div className="threat-cred-item">
                                  <span className="threat-cred-label">
                                    Provisioned IP
                                  </span>
                                  <code className="threat-cred-value">
                                    {user.ip_address ?? '—'}
                                  </code>
                                </div>
                                <div className="threat-cred-item">
                                  <span className="threat-cred-label">
                                    Decision
                                  </span>
                                  <span className="threat-cred-value">
                                    {decisionLabel(user.decision)}
                                  </span>
                                </div>
                                <div className="threat-cred-item">
                                  <span className="threat-cred-label">
                                    Created
                                  </span>
                                  <span className="threat-cred-value">
                                    {formatCreated(user.created_at)}
                                  </span>
                                </div>
                                <div className="threat-cred-item threat-cred-wide">
                                  <span className="threat-cred-label">
                                    bcrypt digest
                                  </span>
                                  <code className="threat-cred-value threat-cred-digest">
                                    {user.password || '—'}
                                  </code>
                                </div>
                              </div>

                              <div className="threat-cred-health">
                                <Chip
                                  size="sm"
                                  variant="soft"
                                  color={digestValid ? 'success' : 'danger'}
                                >
                                  {digestValid
                                    ? 'bcrypt digest'
                                    : 'digest unsupported'}
                                </Chip>
                                <Chip
                                  size="sm"
                                  variant="soft"
                                  color={
                                    user.unique_peper ? 'success' : 'warning'
                                  }
                                >
                                  {user.unique_peper
                                    ? 'pepper present'
                                    : 'no pepper'}
                                </Chip>
                                <Chip
                                  size="sm"
                                  variant="soft"
                                  color={user.ip_address ? 'success' : 'warning'}
                                >
                                  {user.ip_address
                                    ? 'IP provisioned'
                                    : 'no IP'}
                                </Chip>
                                <Chip
                                  size="sm"
                                  variant="soft"
                                  color={
                                    user.decision === true ? 'success' : 'danger'
                                  }
                                >
                                  decision {decisionLabel(user.decision)}
                                </Chip>
                              </div>

                              <form
                                className="threat-cred-test"
                                onSubmit={(event) => {
                                  event.preventDefault()
                                  void verifyCredentials(user.id_user)
                                }}
                              >
                                <label>
                                  <span>Candidate password</span>
                                  <input
                                    type="password"
                                    value={passwords[user.id_user] ?? ''}
                                    onChange={(event) =>
                                      setPasswords((current) => ({
                                        ...current,
                                        [user.id_user]: event.target.value,
                                      }))
                                    }
                                    autoComplete="new-password"
                                    spellCheck={false}
                                    placeholder="Used once, never stored"
                                  />
                                </label>
                                <label>
                                  <span>Test IP (optional)</span>
                                  <input
                                    type="text"
                                    value={testIps[user.id_user] ?? ''}
                                    onChange={(event) =>
                                      setTestIps((current) => ({
                                        ...current,
                                        [user.id_user]: event.target.value,
                                      }))
                                    }
                                    autoComplete="off"
                                    spellCheck={false}
                                    placeholder={
                                      user.ip_address ??
                                      'defaults to the provisioned IP'
                                    }
                                  />
                                </label>
                                <button
                                  type="submit"
                                  className="artifact-action"
                                  disabled={
                                    isTesting(user.id_user) ||
                                    !(passwords[user.id_user] ?? '')
                                  }
                                >
                                  <Icon name="check" size={12} />
                                  {isTesting(user.id_user)
                                    ? 'Checking…'
                                    : 'Test login'}
                                </button>
                              </form>

                              {checkError && (
                                <p className="threat-cred-error">{checkError}</p>
                              )}

                              {check && (
                                <div
                                  className={`threat-cred-result ${
                                    check.allowed ? 'ok' : 'bad'
                                  }`}
                                  aria-live="polite"
                                >
                                  <div className="threat-cred-result-head">
                                    <strong>
                                      {check.allowed
                                        ? 'Login would succeed'
                                        : 'Login would be refused'}
                                    </strong>
                                    <span>{check.detail}</span>
                                  </div>
                                  <div className="threat-cred-result-chips">
                                    <Chip
                                      size="sm"
                                      variant="soft"
                                      color={
                                        check.password_ok ? 'success' : 'danger'
                                      }
                                    >
                                      password{' '}
                                      {check.password_ok ? 'match' : 'mismatch'}
                                    </Chip>
                                    <Chip
                                      size="sm"
                                      variant="soft"
                                      color={check.ip_ok ? 'success' : 'danger'}
                                    >
                                      IP {check.ip_ok ? 'allowed' : 'refused'}
                                    </Chip>
                                    <Chip
                                      size="sm"
                                      variant="soft"
                                      color={
                                        check.decision === true
                                          ? 'success'
                                          : 'danger'
                                      }
                                    >
                                      decision {decisionLabel(check.decision)}
                                    </Chip>
                                    <Chip
                                      size="sm"
                                      variant="soft"
                                      color={
                                        check.pepper_present
                                          ? 'success'
                                          : 'warning'
                                      }
                                    >
                                      {check.pepper_present
                                        ? 'pepper present'
                                        : 'no pepper'}
                                    </Chip>
                                    <Chip
                                      size="sm"
                                      variant="soft"
                                      color={
                                        check.hash_valid ? 'success' : 'danger'
                                      }
                                    >
                                      {check.hash_valid
                                        ? 'digest valid'
                                        : 'digest unsupported'}
                                    </Chip>
                                  </div>
                                  <p className="threat-cred-result-ip">
                                    Tested address:{' '}
                                    <code>{check.test_ip ?? '—'}</code>
                                    {' · '}
                                    stored: <code>{check.stored_ip ?? '—'}</code>
                                  </p>
                                  {check.reasons.length > 0 && (
                                    <ul className="threat-cred-reasons">
                                      {check.reasons.map((reason) => (
                                        <li key={reason}>{reason}</li>
                                      ))}
                                    </ul>
                                  )}
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
