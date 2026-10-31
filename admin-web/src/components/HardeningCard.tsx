import { useEffect, useState } from 'react'
import { Alert, Card, Chip } from '@heroui/react'
import Icon from '../components/Icon'
import Checkbox from '../components/Checkbox'
import type { BuildHardening, BuildHardeningRow } from '../types'

// ---------------------------------------------------------------------------
// Hardening: the build's protection flags, and whether the binary carries them.
//
// This answers one comparison question - "does the binary match what the
// settings ask for?" - so both halves live on one card rather than in two
// places that could render a green toggle beside a binary built before it.
//
// The settings file (config/hardening.json) is what the NEXT build is asked
// for; the compliance rows are what the binary already carries. They differ
// between a toggle being flipped and the build that honours it, which is the
// gap this card exists to make visible.
//
// Turning a protection OFF is as compliant as turning one ON. The defaults are
// on because MinGW's own defaults are on; the switches exist to record a
// deliberate OFF, and a binary that matches that intent is passing. The card
// marks a non-default choice rather than judging it.
//
// Lives here rather than in BuildChecks.tsx because it is shown on two pages:
// the Build page, where the settings are written, and Analysis Configuration,
// where it documents the binary an analysis will actually run.
// ---------------------------------------------------------------------------

function ComplianceRow({ row }: { row: BuildHardeningRow }) {
  return (
    <div className="flex items-center justify-between gap-3 py-1">
      <span className="flex min-w-0 items-center gap-2">
        <span
          aria-hidden
          className={
            'inline-block h-1.5 w-1.5 shrink-0 rounded-full ' +
            (row.ok ? 'bg-success' : 'bg-danger')
          }
        />
        <span className="truncate text-foreground text-[11px]">{row.label}</span>
      </span>
      <span
        className={
          'shrink-0 truncate font-mono text-[10px] ' +
          (row.ok ? 'text-default-500' : 'text-danger')
        }
        title={row.detail}
      >
        {row.detail}
      </span>
    </div>
  )
}

export function HardeningCard({
  hardening,
  onSave,
  saving,
}: {
  hardening: BuildHardening
  onSave: (patch: Record<string, boolean>) => void
  saving: boolean
}) {
  const { settings, compliance } = hardening

  // The toggles stage an edit; the server holds the truth. Reseeded by VALUE
  // rather than by object identity, so a refetch that returns the same four
  // booleans cannot clobber an edit still sitting here unsaved, while a save
  // - or another operator editing the same file - still lands.
  const serverSignature = JSON.stringify(settings.settings)
  const [draft, setDraft] = useState<Record<string, boolean>>(
    () => ({ ...settings.settings }))
  useEffect(() => { setDraft(JSON.parse(serverSignature)) }, [serverSignature])

  const dirty = settings.options.some(
    (o) => draft[o.key] !== settings.settings[o.key])

  const verdict = compliance.compliant === false
    ? { text: 'binary does not match — rebuild', tone: 'danger' as const }
    : compliance.compliant === true
      ? { text: 'settings and binary agree', tone: 'success' as const }
      : { text: 'not verified against a binary', tone: undefined }

  return (
    <Card className="build-card">
      <Card.Header className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <Card.Title>Hardening</Card.Title>
          <p className="mt-0.5 truncate font-mono text-[10px] text-default-500" title={settings.path}>
            {settings.path}
            {settings.exists ? '' : ' · not written yet — the defaults are in force'}
          </p>
        </div>
        <Chip size="sm" variant="soft" color={verdict.tone}>{verdict.text}</Chip>
      </Card.Header>
      <Card.Content className="build-card-body gap-2">
        {/* A malformed settings file is refused, not silently defaulted: a typo
            must not produce a binary the file claims to describe. The refusal
            is shown here because it also blocks saving from this card - the
            operator has to fix the file, and needs the sentence to know why. */}
        {settings.error && (
          <Alert status="danger">
            <Alert.Title>{settings.path} could not be read</Alert.Title>
            <Alert.Description>
              {settings.error} — the defaults are shown below, and saving is
              refused until the file is fixed by hand.
            </Alert.Description>
          </Alert>
        )}

        <div className="flex flex-col gap-1">
          {settings.options.map((option) => (
            <label
              key={option.key}
              className="flex cursor-pointer items-start gap-3 rounded-lg border border-default-200 p-3 transition-colors hover:bg-default-50"
            >
              <span className="pt-0.5">
                <Checkbox
                  checked={!!draft[option.key]}
                  disabled={saving}
                  onChange={(next) =>
                    setDraft((cur) => ({ ...cur, [option.key]: next }))}
                />
              </span>
              <span className="min-w-0 flex-1">
                <span className="flex flex-wrap items-center gap-2">
                  <span className="text-[13px] font-semibold text-foreground">
                    {option.label}
                  </span>
                  {/* A non-default choice is worth naming, not judging: the
                      point of the file is that an intentional OFF survives as
                      recorded intent instead of looking like a lost default. */}
                  {draft[option.key] !== option.default && (
                    <Chip size="sm" variant="soft" color="warning">
                      {option.default ? 'off by choice' : 'on by choice'}
                    </Chip>
                  )}
                </span>
                <span className="mt-1 block text-[11px] text-default-500">
                  {option.detail}
                </span>
              </span>
            </label>
          ))}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-[11px] text-default-500">
            Saved to <code className="font-mono">{settings.path}</code>;{' '}
            <code className="font-mono">build.ps1</code> reads it, so a build
            from here and one from a terminal produce the same binary. Settings
            take effect at the <b>next</b> build.
          </p>
          <span className="flex gap-2">
            {dirty && (
              <button
                type="button"
                className="artifact-action"
                onClick={() => setDraft(JSON.parse(serverSignature))}
                disabled={saving}
              >
                Revert
              </button>
            )}
            <button
              type="button"
              className="artifact-refresh"
              onClick={() => onSave(settings.options
                .filter((o) => draft[o.key] !== settings.settings[o.key])
                .reduce<Record<string, boolean>>((acc, o) => {
                  acc[o.key] = draft[o.key]
                  return acc
                }, {}))}
              disabled={saving || !dirty}
              title={dirty
                ? 'Write the changed settings to config/hardening.json'
                : 'Nothing changed yet'}
            >
              {saving ? 'Saving…' : 'Save settings'}
              <Icon name="check" size={13} />
            </button>
          </span>
        </div>

        {/* The comparison. Both halves are always described, and a mismatch is
            an instruction (rebuild), not an error - the file is the intent,
            the binary is the fact, and only a build makes them the same thing. */}
        <div>
          <p className="eyebrow mb-0.5">The binary</p>
          {!compliance.available ? (
            <p className="text-[11px] text-default-500">{compliance.reason}</p>
          ) : (
            <div className="flex flex-col">
              <div className="divide-y divide-default-100">
                {compliance.rows.map((r) => (
                  <ComplianceRow key={r.key} row={r} />
                ))}
              </div>
              <p className="mt-1 font-mono text-[10px] text-default-400">
                DllCharacteristics 0x
                {(compliance.dll_characteristics ?? 0).toString(16).padStart(4, '0')}
                {' · '}
                {compliance.format}
              </p>
              <p className="mt-1 text-[10px] text-default-500">
                The stack protector has no PE header bit; it is inferred from the
                canary runtime being linked in — a weaker signal than the other
                three, and reported as such.
              </p>
              {compliance.compliant === false && (
                <Alert status="warning" className="mt-2">
                  <Alert.Description>
                    {compliance.note} The settings above are what the next build
                    will ask for; the rows are what this binary already carries.
                  </Alert.Description>
                </Alert>
              )}
            </div>
          )}
        </div>

        {compliance.binary && (
          <p className="truncate font-mono text-[10px] text-default-400" title={compliance.binary}>
            {compliance.binary}
          </p>
        )}
      </Card.Content>
    </Card>
  )
}
