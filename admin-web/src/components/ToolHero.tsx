import type { ReactNode } from 'react'

// ---------------------------------------------------------------------------
// The header of a tool page (ClamAV, Qiling).
//
// Both are guests on the same VM and answer the same first question: is it up,
// where, and when did anyone last check? That answer used to be spread across a
// "Connection" card, a status chip, a transcript and a step list. It now sits in
// one strip so the page opens on the verdict, and the cards below are detail.
// ---------------------------------------------------------------------------

export type ToolTone = 'ok' | 'warn' | 'bad' | 'idle'

export interface ToolFact {
  label: string
  value: ReactNode
  mono?: boolean
  title?: string
}

export default function ToolHero({
  eyebrow,
  title,
  lead,
  tone,
  state,
  facts,
  actions,
}: {
  eyebrow: string
  title: string
  lead?: string
  tone: ToolTone
  /** The verdict in a word or two: "Ready", "Not ready", "Checking…". */
  state: string
  facts: ToolFact[]
  actions?: ReactNode
}) {
  return (
    <header className={`tool-hero is-${tone}`}>
      <div className="tool-hero-top">
        <span className="tool-orb" aria-hidden="true"><i /></span>
        <div className="tool-hero-title">
          <p className="eyebrow">{eyebrow}</p>
          <h2 className="page-title">
            {title}
            <span className="tool-state" role="status">{state}</span>
          </h2>
          {lead && <p className="tool-lead">{lead}</p>}
        </div>
        {actions && <div className="tool-hero-actions">{actions}</div>}
      </div>
      <dl className="tool-facts">
        {facts.map((fact) => (
          <div key={fact.label} title={fact.title}>
            <dt>{fact.label}</dt>
            <dd className={fact.mono ? 'is-mono' : ''}>{fact.value}</dd>
          </div>
        ))}
      </dl>
    </header>
  )
}
