import { useCopy } from './CopyButton'

// ---------------------------------------------------------------------------
// One command, shown the way an operator would type it.
//
// Rendered as a small terminal prompt: a green `$`, the command in monospace on
// a dark bar, and a Copy action that is always one click away. Every command in
// a capture looks like the same object instead of ordinary log text, and copying
// it never means selecting the surrounding output.
// ---------------------------------------------------------------------------

export default function CommandLine({
  value,
  label,
  compact = false,
}: {
  value: string
  /** Optional caption above the command, for a list of different steps. */
  label?: string
  /** Tighter padding for a command that sits inside a log stream. */
  compact?: boolean
}) {
  const { copied, copy } = useCopy()

  return (
    <div className={`cmdline ${compact ? 'is-compact' : ''}`}>
      <span className="cmdline-prompt" aria-hidden="true">$</span>
      <div className="cmdline-main">
        {label && <p className="cmdline-label">{label}</p>}
        <code className="cmdline-code">{value}</code>
      </div>
      <button
        type="button"
        onClick={() => void copy(value)}
        className={`cmdline-copy ${copied ? 'is-copied' : ''}`}
        title={copied ? 'Copied' : 'Copy command'}
        aria-label={copied ? 'Copied' : 'Copy command'}
      >
        {copied ? '✓ Copied' : 'Copy'}
      </button>
    </div>
  )
}
