import type { ReactNode } from 'react'

// ---------------------------------------------------------------------------
// A labelled on/off control.
//
// Hand-rolled rather than a library Switch because it has to sit inside a
// config row that also carries an explanation and a source reference, and the
// off state is the one that matters here - "uploading is off" and "uploading is
// on" are not the same amount of information, and this control has to make the
// off state as visible as the on state rather than leaving it as a dimmed label.
//
// `role="switch"` with aria-checked, so it is announced as a switch and not as
// an unlabelled button, and the whole row is the click target: a 16px toggle is
// not a hit target.
// ---------------------------------------------------------------------------

export default function Switch({
  label,
  checked,
  onChange,
  detail,
  footnote,
  disabled,
  pending,
}: {
  label: string
  checked: boolean
  onChange: (next: boolean) => void
  /** Why this option exists. One or two sentences, in the operator's terms. */
  detail: string
  /**
   * Where the behaviour is actually implemented - a file and line in the
   * analyzer. Rendered because the panel is making a claim on the operator's
   * behalf and a claim should be checkable.
   */
  footnote?: ReactNode
  disabled?: boolean
  /** A write for this control is in flight. */
  pending?: boolean
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`flex w-full items-start gap-3 rounded-xl border px-3.5 py-3 text-left transition-colors ${
        disabled
          ? 'cursor-not-allowed border-default-200 opacity-60'
          : 'border-default-200 hover:border-accent/40 hover:bg-default-50/40'
      }`}
    >
      <span
        aria-hidden="true"
        className={`mt-0.5 flex h-4 w-7 shrink-0 items-center rounded-full p-0.5 transition-colors ${
          checked ? 'bg-accent' : 'bg-default-200'
        }`}
      >
        <span
          className={`h-3 w-3 rounded-full bg-white transition-transform ${
            checked ? 'translate-x-3' : ''
          }`}
        />
      </span>

      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-2">
          <span className="text-[12px] font-medium text-foreground">{label}</span>
          <span
            className={`metric font-mono text-[10px] ${checked ? 'text-accent' : 'text-default-400'}`}
          >
            {pending ? 'saving…' : checked ? 'on' : 'off'}
          </span>
        </span>
        <span className="mt-1 block text-[11px] leading-relaxed text-default-500">
          {detail || ' '}
        </span>
        {footnote && (
          <span className="mt-1 block font-mono text-[9px] text-default-400">{footnote}</span>
        )}
      </span>
    </button>
  )
}

/** Row wrapper for a text or number option, matching Switch's geometry. */
export function OptionField({
  label,
  detail,
  footnote,
  children,
}: {
  label: string
  detail: string
  footnote?: ReactNode
  children: ReactNode
}) {
  return (
    <label className="flex flex-col gap-2 rounded-xl border border-default-200 px-3.5 py-3 transition-colors hover:border-accent/40">
      <span className="flex items-center justify-between gap-2">
        <span className="text-[12px] font-medium text-foreground">{label}</span>
        {footnote && <span className="font-mono text-[9px] text-default-400">{footnote}</span>}
      </span>
      <span className="text-[11px] leading-relaxed text-default-500">{detail}</span>
      {children}
    </label>
  )
}