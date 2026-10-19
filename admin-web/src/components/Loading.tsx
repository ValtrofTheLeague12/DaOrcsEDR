import { Spinner } from '@heroui/react/spinner'
// First-load indicator, shared so every panel says the same thing while it is
// still waiting on a probe.
//
// Only for the FIRST load: `usePoll` keeps the previous `data` while it
// refreshes, so this renders once on entry and never again - a panel that
// flashed a spinner on every 5s poll would strobe. Later refreshes update the
// numbers in place with no indicator at all, which is the correct behaviour for
// a value that is already on screen.
//
// Skeleton placeholders were the alternative here. They were dropped because
// this page already has four live stat tiles that arrive in the same payload as
// the charts: the tiles would appear complete-looking while the charts below
// them were still empty, so the skeleton implied data that was not there yet.
// One honest "reading" state beats a screen of plausible-looking zeroes.
export default function Loading({
  label = 'Loading…',
  hint,
  className = '',
}: {
  label?: string
  /** Optional second line, e.g. what the panel is waiting on. */
  hint?: string
  className?: string
}) {
  return (
    <div
      className={`flex flex-col items-center justify-center gap-3 py-16 ${className}`}
      role="status"
      aria-live="polite"
    >
      <Spinner size="md" />
      <div className="text-center">
        <p className="text-sm text-default-500">{label}</p>
        {hint && <p className="mt-1 font-mono text-[10px] text-default-400">{hint}</p>}
      </div>
    </div>
  )
}