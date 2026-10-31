import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Button } from '@heroui/react/button'
import { Chip } from '@heroui/react/chip'
import Icon from './Icon'

// ---------------------------------------------------------------------------
// Modal log viewer for any long job the panel runs.
//
// One shell because two jobs wanted the same thing - `docker compose build` and
// the MEGA export - and a second copy of a modal with a scroller, a follow
// toggle and an escape handler is a second thing to keep correct. What differs
// between the two is only the fetch, the wording and how a line is coloured, so
// those are the props.
//
// Polled rather than streamed: the panel is a threaded Flask dev server and a
// poll is one line here and one dict lookup on the server, with no half-open
// connection to go stale when the tab is backgrounded. The log already arrives
// in chunks.
//
// No cancel button, deliberately. Killing a job mid-flight leaves whatever it
// was building in a state the operator would have to reason about - a half
// written image, a half-pushed bundle - and this console does not pretend to own
// that. Stop it from the terminal that owns the work.
// ---------------------------------------------------------------------------

const POLL_MS = 900

export interface JobState {
  state: 'running' | 'done' | 'error'
  lines: string[]
  dropped: number
  exit_code: number | null
  elapsed: number
}

const STATE_TONE = {
  running: 'accent',
  done: 'success',
  error: 'danger',
} as const

/** Neutral colouring for a log this component knows nothing about.
 *
 *  Only the shape of the line decides its colour - never a match on words the
 *  command might be using. An uploader that prints "0 errors" must not be
 *  coloured as a failure because it contains the word "error", and a command
 *  that uses different words for failure is still readable; the state chip
 *  carries the verdict, not a regex.
 */
function plainLineClass(line: string): string {
  if (/^\s*(trace|debug|info|\[+\s)/i.test(line)) return 'compose-tok-plain'
  if (line.trim().startsWith('#')) return 'compose-tok-comment'
  return 'compose-tok-plain'
}

export default function JobLog({
  jobId,
  title,
  subtitle,
  fetchJob,
  onClose,
  onFinished,
  lineClass = plainLineClass,
  icon,
}: {
  jobId: string
  title: string
  /** Second line under the title; the caller knows what is running. */
  subtitle: string
  fetchJob: (jobId: string) => Promise<JobState>
  onClose: () => void
  /** Called once when the job reaches a terminal state. */
  onFinished?: (job: JobState) => void
  lineClass?: (line: string) => string
  icon?: ReactNode
}) {
  const [job, setJob] = useState<JobState | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [follow, setFollow] = useState(true)
  const scroller = useRef<HTMLDivElement>(null)
  const finishedRef = useRef(false)

  useEffect(() => {
    let cancelled = false
    const tick = async () => {
      try {
        const next = await fetchJob(jobId)
        if (cancelled) return
        setJob(next)
        setError(null)
        if (next.state !== 'running' && !finishedRef.current) {
          finishedRef.current = true
          onFinished?.(next)
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e))
      }
    }
    void tick()
    const id = window.setInterval(() => {
      // Skip polling a hidden tab: nothing is watching the log scroll by.
      if (document.visibilityState === 'visible' || job === null) void tick()
    }, POLL_MS)
    return () => {
      cancelled = true
      window.clearInterval(id)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId])

  // Auto-scroll, but stop following the moment the operator scrolls up to read
  // something: yanking them back to the bottom mid-read is worse than a stale
  // viewport.
  useEffect(() => {
    if (follow && scroller.current) {
      scroller.current.scrollTop = scroller.current.scrollHeight
    }
  }, [job?.lines.length, follow])

  const onScroll = () => {
    const el = scroller.current
    if (!el) return
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24
    setFollow(atBottom)
  }

  const running = job?.state === 'running'
  const state = job?.state ?? 'running'
  const lines = job?.lines ?? []

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div
      className="compose-viewer-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="job-log-title"
      onClick={onClose}
    >
      <div className="compose-viewer-panel" onClick={(e) => e.stopPropagation()}>
        <header className="compose-viewer-header">
          <div className="flex min-w-0 items-center gap-3">
            <span className="compose-file-icon" aria-hidden="true">
              {icon ?? (
                <Icon
                  name={running ? 'refresh' : state === 'done' ? 'check' : 'alert-circle'}
                  size={16}
                />
              )}
            </span>
            <div className="min-w-0">
              <p className="text-sm font-semibold" id="job-log-title">{title}</p>
              <p className="font-mono text-[10px] text-default-400">
                {subtitle}
                {job ? ` · ${job.elapsed}s` : ''}
                {job?.dropped ? ` · ${job.dropped} earlier line${job.dropped === 1 ? '' : 's'} dropped` : ''}
              </p>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <Chip size="sm" variant="soft" color={STATE_TONE[state]}>
              {running ? 'running' : state === 'done' ? 'done' : `failed (exit ${job?.exit_code})`}
            </Chip>
            <button
              type="button"
              onClick={onClose}
              className="compose-viewer-close"
              aria-label="Close log"
            >
              <Icon name="x" size={15} />
            </button>
          </div>
        </header>

        {error && !job && (
          <div className="flex flex-1 flex-col items-center justify-center gap-3 p-12 text-center">
            <Icon name="alert-circle" size={28} className="text-danger" />
            <span className="text-xs text-danger">{error}</span>
          </div>
        )}

        {job && (
          <>
            <div className="compose-viewer-body">
              <div className="compose-viewer-pane" ref={scroller} onScroll={onScroll}>
                <div className="compose-build-log">
                  {lines.length === 0 ? (
                    <p className="compose-viewer-empty">Waiting for output…</p>
                  ) : (
                    lines.map((line, i) => (
                      <div className={`compose-build-log-line ${lineClass(line)}`} key={i}>
                        {line || ' '}
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>

            <footer className="compose-viewer-footer">
              <button
                type="button"
                className="compose-viewer-follow"
                onClick={() => setFollow((f) => !f)}
                disabled={lines.length === 0}
              >
                <Icon name="chevron" size={12} className={follow ? 'rotate-180' : ''} />
                {follow ? 'Following output' : 'Jump to latest'}
              </button>
              <div className="flex shrink-0 items-center gap-2">
                <span className="font-mono text-[10px] text-default-400">
                  {lines.length} line{lines.length === 1 ? '' : 's'}
                </span>
                <Button size="sm" variant="secondary" onPress={onClose}>
                  {running ? 'Hide' : 'Close'}
                </Button>
              </div>
            </footer>
          </>
        )}
      </div>
    </div>
  )
}