import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import CopyButton from './CopyButton'
import Icon, { type IconName } from './Icon'

// ---------------------------------------------------------------------------
// Console - one read-only terminal panel.
//
// The panel shows three kinds of machine text and they are read the same way:
// the connection test (a few dozen status lines), a scan log (streaming, long)
// and a result document (JSON evidence). Each used to bring its own card, its
// own scroller and its own copy story, so the three looked like three features.
// They are one feature: a titled box of monospace text with a copy button.
//
// The body reuses the build log's classes - `.build-log-line`, `.build-log-num`,
// `.build-log-text`, `.build-empty` - so a line highlights, wraps and numbers
// exactly like the compose log. Only the height differs, and that is the
// `console-body` modifiers in styles.css.
//
// `live` is the one behavioural switch: a running job follows the tail and
// offers a follow toggle; a finished document stays where the reader put it.
// ---------------------------------------------------------------------------

export type ConsoleTone = 'default' | 'accent' | 'success' | 'warning' | 'danger'
export type ConsoleSize = 'default' | 'tall' | 'short'

const SIZE_CLASS: Record<ConsoleSize, string> = {
  default: '',
  tall: 'is-tall',
  short: 'is-short',
}

export default function Console({
  title,
  subtitle,
  icon = 'terminal',
  status,
  meta,
  actions,
  lines,
  lineClass,
  size = 'default',
  live = false,
  numbered = false,
  truncated = 0,
  empty = 'Nothing to show yet.',
  ariaLabel,
  copyText,
  className = '',
}: {
  title: ReactNode
  /** Second line under the title: where the text came from. */
  subtitle?: ReactNode
  icon?: IconName
  status?: { label: string; tone?: ConsoleTone }
  /** Short right-aligned count, usually "12 lines". */
  meta?: ReactNode
  /** Buttons that act on the output (Run check, Reload…). */
  actions?: ReactNode
  lines: string[]
  lineClass?: (line: string, index: number) => string
  size?: ConsoleSize
  /** A running job: follow the tail and offer the follow toggle. */
  live?: boolean
  numbered?: boolean
  /** Lines dropped before the first visible one. */
  truncated?: number
  empty?: ReactNode
  ariaLabel?: string
  /** Defaults to the visible lines joined by newlines. */
  copyText?: string
  className?: string
}) {
  const scroller = useRef<HTMLDivElement>(null)
  const [follow, setFollow] = useState(live)

  useEffect(() => {
    if (live) setFollow(true)
  }, [live])

  useEffect(() => {
    const el = scroller.current
    if (follow && el) el.scrollTop = el.scrollHeight
  }, [lines.length, follow])

  const onScroll = () => {
    if (!live) return
    const el = scroller.current
    if (!el) return
    // Stop following the moment the operator scrolls up to read something;
    // yanking them back to the bottom mid-read is worse than a stale viewport.
    setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 32)
  }

  return (
    <Card className={`w-full ${className}`}>
      <Card.Header className="flex flex-row flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <Icon name={icon} size={13} className="shrink-0 text-default-400" />
          <div className="min-w-0">
            <Card.Title className="truncate text-sm font-semibold">{title}</Card.Title>
            {subtitle && (
              <p className="truncate font-mono text-[10px] text-default-400">{subtitle}</p>
            )}
          </div>
          {status && (
            <Chip size="sm" variant="soft" color={status.tone ?? 'default'}>
              {status.label}
            </Chip>
          )}
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-1.5">
          {meta && <span className="console-count">{meta}</span>}
          {live && lines.length > 0 && (
            <button
              type="button"
              onClick={() => setFollow((f) => !f)}
              aria-pressed={follow}
              className={`log-toggle ${follow ? 'is-on' : ''}`}
              title={follow ? 'Following the newest line' : 'Follow the newest line'}
            >
              <Icon name="chevron" size={11} className={follow ? 'rotate-180' : ''} />
              {follow ? 'Following' : 'Follow'}
            </button>
          )}
          {actions}
          <CopyButton text={copyText ?? lines.join('\n')} />
        </div>
      </Card.Header>
      <div className={`console-accent is-${status?.tone ?? 'default'}`} aria-hidden="true" />
      <Card.Content className="p-2">
        <div
          className={`build-log console-body ${SIZE_CLASS[size]}`}
          role="log"
          aria-label={ariaLabel ?? (typeof title === 'string' ? title : 'Output')}
          aria-live={live ? 'polite' : undefined}
          ref={scroller}
          onScroll={onScroll}
        >
          {truncated > 0 && (
            <div className="build-log-line is-truncated">
              {numbered && <span className="build-log-num">…</span>}
              <span className="build-log-text">
                … {truncated} earlier line{truncated === 1 ? '' : 's'} dropped
              </span>
            </div>
          )}
          {lines.length === 0 ? (
            <p className="build-empty">{empty}</p>
          ) : (
            lines.map((line, i) => (
              <div className={`build-log-line ${lineClass?.(line, i) ?? ''}`} key={i}>
                {numbered && <span className="build-log-num">{i + 1}</span>}
                <span className="build-log-text">{line || ' '}</span>
              </div>
            ))
          )}
        </div>
      </Card.Content>
    </Card>
  )
}
