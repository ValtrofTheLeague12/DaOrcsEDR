// Rendering for parsed log lines. The parser itself lives in logParse.ts.
//
// This file re-exports the parser so the five viewers that already import from
// here keep working; what is left is the JSX - the row layout and the two
// legacy helpers other panels still call.

import type { ReactNode } from 'react'
import {
  TONE_CLASS,
  type ParsedLine,
  type Piece,
  type Tone,
  colorize,
  parseLine,
} from './logParse'

export * from './logParse'

/**
 * Highlight every occurrence of `needle`, not just the first.
 *
 * The first version used indexOf and stopped, so a line that named the same
 * symbol three times lit up once - which reads as "the other two are not
 * matches" when the counter says three. Splitting on a case-insensitive regex
 * keeps the original casing of each hit.
 */
function highlight(text: string, needle: string): ReactNode {
  if (!needle) return text
  const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const parts = text.split(new RegExp(`(${escaped})`, 'gi'))
  if (parts.length === 1) return text
  return parts.map((part, i) =>
    i % 2 === 1
      ? <mark className="log-view-hit" key={i}>{part}</mark>
      : part,
  )
}

/**
 * One row of the structured viewer.
 *
 * `parsed` is optional: the Logs panel parses a whole tail once and passes the
 * records in, because parsing 2,000 lines inside 2,000 rows on every keystroke
 * is the difference between a filter that feels instant and one that stutters.
 * Callers that render a handful of lines (the fleet view) can leave it out and
 * let the row parse itself.
 */
export function LogRow({
  line,
  number,
  wrap = true,
  query = '',
  parsed,
  active = false,
}: {
  line: string
  number: number
  wrap?: boolean
  /** Substring to emphasise. Case-insensitive; empty means no highlighting. */
  query?: string
  /** Pre-parsed record, when the caller already parsed the window. */
  parsed?: ParsedLine
  /** The row the search is currently sitting on. */
  active?: boolean
}) {
  const p = parsed ?? parseLine(line)
  const needle = query.trim()

  // `pieces` is not only the 'plain' colouriser: an ANSI line parses as 'build'
  // and carries the colours the process itself chose. Testing the shape made
  // every coloured line fall through to `message`, which has already had its
  // escapes stripped - a build log lost its own colouring here while the Build
  // page, which tests `pieces`, kept it.
  const body = p.pieces ? (
    p.pieces.map((piece: Piece, i: number) => (
      <span key={i} className={TONE_CLASS[piece.tone]}>
        {highlight(piece.text, needle)}
      </span>
    ))
  ) : (
    <span className={p.shape === 'access' ? 'text-accent' : TONE_CLASS[p.tone]}>
      {highlight(p.message, needle)}
    </span>
  )

  // A compiler diagnostic says "error" in a level word; a build line that only
  // *is* an error (a FAILED: line, a Python traceback) has no word to show, so
  // the badge comes from the normalised severity instead. Without this the
  // worst lines in a build log were the ones with an empty level column.
  const badge = p.level
    ? p.level
    : p.severity === 'error' ? 'error'
      : p.severity === 'warning' ? 'warn'
        : null

  const classes = [
    'log-view-row',
    p.notable ? 'is-notable' : '',
    `is-${p.tone}`,
    p.continuation ? 'is-continuation' : '',
    active ? 'is-active-hit' : '',
  ].filter(Boolean).join(' ')

  return (
    <div
      className={classes}
      title={p.stamp ?? p.location?.file ?? undefined}
      data-line={number}
    >
      <span className="log-view-gutter">{number}</span>
      <span className="log-view-time">{p.time ?? ''}</span>
      <span className="log-view-level">
        {badge && <span className={`log-view-badge is-${p.tone}`}>{badge}</span>}
        {p.shape === 'access' && p.code && (
          <span className={`log-view-badge is-${p.tone}`}>{p.code}</span>
        )}
      </span>
      <span className="log-view-source" title={p.source ?? undefined}>{p.source ?? ''}</span>
      <span className={`log-view-body ${wrap ? 'is-wrap' : 'is-nowrap'}`}>
        {body}
      </span>
    </div>
  )
}

/** Kept for existing callers. */
export function LogLine({ line, number }: { line: string; number: number }) {
  const pieces = colorize(line)
  return (
    <div className="flex gap-3 px-1 hover:bg-default-50">
      <span className="w-12 shrink-0 select-none text-right text-default-300 tabular-nums">
        {number}
      </span>
      <span className="min-w-0 flex-1 whitespace-pre-wrap break-all">
        {pieces.map((p, i) => (
          <span key={i} className={`${TONE_CLASS[p.tone]} ${p.strong ? 'font-semibold' : ''}`}>
            {p.text}
          </span>
        ))}
      </span>
    </div>
  )
}

export function renderPieces(line: string): ReactNode {
  return colorize(line).map((p: Piece, i: number) => (
    <span key={i} className={`${TONE_CLASS[p.tone]} ${p.strong ? 'font-semibold' : ''}`}>
      {p.text}
    </span>
  ))
}

export type { ParsedLine, Piece, Tone }
