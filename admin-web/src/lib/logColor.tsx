import type { ReactNode } from 'react'

// Colourises log lines by CONTENT, not by file extension.
//
// Three real shapes come out of this repo (sampled, not assumed):
//
//   banner   === 2026-10-12 15:49:26 $ ssh ... (cwd=...)     [dim, monospace]
//   levelled 2026-10-13 14:16:37 ERROR   ml.serve: [*] ...    [level coloured]
//   jsonl    {"ts":...,"level":"error","msg":"..."}          [level coloured]
//
// plus Flask access lines, whose status code is the only thing worth reading:
//
//   100.95.199.25 - - [09/Oct/2026 13:33:44] "GET /malapi/x" 200 -
//
// Everything here maps onto HeroUI's own tokens (text-danger, text-warning,
// text-accent, text-default-400), so the viewer restyles itself when the theme
// flips without knowing anything about them.

type Tone = 'default' | 'accent' | 'success' | 'warning' | 'danger' | 'muted'

const TONE_CLASS: Record<Tone, string> = {
  default: 'text-default-300',
  accent: 'text-accent',
  success: 'text-success',
  warning: 'text-warning',
  danger: 'text-danger',
  muted: 'text-default-400',
}

const LEVEL_TONE: Record<string, Tone> = {
  error: 'danger',
  err: 'danger',
  fatal: 'danger',
  critical: 'danger',
  crit: 'danger',
  panic: 'danger',
  warn: 'warning',
  warning: 'warning',
  notice: 'warning',
  info: 'accent',
  information: 'accent',
  debug: 'muted',
  trace: 'muted',
  verbose: 'muted',
}

const TIMESTAMP = /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?/
const BRACKET_TIME = /\[\d{2}\/\w{3}\/\d{4}(?::\d{2}:\d{2}:\d{2}(?:\s[+-]\d{4})?)?\]/
const LEVEL_WORD = /\b(TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|FATAL|CRITICAL|CRIT|PANIC)\b/
const HTTP_LINE = /^(\S+)\s+(\S+)\s+(\S+)\s+(\[[^\]]+\])\s+"([A-Z]+)\s+([^"]+)"\s+(\d{3})\b/
const BANNER = /^===\s+\d{4}-\d{2}-\d{2}/

function statusTone(code: string): Tone {
  const n = Number(code)
  if (!Number.isFinite(n)) return 'muted'
  if (n < 300) return 'success'
  if (n < 400) return 'accent'
  if (n < 500) return 'warning'
  return 'danger'
}

interface Piece {
  text: string
  tone: Tone
  strong?: boolean
}

/** Break one raw line into coloured pieces. */
export function colorize(line: string): Piece[] {
  // Banner: the command the admin terminal ran. Interesting, but not a
  // severity, so it is muted rather than dressed up as one.
  if (BANNER.test(line)) return [{ text: line, tone: 'muted' }]

  // Flask access line: colour the status code, dim the rest.
  const http = HTTP_LINE.exec(line)
  if (http) {
    const [, ip, ident, user, when, method, path, code] = http
    return [
      { text: `${ip} ${ident} ${user} `, tone: 'muted' },
      { text: when, tone: 'muted' },
      { text: ` "${method} `, tone: 'default' },
      { text: path, tone: 'accent' },
      { text: '" ', tone: 'default' },
      { text: code, tone: statusTone(code), strong: true },
    ]
  }

  // Structured level word (plain-text logs: "2026-.. INFO    ml.serve: ...").
  const lvl = LEVEL_WORD.exec(line)
  if (lvl) {
    const tone = LEVEL_TONE[lvl[1].toLowerCase()] ?? 'default'
    const at = lvl.index
    const pieces: Piece[] = []
    const ts = TIMESTAMP.exec(line)
    if (ts && ts.index < at) {
      pieces.push({ text: line.slice(0, ts.index), tone: 'muted' })
      pieces.push({ text: ts[0], tone: 'muted' })
      pieces.push({ text: line.slice(ts.index + ts[0].length, at), tone: 'default' })
    } else if (at > 0) {
      pieces.push({ text: line.slice(0, at), tone: 'default' })
    }
    pieces.push({ text: lvl[0], tone, strong: true })
    pieces.push({ text: line.slice(at + lvl[0].length), tone })
    return pieces
  }

  // JSON / JSONL: pull level, status and msg out; render the rest dim.
  const trimmed = line.trimStart()
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      const obj = JSON.parse(trimmed) as Record<string, unknown>
      const level = String(obj.level ?? obj.severity ?? obj.status ?? '')
      const tone = LEVEL_TONE[level.toLowerCase()] ?? 'default'
      const parts: Piece[] = []
      const ts = typeof obj.ts === 'string' ? obj.ts : typeof obj.time === 'string' ? obj.time : null
      if (ts) parts.push({ text: `${ts} `, tone: 'muted' })
      if (level) parts.push({ text: `${level.toUpperCase()} `, tone, strong: true })
      if (typeof obj.logger === 'string') parts.push({ text: `${obj.logger}: `, tone: 'muted' })
      if (typeof obj.msg === 'string') {
        parts.push({ text: obj.msg, tone })
      } else {
        // Not a recognised record - show a trimmed preview rather than dumping
        // a whole nested object into the pane.
        const preview = trimmed.length > 400 ? `${trimmed.slice(0, 400)}…` : trimmed
        parts.push({ text: preview, tone })
      }
      return parts
    } catch {
      // malformed JSON - fall through to the generic path
    }
  }

  // Generic: dim any leading timestamp, leave the rest readable.
  const ts = TIMESTAMP.exec(line) ?? BRACKET_TIME.exec(line)
  if (ts && ts.index < 40) {
    return [
      { text: line.slice(0, ts.index), tone: 'muted' },
      { text: ts[0], tone: 'muted' },
      { text: line.slice(ts.index + ts[0].length), tone: 'default' },
    ]
  }

  return [{ text: line, tone: 'default' }]
}

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

/** Counts by severity, for the header strip. */
export function summarize(lines: string[]): Record<Tone, number> {
  const counts: Record<Tone, number> = {
    default: 0, accent: 0, success: 0, warning: 0, danger: 0, muted: 0,
  }
  for (const line of lines) {
    const first = colorize(line)[0]
    if (first) counts[first.tone] += 1
  }
  return counts
}

export function renderPieces(line: string): ReactNode {
  return colorize(line).map((p, i) => (
    <span key={i} className={`${TONE_CLASS[p.tone]} ${p.strong ? 'font-semibold' : ''}`}>
      {p.text}
    </span>
  ))
}

export { TONE_CLASS }