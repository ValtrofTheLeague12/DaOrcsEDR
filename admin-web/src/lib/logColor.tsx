import type { ReactNode } from 'react'

// Colourises and STRUCTURES log lines by CONTENT, not by file extension.
//
// The first version of this viewer coloured a line and nothing else, which made
// a wall of undifferentiated monospace: the timestamp, the severity and the
// message all ran together at the same weight, so the only way to find the one
// error in two thousand lines was to read all two thousand. That is the reason
// the panel is being reworked.
//
// `parseLine` is the new entry point. It splits a raw line into the fields that
// are actually worth reading - when, how bad, who said it, what they said - and
// `LogRow` lays them out as columns. `colorize` stays for the pieces that
// refuse to parse, because a log viewer that drops an unrecognised line is
// worse than one that shows it plainly.
//
// Four real shapes come out of this repo (sampled, not assumed):
//
//   banner   === 2026-10-12 15:49:26 $ ssh ... (cwd=...)     [dim, monospace]
//   levelled 2026-10-13 14:16:37 ERROR   ml.serve: [*] ...    [level coloured]
//   jsonl    {"ts":...,"level":"error","msg":"..."}          [level coloured]
//   vbox     00:01:29.919425 E1000#0: Interrupts skipped: 18 [elapsed, subsystem]
//
// plus Flask access lines, whose status code is the only thing worth reading:
//
//   100.95.199.25 - - [09/Oct/2026 13:33:44] "GET /malapi/x" 200 -
//
// and the native analyzer trace, which is handled in the Trace tab rather than
// here because it is not a log at all.
//
// Everything maps onto HeroUI's own tokens (text-danger, text-warning,
// text-accent, text-muted), so the viewer restyles itself when the theme flips
// without knowing anything about them.

export type Tone = 'default' | 'accent' | 'success' | 'warning' | 'danger' | 'muted'

const TONE_CLASS: Record<Tone, string> = {
  default: 'text-foreground',
  accent: 'text-accent',
  success: 'text-success',
  warning: 'text-warning',
  danger: 'text-danger',
  muted: 'text-muted',
}

export const LEVEL_TONE: Record<string, Tone> = {
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
const BRACKET_TIME_PARTS = /^\[(\d{2})\/(\w{3})\/(\d{4})(?::(\d{2}):(\d{2}):(\d{2}))?/
const LEVEL_WORD = /\b(TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|FATAL|CRITICAL|CRIT|PANIC)\b/
const HTTP_LINE = /^(\S+)\s+(\S+)\s+(\S+)\s+(\[[^\]]+\])\s+"([A-Z]+)\s+([^"]+)"\s+(\d{3})\b/
const BANNER = /^===\s+\d{4}-\d{2}-\d{2}/
// "logger.name:" or "[logger.name]:" at the head of a levelled line.
const LOGGER = /^\[?([A-Za-z_][\w.]*)\]?:\s*/

// --- build output ------------------------------------------------------------
//
// cmake + make + g++, which is what build.ps1 drives. Worth its own shape
// because a compile log is the one place where the line that matters is
// visually the least interesting: the useful line is usually `FAILED:`, an
// `error:`, or the `-- Build files have been written to` line, buried among
// thousands of `Building CXX object` lines that all look the same.
//
// The severity ordering below is deliberate. `error:` and `FAILED:` are danger.
// `-- Configuring done` / `Built target` are success - the two lines that mean
// the build worked. A bare `[ 42%] Building` is muted, because a progress line
// is not news and colouring it would mean colouring 2000 lines.
// ---------------------------------------------------------------------------

const CMAKE_OK = /^--\s+(Configuring done|Generating done|Build files have been written to)/
const CMAKE_STAGE = /^--\s+(The\s+\S+|Detecting|Check for|Performing|Configuring incomplete)/
const CMAKE_ERROR = /^CMake\s+Error\b/i
const CMAKE_WARNING = /^CMake\s+Warning\b/i
const MAKE_PROGRESS = /^\[\s*\d+%\]\s/
const MAKE_BUILT = /^\[\s*\d+%\]\s+Built target\s+(\S+)/
const MAKE_LINK = /^\[\s*\d+%\]\s+Linking\s+/
const MAKE_FAILED = /^FAILED:/i
const BUILD_COMMAND = /^>\s/
const GCC_ERROR = /^([^:]+):(\d+):(\d+):\s*error:/
const GCC_WARNING = /^([^:]+):(\d+):(\d+):\s*warning:/

// Which line a compiler/CMake error names, so the reader can go straight there
// instead of counting through the log.
const LOC = /^(.+?):(\d+):(\d+):\s*(error|warning|note)/

function buildTone(line: string): { tone: Tone; notable: boolean } {
  if (CMAKE_ERROR.test(line) || MAKE_FAILED.test(line) || GCC_ERROR.test(line)) {
    return { tone: 'danger', notable: true }
  }
  if (CMAKE_WARNING.test(line) || GCC_WARNING.test(line)) {
    return { tone: 'warning', notable: true }
  }
  if (CMAKE_OK.test(line) || MAKE_BUILT.test(line)) {
    return { tone: 'success', notable: true }
  }
  if (MAKE_LINK.test(line)) return { tone: 'accent', notable: false }
  if (BUILD_COMMAND.test(line) || CMAKE_STAGE.test(line)) {
    return { tone: 'accent', notable: false }
  }
  if (MAKE_PROGRESS.test(line)) return { tone: 'muted', notable: false }
  if (/^\s*(?:ccache|CMake|Target|Rule)\b/.test(line)) {
    return { tone: 'muted', notable: false }
  }
  return { tone: 'default', notable: false }
}

// --- VirtualBox runtime log ------------------------------------------------
//
// A fourth shape, and the one the fleet view actually shows:
//
//   00:01:29.919425 E1000#0: Interrupts skipped: 18
//   └── elapsed ──┘└ component ┘└── message ──────┘
//
// The clock is ELAPSED time since the process started, not a wall clock. It
// says nothing about when anything happened in the world, only how far into
// this run you are - so it is shown as-is rather than relabelled as a time.
//
// Nothing else here matched it. No level word, no ISO date for TIMESTAMP, no
// [dd/Mon/yyyy] for BRACKET_TIME, so every line of a VM run log fell through to
// the generic path and came out the same undifferentiated grey - which is
// exactly the "wall of undifferentiated monospace" this module exists to end.
// Measured on a real 80-line run log: 80 of 80 lines carry this shape, and 0 of
// them were distinguishable by tone before it was parsed.
//
// The component charset is not [A-Za-z]. VirtualBox names subsystems E1000#0,
// VMM#0 and HM#0, so '#' has to be in the class or the most common lines in the
// log do not match.
const VBOX_TIME = /^(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+/
const VBOX_LINE =
  /^(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+([A-Za-z][\w.#]*(?:\/[A-Za-z][\w.#]*)?):\s?(.*)$/

// "Changing the VM state from 'POWERING' to 'RUNNING'" carries no component but
// is the one line that answers "did this machine actually come up, or fall
// over".
const VBOX_STATE = /Changing the VM state from '([^']+)' to '([^']+)'/

// States a machine can only reach by failing. Anything else is an ordinary
// transition and is not dressed up as a problem.
const VBOX_FAILED_STATES = new Set(['aborted', 'baddimage', 'unavailable', 'unreachable'])

// A VERR_ result code is not automatically a fault: a clean Close emits
// VERR_OBJECT_DESTROYED on the way down, so colouring every code red trains the
// eye to ignore red. A code is a warning; prose that names a failure outright
// is the thing worth interrupting someone for.
const VBOX_CODE = /\bVERR_[A-Z0-9_]+/
const VBOX_FAIL = /\b(Error|Failed|Failure|Aborted|Aborting)\b/i
const VBOX_WARN = /\b(Warn|Warning)\b/i

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

// --- ANSI --------------------------------------------------------------------
//
// Roughly 80% of a build log arrives already coloured. build.ps1 runs the freshly
// linked analyzer on itself as a smoke test, and that analyzer annotates its own
// imports - a red "*" on VirtualProtect means "this is the injection API", which
// is precisely the kind of signal worth seeing. Those colours are SGR escape
// sequences written to the pipe, so they arrive as literal bytes and render as
// control junk unless something interprets them.
//
// Interpreting them beats stripping them: the point of running the binary at the
// end of a build is that it has something to say, and what it says is mostly
// colour-coded.

/** Matches one SGR sequence, and any bare CSI that is not one. */
// eslint-disable-next-line no-control-regex
const ANSI_SGR = /\[([0-9;]*)m|\[[0-9;?]*[A-Za-z]/g

/** SGR parameter -> tone, for the codes the analyzer and cmake actually emit. */
const ANSI_TONE: Record<string, Tone> = {
  '30': 'muted',
  '31': 'danger',
  '32': 'success',
  '33': 'warning',
  '34': 'accent',
  '35': 'accent',
  '36': 'accent',
  '37': 'default',
  '90': 'muted',
  '91': 'danger',
  '92': 'success',
  '93': 'warning',
  '96': 'accent',
}

/** How loudly each tone counts when picking a single tone for the whole line. */
const TONE_RANK: Record<Tone, number> = {
  default: 0,
  muted: 1,
  accent: 2,
  success: 3,
  warning: 4,
  danger: 5,
}

export function hasAnsi(line: string): boolean {
  return new RegExp(ANSI_SGR.source).test(line)
}

/** Strip every escape sequence, for the plain-text message. */
export function stripAnsi(line: string): string {
  return line.replace(new RegExp(ANSI_SGR.source, 'g'), '')
}

/** Split a line into tone-coloured pieces, honouring SGR state changes. */
export function ansiPieces(line: string): Piece[] {
  const pieces: Piece[] = []
  let tone: Tone = 'default'
  let last = 0
  ANSI_SGR.lastIndex = 0
  for (let m = ANSI_SGR.exec(line); m; m = ANSI_SGR.exec(line)) {
    if (m.index > last) {
      pieces.push({ text: line.slice(last, m.index), tone })
    }
    // A bare CSI (cursor movement, erase) has no captured group and carries no
    // colour; everything else resets to default, and a bold run keeps the colour.
    if (m[1] !== undefined) {
      const code = m[1] === '' ? '0' : m[1].split(';').filter(Boolean).pop() ?? '0'
      if (code === '0') tone = 'default'
      else if (ANSI_TONE[code]) tone = ANSI_TONE[code]
    }
    last = m.index + m[0].length
  }
  if (last < line.length) pieces.push({ text: line.slice(last), tone })
  return pieces
}

/** Severity of one line, or null when the line does not declare one. */
export function levelOf(line: string): string | null {
  const hit = LEVEL_WORD.exec(line)
  return hit ? hit[1].toLowerCase() : null
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

// ---------------------------------------------------------------------------
// structured view
// ---------------------------------------------------------------------------

export type LogShape = 'levelled' | 'access' | 'jsonl' | 'banner' | 'vbox' | 'build' | 'plain'

export interface ParsedLine {
  shape: LogShape
  /** Clock time only, for the gutter column. Null when the line has no time. */
  time: string | null
  /** Full date-time when there is one, shown on hover. */
  stamp: string | null
  /** Lower-case level word, or null. */
  level: string | null
  tone: Tone
  /** Logger / module / client, whichever the shape exposes. */
  source: string | null
  /** Everything that is not time, level or source. */
  message: string
  /** Rendered with colorize() when the shape has no better rendering. */
  pieces?: Piece[]
  /** True when this line should stand out even without a level word. */
  notable: boolean
}

const MONTHS: Record<string, string> = {
  Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06',
  Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12',
}

function bracketTime(line: string): { stamp: string; clock: string } | null {
  const m = BRACKET_TIME_PARTS.exec(line)
  if (!m) return null
  const [, dd, mon, yyyy, hh, mm, ss] = m
  const clock = `${hh ?? '00'}:${mm ?? '00'}:${ss ?? '00'}`
  return { stamp: `${yyyy}-${MONTHS[mon] ?? mon}-${dd} ${clock}`, clock }
}

function isoTime(line: string): { stamp: string; clock: string } | null {
  const m = TIMESTAMP.exec(line)
  if (!m || m.index > 12) return null
  const stamp = m[0].replace('T', ' ').replace(',', '.')
  const clock = stamp.slice(11, 19) || stamp
  return { stamp, clock }
}

/** Split a raw line into the fields worth giving their own column. */
export function parseLine(rawLine: string): ParsedLine {
  // A trailing carriage return is dropped here rather than at every call site.
  //
  // It is not cosmetic: JavaScript's `.` does not match \r, so a line that kept
  // its CR fails every anchored regex in this file and falls through to the
  // generic path. The line that exposed this was exactly
  // "VBoxHeadless: exiting\r", which parsed as nothing at all. Windows tooling
  // writes CRLF, so this is a routine input rather than a corrupted file, and
  // three viewers feed this function with lines they split themselves.
  const line = rawLine.replace(/\r$/, '')
  const level = levelOf(line)

  // --- HTTP access ---
  const http = HTTP_LINE.exec(line)
  if (http) {
    const [, ip, , , , method, path, code] = http
    const t = bracketTime(line)
    return {
      shape: 'access',
      time: t?.clock ?? null,
      stamp: t?.stamp ?? null,
      level: null,
      tone: statusTone(code),
      source: ip,
      message: `${method} ${path}`,
      notable: Number(code) >= 400,
    }
  }

  // --- JSON / JSONL ---
  const trimmed = line.trimStart()
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      const obj = JSON.parse(trimmed) as Record<string, unknown>
      const lvl = String(obj.level ?? obj.severity ?? obj.status ?? '').toLowerCase()
      const ts = typeof obj.ts === 'string' ? obj.ts
        : typeof obj.time === 'string' ? obj.time
        : typeof obj.timestamp === 'string' ? obj.timestamp : null
      const t = ts ? isoTime(ts) ?? { stamp: ts, clock: ts.slice(11, 19) } : null
      return {
        shape: 'jsonl',
        time: t?.clock ?? null,
        stamp: t?.stamp ?? null,
        level: lvl || null,
        tone: LEVEL_TONE[lvl] ?? 'default',
        source: typeof obj.logger === 'string' ? obj.logger : null,
        message: typeof obj.msg === 'string' ? obj.msg
          : typeof obj.message === 'string' ? obj.message
          : trimmed.slice(0, 400),
        notable: !!lvl && LEVEL_TONE[lvl] !== 'muted' && LEVEL_TONE[lvl] !== 'accent',
      }
    } catch {
      // malformed JSON - fall through
    }
  }

  // --- build output ---
  //
  // ANSI first, before every pattern below. A line that arrives already
  // colour-coded is carrying meaning that none of these patterns would recover -
  // the analyzer marks its own imported APIs red when they are injection or
  // enumeration primitives - and an escape sequence at position 0 also defeats
  // every anchored regex here, so the line would fall through to 'plain' with
  // raw control bytes in it.
  if (hasAnsi(line)) {
    const pieces = ansiPieces(line)
    const loudest = pieces.reduce<Piece | null>(
      (best, p) => (!best || TONE_RANK[p.tone] > TONE_RANK[best.tone] ? p : best),
      null,
    )
    const tone = loudest?.tone ?? 'default'
    return {
      shape: 'build',
      time: null,
      stamp: null,
      level: null,
      tone,
      source: null,
      message: stripAnsi(line),
      pieces,
      // Danger and warning only. Unlike the cmake population above, where
      // green means "the build worked", the analyzer uses green for ordinary
      // output - counting those as notable would put the counter in the
      // hundreds and make it worthless as a signal.
      notable: tone === 'danger' || tone === 'warning',
    }
  }

  // The pattern branch, for output that carries no colour of its own. Ahead of
  // the levelled branch and deliberately ahead of the VirtualBox branch: a gcc
  // `error:` line would otherwise be caught by LEVEL_WORD and rendered as a
  // levelled log line, which loses the file:line that makes it actionable.
  if (CMAKE_ERROR.test(line) || MAKE_FAILED.test(line) || GCC_ERROR.test(line)
      || GCC_WARNING.test(line) || CMAKE_WARNING.test(line)
      || CMAKE_OK.test(line) || MAKE_BUILT.test(line) || MAKE_PROGRESS.test(line)
      || BUILD_COMMAND.test(line)) {
    const { tone, notable } = buildTone(line)
    const loc = LOC.exec(line)
    return {
      shape: 'build',
      time: null,
      stamp: loc ? `${loc[1]}:${loc[2]}` : null,
      level: null,
      tone,
      source: loc ? loc[1] : null,
      message: loc ? `${loc[2]}:${loc[3]}  ${line.slice(loc[0].length).trim()}` : line,
      notable,
    }
  }

  // --- VirtualBox runtime log ---
  //
  // Checked before the levelled branch because it is prefix-anchored and
  // unambiguous: a bare `\d{2}:\d{2}:\d{2}` followed by a token-and-colon cannot
  // collide with a dated line. A levelled line like "14:16:37 ERROR ml.serve:"
  // still falls through correctly, because ERROR is followed by a space rather
  // than the colon this shape requires.
  const vbTime = VBOX_TIME.exec(line)
  if (vbTime) {
    const elapsed = vbTime[1]
    const state = VBOX_STATE.exec(line)
    if (state) {
      const target = state[2].toUpperCase()
      const failed = VBOX_FAILED_STATES.has(target.toLowerCase())
      return {
        shape: 'vbox',
        time: elapsed,
        // Elapsed time is not a wall clock, so there is no honest full stamp to
        // offer on hover and the cell is left empty rather than faked.
        stamp: null,
        level: null,
        tone: failed ? 'danger' : 'accent',
        source: null,
        message: line.slice(vbTime[0].length),
        notable: true,
      }
    }
    const vb = VBOX_LINE.exec(line)
    // A level word is never a subsystem name. "14:16:37 WARNING: boot slow"
    // would otherwise be read as a VirtualBox component called WARNING and lose
    // its severity entirely.
    if (vb && !(vb[2].toLowerCase() in LEVEL_TONE)) {
      const [, , component, rest] = vb
      const tone: Tone = VBOX_FAIL.test(rest)
        ? 'danger'
        : VBOX_CODE.test(rest) || VBOX_WARN.test(rest)
          ? 'warning'
          : 'default'
      return {
        shape: 'vbox',
        time: elapsed,
        stamp: null,
        level: null,
        tone,
        source: component,
        message: rest,
        notable: tone !== 'default',
      }
    }
  }

  // --- levelled plain text ---
  if (level && LEVEL_WORD.exec(line)?.index !== undefined) {
    const hit = LEVEL_WORD.exec(line)
    const t = isoTime(line) ?? bracketTime(line)
    const tone = LEVEL_TONE[level] ?? 'default'
    let rest = hit ? line.slice(hit.index + hit[0].length) : line
    if (t) {
      const at = line.indexOf(t.stamp)
      if (at >= 0) rest = line.slice(at + t.stamp.length)
      rest = rest.replace(/^[\s:,\-]+/, '')
    }
    rest = rest.replace(LEVEL_WORD, '').replace(/^[\s:,\-]+/, '')
    const source = LOGGER.exec(rest)?.[1] ?? null
    const message = source ? rest.slice(source.length).replace(/^:\s*/, '') : rest
    return {
      shape: 'levelled',
      time: t?.clock ?? null,
      stamp: t?.stamp ?? null,
      level,
      tone,
      source,
      message,
      notable: tone === 'danger' || tone === 'warning',
    }
  }

  // --- admin terminal banner ---
  if (BANNER.test(line)) {
    return {
      shape: 'banner', time: null, stamp: null, level: null, tone: 'muted',
      source: null, message: line.replace(/^===\s*/, ''), notable: false,
    }
  }

  // --- anything else, rendered through the colouriser ---
  const t = isoTime(line) ?? bracketTime(line)
  return {
    shape: 'plain',
    time: t?.clock ?? null,
    stamp: t?.stamp ?? null,
    level: null,
    tone: 'default',
    source: null,
    message: line,
    pieces: colorize(line),
    notable: false,
  }
}

export function LogRow({
  line,
  number,
  wrap = true,
  query = '',
}: {
  line: string
  number: number
  wrap?: boolean
  /** Substring to emphasise. Case-insensitive; empty means no highlighting. */
  query?: string
}) {
  const parsed = parseLine(line)
  const needle = query.trim().toLowerCase()

  const highlight = (text: string) => {
    if (!needle) return text
    const at = text.toLowerCase().indexOf(needle)
    if (at < 0) return text
    return (
      <>
        {text.slice(0, at)}
        <mark className="log-view-hit">{text.slice(at, at + needle.length)}</mark>
        {text.slice(at + needle.length)}
      </>
    )
  }

  const body =
    parsed.shape === 'plain' && parsed.pieces ? (
      parsed.pieces.map((p, i) => (
        <span key={i} className={TONE_CLASS[p.tone]}>
          {highlight(p.text)}
        </span>
      ))
    ) : (
      <span className={parsed.shape === 'access' ? 'text-accent' : undefined}>
        {highlight(parsed.message)}
      </span>
    )

  return (
    <div
      className={`log-view-row ${parsed.notable ? 'is-notable' : ''} is-${parsed.tone}`}
      title={parsed.stamp ?? undefined}
    >
      <span className="log-view-gutter">{number}</span>
      <span className="log-view-time">{parsed.time ?? ''}</span>
      <span className="log-view-level">
        {parsed.level && (
          <span className={`log-view-badge is-${parsed.tone}`}>{parsed.level}</span>
        )}
        {parsed.shape === 'access' && (
          <span className={`log-view-badge is-${parsed.tone}`}>
            {HTTP_LINE.exec(line)?.[7]}
          </span>
        )}
      </span>
      {parsed.source && <span className="log-view-source">{parsed.source}</span>}
      <span
        className={`log-view-body ${wrap ? 'is-wrap' : 'is-nowrap'}`}
      >
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

/** Counts by severity, for the header strip. */
export function summarize(lines: string[]): Record<Tone, number> {
  const counts: Record<Tone, number> = {
    default: 0, accent: 0, success: 0, warning: 0, danger: 0, muted: 0,
  }
  // Via parseLine, not colorize. colorize() only knows the plain-text shapes,
  // so counting through it files every VirtualBox run-log line under `default`
  // and reports a healthy boot as an absence of problems - which is worse than
  // reporting nothing, because it looks like a measurement.
  for (const line of lines) counts[parseLine(line).tone] += 1
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