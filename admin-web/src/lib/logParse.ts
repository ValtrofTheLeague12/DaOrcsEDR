// Parsing for every log shape this repo writes.
//
// Split out of logColor.tsx on purpose: this file has no JSX and no React, so
// it can be run under plain `node` and tested without a DOM. logColor.tsx
// re-exports all of it, so callers keep importing from the same place.
//
// The contract is one pass, one shape:
//
//   raw line ──▶ normalize ──▶ detect ──▶ ParsedLine
//                                            ├─ time / stamp
//                                            ├─ level / severity
//                                            ├─ source
//                                            ├─ location (build diagnostics)
//                                            ├─ message
//                                            └─ pieces (ANSI or colourised)
//
// Everything the Logs panel shows is derived from that record - the severity
// chips, the filters, the counts, the rails. Nothing re-reads the raw line with
// its own regex, which is how the previous version ended up with a header that
// said "12 errors" above a filter that found 3.
//
// The shapes, sampled from this repo rather than invented:
//
//   banner    === 2026-10-12 15:49:26 $ ssh ... (cwd=...)     [dim]
//   levelled 2026-10-13 14:16:37 ERROR   ml.serve: [*] ...    [level coloured]
//   jsonl    {"ts":...,"level":"error","msg":"..."}           [level coloured]
//   vbox     00:01:29.919425 E1000#0: Interrupts skipped: 18  [elapsed, subsystem]
//   access   100.95.199.25 - - [09/Oct/2026 13:33:44] "GET /x" 200 -
//   build    foo.cpp(12,5): error C2065: 'x': undeclared identifier
//            foo.cpp:12:5: error: 'x' was not declared
//            CMake Error at CMakeLists.txt:4 (cmake_minimum_required):
//            FAILED: [code=1] CMakeFiles/foo.dir/bar.cpp.obj
//
// Detection is ordered, and the order is the design:
//
//   1. ANSI    an escape byte at position 0 defeats every anchored pattern
//              below, so it is peeled off first and the process keeps its own
//              colours (the analyzer marks its own imported APIs red).
//   2. JSON    a structured record is never guessed at.
//   3. access  Flask lines: the status code is the only field worth reading.
//   4. build   ahead of levelled, or a gcc `error:` becomes a generic levelled
//              line and loses the file:line that makes it actionable.
//   5. vbox    prefix-anchored on an elapsed clock; cannot collide with a date.
//   6. level   timestamped plain text.
//   7. banner / plain.
//
// A line that matches nothing is never dropped: it comes back as `plain` with
// its colourised pieces. A viewer that hides what it does not understand is
// worse than one that shows it plainly.

export type Tone = 'default' | 'accent' | 'success' | 'warning' | 'danger' | 'muted'

/**
 * Normalised severity. The raw level word stays on the record (`level`), but
 * everything that counts or filters uses this, so `ERR`, `fatal` and `panic`
 * are one bucket instead of three near-duplicates.
 */
export type Severity = 'error' | 'warning' | 'info' | 'debug'

export const TONE_CLASS: Record<Tone, string> = {
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

export const LEVEL_SEVERITY: Record<string, Severity> = {
  error: 'error',
  err: 'error',
  fatal: 'error',
  critical: 'error',
  crit: 'error',
  panic: 'error',
  warn: 'warning',
  warning: 'warning',
  notice: 'warning',
  info: 'info',
  information: 'info',
  debug: 'debug',
  trace: 'debug',
  verbose: 'debug',
}

const SEVERITY_TONE: Record<Severity, Tone> = {
  error: 'danger',
  warning: 'warning',
  info: 'accent',
  debug: 'muted',
}

// --- patterns ----------------------------------------------------------------

const TIMESTAMP = /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?/
const BRACKET_TIME = /\[\d{2}\/\w{3}\/\d{4}(?::\d{2}:\d{2}:\d{2}(?:\s[+-]\d{4})?)?\]/
const BRACKET_TIME_PARTS = /^\[(\d{2})\/(\w{3})\/(\d{4})(?::(\d{2}):(\d{2}):(\d{2}))?/
const LEVEL_WORD = /\b(TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|FATAL|CRITICAL|CRIT|PANIC)\b/
const HTTP_LINE = /^(\S+)\s+(\S+)\s+(\S+)\s+(\[[^\]]+\])\s+"([A-Z]+)\s+([^"]+)"\s+(\d{3})\b/
const BANNER = /^===\s+\d{4}-\d{2}-\d{2}/
// "logger.name:" or "[logger.name]:" at the head of a levelled line.
const LOGGER = /^\[?([A-Za-z_][\w.]*)\]?:\s*/

// A level word is only a level when it is near the head of the line. Without
// this bound, a message that mentions "ERROR" in passing becomes an error line
// and the count lies. 48 characters clears every real prefix this repo writes
// (an ISO stamp plus a pid plus brackets).
const LEVEL_WINDOW = 48

// --- build output ------------------------------------------------------------
//
// cmake + ninja + cl + g++, which is what build.ps1 and the EagleVM tree drive.
// A compile log is the one place where the line that matters is visually the
// least interesting: the useful line is `FAILED:`, a diagnostic, or
// `-- Build files have been written to`, buried among thousands of
// `Building CXX object` lines that all look the same.
//
// MSVC is first because it is the toolchain this repo actually builds with:
//
//   hello.c(1): fatal error C1083: cannot open include file: 'stdio.h'
//   foo.cpp(12,5): error C2065: 'x': undeclared identifier
//   LINK : fatal error LNK1104: cannot open file 'kernel32.lib'
//
// Note the file(line,col) shape - a GCC-only parser reads every one of those as
// an unremarkable plain line, which is exactly how a wall of MSVC errors looks
// like a successful build.
const MSVC_DIAG =
  /^(.*?)\((\d+)(?:,(\d+))?\)\s*:\s*(fatal error|error|warning|note)\s*([A-Z]+\d+)?\s*:?\s*(.*)$/i
const GCC_DIAG = /^(.+?):(\d+)(?::(\d+))?:\s*(fatal error|error|warning|note)\s*:\s*(.*)$/i
const LINK_DIAG =
  /^(?:LINK|link|MSBUILD|MSBuild)\s*:\s*(fatal error|error|warning)\s+((?:LNK|MSB)\d+)\s*:?\s*(.*)$/i
const LINK_BARE = /^(fatal error|error|warning)\s+(LNK\d+)\s*:\s*(.*)$/i

const CMAKE_ERROR_AT = /^CMake (?:Error|Error \(dev\)) at (.+?):(\d+)(?: \(([^)]+)\))?:/i
const CMAKE_WARNING_AT =
  /^CMake (?:Deprecation )?Warning(?: \([^)]*\))? at (.+?):(\d+)(?: \(([^)]+)\))?:/i
const CMAKE_ERROR = /^CMake (?:Error|Error \(dev\))/i
const CMAKE_WARNING = /^CMake (?:Deprecation )?Warning/i
const CMAKE_OK = /^--\s+(?:Configuring done|Generating done|Build files have been written to)/
const CMAKE_STAGE =
  /^--\s+(?:The\s+\S+|Detecting|Check for|Performing|Found|Could NOT find|Configuring incomplete)/
const NINJA_FAILED = /^FAILED:\s*(?:\[code=(\d+)\]\s*)?(.*)$/i
const NINJA_STOP = /^ninja: build stopped/i
const MAKE_PROGRESS = /^\[\s*\d+%\]\s/
const MAKE_BUILT = /^\[\s*\d+%\]\s+Built target\s+(\S+)/
const MAKE_LINK = /^\[\s*\d+%\]\s+Linking\s+/
const MAKE_ERROR = /^make(?:\[\d+\])?: \*\*\* .*\bError \d+/i
const BUILD_COMMAND = /^>\s/

// Python failures. This panel runs plenty of Python, and a traceback is a
// failure whose header line carries no level word at all.
const PY_TRACEBACK = /^Traceback \(most recent call last\):/
const PY_EXCEPTION = /^[A-Za-z_][\w.]*(?:Error|Exception|Exit|Interrupt)\s*:\s/

// --- setup-script markers ----------------------------------------------------
//
// The qiling setup scripts (and several of this repo's own helpers) prefix
// every line with a bracketed marker instead of a level word:
//
//   [+] loaded rpcrt4.dll
//   [=] loading version.dll ...
//   [!] failed to resolve api-ms-win-…  (common, non-fatal)
//   [x] could not find DLL file:
//
// The server strips the SGR colour before the browser sees it, so all that is
// left is the marker - and without this branch a 65 KB qiling log parsed as 300
// undifferentiated plain rows with an empty level column.
const MARKER_LINE = /^\[([=!+\-xX])\]\s*(.*)$/

// --- VirtualBox runtime log --------------------------------------------------
//
//   00:01:29.919425 E1000#0: Interrupts skipped: 18
//   └── elapsed ──┘└ component ┘└── message ──────┘
//
// The clock is ELAPSED time since the process started, not a wall clock. It
// says nothing about when anything happened in the world, only how far into
// this run you are - so it is shown as-is rather than relabelled as a time.
//
// The component charset is not [A-Za-z]. VirtualBox names subsystems E1000#0,
// VMM#0 and HM#0, so '#' has to be in the class or the most common lines in the
// log do not match.
const VBOX_TIME = /^(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+/
const VBOX_LINE =
  /^(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+([A-Za-z][\w.#]*(?:\/[A-Za-z][\w.#]*)?):\s?(.*)$/
const VBOX_STATE = /Changing the VM state from '([^']+)' to '([^']+)'/
const VBOX_FAILED_STATES = new Set(['aborted', 'baddimage', 'unavailable', 'unreachable'])

// A VERR_ result code is not automatically a fault: a clean Close emits
// VERR_OBJECT_DESTROYED on the way down, so colouring every code red trains the
// eye to ignore red. A code is a warning; prose that names a failure outright
// is the thing worth interrupting someone for.
const VBOX_CODE = /\bVERR_[A-Z0-9_]+/
const VBOX_FAIL = /\b(Error|Failed|Failure|Aborted|Aborting)\b/i
const VBOX_WARN = /\b(Warn|Warning)\b/i

// --- ANSI --------------------------------------------------------------------
//
// Roughly 80% of a build log arrives already coloured. build.ps1 runs the freshly
// linked analyzer on itself as a smoke test, and that analyzer annotates its own
// imports - a red "*" on VirtualProtect means "this is the injection API", which
// is precisely the kind of signal worth seeing. Those colours are SGR escape
// sequences written to the pipe, so they arrive as literal bytes and render as
// control junk unless something interprets them.
//
// One pattern for every sequence a log can carry, not just SGR. A compiler
// forced to colourise a pipe emits `ESC[K` after its colour runs, and a wrapper
// may emit an OSC title or a two-byte escape. Matching only `ESC[...m` leaves
// the rest in the text as an invisible byte followed by a visible `[K` or
// `]0;...`, which is exactly what "the log shows raw escape junk" looks like.
const ANSI_PATTERN =
  // SGR: the only form whose parameters carry colour.
  '\u001b\\[([0-9;]*)m' +
  // Any other CSI: cursor movement, erase-line, bracketed paste, ...
  '|\u001b\\[[0-9;?]*[ -/]*[@-~]' +
  // OSC, terminated by BEL or ST. Unterminated ones claim the rest of the line.
  '|\u001b\\][^\u0007\u001b]*(?:\u0007|\u001b\\\\)' +
  '|\u001b\\][^\u0007\u001b]*$' +
  // C1 CSI, the single-byte form of the same introducer.
  '|\u009b[0-9;?]*[ -/]*[@-~]' +
  // Two-byte escapes with an intermediate: charset selection ESC ( B, ESC # 8.
  '|\u001b[ -/][0-9A-Za-z]?' +
  // Two-byte escapes: keypad modes, save/restore, ...
  '|\u001b[@-_]'

const ANSI_TEST = new RegExp(ANSI_PATTERN)

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
  '39': 'default',
  '90': 'muted',
  '91': 'danger',
  '92': 'success',
  '93': 'warning',
  '94': 'accent',
  '95': 'accent',
  '96': 'accent',
  '97': 'default',
}

/** Nearest tone for an xterm 256-colour index. */
function tone256(n: number): Tone {
  if (n < 8) return ANSI_TONE[String(30 + n)] ?? 'default'
  if (n < 16) return ANSI_TONE[String(82 + n)] ?? 'default'
  if (n >= 232) {
    // 232..255 is a 24-step grey ramp; the dark end is the "dim" tone the
    // palette uses for timestamps and plumbing.
    return 8 + (n - 232) * 10 < 96 ? 'muted' : 'default'
  }
  const cube = n - 16
  const level = (v: number) => (v === 0 ? 0 : 55 + v * 40)
  return toneRgb(level(Math.floor(cube / 36)),
                 level(Math.floor((cube % 36) / 6)),
                 level(cube % 6))
}

/** Nearest tone for a truecolour triple. */
function toneRgb(r: number, g: number, b: number): Tone {
  const max = Math.max(r, g, b)
  const min = Math.min(r, g, b)
  if (max - min < 30) return max < 90 ? 'muted' : 'default'
  const d = max - min
  let hue = max === r ? ((g - b) / d) % 6
    : max === g ? (b - r) / d + 2
      : (r - g) / d + 4
  hue = (hue * 60 + 360) % 360
  if (hue < 20 || hue >= 330) return 'danger'
  if (hue < 75) return 'warning'
  if (hue < 165) return 'success'
  return 'accent'
}

/**
 * Apply one SGR parameter list, in order, to a tone.
 *
 * Parameters are processed left to right rather than "last one wins": a
 * compiler writes `ESC[1;31m` and `ESC[31;1m` for the same red, and reading
 * only the final parameter makes the second one colourless. Extended colours
 * (`38;5;n`, `38;2;r;g;b`) are consumed whole so their numbers are not mistaken
 * for intensity or background codes.
 */
function applySgr(params: string, tone: Tone): Tone {
  const codes = params === '' ? ['0'] : params.split(';')
  for (let i = 0; i < codes.length; i += 1) {
    const code = codes[i] || '0'
    if (code === '38' || code === '48') {
      const kind = codes[i + 1]
      if (kind === '5') {
        const n = Number(codes[i + 2])
        if (code === '38' && Number.isFinite(n)) tone = tone256(n)
        i += 2
      } else if (kind === '2') {
        const r = Number(codes[i + 2])
        const g = Number(codes[i + 3])
        const b = Number(codes[i + 4])
        if (code === '38' && [r, g, b].every(Number.isFinite)) tone = toneRgb(r, g, b)
        i += 4
      }
      continue
    }
    const mapped = ANSI_TONE[code]
    if (mapped) tone = mapped
    else if (code === '0') tone = 'default'
    // Everything else (1 bold, 2 dim, 3 italic, 4 underline, 22 normal
    // intensity, background colours) changes emphasis or the cell, not the
    // foreground colour this viewer paints.
  }
  return tone
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
  return ANSI_TEST.test(line)
}

/** Strip every escape sequence, for the plain-text message. */
export function stripAnsi(line: string): string {
  return line.replace(new RegExp(ANSI_PATTERN, 'g'), '')
}

export interface Piece {
  text: string
  tone: Tone
  strong?: boolean
}

/** Split a line into tone-coloured pieces, honouring SGR state changes. */
export function ansiPieces(line: string): Piece[] {
  const pieces: Piece[] = []
  let tone: Tone = 'default'
  let last = 0
  const re = new RegExp(ANSI_PATTERN, 'g')
  for (let m = re.exec(line); m; m = re.exec(line)) {
    if (m.index > last) {
      pieces.push({ text: line.slice(last, m.index), tone })
    }
    // Only the SGR alternative captures parameters; every other sequence is
    // consumed silently, which is what keeps erase-line and OSC bytes out of
    // the rendered text.
    if (m[1] !== undefined) tone = applySgr(m[1], tone)
    last = m.index + m[0].length
  }
  if (last < line.length) pieces.push({ text: line.slice(last), tone })
  return pieces
}

// --- shared helpers ----------------------------------------------------------

export type LogShape = 'levelled' | 'access' | 'jsonl' | 'banner' | 'vbox' | 'build' | 'marker' | 'plain'

export interface SourceLocation {
  file: string
  line: number
  column: number | null
}

export interface ParsedLine {
  shape: LogShape
  /** Clock time only, for the gutter column. Null when the line has no time. */
  time: string | null
  /** Full date-time when there is one, shown on hover. */
  stamp: string | null
  /** Lower-case level word as written, or null. */
  level: string | null
  /** Normalised bucket for counting and filtering, or null. */
  severity: Severity | null
  tone: Tone
  /** Logger / module / client / source file, whichever the shape exposes. */
  source: string | null
  /** Everything that is not time, level or source. */
  message: string
  /** Rendered with colorize() when the shape has no better rendering. */
  pieces?: Piece[]
  /** True when this line should stand out even without a level word. */
  notable: boolean
  /** file:line:col for a compiler diagnostic. */
  location: SourceLocation | null
  /** Compiler, linker or HTTP code the line carries (C1083, LNK2019, 404). */
  code: string | null
  /** True when this line belongs to the block opened by `owner`. */
  continuation?: boolean
  /** Index of the line this one continues. */
  owner?: number
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

/** The level word near the head of the line, with its position. */
function levelHit(line: string): { word: string; index: number; length: number } | null {
  const head = line.slice(0, LEVEL_WINDOW)
  const m = LEVEL_WORD.exec(head)
  return m ? { word: m[1].toLowerCase(), index: m.index, length: m[0].length } : null
}

/** Severity of one line, or null when the line does not declare one. */
export function levelOf(line: string): string | null {
  return levelHit(line)?.word ?? null
}

function basename(file: string): string {
  const at = Math.max(file.lastIndexOf('/'), file.lastIndexOf('\\'))
  return at >= 0 ? file.slice(at + 1) : file
}

function statusTone(code: string): Tone {
  const n = Number(code)
  if (!Number.isFinite(n)) return 'muted'
  if (n < 300) return 'success'
  if (n < 400) return 'accent'
  if (n < 500) return 'warning'
  return 'danger'
}

function statusSeverity(code: string): Severity | null {
  const n = Number(code)
  if (!Number.isFinite(n) || n < 400) return null
  return n < 500 ? 'warning' : 'error'
}

// --- colouriser (plain fallback) ---------------------------------------------

/** Break one raw line into coloured pieces, for shapes with no better render. */
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
  const lvl = levelHit(line)
  if (lvl) {
    const tone = LEVEL_TONE[lvl.word] ?? 'default'
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
    pieces.push({ text: line.slice(at, at + lvl.length), tone, strong: true })
    pieces.push({ text: line.slice(at + lvl.length), tone })
    return pieces
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

// --- detectors ---------------------------------------------------------------

function parseJson(trimmed: string): ParsedLine | null {
  if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) return null
  let obj: Record<string, unknown>
  try {
    obj = JSON.parse(trimmed) as Record<string, unknown>
  } catch {
    // malformed JSON - fall through to the other shapes
    return null
  }
  const level = String(obj.level ?? obj.severity ?? obj.status ?? '').toLowerCase()
  const ts = typeof obj.ts === 'string' ? obj.ts
    : typeof obj.time === 'string' ? obj.time
      : typeof obj.timestamp === 'string' ? obj.timestamp : null
  const t = ts ? isoTime(ts) ?? { stamp: ts, clock: ts.slice(11, 19) } : null
  const severity = LEVEL_SEVERITY[level] ?? null
  return {
    shape: 'jsonl',
    time: t?.clock ?? null,
    stamp: t?.stamp ?? null,
    level: level || null,
    severity,
    tone: severity ? SEVERITY_TONE[severity] : 'default',
    source: typeof obj.logger === 'string' ? obj.logger : null,
    message: typeof obj.msg === 'string' ? obj.msg
      : typeof obj.message === 'string' ? obj.message
        : trimmed.slice(0, 400),
    notable: severity === 'error' || severity === 'warning',
    location: null,
    code: null,
  }
}

function parseAccess(line: string): ParsedLine | null {  const http = HTTP_LINE.exec(line)
  if (!http) return null
  const [, ip, , , , method, path, code] = http
  const t = bracketTime(line)
  return {
    shape: 'access',
    time: t?.clock ?? null,
    stamp: t?.stamp ?? null,
    level: null,
    severity: statusSeverity(code),
    tone: statusTone(code),
    source: ip,
    message: `${method} ${path}`,
    notable: Number(code) >= 400,
    location: null,
    code,
  }
}

/**
 * Setup-script marker line. The marker IS the severity: `[x]` failed, `[!]`
 * warned, `[+]` succeeded, `[=]` is progress, `[-]` is plumbing.
 */
function parseMarker(line: string): ParsedLine | null {
  const m = MARKER_LINE.exec(line)
  if (!m) return null
  const key = m[1].toLowerCase()
  const severity: Severity | null = key === 'x' ? 'error' : key === '!' ? 'warning' : null
  const tone: Tone = key === 'x' ? 'danger'
    : key === '!' ? 'warning'
      : key === '+' ? 'success'
        : key === '=' ? 'accent'
          : 'muted'
  return {
    shape: 'marker',
    time: null,
    stamp: null,
    level: severity,
    severity,
    tone,
    source: null,
    message: m[2],
    notable: severity !== null,
    location: null,
    code: null,
  }
}

/** One compiler/linker diagnostic: file, line, column, level, code, message. */
function diagnostic(
  file: string, line: string, column: string | undefined,
  levelWord: string, code: string | undefined, message: string,
): ParsedLine {
  const word = levelWord.toLowerCase()
  // "fatal error" is one diagnostic level, not a level called "fatal" followed
  // by the word error. Looking it up whole missed the map and made the worst
  // MSVC diagnostic (`fatal error C1083`) count as no severity at all.
  const severity = word === 'note'
    ? null
    : (LEVEL_SEVERITY[word] ?? LEVEL_SEVERITY[word.replace(/^fatal /, '')] ?? null)
  const lineNo = Number(line)
  return {
    shape: 'build',
    time: null,
    stamp: `${file}:${line}`,
    level: word,
    severity,
    tone: severity ? SEVERITY_TONE[severity] : 'muted',
    source: basename(file),
    message: code ? `${code}: ${message}` : message,
    notable: severity === 'error' || severity === 'warning',
    location: { file, line: lineNo, column: column ? Number(column) : null },
    code: code ?? null,
  }
}

function parseBuild(line: string): ParsedLine | null {
  const msvc = MSVC_DIAG.exec(line)
  if (msvc) {
    const [, file, at, col, word, code, msg] = msvc
    return diagnostic(file, at, col, word, code, msg)
  }
  const gcc = GCC_DIAG.exec(line)
  if (gcc) {
    const [, file, at, col, word, msg] = gcc
    return diagnostic(file, at, col, word, undefined, msg)
  }
  const link = LINK_DIAG.exec(line) ?? LINK_BARE.exec(line)
  if (link) {
    const [, word, code, msg] = link
    const severity = LEVEL_SEVERITY[word.toLowerCase()]
      ?? LEVEL_SEVERITY[word.toLowerCase().replace(/^fatal /, '')]
      ?? null
    return {
      shape: 'build', time: null, stamp: null, level: word.toLowerCase(), severity,
      tone: severity ? SEVERITY_TONE[severity] : 'muted',
      source: 'link', message: `${code}: ${msg}`, notable: severity !== null,
      location: null, code,
    }
  }

  const cmakeError = CMAKE_ERROR_AT.exec(line)
  const cmakeWarning = cmakeError ? null : CMAKE_WARNING_AT.exec(line)
  if (cmakeError || cmakeWarning) {
    const m = (cmakeError ?? cmakeWarning)!
    const [, file, at, command] = m
    const severity: Severity = cmakeError ? 'error' : 'warning'
    return {
      shape: 'build', time: null, stamp: `${file}:${at}`, level: severity, severity,
      tone: SEVERITY_TONE[severity], source: basename(file),
      message: command ? `${command}(): ${line.slice(m[0].length).trim()}` : line.slice(m[0].length).trim(),
      notable: true,
      location: { file, line: Number(at), column: null },
      code: null,
    }
  }

  const simple = (
    severity: Severity | null, tone: Tone, notable: boolean, message = line,
    code: string | null = null,
  ): ParsedLine => ({
    shape: 'build', time: null, stamp: null, level: severity, severity, tone,
    source: null, message, notable, location: null, code,
  })

  if (CMAKE_ERROR.test(line)) return simple('error', 'danger', true)
  if (CMAKE_WARNING.test(line)) return simple('warning', 'warning', true)
  if (MAKE_ERROR.test(line)) return simple('error', 'danger', true)

  const failed = NINJA_FAILED.exec(line)
  if (failed) {
    const [, code, rest] = failed
    return simple('error', 'danger', true, rest || line, code ?? null)
  }
  if (NINJA_STOP.test(line)) return simple('error', 'danger', true)

  if (PY_TRACEBACK.test(line)) return simple('error', 'danger', true)
  if (PY_EXCEPTION.test(line)) return simple('error', 'danger', true)

  if (CMAKE_OK.test(line) || MAKE_BUILT.test(line)) {
    return simple(null, 'success', true)
  }
  if (MAKE_LINK.test(line)) return simple(null, 'accent', false)
  if (BUILD_COMMAND.test(line) || CMAKE_STAGE.test(line)) {
    return simple(null, 'accent', false)
  }
  if (MAKE_PROGRESS.test(line)) return simple(null, 'muted', false)
  return null
}

function parseVbox(line: string): ParsedLine | null {
  const vbTime = VBOX_TIME.exec(line)
  if (!vbTime) return null
  const elapsed = vbTime[1]

  // "Changing the VM state from 'POWERING' to 'RUNNING'" carries no component
  // but is the one line that answers "did this machine actually come up, or
  // fall over".
  const state = VBOX_STATE.exec(line)
  if (state) {
    const target = state[2].toUpperCase()
    const failed = VBOX_FAILED_STATES.has(target.toLowerCase())
    return {
      shape: 'vbox', time: elapsed, stamp: null, level: null,
      severity: failed ? 'error' : 'info',
      tone: failed ? 'danger' : 'accent', source: null,
      message: line.slice(vbTime[0].length), notable: true,
      location: null, code: null,
    }
  }

  const vb = VBOX_LINE.exec(line)
  // A level word is never a subsystem name. "14:16:37 WARNING: boot slow"
  // would otherwise be read as a VirtualBox component called WARNING and lose
  // its severity entirely.
  if (!vb || vb[2].toLowerCase() in LEVEL_TONE) return null

  const [, , component, rest] = vb
  const severity: Severity | null = VBOX_FAIL.test(rest) ? 'error'
    : VBOX_CODE.test(rest) || VBOX_WARN.test(rest) ? 'warning'
      : null
  return {
    shape: 'vbox', time: elapsed, stamp: null, level: null, severity,
    tone: severity ? SEVERITY_TONE[severity] : 'default',
    source: component, message: rest,
    notable: severity !== null, location: null, code: null,
  }
}

function parseLevelled(line: string): ParsedLine | null {
  const hit = levelHit(line)
  if (!hit) return null
  const severity = LEVEL_SEVERITY[hit.word] ?? null
  const t = isoTime(line) ?? bracketTime(line)

  let rest = line.slice(hit.index + hit.length)
  if (t) {
    const at = line.indexOf(t.stamp)
    // Only when the stamp sits AFTER the level ("ERROR 2026-… msg"). The usual
    // shape is stamp first, level second, and slicing from the stamp there put
    // the level back into the message and blanked the logger column - which is
    // why every line of the real ml_serve log had no source.
    if (at > hit.index) rest = line.slice(at + t.stamp.length)
  }
  rest = rest.replace(/^[\s:,\-|]+/, '')

  // "logger.name:" or "[logger.name]:" - and the slice uses the WHOLE match, so
  // the bracket and the colon go with it instead of being left on the message.
  const lm = LOGGER.exec(rest)
  const source = lm?.[1] ?? null
  const message = lm ? rest.slice(lm[0].length) : rest

  return {
    shape: 'levelled',
    time: t?.clock ?? null,
    stamp: t?.stamp ?? null,
    level: hit.word,
    severity,
    tone: severity ? SEVERITY_TONE[severity] : 'default',
    source,
    message,
    notable: severity === 'error' || severity === 'warning',
    location: null,
    code: null,
  }
}

/** Split one raw line into the fields worth giving their own column. */
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
      // Red means the process called it red; that is a claim about severity,
      // but a line-level one, so it counts once and never inflates a block.
      severity: tone === 'danger' ? 'error' : tone === 'warning' ? 'warning' : null,
      tone,
      source: null,
      message: stripAnsi(line),
      pieces,
      // Danger and warning only. Unlike the cmake population below, where
      // green means "the build worked", the analyzer uses green for ordinary
      // output - counting those as notable would put the counter in the
      // hundreds and make it worthless as a signal.
      notable: tone === 'danger' || tone === 'warning',
      location: null,
      code: null,
    }
  }

  const trimmed = line.trimStart()
  const json = parseJson(trimmed)
  if (json) return json

  const access = parseAccess(line)
  if (access) return access

  // Ahead of the build branch: a setup script's `[!]` line is a warning even
  // when it happens to be running the compiler.
  const marker = parseMarker(line)
  if (marker) return marker

  // Ahead of the levelled branch and deliberately ahead of VirtualBox: a gcc
  // `error:` line would otherwise be caught by the level word and rendered as a
  // levelled log line, which loses the file:line that makes it actionable.
  const build = parseBuild(line)
  if (build) return build

  const vbox = parseVbox(line)
  if (vbox) return vbox

  const levelled = parseLevelled(line)
  if (levelled) return levelled

  if (BANNER.test(line)) {
    return {
      shape: 'banner', time: null, stamp: null, level: null, severity: null,
      tone: 'muted', source: null, message: line.replace(/^===\s*/, ''),
      notable: false, location: null, code: null,
    }
  }

  const t = isoTime(line) ?? bracketTime(line)
  return {
    shape: 'plain',
    time: t?.clock ?? null,
    stamp: t?.stamp ?? null,
    level: null,
    severity: null,
    tone: 'default',
    source: null,
    message: line,
    pieces: colorize(line),
    notable: false,
    location: null,
    code: null,
  }
}

// --- blocks ------------------------------------------------------------------
//
// A failure is rarely one line. A Python traceback, an MSVC `note:` and the
// indented command ninja echoes under FAILED: all belong to the line above
// them. Marking them as continuations keeps them visually attached and - more
// importantly - keeps the severity counts honest: one error stays one error
// whether it took one line or twelve.

const STACK_FRAME = /^\s+(?:at\s|File\s+"|#\d+\s|0x[0-9a-f]{4,}\b|\^{2,}\s*$)/
const INDENTED = /^[ \t]{2,}\S/

function isContinuation(raw: string, p: ParsedLine, prev: ParsedLine | undefined): boolean {
  if (!prev || raw.trim() === '') return false
  // A compiler `note:` always explains the diagnostic above it.
  if (p.shape === 'build' && p.level === 'note') return true
  // The last line of a traceback ("ValueError: bad") is the one that names the
  // failure, but it belongs to the traceback above it: counting it separately
  // turned one crash into two errors. It is attached when the line above is a
  // frame, or when it directly follows the traceback header.
  if (PY_EXCEPTION.test(raw) && (prev.continuation === true || PY_TRACEBACK.test(prev.message))) {
    return true
  }
  // A traceback is the elaboration of the failure logged on the line above it,
  // not a second failure. Standalone (nothing notable above) it keeps its own
  // severity, because then it is the only evidence there is.
  if (PY_TRACEBACK.test(raw) && prev.notable) return true
  if (STACK_FRAME.test(raw)) return true
  return INDENTED.test(raw) && (prev.notable || prev.continuation === true)
}

/**
 * Parse a whole window at once, attaching continuations and deriving the
 * numbers the header shows. One call per tail, not one per row per render.
 */
export function parseLines(lines: string[]): ParsedLine[] {
  const out = lines.map(parseLine)
  let owner: number | null = null

  for (let i = 0; i < out.length; i += 1) {
    const p = out[i]
    if (isContinuation(lines[i], p, out[i - 1])) {
      const parent = owner ?? i - 1
      p.continuation = true
      p.owner = parent
      // The block inherits the colour of the line that opened it, but not its
      // severity: the error was counted once, at the top. Clearing severity
      // (not just `notable`) is what keeps statsOf honest - the closing
      // "ValueError: bad" of a traceback still arrives with severity error, and
      // leaving it set made one crash count as two.
      if (!p.severity) p.tone = out[parent]?.tone ?? 'muted'
      p.severity = null
      p.notable = false
      continue
    }
    owner = p.notable ? i : null
  }
  return out
}

export interface LogStats {
  total: number
  counts: Record<Severity, number>
  notable: number
  sources: { name: string; count: number }[]
  /** Line counts per minute, when the lines carry a wall-clock stamp. */
  buckets: { key: string; count: number }[]
  firstError: number | null
}

/** Counts by severity, sources and volume, from the SAME parse that renders. */
export function statsOf(rows: ParsedLine[]): LogStats {
  const counts: Record<Severity, number> = { error: 0, warning: 0, info: 0, debug: 0 }
  const sources = new Map<string, number>()
  const minutes = new Map<string, number>()
  let notable = 0
  let firstError: number | null = null

  for (let i = 0; i < rows.length; i += 1) {
    const p = rows[i]
    if (p.severity) counts[p.severity] += 1
    if (p.notable) notable += 1
    if (p.severity === 'error' && firstError === null) firstError = i
    if (p.source) sources.set(p.source, (sources.get(p.source) ?? 0) + 1)
    // Only wall-clock stamps make a bucket. A VirtualBox elapsed clock says
    // nothing about when anything happened, and bucketing it would draw a
    // chart of the run's own duration as if it were a timeline.
    if (p.stamp && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(p.stamp)) {
      const key = p.stamp.slice(0, 16)
      minutes.set(key, (minutes.get(key) ?? 0) + 1)
    }
  }

  const buckets = [...minutes.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .slice(-48)
    .map(([key, count]) => ({ key, count }))

  return {
    total: rows.length,
    counts,
    notable,
    sources: [...sources.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([name, count]) => ({ name, count })),
    buckets,
    firstError,
  }
}

/** The text a row actually shows, for search and match counting. */
export function rowText(p: ParsedLine): string {
  return p.pieces ? p.pieces.map((piece) => piece.text).join('') : p.message
}
