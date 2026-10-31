import { useCallback, useEffect, useMemo, useRef, useState, memo } from 'react'
import { Alert, Card, Chip } from '@heroui/react'
import { api } from '../api'
import Icon from '../components/Icon'
import Loading from '../components/Loading'
import SubNav from '../components/SubNav'
import Checkbox from '../components/Checkbox'
import GeneratorResources from '../components/GeneratorResources'
import { ago, bytes } from '../lib/format'
import { colorize, parseLine, stripAnsi, TONE_CLASS, type Tone } from '../lib/logColor'
import type {
  AnalyzerBuildJob,
  EagleState,
  MalapiState,
  SampleResourcesSnapshot,
  SbomState,
  UtilEntry,
  UtilsOverview,
  YaraState,
  YargenState,
} from '../types'

// ---------------------------------------------------------------------------
// Utils.
//
// Six things that can only be maintained by reading the source: the CycloneDX
// SBOM, the MalAPI rule checkout, the unpacked YARA rule packs, yarGen-Go's
// databases, the sample factory's value pools, and the in-tree EagleVM build.
//
// One card per utility, each with its own button, rather than one picker with
// five rows. The reason is that these are not variants of one operation - one
// rewrites two JSON files, one runs `git pull`, one compiles three thousand
// rules, one downloads 794 MB, one fetches value lists, one drives CMake - so
// the button belongs next to the state it acts on, where the cost is legible
// before it is paid.
//
// Every action declares what it touches, and the chips are shown before the
// button is pressed, not in a log afterwards.
// ---------------------------------------------------------------------------

type ChipColor = 'accent' | 'danger' | 'success' | 'warning' | undefined

// ---------------------------------------------------------------------------
// Sectioning.
//
// The page used to be a 2x2 card grid and two loose cards after it - four
// utilities that have nothing to do with each other except "they are
// maintenance jobs", plus results and output floating at the end. The grouping
// it answers with is the one the utilities' own work implies:
//
//   1. Detection content - YARA, MalAPI, yarGen-Go: what the analyzer READS at
//      scan time. Stale here means blind, not slow.
//   2. Software inventory - the SBOM: what this binary itself is made of.
//      Stale here is an audit problem, not a detection one.
//   3. Instruction virtualisation - the in-tree EagleVM the sample factory
//      calls. Not built means the factory's virtualisation option is refused,
//      so the build button belongs beside the gate it opens.
//   4. Generator resources - value pools the Build page's sample
//      factory samples from. They are bait literals, not rules, so they sit
//      apart from detection content rather than beside it.
//   5. Run log & results - what the buttons did, once pressed.
//
// It reuses the Build page's .build-section classes deliberately: the two
// panels are different jobs on the same machine, and identical sectioning
// means an operator's learned scan of one transfers to the other. The number
// chip carries the group's health colour, computed from exactly the booleans
// the cards below show as chips - a rail that disagrees with the cards on it
// would itself be the lie.
// ---------------------------------------------------------------------------

function Section({ n, title, hint, tone, children }: {
  n: number
  title: string
  hint: string
  tone: ChipColor
  children: React.ReactNode
}) {
  return (
    <section className="build-section">
      <header className="build-section-header">
        <span
          className={'build-section-n ' + (
            tone === 'danger' ? 'is-danger' : tone === 'warning' ? 'is-warning'
              : tone === 'success' ? 'is-success' : '')}
          aria-hidden="true"
        >
          {n}
        </span>
        <div className="min-w-0 flex-1">
          <h2 className="build-section-title">{title}</h2>
          <p className="build-section-hint">{hint}</p>
        </div>
      </header>
      <div className="build-section-body">{children}</div>
    </section>
  )
}

function Fact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <span className="eyebrow block">{label}</span>
      <span
        className={'block truncate text-[12px] text-foreground ' + (mono ? 'font-mono' : '')}
        title={value}
      >
        {value}
      </span>
    </div>
  )
}

/** The action row: what it does, what it touches, and the button. */
function Action({
  entry,
  busy,
  onRun,
}: {
  entry: UtilEntry | undefined
  busy: boolean
  onRun: (ids: string[]) => void
}) {
  if (!entry) return null
  const enabled = entry.available && !busy
  return (
    <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-t border-default-100 pt-3">
      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        {entry.effects.map((e) => (
          <Chip key={e} size="sm" variant="soft" color={/network|reach/i.test(e) ? 'warning' : undefined}>
            {e}
          </Chip>
        ))}
      </div>
      <button
        type="button"
        className="artifact-refresh"
        disabled={!enabled}
        onClick={() => onRun([entry.id])}
        title={
          entry.available
            ? entry.description
            : (entry.unavailable_reason ?? 'unavailable')
        }
      >
        {busy ? 'Running…' : entry.label}
        <Icon name="refresh" size={13} />
      </button>
    </div>
  )
}

function Shell({
  title,
  verdict,
  note,
  children,
  entry,
  busy,
  onRun,
}: {
  title: string
  verdict: { text: string; tone: ChipColor }
  note?: string
  children: React.ReactNode
  entry?: UtilEntry
  busy: boolean
  onRun: (ids: string[]) => void
}) {
  return (
    <Card className="w-full">
      <Card.Header className="flex flex-wrap items-center justify-between gap-3">
        <Card.Title>{title}</Card.Title>
        <Chip size="sm" variant="soft" color={verdict.tone}>{verdict.text}</Chip>
      </Card.Header>
      <Card.Content className="flex flex-col gap-3">
        {children}
        {note && <p className="text-[11px] text-default-500">{note}</p>}
        <Action entry={entry} busy={busy} onRun={onRun} />
      </Card.Content>
    </Card>
  )
}

function SbomCard({ s, entry, busy, onRun }: {
  s: SbomState; entry?: UtilEntry; busy: boolean; onRun: (ids: string[]) => void
}) {
  const verdict = !s.available
    ? { text: 'not generated', tone: 'warning' as ChipColor }
    : s.stale
      ? { text: 'stale', tone: 'warning' as ChipColor }
      : { text: 'current', tone: 'success' as ChipColor }

  return (
    <Shell title="SBOM" verdict={verdict} note={s.note} entry={entry} busy={busy} onRun={onRun}>
      {!s.available ? (
        <p className="text-[12px] text-default-500">{s.reason}</p>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-x-6 gap-y-2 md:grid-cols-4">
            <Fact label="components" value={(s.total_components ?? 0).toLocaleString()} />
            <Fact label="format" value={`${s.format ?? '—'} ${s.spec_version ?? ''}`} />
            <Fact label="generated" value={s.generated_at ? ago(Date.parse(s.generated_at) / 1000) : '—'} />
            <Fact label="cyclonedx" value={s.cyclonedx_present ? bytes(s.cyclonedx_bytes ?? 0) : 'missing'} />
          </div>
          {Object.keys(s.by_origin ?? {}).length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(s.by_origin ?? {}).map(([k, v]) => (
                <Chip key={k} size="sm" variant="soft">{k} {v}</Chip>
              ))}
            </div>
          )}
          {(s.unresolved?.length ?? 0) > 0 && (
            <div className="mt-2">
              <p className="text-[11px] text-default-500">
                {s.unresolved!.length} component(s) with no resolvable version. A
                Windows system library has no version to pin; a third-party
                library's lives in the MSYS2 package that installed it, not in
                CMakeLists.txt. What each one actually does:
              </p>
              {/* A bare name tells a reader nothing - "gnurx" is not a hint. The
                  details are grouped by kind, because the two kinds call for
                  different follow-up: a system library is a question you stop
                  asking, a third-party library is one you go and answer. */}
              <div className="mt-1.5 flex flex-col gap-1">
                {(s.unresolved_details ?? []).map((u) => (
                  <div key={u.name} className="flex gap-2 text-[11px]">
                    <span className="w-28 shrink-0 truncate font-mono text-default-500"
                      title={u.name}>{u.name}</span>
                    <span className="text-default-500">{u.description}</span>
                  </div>
                ))}
              </div>
              {(s.unresolved_details?.length ?? 0) === 0 && (
                <p className="mt-1 font-mono text-[11px] text-default-400">
                  {s.unresolved!.slice(0, 12).join(', ')}
                  {(s.unresolved!.length > 12) && ` +${s.unresolved!.length - 12} more`}
                </p>
              )}
            </div>
          )}
          {s.behind_last_commit && (
            <Alert status="warning">
              <Alert.Description>
                Regenerated after the last commit, so it may not describe the current tree.
              </Alert.Description>
            </Alert>
          )}
        </>
      )}
    </Shell>
  )
}

function MalapiCard({ m, entry, busy, onRun }: {
  m: MalapiState; entry?: UtilEntry; busy: boolean; onRun: (ids: string[]) => void
}) {
  // No "up to date" verdict, because there is nothing to compare against:
  // malapi.io publishes no version to pull, so the only honest thing to report
  // is how old the mirror is and whether a refresh would even run. The old
  // card said "up to date" off a git checkout that had nothing to do with the
  // rules, which is why the button could report success and change nothing.
  const verdict = !m.available
    ? { text: 'absent', tone: 'warning' as ChipColor }
    : m.blocked
      ? { text: 'refresh blocked', tone: 'danger' as ChipColor }
      : m.generated_stale
        ? { text: 'api out of date', tone: 'warning' as ChipColor }
        : {
            text: m.mirror_age_days === null || m.mirror_age_days === undefined
              ? 'mirrored'
              : `mirrored ${m.mirror_age_days}d ago`,
            tone: 'success' as ChipColor,
          }

  // "MalAPI classification", not "MalAPI rules": the rules live on malapi.io and
  // are mirrored, while malt/ is the MalAPI *tool*. The old title invited
  // exactly the confusion that made someone believe a git pull on malt/
  // refreshed the analyzer's classifications.

  return (
      <Shell title="MalAPI classification" verdict={verdict} note={m.note} entry={entry} busy={busy} onRun={onRun}>
      {!m.available ? (
        <p className="text-[12px] text-default-500">{m.reason}</p>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-x-6 gap-y-2 md:grid-cols-4">
            <Fact label="source" value={m.source ?? '—'} />
            <Fact label="mirror" value={m.mirror_path ?? '—'} mono />
            <Fact label="definitions" value={`${(m.yaml_count ?? 0).toLocaleString()} yaml`} />
            <Fact
              label="api built"
              value={m.yaml_age_days === null || m.yaml_age_days === undefined
                ? '—'
                : `${m.yaml_age_days}d ago`}
            />
          </div>

          {m.generated_stale && (
            <Alert status="danger">
              <Alert.Title>The analyzer is serving stale rules</Alert.Title>
              <Alert.Description>
                python/api/server.py is older than the mirror it was built from,
                so it answers from rules malapi.io has since replaced. Refresh to
                regenerate it.
              </Alert.Description>
            </Alert>
          )}

          {m.lock?.stale && (
            <Alert status="warning">
              <Alert.Title>A stale mirror lock was left behind</Alert.Title>
              <Alert.Description>
                <code className="font-mono">{m.lock.path}</code> is{' '}
                {m.lock.age_days} day(s) old — an interrupted mirror, not a live
                one. HTTrack will not start while it exists, and the refresh
                clears it before mirroring, so nothing is blocked until you
                press the button.
              </Alert.Description>
            </Alert>
          )}

          {m.blocked && m.blocked_reason && (
            <Alert status="danger">
              <Alert.Title>Cannot refresh</Alert.Title>
              <Alert.Description>{m.blocked_reason}</Alert.Description>
            </Alert>
          )}

          {m.malt_tool && (
            <p className="text-[11px] text-default-400">
              {m.malt_tool.path} ({m.malt_tool.short ?? 'unknown'}) is the MalAPI
              tool, not the rules. {m.malt_tool.note}
            </p>
          )}
        </>
      )}
    </Shell>
  )
}

function YaraCard({ y, entry, busy, onRun, onToggleIgnore }: {
  y: YaraState; entry?: UtilEntry; busy: boolean
  onRun: (ids: string[]) => void
  onToggleIgnore: (next: { ignore_compile_failures: boolean }) => void
}) {
  const ignore = y.ignore_compile_failures ?? false
  return (
    <Shell
      title="YARA rules"
      verdict={y.available
        ? { text: `${y.total.toLocaleString()} rules`, tone: 'success' as ChipColor }
        : { text: 'absent', tone: 'warning' as ChipColor }}
      note={y.note}
      entry={entry}
      busy={busy}
      onRun={onRun}
    >
      {!y.available ? (
        <p className="text-[12px] text-default-500">{y.reason}</p>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-x-6 gap-y-2 md:grid-cols-3">
            <Fact label="compiler" value={y.yara_version ?? 'yarac not found'} mono />
            <Fact label="on disk" value={bytes(y.bytes)} />
            <Fact label="collections" value={String(y.collections.length)} />
          </div>
          <div className="flex flex-col gap-1">
            {y.collections.map((c) => {
              const share = y.total ? (c.rules / y.total) * 100 : 0
              return (
                <div key={c.name} className="flex items-center gap-2">
                  <span className="w-44 shrink-0 truncate font-mono text-[11px] text-default-500" title={c.name}>
                    {c.name}
                  </span>
                  <span className="h-1.5 min-w-0 flex-1 overflow-hidden rounded-full bg-default-100">
                    <span className="block h-full rounded-full bg-accent/60" style={{ width: `${share}%` }} />
                  </span>
                  <span className="w-12 shrink-0 text-right font-mono text-[11px] text-default-500">
                    {c.rules.toLocaleString()}
                  </span>
                </div>
              )
            })}
          </div>
          {/* Said here rather than omitted: there is no upstream for these, so a
              missing "update" is a fact about the project, not a gap in the UI. */}
          {y.update_reason && (
            <Alert status="warning">
              <Alert.Description>{y.update_reason}.</Alert.Description>
            </Alert>
          )}
          <IgnoreCompileCheckbox
            checked={ignore}
            disabled={busy}
            onSave={onToggleIgnore}
          />
        </>
      )}
    </Shell>
  )
}

function IgnoreCompileCheckbox({ checked, disabled, onSave }: {
  checked: boolean; disabled: boolean
  onSave: (next: { ignore_compile_failures: boolean }) => void
}) {
  return (
    <label className="flex items-start gap-2 border-t border-default-100 pt-3 text-[11px] text-default-500">
      <Checkbox
        checked={checked}
        disabled={disabled}
        onChange={(next) => {
          /* Not a client-only toggle. The PUT below persists it in
             config/yara_check.json before anything re-renders, so what this box
             shows is what the check will actually do, including after a reload -
             the same rule the SBOM and MalAPI cards answer to. */
          onSave({ ignore_compile_failures: next })
        }}
      />
      <span>
        Ignore files that fail to compile (currently{' '}
        <span className="font-mono">{checked ? 'on' : 'off'}</span>)
        {!checked && ' — a compile failure fails the check'}
      </span>
    </label>
  )
}

function YargenCard({ g, entry, busy, onRun }: {
  g: YargenState; entry?: UtilEntry; busy: boolean; onRun: (ids: string[]) => void
}) {
  const verdict = !g.available
    ? { text: 'absent', tone: 'warning' as ChipColor }
    : g.ok
      ? { text: 'ready', tone: 'success' as ChipColor }
      : { text: `${g.faults?.length ?? 0} gap(s)`, tone: 'warning' as ChipColor }

  return (
    <Shell title="yarGen-Go" verdict={verdict} note={g.note} entry={entry} busy={busy} onRun={onRun}>
      {!g.available ? (
        <p className="text-[12px] text-default-500">{g.reason}</p>
      ) : (
        <>
          <div className="divide-y divide-default-100">
            {g.checks.map((c) => (
              <div key={c.id} className="flex items-center justify-between gap-3 py-1.5">
                <span className="flex min-w-0 items-center gap-2">
                  <span
                    aria-hidden
                    className={'inline-block h-2 w-2 shrink-0 rounded-full ' +
                      (c.ok ? 'bg-success' : 'bg-warning')}
                  />
                  <span className="truncate text-[12px]">{c.label}</span>
                </span>
                <span
                  className={'shrink-0 truncate font-mono text-[11px] ' +
                    (c.ok ? 'text-default-500' : 'text-warning')}
                  title={c.fix ? `${c.detail} — ${c.fix}` : c.detail}
                >
                  {c.detail}
                </span>
              </div>
            ))}
          </div>
          {/* A missing config.yaml does not stop yarGen, so nothing else would
              ever tell you it is missing. It only costs the LLM pass. */}
          {(g.faults ?? []).includes('config/config.yaml') && (
            <Alert status="warning">
              <Alert.Description>
                Without <code className="font-mono">config.yaml</code> yarGen
                still runs, but skips the LLM pass — so generated rules are
                weaker than the tool can produce and nothing else will say so.
                Rule generation works without it.
              </Alert.Description>
            </Alert>
          )}
        </>
      )}
    </Shell>
  )
}

function EagleCard({ e, entry, busy, onRun }: {
  e: EagleState; entry?: UtilEntry; busy: boolean; onRun: (ids: string[]) => void
}) {
  const artifacts = Object.values(e.artifacts ?? {})
  const present = artifacts.filter((a) => a.exists).length
  const verdict = e.ready
    ? { text: 'built', tone: 'success' as ChipColor }
    : e.available
      ? { text: 'not built', tone: 'warning' as ChipColor }
      : { text: 'cannot build', tone: 'warning' as ChipColor }

  return (
    <Shell
      title="EagleVM"
      verdict={verdict}
      note={e.note}
      entry={entry}
      busy={busy}
      onRun={onRun}
    >
      <div className="grid grid-cols-2 gap-x-6 gap-y-2 md:grid-cols-4">
        <Fact label="preset" value={e.preset || '—'} mono />
        <Fact label="artefacts" value={`${present}/${artifacts.length}`} />
        <Fact label="build dir" value={e.build_dir || '—'} mono />
        <Fact
          label="built"
          value={artifacts.length
            ? ago(Math.max(...artifacts.map((a) => a.modified ?? 0)))
            : '—'}
        />
      </div>

      {!e.repo_exists && (
        <Alert status="warning">
          <Alert.Description>
            <code className="font-mono">{e.repo}</code> is missing — the in-tree
            EagleVM checkout is what this button builds.
          </Alert.Description>
        </Alert>
      )}

      {e.reason && (
        <Alert status={e.ready ? 'success' : 'warning'}>
          <Alert.Description>{e.reason}</Alert.Description>
        </Alert>
      )}

      <div className="divide-y divide-default-100">
        {artifacts.map((a) => (
          <div key={a.name} className="flex items-center justify-between gap-3 py-1.5">
            <span className="flex min-w-0 items-center gap-2">
              <span
                aria-hidden
                className={'inline-block h-2 w-2 shrink-0 rounded-full ' +
                  (a.exists ? 'bg-success' : 'bg-warning')}
              />
              <span className="truncate font-mono text-[11px]">{a.name}</span>
            </span>
            <span className="shrink-0 truncate font-mono text-[11px] text-default-500"
              title={a.path}>
              {a.exists
                ? `${bytes(a.bytes ?? 0)} · ${ago(a.modified)}`
                : 'missing'}
            </span>
          </div>
        ))}
      </div>

      {(e.missing?.length ?? 0) > 0 && (
        <p className="text-[11px] text-default-400">
          Missing: <span className="font-mono">{e.missing.join(', ')}</span>.
          Building with the button below produces them.
        </p>
      )}

      <div className="grid grid-cols-1 gap-x-6 gap-y-2 md:grid-cols-3">
        <Fact label="vcvars64" value={e.toolchain?.vcvars64 ?? 'not found'} mono />
        <Fact label="cmake" value={e.toolchain?.cmake ?? 'not found'} mono />
        <Fact label="ninja" value={e.toolchain?.ninja ?? 'bundled with CMake'} mono />
      </div>
    </Shell>
  )
}

// ---------------------------------------------------------------------------
// Output colouring.
//
// parseLine() in lib/logColor already knows timestamps, level words and ANSI -
// and none of that is what this page's output is mostly made of. The utilities
// emit about a dozen shapes of their own (a section header, the command, a
// verdict, the YARA buckets) and then whatever git, python or yarac printed.
// Those own shapes are matched first; every line they do not claim is handed to
// parseLine, so a child process that speaks its own dialect still gets coloured
// rather than falling through grey.
//
// One convention, and it is the same one the YARA buckets need: colour means
// "look here", the left rail means "stop scrolling". A genuine failure gets
// both. An informational line - the sibling-reference count, the absent-module
// count, the 15-second progress ticks - gets colour only, and is kept muted.
// Painting those as loudly as a real failure is how a log viewer teaches people
// to stop reading it.
// ---------------------------------------------------------------------------

type Verdict = { tone: Tone; notable: boolean }

/**
 * Ordered, first match wins - so the specific shapes come before the general
 * ones. Every pattern is anchored on a prefix the backend actually emits; see
 * the _append() calls in python/panel/utils.py for the strings they match.
 */
const UTILS_MARKERS: ReadonlyArray<readonly [RegExp, Verdict]> = [
  // A real compile failure, naming the file. In a 3000-file run this is the one
  // line the whole card exists to make findable.
  [/^\s*FAIL\s+\S/, { tone: 'danger', notable: true }],
  [/genuinely failed to compile:/, { tone: 'danger', notable: true }],

  // The per-utility verdict lines. A SKIP is its own colour: the work did not
  // fail, it was refused or unavailable, and calling that a failure would train
  // people to ignore the PASS/FAIL pair.
  [/^---\s.*:\s*FAIL\b/, { tone: 'danger', notable: true }],
  [/^---\s.*:\s*PASS\b/, { tone: 'success', notable: true }],
  [/^---\s.*:\s*SKIPPED\b/, { tone: 'warning', notable: true }],

  // The run's own summary at the foot. Two rules rather than one with logic in
  // it: "0 failed" and "3 failed" are different colours, and someone scanning
  // the tail should not have to read the number to know which one they are on.
  [/^===\s+\d+\s+passed,\s+0\s+failed/, { tone: 'success', notable: true }],
  [/^===\s+\d+\s+passed,\s+\d+\s+failed/, { tone: 'danger', notable: true }],

  // A refused selection: the run went ahead without one of the requested ids.
  [/^skipped unknown utility id\(s\)/, { tone: 'warning', notable: true }],

  // Failure reporting from the child-process wrapper. All of it is indented by
  // four spaces, and matching on that indent is deliberate: a child's own
  // "TimeoutError:" is not ours and must not wear our rail.
  [/^ {4}(?:timed out after|[A-Z]\w*(?:Error|Exception|Exit)\b[^\n]*:)/, { tone: 'danger', notable: true }],
  // A python traceback: the head is the alarm, the frames are the address.
  [/^Traceback \(most recent call last\):/, { tone: 'danger', notable: true }],
  [/^\s*File "\S+", line \d+/, { tone: 'muted', notable: false }],

  // The two informational buckets, kept muted: these are not defects and the
  // backend already says so in the sentence under each count.
  [/file\(s\) reference identifiers defined in a/, { tone: 'muted', notable: false }],
  [/file\(s\) need a YARA module this build/, { tone: 'muted', notable: false }],
  [/^ {4}(?:expected for an interdependent pack|these rules are valid)/, { tone: 'muted', notable: false }],

  // What the run is about to touch, then the section header and the command
  // itself - accent, the same colour build.ps1's own `> cmd` echo gets.
  [/:\s*touches\s/, { tone: 'accent', notable: false }],
  [/^=== .+$/, { tone: 'accent', notable: false }],
  [/^ {4}\$ /, { tone: 'accent', notable: false }],

  // Progress: one line every fifteen seconds over three thousand files. A
  // progress line is not news, and colouring it would colour all of it.
  [/^\s*\.\.\. /, { tone: 'muted', notable: false }],
  [/^\s*[\w ]+: \d+ rule file\(s\)/, { tone: 'default', notable: false }],
]

interface ColouredLine {
  tone: Tone
  notable: boolean
  /** Pre-coloured spans. A marker-matched line is one span in its own tone. */
  spans: { text: string; tone: Tone }[]
}

/**
 * One output line, resolved to a tone and a set of coloured spans.
 *
 * The spans come from colorize() rather than ParsedLine.message because message
 * is the log-file projection of a line: it moves a level word such as "error:"
 * into a badge this row does not draw, so the severity would vanish from the
 * text while remaining in the colour. colorize() keeps the word and still
 * colours it.
 */
function colourLine(line: string): ColouredLine {
  // The backend separates utilities with a blank line. Left alone it collapses
  // to nothing and the two runs run together, so it renders as a blank row
  // rather than an absent one.
  if (!line.trim()) return { tone: 'muted', notable: false, spans: [{ text: ' ', tone: 'muted' }] }

  const own = UTILS_MARKERS.find(([re]) => re.test(line))
  if (own) {
    // stripAnsi: a marker is anchored to the first characters, so an escaped
    // line can only match if the escape sits after them - but a child that
    // prints colour codes should not leave them visible in a line we paint.
    return {
      tone: own[1].tone,
      notable: own[1].notable,
      spans: [{ text: stripAnsi(line), tone: own[1].tone }],
    }
  }

  const parsed = parseLine(line)
  return {
    tone: parsed.tone,
    notable: parsed.notable,
    spans: (parsed.pieces ?? colorize(line)).map((p) => ({ text: p.text, tone: p.tone })),
  }
}

// One row, memoised on the raw line. parseLine runs inside the memo rather than
// being handed a pre-parsed object, because the log is replaced wholesale every
// poll: passing the parsed object would give every row a fresh identity twice a
// second and the memo would never hit. Strings compare by value, so an unchanged
// line fails the shallow compare and only the lines just appended do any work.
const OutputRow = memo(function OutputRow({ line, n }: { line: string; n: number }) {
  const c = useMemo(() => colourLine(line), [line])
  return (
    <div className={`build-log-line ${c.notable ? 'is-notable' : ''}`}>
      <span className="build-log-num">{n}</span>
      <span className="build-log-text">
        {c.spans.map((s, i) => (
          <span key={i} className={TONE_CLASS[s.tone]}>{s.text}</span>
        ))}
      </span>
    </div>
  )
})

export default function Utils() {
  const [data, setData] = useState<UtilsOverview | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [job, setJob] = useState<AnalyzerBuildJob | null>(null)
  const [notice, setNotice] = useState<{ tone: 'ok' | 'bad'; text: string } | null>(null)
  const [starting, setStarting] = useState(false)
  const logRef = useRef<HTMLDivElement>(null)
  const [follow, setFollow] = useState(true)
  // The generator's value pools have their own endpoint: they are not a
  // utility job and do not become stale with the SBOM, so folding them into
  // /api/utils would only make two unrelated reads look like one.
  const [resources, setResources] = useState<SampleResourcesSnapshot | null>(null)
  const [resourcesError, setResourcesError] = useState<string | null>(null)
  // Sections as tabs, the Pipelines Configuration pattern. Running anything
  // switches to the log tab for the same reason Build does: a button whose
  // only effect is on another tab reads as a button that did nothing.
  const [tab, setTab] = useState<'detection' | 'inventory' | 'eagle' | 'resources' | 'run'>('detection')

  const load = useCallback(async () => {
    try {
      setData(await api.utilsOverview())
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  const loadResources = useCallback(async () => {
    try {
      setResources(await api.sampleResources())
      setResourcesError(null)
    } catch (e) {
      setResourcesError(e instanceof Error ? e.message : String(e))
    }
  }, [])

  useEffect(() => {
    void load()
    void loadResources()
    const id = window.setInterval(() => void load(), 30000)
    return () => window.clearInterval(id)
  }, [load, loadResources])

  const running = job?.state === 'running'

  useEffect(() => {
    if (!running || !job) return
    const id = window.setInterval(async () => {
      try {
        const next = await api.buildJob(job.id)
        setJob(next)
        // The whole page is state, and every utility just changed some of it.
        if (next.state !== 'running') void load()
      } catch {
        // A dropped poll is not a failure; the next tick tries again.
      }
    }, 1500)
    return () => window.clearInterval(id)
  }, [running, job?.id, load])

  useEffect(() => {
    if (follow && logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [job?.log?.length, follow])

  const run = useCallback(async (ids: string[]) => {
    setStarting(true)
    setNotice(null)
    try {
      const res = await api.runUtils(ids)
      if (!res.ok || !res.job_id) {
        setNotice({ tone: 'bad', text: res.error ?? 'the run was refused' })
        return
      }
      setJob(await api.buildJob(res.job_id))
      setFollow(true)
      setTab('run')
    } catch (e) {
      setNotice({ tone: 'bad', text: e instanceof Error ? e.message : String(e) })
    } finally {
      setStarting(false)
    }
  }, [])

  const saveYaraOptions = useCallback(async (next: {
    ignore_compile_failures: boolean
  }) => {
    setStarting(true)
    setNotice(null)
    try {
      await api.setYaraOptions(next)
      // The backend echoes state alongside, but reloading is simpler and the
      // poll loop would restock the card within 30s anyway - doing it now
      // means the checkbox never displays a value the backend has not got.
      await load()
    } catch (e) {
      setNotice({ tone: 'bad', text: e instanceof Error ? e.message : String(e) })
    } finally {
      setStarting(false)
    }
  }, [load])

  const entryOf = useMemo(() => {
    const map = new Map<string, UtilEntry>()
    for (const e of data?.entries ?? []) map.set(e.id, e)
    return (id: string) => map.get(id)
  }, [data?.entries])

  const results = job?.results ?? []
  const lines = useMemo(() => job?.log ?? [], [job?.log])

  // Same trade as the Build panel's `problems`: the whole array is re-parsed
  // each poll, and the count is worth more than the microseconds. It is what
  // makes a 3000-line rule compile scannable - the answer is "are any red".
  const notable = useMemo(
    () => lines.filter((line) => colourLine(line).notable).length,
    [lines],
  )

  if (loading && !data) return <Loading label="utils" />

  // The section rails read the state the cards display - not a second, smarter
  // machine. One degraded utility is warning; a blocked one is danger only
  // when nothing else in the group can act either (a blocked refresh with a
  // live mirror is 'warning', the lock alert already says why).
  const detectionTone: ChipColor = !data
    ? undefined
    : [data.yara, data.yargen, data.malapi].every((s) => s.available)
      ? 'success'
      : data.malapi.blocked || data.malapi.generated_stale ? 'danger' : 'warning'
  const inventoryTone: ChipColor = !data
    ? undefined
    : data.sbom.available && !data.sbom.stale ? 'success' : 'warning'
  // The virtualiser is a build product, so its rail is "can the factory gate
  // open": built is success, anything else is a warning with the reason on the
  // card. It is never danger - nothing downstream is broken, it is not built.
  const eagleTone: ChipColor = !data
    ? undefined
    : data.eagle.ready ? 'success' : 'warning'

  // Resources have no "stale" verdict of their own - a two-day-old pool is
  // still a pool. The rail warns only when a refresh failed or a pool the
  // factory offers is empty; an unconfigured tab (no sources at all) stays
  // neutral rather than nagging about an optional integration.
  const anyResourceSource = resources?.kinds.some((k) => k.resources.length > 0) ?? false
  const resourcesTone: ChipColor = !resources
    ? undefined
    : resources.error
      ? 'danger'
      : anyResourceSource
        ? (Object.values(resources.features).every((f) => f.available)
            && !resources.kinds.some((k) =>
              k.resources.some((r) => r.enabled && r.last_error))
          ? 'success' : 'warning')
        : undefined

  return (
    <div className="flex flex-col gap-4">
      {/* Sections as tabs, like Pipelines Configuration: one concern at a
          time, with a dot for the ones that need attention. */}
      <SubNav
        tabs={[
          {
            id: 'detection', label: 'Detection content', icon: 'clamd',
            tone: !data ? undefined
              : [data.yara, data.yargen, data.malapi].every((s) => s.available)
                ? 'ok'
                : data.malapi.blocked || data.malapi.generated_stale ? 'bad' : 'warn',
          },
          {
            id: 'inventory', label: 'Software inventory', icon: 'artifacts',
            tone: !data ? undefined
              : data.sbom.available && !data.sbom.stale ? 'ok' : 'warn',
          },
          {
            id: 'eagle', label: 'Instruction virtualisation', icon: 'build',
            tone: !data ? undefined : data.eagle.ready ? 'ok' : 'warn',
          },
          {
            id: 'resources', label: 'Generator resources', icon: 'database',
            tone: resourcesTone === 'danger' ? 'bad'
              : resourcesTone === 'warning' ? 'warn'
                : resourcesTone === 'success' ? 'ok' : undefined,
          },
          {
            id: 'run', label: 'Run log & results', icon: 'terminal',
            tone: job
              ? (job.state === 'running' ? 'warn'
                : job.state === 'passed' ? 'ok' : 'bad')
              : undefined,
          },
        ]}
        active={tab}
        onChange={(id) => setTab(id as 'detection' | 'inventory' | 'eagle' | 'resources' | 'run')}
      />

      {error && (
        <Alert status="danger">
          <Alert.Title>Cannot read the utility state</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      {notice && (
        <Alert status={notice.tone === 'ok' ? 'success' : 'danger'}>
          <Alert.Description>{notice.text}</Alert.Description>
        </Alert>
      )}

      {data && tab === 'detection' && (
          <Section
            n={1}
            title="Detection content"
            hint="YARA rules, MalAPI classification, yarGen-Go's databases - what the analyzer reads at scan time. Stale here means blind, not slow."
            tone={detectionTone}
          >
            <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
              <YaraCard y={data.yara} entry={entryOf('yara-check')} busy={starting || running} onRun={run} onToggleIgnore={saveYaraOptions} />
              <MalapiCard m={data.malapi} entry={entryOf('malapi-update')} busy={starting || running} onRun={run} />
              <YargenCard g={data.yargen} entry={entryOf('yargen-update')} busy={starting || running} onRun={run} />
            </div>
          </Section>
      )}

      {data && tab === 'inventory' && (
          <Section
            n={2}
            title="Software inventory"
            hint="The CycloneDX SBOM - what this binary is made of. Stale here is an audit problem, not a detection one."
            tone={inventoryTone}
          >
            <SbomCard s={data.sbom} entry={entryOf('sbom')} busy={starting || running} onRun={run} />
          </Section>
      )}

      {data && tab === 'eagle' && (
          <Section
            n={3}
            title="Instruction virtualisation"
            hint="EagleVM — the in-tree virtualiser the sample factory calls. Build it here (CMake, Release, tests off); its artefacts are what the factory's virtualisation option requires."
            tone={eagleTone}
          >
            <EagleCard e={data.eagle} entry={entryOf('eagle-build')} busy={starting || running} onRun={run} />
          </Section>
      )}

      {tab === 'resources' && (
          <Section
            n={4}
            title="Generator resources"
            hint="Value pools the sample factory samples from - malicious IPs, domains, URLs and file hashes. Bait literals, not detection rules: the sampled values are stored in the generated source plain, ROT13-, XOR- or Base64-encoded as the factory's encoding option says. A stale pool means older bait, not a blind scan."
            tone={resourcesTone}
          >
            <GeneratorResources
              snapshot={resources}
              error={resourcesError}
              onReload={loadResources}
            />
          </Section>
      )}

      {tab === 'run' && (
      <Section
        n={5}
        title="Run log & results"
        hint="What the buttons above actually did, and what each utility came back as."
        tone={job?.state === 'failed' ? 'danger' : job?.state === 'passed' ? 'success' : 'accent'}
      >
        {results.length > 0 && (
          <Card className="w-full">
            <Card.Header className="flex flex-wrap items-center justify-between gap-2">
              <Card.Title>Results</Card.Title>
            {job?.summary && (
              <Chip
                size="sm"
                variant="soft"
                color={job.state === 'passed' ? 'success' : job.state === 'failed' ? 'danger' : 'accent'}
              >
                {job.summary}
              </Chip>
            )}
          </Card.Header>
          <Card.Content>
            <div className="divide-y divide-default-100">
              {results.map((r) => (
                <div key={r.id} className="flex items-center justify-between gap-3 py-1.5">
                  <span className="flex min-w-0 items-center gap-2">
                    <Icon
                      name={r.state === 'passed' ? 'check' : r.state === 'failed' ? 'x' : 'refresh'}
                      size={13}
                      className={r.state === 'passed' ? 'text-success'
                        : r.state === 'failed' ? 'text-danger' : 'text-default-400'}
                    />
                    <span className="truncate text-[12px]">{r.label}</span>
                  </span>
                  <span className="shrink-0 font-mono text-[11px] text-default-500">
                    {r.detail ?? r.state}{r.duration != null && ` · ${r.duration}s`}
                  </span>
                </div>
              ))}
            </div>
          </Card.Content>
        </Card>
      )}

      <Card className="w-full">
        <Card.Header className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-baseline gap-2">
            <Card.Title>Output</Card.Title>
            {job && (
              <span className="build-log-meta">
                job {job.id} · {job.log_line_count} line{job.log_line_count === 1 ? '' : 's'}
                {job.exit_code !== null && ` · exit ${job.exit_code}`}
              </span>
            )}
          </div>
          <div className="build-log-controls">
            {notable > 0 && (
              <Chip size="sm" variant="soft" color="warning">
                {notable} notable line{notable === 1 ? '' : 's'}
              </Chip>
            )}
            {!follow && (
              <button type="button" className="build-link" onClick={() => setFollow(true)}>
                Jump to tail
              </button>
            )}
          </div>
        </Card.Header>
        <Card.Content>
          {!job ? (
            <p className="build-empty">
              Nothing has run this session. Pick an action above and its output
              streams here.
            </p>
          ) : lines.length === 0 ? (
            <p className="build-empty">Waiting for the first line…</p>
          ) : (
            <div
              className="build-log"
              role="log"
              aria-label="Utility output"
              aria-live="polite"
              ref={logRef}
              onScroll={(e) => {
                const el = e.currentTarget
                setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 40)
              }}
            >
              {job.log_truncated ? (
                <div className="build-log-line is-truncated">
                  … {job.log_truncated} earlier line{job.log_truncated === 1 ? '' : 's'} dropped
                </div>
              ) : null}
              {lines.map((line, i) => (
                <OutputRow key={i} line={line} n={i + 1} />
              ))}
            </div>
          )}
        </Card.Content>
      </Card>
      </Section>
      )}
    </div>
  )
}