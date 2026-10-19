import { useMemo, useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { Button } from '@heroui/react/button'
import { Card } from '@heroui/react/card'
import Icon from './Icon'
import CopyButton from './CopyButton'
import Switch, { OptionField } from './Switch'
import { api } from '../api'
import type { EnvOption, PhaseInfo } from '../types'

// ---------------------------------------------------------------------------
// Build a pipeline from the analyzer's own phase catalog.
//
// The steps here are not a hardcoded list. They arrive from `GET /phases`,
// which the analyzer serves from `static_analyzer --list-phases --json`, so the
// admin picks from exactly the set the binary will accept - a name that is not
// in that catalog is an exit code 2, and this is where that is worth catching.
//
// Two things the form has to get right, both from the planner rather than from
// taste:
//
//  * Order is the pipeline. Phases run in the order the file lists them, so the
//    selection is a numbered list you can reorder, not a set. The catalog's own
//    order is the classic 27-phase order, so "reset to the recommended order" is
//    a real default rather than an arbitrary one.
//  * Prerequisites are inserted for you. Picking `hexdump` gets `extraction`
//    placed before it, and `export`/`summary` are appended. The wizard shows
//    that resolved order while you build, because a list of five phases that
//    runs seven is not a surprise to be left with.
//
// The preview is a convenience; the file the server writes is authoritative and is
// re-validated against the same rules on save.
// ---------------------------------------------------------------------------

/** Mirrors planner::close(): prerequisites before what needs them, then export
 *  and summary appended. Display-only - the server recomputes on save. */
function resolve(picked: PhaseInfo[]): { order: PhaseInfo[]; inserted: string[] } {
  const byName = new Map<string, PhaseInfo>()
  for (const phase of picked) byName.set(phase.name, phase)

  const order: PhaseInfo[] = []
  const seen = new Set<string>()
  const push = (name: string) => {
    if (seen.has(name)) return
    const phase = byName.get(name)
    if (!phase) return
    for (const req of phase.requires) {
      const dependency = picked.find((p) => p.name === req)
      if (dependency) push(dependency.name)
    }
    seen.add(name)
    order.push(phase)
  }
  picked.forEach((p) => push(p.name))

  const inserted = order
    .filter((p) => !picked.some((q) => q.name === p.name))
    .map((p) => p.name)
  return { order, inserted }
}

const slugify = (name: string): string =>
  name.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '')

/** The YAML this wizard would write. Quoting is not decoration here: a
 *  description is free text in a text box, and an unquoted one containing ": "
 *  or a leading "#" produces a file the analyzer rejects. */
function renderYaml(
  slug: string,
  description: string,
  picked: PhaseInfo[],
  env: Record<string, boolean | number | string | undefined>,
  options: EnvOption[],
): string {
  const text = description.trim().replace(/\s+/g, ' ') || 'Custom pipeline'
  const quoted = `"${text.replace(/["\\]/g, '\\$&')}"`
  const comment = (s: string) => s.replace(/[#\r\n]+/g, ' ').trim()

  const lines = [
    `# ${comment(text)}`,
    '# The analyzer reads this file directly:',
    `#     static_analyzer --pipeline ${slug} sample.exe`,
    `name: ${slug}`,
    `description: ${quoted}`,
    '',
    'phases:',
  ]
  for (const phase of picked) {
    lines.push(`  - ${phase.name}${phase.description ? `   # ${comment(phase.description)}` : ''}`)
  }

  // Only options the author actually set: an environment block full of defaults
  // is noise that has to be re-read every time the file is opened.
  const set = options.filter((o) => env[o.key] !== undefined && env[o.key] !== o.default)
  if (set.length > 0) {
    lines.push('', 'environment:')
    for (const option of set) {
      const value = env[option.key]
      if (option.kind === 'flag') {
        if (value) lines.push(`  ${option.key}: "1"`)
        continue
      }
      lines.push(`  ${option.key}: "${value}"`)
    }
  }

  lines.push(
    '',
    "# 'export' and 'summary' are appended automatically, and a phase that needs a",
    '# prerequisite gets it inserted before it. Neither needs to be listed here.',
  )
  return lines.join('\n') + '\n'
}

export default function PipelineWizard({
  catalog,
  options,
  slowPhases,
  onCreated,
}: {
  catalog: PhaseInfo[]
  options: EnvOption[]
  slowPhases: string[]
  /** Called with the new pipeline's name once the file is on disk. */
  onCreated: (name: string) => void
}) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [picked, setPicked] = useState<string[]>([])
  // `undefined` means "not set", which is different from "set to the default" -
  // an option left alone must not appear in the generated file at all.
  const [env, setEnv] = useState<Record<string, boolean | number | string | undefined>>({})
  const [query, setQuery] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const slug = slugify(name) || 'my_pipeline'
  const selected = useMemo(
    () => picked.map((n) => catalog.find((p) => p.name === n)).filter((p): p is PhaseInfo => Boolean(p)),
    [picked, catalog],
  )
  const { order, inserted } = useMemo(() => resolve(selected), [selected])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return catalog
    return catalog.filter(
      (p) => p.name.toLowerCase().includes(q) || p.description.toLowerCase().includes(q),
    )
  }, [catalog, query])

  const draft = useMemo(
    () => renderYaml(slug, description, selected, env, options),
    [slug, description, selected, env, options],
  )

  const validName = /^[a-z0-9][a-z0-9_-]{0,63}$/.test(slug)
  const canSave = selected.length > 0 && validName && !saving

  const toggle = (phase: string) =>
    setPicked((prev) => (prev.includes(phase) ? prev.filter((p) => p !== phase) : [...prev, phase]))

  const move = (index: number, delta: number) =>
    setPicked((prev) => {
      const target = index + delta
      if (target < 0 || target >= prev.length) return prev
      const next = [...prev]
      ;[next[index], next[target]] = [next[target], next[index]]
      return next
    })

  // --- drag to reorder -----------------------------------------------------
  //
  // Drag ADDS a way to reorder; it does not replace the arrows. That is the
  // deliberate part, because order is the pipeline here and the list can be
  // thirty items long - moving the last one to the front with buttons is
  // twenty-nine clicks, and with a mouse it is one gesture.
  //
  // The arrows stay anyway, for two reasons that are not politeness: they are
  // what a keyboard and a screen reader use, since HTML5 drag-and-drop is not
  // reachable without a mouse, and they are more precise for a single-step
  // nudge. Drag suits a long move, buttons suit an adjacent one.
  const [dragFrom, setDragFrom] = useState<number | null>(null)
  // Which row the pointer is currently over, and on which side - the line is
  // drawn above or below the row depending on which way the item would land.
  const [dropAt, setDropAt] = useState<{ index: number; after: boolean } | null>(null)

  const reorder = (from: number, to: number) =>
    setPicked((prev) => {
      if (from === to || from < 0 || from >= prev.length) return prev
      const next = [...prev]
      const [moved] = next.splice(from, 1)
      next.splice(to, 0, moved)
      return next
    })

  /**
   * Where a drop on row `index` should actually land.
   *
   * Removing the dragged row shifts every row after it up by one, so the raw
   * index is wrong for any downward drag. Dragging `a` down one row and letting
   * the target read as "after this row" would otherwise put `a` two positions
   * down: remove `a` first, then insert at the pre-removal index of `b`.
   *
   *   [a b c], drag a onto b's lower half -> [b c a]  (wrong)
   *                        correct        -> [b a c]
   *
   * The fix is to shift the target first, then apply the before/after half.
   */
  const dropTarget = (from: number, index: number, after: boolean) =>
    index - (from < index ? 1 : 0) + (after ? 1 : 0)

  const endDrag = () => {
    setDragFrom(null)
    setDropAt(null)
  }

  // The catalog arrives in the order the built-in pipeline runs them, which is
  // the one ordering that is known to work end to end.
  const resetOrder = () => setPicked(picked.slice().sort(
    (a, b) => catalog.findIndex((p) => p.name === a) - catalog.findIndex((p) => p.name === b),
  ))

  // Triage: everything except the phases phase-rush drops. One click, because
  // "run it fast" is a question with a known answer on this page.
  const triagePreset = () =>
    setPicked(catalog.filter((p) => !slowPhases.includes(p.name)).map((p) => p.name))

  const save = async () => {
    setSaving(true)
    setError(null)
    try {
      await api.savePipeline(slug, draft)
      onCreated(slug)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setSaving(false)
    }
  }

  if (catalog.length === 0) {
    return (
      <Card className="w-full">
        <Card.Content className="py-8 text-[11px] leading-relaxed text-default-500">
          <p className="mb-2 text-sm font-semibold text-foreground">
            No steps to build from.
          </p>
          The step list is the analyzer's own phase catalog, served from{' '}
          <code className="font-mono">GET /phases</code> and cached in{' '}
          <code className="font-mono">server.py</code> from{' '}
          <code className="font-mono">--list-phases --json</code>. Building a pipeline out of names
          this panel invented would produce exactly the config the analyzer rejects with exit 2,
          so the wizard waits for the real list. Start the analyzer and this tab fills in.
        </Card.Content>
      </Card>
    )
  }

  return (
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      {/* --- the steps ------------------------------------------------------ */}
      <Card className="w-full">
        <Card.Header className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <Card.Title className="text-sm font-semibold">1 · Pick the steps</Card.Title>
            <p className="mt-1 text-[11px] text-default-500">
              {catalog.length} from the analyzer. Click to add; they run in the order you pick them.
            </p>
          </div>
          <div className="compose-viewer-search">
            <Icon name="filter" size={13} className="text-default-400" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter steps…"
              aria-label="Filter steps"
            />
            {query && (
              <button type="button" onClick={() => setQuery('')} aria-label="Clear filter">
                <Icon name="x" size={12} />
              </button>
            )}
          </div>
        </Card.Header>

        <Card.Content className="flex flex-col gap-2">
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" onPress={triagePreset}>
              <Icon name="rocket" size={13} />
              Triage preset
            </Button>
            <Button size="sm" variant="ghost" onPress={() => setPicked([])} isDisabled={picked.length === 0}>
              Clear
            </Button>
            <Button size="sm" variant="ghost" onPress={resetOrder} isDisabled={picked.length < 2}>
              Recommended order
            </Button>
          </div>

          <div className="max-h-[22rem] overflow-y-auto rounded-lg border border-default-200/70">
            {filtered.map((phase) => {
              const on = picked.includes(phase.name)
              const slow = slowPhases.includes(phase.name)
              return (
                <button
                  key={phase.name}
                  type="button"
                  onClick={() => toggle(phase.name)}
                  title={phase.description}
                  aria-pressed={on}
                  className={`flex w-full items-start gap-2.5 border-b border-default-200/60 px-3 py-2 text-left transition-colors last:border-b-0 ${
                    on ? 'bg-accent/10' : 'hover:bg-default-50'
                  }`}
                >
                  <span
                    aria-hidden="true"
                    className={`mt-1 flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded border ${
                      on ? 'border-accent bg-accent text-white' : 'border-default-300'
                    }`}
                  >
                    {on && <Icon name="check" size={9} />}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-center gap-1.5">
                      <span className="font-mono text-[12px] font-medium text-foreground">
                        {phase.name}
                      </span>
                      {slow && (
                        <span className="metric rounded border border-warning/40 px-1 font-mono text-[9px] text-warning">
                          slow
                        </span>
                      )}
                      {phase.service && (
                        <span className="metric rounded border border-default-200 px-1 font-mono text-[9px] text-default-400">
                          {phase.service}
                        </span>
                      )}
                      {phase.requires.map((req) => (
                        <span
                          key={req}
                          title="inserted automatically before this phase"
                          className="metric rounded border border-accent/30 bg-accent/8 px-1 font-mono text-[9px] text-accent"
                        >
                          +{req}
                        </span>
                      ))}
                    </span>
                    <span className="mt-0.5 block text-[11px] leading-snug text-default-500">
                      {phase.description}
                    </span>
                  </span>
                </button>
              )
            })}
            {filtered.length === 0 && (
              <p className="px-3 py-6 text-center text-[11px] text-default-400">
                No step matches “{query}”.
              </p>
            )}
          </div>
        </Card.Content>
      </Card>

      {/* --- the pipeline --------------------------------------------------- */}
      <div className="flex min-w-0 flex-col gap-3">
        <Card className="w-full">
          <Card.Header className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <Card.Title className="text-sm font-semibold">2 · Order and options</Card.Title>
              <p className="mt-1 text-[11px] text-default-500">
                {selected.length} selected ·{' '}
                <span className="font-mono text-accent">{order.length} will run</span>
                {inserted.length > 0 && ` (${inserted.length} added for you)`}
              </p>
            </div>
          </Card.Header>

          <Card.Content className="flex flex-col gap-3">
            {selected.length === 0 ? (
              <p className="py-4 text-[11px] text-default-400">
                Nothing picked yet. Start from the triage preset, or click steps on the left.
              </p>
            ) : (
              <ol className="flex flex-col gap-1">
                {selected.map((phase, index) => {
                  const dragging = dragFrom === index
                  const showBefore = dropAt?.index === index && !dropAt.after && dragFrom !== null
                  const showAfter =
                    dropAt?.index === index && dropAt.after && dragFrom !== null &&
                    // No trailing line on the last row, which is where "after"
                    // and "the end" are the same position.
                    index < selected.length - 1
                  return (
                    <li
                      key={phase.name}
                      draggable
                      onDragStart={(e) => {
                        setDragFrom(index)
                        // Firefox refuses to start a drag without payload.
                        e.dataTransfer.effectAllowed = 'move'
                        e.dataTransfer.setData('text/plain', phase.name)
                      }}
                      onDragOver={(e) => {
                        // Without preventDefault the browser refuses the drop.
                        e.preventDefault()
                        e.dataTransfer.dropEffect = 'move'
                        const box = e.currentTarget.getBoundingClientRect()
                        setDropAt({ index, after: e.clientY > box.top + box.height / 2 })
                      }}
                      onDragLeave={() => setDropAt((cur) => (cur?.index === index ? null : cur))}
                      onDrop={(e) => {
                        e.preventDefault()
                        const box = e.currentTarget.getBoundingClientRect()
                        const after = e.clientY > box.top + box.height / 2
                        if (dragFrom !== null) {
                          reorder(dragFrom, dropTarget(dragFrom, index, after))
                        }
                        endDrag()
                      }}
                      onDragEnd={endDrag}
                      aria-label={`${index + 1}. ${phase.name} - drag to reorder`}
                      className={
                        'flex items-center gap-2 rounded-lg border px-2.5 py-1.5 transition-colors ' +
                        // The dragged row dims rather than disappearing, so the
                        // list does not reflow and lose the thing being moved.
                        (dragging ? 'border-accent/40 bg-accent/5 opacity-45 ' : 'border-default-200 ') +
                        // The insertion line, not a highlight on the row: the row
                        // is about to move out of the way, so colouring it says
                        // less than showing where the item will land. Top and
                        // bottom are different answers, hence two rules.
                        (showBefore ? 'border-t-2 border-t-accent ' : '') +
                        (showAfter ? 'border-b-2 border-b-accent ' : '')
                      }
                    >
                      {/* The grip is the affordance. Without it the row looks
                          draggable only after you have already tried to drag
                          it, which is how nobody discovers it. */}
                      <span
                        aria-hidden
                        title="Drag to reorder"
                        className="shrink-0 cursor-grab text-default-400 active:cursor-grabbing"
                      >
                        <Icon name="grip" size={12} />
                      </span>
                      <span className="metric w-5 shrink-0 text-center font-mono text-[10px] text-default-400">
                        {index + 1}
                      </span>
                    <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-foreground">
                      {phase.name}
                    </span>
                    {inserted.includes(phase.name) && (
                      <span className="metric rounded border border-accent/30 bg-accent/8 px-1 font-mono text-[9px] text-accent">
                        +{phase.requires.join(' ')}
                      </span>
                    )}
                    <button
                      type="button"
                      className="btn-ghost px-1"
                      onClick={() => move(index, -1)}
                      disabled={index === 0}
                      aria-label={`Move ${phase.name} earlier`}
                    >
                      <Icon name="chevron-up" size={12} />
                    </button>
                    <button
                      type="button"
                      className="btn-ghost px-1"
                      onClick={() => move(index, 1)}
                      disabled={index === selected.length - 1}
                      aria-label={`Move ${phase.name} later`}
                    >
                      <Icon name="chevron-down" size={12} />
                    </button>
                    <button
                      type="button"
                      className="btn-ghost px-1"
                      onClick={() => toggle(phase.name)}
                      aria-label={`Remove ${phase.name}`}
                    >
                      <Icon name="x" size={12} />
                    </button>
                    </li>
                  )
                })}
              </ol>
            )}

            {order.length > 0 && (
              <div>
                <p className="section-label mb-1.5">
                  Run order
                  <span className="ml-1.5 font-normal normal-case tracking-normal text-default-400">
                    as the analyzer will execute it
                  </span>
                </p>
                <div className="flex flex-wrap gap-1">
                  {order.map((phase, i) => (
                    <span
                      key={`${phase.name}-${i}`}
                      className={`metric inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[10px] ${
                        inserted.includes(phase.name)
                          ? 'border-dashed border-accent/50 bg-accent/8 text-accent'
                          : 'border-default-200 bg-default-50 text-default-600'
                      }`}
                      title={phase.description}
                    >
                      {inserted.includes(phase.name) && <Icon name="plus" size={9} />}
                      {phase.name}
                    </span>
                  ))}
                  {['export', 'summary'].map((epilogue) => (
                    <span
                      key={epilogue}
                      className="metric inline-flex items-center gap-1 rounded-md border border-dashed border-accent/50 bg-accent/8 px-1.5 py-0.5 font-mono text-[10px] text-accent"
                      title="appended automatically"
                    >
                      <Icon name="plus" size={9} />
                      {epilogue}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
              <OptionField
                label="Pipeline name"
                detail="Saved as pipelines/<name>.yaml and usable as --pipeline <name>."
                footnote={validName ? undefined : 'letters, digits, - and _'}
              >
                <input
                  className="field font-mono"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="triage_plus"
                  spellCheck={false}
                  aria-invalid={!validName}
                />
              </OptionField>
              <OptionField label="Description" detail="One line; shown by --list-pipelines.">
                <input
                  className="field"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="What this pipeline is for"
                />
              </OptionField>
            </div>

            {options.length > 0 && (
              <div>
                <p className="section-label mb-1.5">
                  Options
                  <span className="ml-1.5 font-normal normal-case tracking-normal text-default-400">
                    left unset means the analyzer default
                  </span>
                </p>
                <div className="grid grid-cols-1 gap-2 xl:grid-cols-2">
                  {options.map((option) =>
                    option.kind === 'flag' ? (
                      <Switch
                        key={option.key}
                        label={option.label}
                        checked={Boolean(env[option.key] ?? option.default)}
                        onChange={(v) => setEnv({ ...env, [option.key]: v })}
                        detail={option.detail}
                        footnote={option.honoured_by}
                      />
                    ) : (
                      <OptionField
                        key={option.key}
                        label={option.label}
                        detail={option.detail}
                        footnote={option.honoured_by}
                      >
                        <input
                          className="field font-mono"
                          type={option.kind === 'number' ? 'number' : 'text'}
                          min={option.min}
                          max={option.max}
                          step={option.kind === 'number' ? 'any' : undefined}
                          spellCheck={false}
                          placeholder={String(option.default ?? '')}
                          value={env[option.key] === undefined ? '' : String(env[option.key])}
                          onChange={(e) =>
                            setEnv({
                              ...env,
                              [option.key]:
                                e.target.value === ''
                                  ? undefined
                                  : option.kind === 'number'
                                    ? Number(e.target.value)
                                    : e.target.value,
                            })
                          }
                          aria-label={option.label}
                        />
                      </OptionField>
                    ),
                  )}
                </div>
              </div>
            )}
          </Card.Content>
        </Card>

        {/* --- the file ------------------------------------------------------ */}
        <Card className="w-full overflow-hidden">
          <Card.Header className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <Card.Title className="text-sm font-semibold">3 · Save it</Card.Title>
              <p className="mt-1 text-[11px] text-default-500">
                The file is validated against the analyzer's own rules before it replaces anything,
                and an existing name is never overwritten.
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <CopyButton text={draft} variant="outline">
                Copy YAML
              </CopyButton>
              <Button size="sm" variant="primary" onPress={() => void save()} isDisabled={!canSave}>
                <Icon name="check" size={13} />
                {saving ? 'Saving…' : `Save as ${slug}.yaml`}
              </Button>
            </div>
          </Card.Header>

          {selected.length === 0 ? (
            <Card.Content className="py-6 text-[11px] text-default-400">
              Pick at least one step - a pipeline with no phases is a config the analyzer refuses.
            </Card.Content>
          ) : (
            <div className="flex max-h-[20rem] flex-col border-t border-default-200">
              <pre className="metric overflow-x-auto px-3 py-2.5 font-mono text-[11px] leading-relaxed text-foreground">
                {draft}
              </pre>
            </div>
          )}

          {error && (
            <Card.Content className="pt-3">
              <Alert status="danger">
                <Alert.Title>Not saved</Alert.Title>
                <Alert.Description>{error}</Alert.Description>
              </Alert>
            </Card.Content>
          )}
        </Card>
      </div>
    </div>
  )
}