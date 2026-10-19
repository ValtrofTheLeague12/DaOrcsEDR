import { useMemo, useRef, useState } from 'react'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import { Alert } from '@heroui/react/alert'
import { api, usePoll } from '../api'
import Pager, { usePaged } from './Pager'
import VmMetricsPanel from './VmMetricsPanel'
import Icon from './Icon'
import { LogRow, parseLine } from '../lib/logColor'
import type { VmInfo, VmList } from '../types'

// ---------------------------------------------------------------------------
// VirtualBox machines - the fleet.
//
// The one list on this page with a real chance of being long: a research host
// accumulates VMs, and most of them are not the one you came to look at. So
// every machine gets a card, and the cards are paged and filterable rather than
// scrolled - a scroll that pushes the machine you want below the fold is the
// problem this is here to solve.
//
// Duplicates are already gone by the time this renders: the backend collapses
// repeated registrations by UUID. The count it dropped is surfaced as a chip
// rather than discarded, because a machine vanishing from the fleet with no
// explanation is exactly the sort of thing an operator assumes is a VirtualBox
// fault and goes debugging for an hour.
//
// Start and Close live here rather than in the CLI because starting a sandbox is
// a thing you do constantly while debugging why a run failed, and making it a
// terminal detour for every attempt is how people end up with six VMs booted at
// once. The actions are still gated: the backend checks the name against the
// registered machine list before VBoxManage is involved, so the button cannot be
// pointed at anything that is not a real machine on this host.
//
// "Close" is a hard poweroff, deliberately labelled the way an operator thinks
// about it rather than the way VBoxManage names it. A guest running malware can
// ignore an ACPI power button, and a sandbox that will not shut down is worse
// than one that loses a snapshot.
// ---------------------------------------------------------------------------

const POLL_MS = 10000

const PAGE_SIZES = [4, 8, 16, 32]

type StatusFilter = 'all' | 'running' | 'stopped'

/** Headless is the default everywhere; GUI opens the guest console. */
type LaunchMode = 'headless' | 'gui'

function ServiceChips({ vm }: { vm: VmInfo }) {
  const open = vm.services.filter((s) => s.open)
  if (!vm.probed) {
    return (
      <span className="text-[11px] text-muted">
        {vm.running ? 'no address' : 'not probed'}
      </span>
    )
  }
  if (open.length === 0) {
    return <span className="text-[11px] text-muted">nothing listening</span>
  }
  return (
    <span className="flex flex-wrap gap-1">
      {open.map((s) => (
        <span
          key={s.port}
          title={`${s.detail} (tcp/${s.port})`}
          className="rounded-full bg-success/12 px-2 py-0.5 font-mono text-[10.5px] text-success"
        >
          {s.name} {s.port}
        </span>
      ))}
    </span>
  )
}

// A VirtualBox run log is the fleet's record of what the last Start or Close
// actually did, so it is the first place an operator looks when a boot failed.
// Two facts about it drove this component:
//
//   1. It is long and almost entirely uninteresting. A real 80-line run log is
//      73 interrupt counters and MSR resets, and the four lines that say what
//      happened are in the last second of it. So it is collapsed to the tail -
//      the end is where the answer is - with the count of what is hidden.
//
//   2. It arrives every 10s with the rest of the poll. So the controls are
//      local to the card and reset when the card unmounts, and the collapsed
//      view stays collapsed rather than re-expanding under the reader on every
//      tick.
//
// The severity split is the part worth having. A run log is mostly telemetry
// with a few lines that matter, and before parseLine understood the VirtualBox
// shape every line in it rendered the same grey - so the reader's only option
// was to read all eighty to find the two that counted. The counts in the header
// and the "first problem" jump are what that cost them, and are the reason this
// is more than a <pre>.
type Severity = 'all' | 'error' | 'warning'

// How much of the log to show, as an index into this list. The last entry is
// Infinity, meaning "the whole thing" - `slice(-Infinity)` is the whole array,
// so one expression covers every step.
//
// This is a series rather than the old one-way "show all / collapse" toggle
// because both extremes are wrong most of the time. A run log's four lines that
// matter sit in its last second, so 6 is a sensible default and all 80 is
// rarely what anyone wants; what is wanted is "a bit more", to see the line
// before the one that failed. A binary toggle answers that with a jump from 6
// to 80 and then all the way back down, re-scrolling past the interesting part
// to get there. Steps land on 6 / 12 / 24 / 48 / 96 / all, which is a click or
// two either way and keeps the tail anchored, because a shorter view is always
// the LAST n lines and never a different window of them.
const LOG_STEPS = [6, 12, 24, 48, 96, Infinity]

function RunLog({ text }: { text: string }) {
  const [rawStep, setRawStep] = useState(0)
  const [needle, setNeedle] = useState('')
  const [severity, setSeverity] = useState<Severity>('all')
  // Wrap is on by default here, unlike the Logs panel.
  //
  // A VirtualBox line is "<component>: <message>" with no natural break, and a
  // card is half the width of the screen. With wrap off the long ones ran off
  // the edge of the card and were simply cut - "Power up failed (Vrc=VINF_SUCCE"
  // is worse than useless, because it looks like a complete sentence. Wrapping
  // costs a second line on the rare long message and clips nothing. The toggle
  // is still there for reading a column of aligned telemetry.
  const [wrap, setWrap] = useState(true)
  const bodyRef = useRef<HTMLDivElement>(null)
  const jumpRef = useRef<HTMLDivElement>(null)

  // Split on \r?\n, not \n.
  //
  // VBoxHeadless runs on Windows and writes CRLF, and the run log captured here
  // really does arrive with mixed endings - 79 bare LF and one trailing CRLF on
  // the final line. A plain \n split leaves that \r sitting on the end of the
  // line, and JavaScript's `.` does not match a carriage return, so the whole
  // regex fails and "VBoxHeadless: exiting" - a genuinely useful last line -
  // rendered as unparsed grey. On a fully CRLF log every line would fail.
  const lines = useMemo(() => text.split(/\r?\n/).filter((l) => l.length > 0), [text])
  const parsed = useMemo(() => lines.map(parseLine), [lines])

  const counts = useMemo(() => {
    let error = 0
    let warning = 0
    for (const p of parsed) {
      if (p.tone === 'danger') error += 1
      else if (p.tone === 'warning') warning += 1
    }
    return { error, warning }
  }, [parsed])

  // First line worth stopping at. -1 means nothing notable, which is a real and
  // common answer for a clean Close and must not be dressed up as a problem.
  const firstProblem = useMemo(
    () => parsed.findIndex((p) => p.notable),
    [parsed],
  )

  const query = needle.trim()
  const filtering = query !== '' || severity !== 'all'

  // The steps this log can actually move between.
  //
  // A step that would show the whole log anyway is removed, because pressing +
  // and having nothing change is worse than having no button: it reads as a
  // broken control rather than as a redundant one. On an 80-line log that drops
  // 96 and leaves 6 / 12 / 24 / 48 / all, so every press moves. On a 27-line log
  // it drops 48 and 96.
  const steps = useMemo(
    () => [...LOG_STEPS.filter((n) => n < lines.length), Infinity],
    [lines.length],
  )
  // Clamped on read, because the log is replaced by every poll and a shorter one
  // can leave `step` pointing past the end of a now-shorter list.
  const step = Math.min(rawStep, steps.length - 1)
  const limit = steps[step]
  const expanded = step > 0

  // Filtered, or not, the row keeps the line number it has in the whole log -
  // a filter that renumbers everything makes "line 74" impossible to go back to.
  const rows = useMemo(() => {
    const hit = query.toLowerCase()
    return parsed
      .map((p, index) => ({ p, index }))
      .filter(({ p, index }) => {
        if (severity === 'error' && p.tone !== 'danger') return false
        if (severity === 'warning' && p.tone !== 'warning') return false
        if (!hit) return true
        return lines[index].toLowerCase().includes(hit)
      })
  }, [parsed, lines, query, severity])

  // Filtering is an explicit request to see something, so it overrides the tail
  // rather than quietly showing six of the matches. Otherwise the view is always
  // the last `limit` rows - `slice(-Infinity)` returns the whole array, so the
  // "show everything" step needs no branch of its own.
  const shown = filtering ? rows : rows.slice(-limit)
  const hidden = filtering || limit === Infinity ? 0 : Math.max(0, rows.length - limit)

  const extend = () => setRawStep((s) => Math.min(s + 1, steps.length - 1))
  const reduce = () => setRawStep((s) => Math.max(s - 1, 0))

  // Nothing to grow into: the whole log already fits in the default view, so the
  // stepper is hidden rather than shown inert.
  const canStep = lines.length > LOG_STEPS[0]

  const jumpToProblem = () => {
    // Extend all the way rather than one step: the point of the jump is to land
    // on the line, and if it is still hidden a scrollIntoView has nothing to
    // scroll to.
    setRawStep(steps.length - 1)
    // The row does not exist until the next paint, so scroll after it lands.
    requestAnimationFrame(() => {
      jumpRef.current?.scrollIntoView({ block: 'center', behavior: 'smooth' })
    })
  }

  return (
    <div className="fleet-vm-log-label">
      <div className="fleet-vm-log-head">
        <span>VM run log</span>
        <span className="font-normal text-muted">
          VirtualBox · {lines.length} line{lines.length === 1 ? '' : 's'}
          {hidden > 0 && ` · showing last ${limit}`}
          {expanded && limit === Infinity && ' · showing all'}
        </span>
      </div>

      <div className="fleet-vm-log-controls">
        {counts.error > 0 && (
          <Chip size="sm" variant="soft" color="danger">{counts.error} error</Chip>
        )}
        {counts.warning > 0 && (
          <Chip size="sm" variant="soft" color="warning">{counts.warning} warn</Chip>
        )}
        {counts.error === 0 && counts.warning === 0 && (
          <Chip size="sm" variant="soft" color="success">clean</Chip>
        )}
        {firstProblem >= 0 && (
          <button type="button" className="fleet-vm-log-toggle" onClick={jumpToProblem}>
            Jump to first problem
          </button>
        )}

        {/* The size stepper. Right-aligned so it sits at the end of the row and
            reads as a control on the log rather than as another piece of
            information about it - the chips beside it are data. */}
        {canStep && (
          <div className="fleet-vm-log-size">
            <button
              type="button"
              onClick={reduce}
              disabled={step === 0}
              title="Show fewer lines"
              aria-label="Show fewer log lines"
            >
              <Icon name="chevron-up" size={11} />
            </button>
            <span
              className="fleet-vm-log-count"
              title={
                limit === Infinity
                  ? `Showing all ${lines.length} lines`
                  : `Showing the last ${limit} of ${lines.length} lines`
              }
            >
              {limit === Infinity ? 'all' : limit}
            </span>
            <button
              type="button"
              onClick={extend}
              disabled={step >= steps.length - 1}
              title={limit === Infinity ? 'Everything is shown' : 'Show more lines'}
              aria-label="Show more log lines"
            >
              <Icon name="chevron-down" size={11} />
            </button>
          </div>
        )}
      </div>

      {/* Search, severity and wrap only appear once the log is actually open.
          In a fleet grid this row was on every card at once, and a search box
          plus a three-way segment plus a toggle is a small toolbar repeated
          eight times on a page whose real subject is eight machines. Collapsed,
          the severity chips and the jump link are what carry the information;
          the controls come when there is something to control. */}
      {(expanded || filtering) && (
        <div className="log-controls">
          <input
            value={needle}
            onChange={(e) => setNeedle(e.target.value)}
            placeholder="Search this run log…"
            aria-label="Search this VM run log"
            className="log-search"
          />
          <div className="log-severity" role="group" aria-label="Filter by severity">
            {(['all', 'error', 'warning'] as Severity[]).map((value) => (
              <button
                key={value}
                type="button"
                onClick={() => setSeverity(value)}
                aria-pressed={severity === value}
                className={severity === value ? 'is-on' : ''}
              >
                {value}
              </button>
            ))}
          </div>
          <button type="button" onClick={() => setWrap((w) => !w)} className="log-toggle">
            {wrap ? 'No wrap' : 'Wrap'}
          </button>
        </div>
      )}

      <div
        className="fleet-vm-log"
        role="log"
        aria-label="VirtualBox run log"
        ref={bodyRef}
      >
        {hidden > 0 && (
          <div className="log-view-row is-faded">
            <span className="log-view-gutter">···</span>
            <span className="log-view-body is-nowrap">
              {hidden} earlier line{hidden === 1 ? '' : 's'} hidden
            </span>
          </div>
        )}
        {shown.map(({ index }) => (
          <div key={index} ref={index === firstProblem ? jumpRef : undefined}>
            <LogRow line={lines[index]} number={index + 1} wrap={wrap} query={query} />
          </div>
        ))}
        {shown.length === 0 && (
          <p className="py-3 text-center text-[11px] text-muted">
            No line matches the current filter.
          </p>
        )}
      </div>

      {/* Only the filter is cleared here. "Show all / collapse" moved to the
          stepper above, where it is one press rather than a separate control
          that duplicates what the + button already does. */}
      {filtering && (
        <button
          type="button"
          onClick={() => { setSeverity('all'); setNeedle('') }}
          className="fleet-vm-log-toggle"
        >
          Clear filter
        </button>
      )}
    </div>
  )
}

/**
 * What the guest says about itself, from `VBoxManage guestproperty enumerate`.
 *
 * Separate from the card's `os` field on purpose, because they routinely
 * disagree: `os` is the ostype the machine was CONFIGURED as, and this host's
 * own machine is configured "Ubuntu (64-bit)" while the guest reports
 * "7.0.12+kali-amd64". A card that only ever showed the configured type would
 * be confidently wrong about what it is running.
 *
 * Rendered only when there is something to say. A powered-off machine has no
 * live guest properties and a machine without Guest Additions never has any -
 * neither is worth a row that says "unknown".
 */
function GuestBlock({ vm }: { vm: VmInfo }) {
  const g = vm.guest
  // Read the list before the guard rather than inside it.
  //
  // The backend sends `{}` for a machine with no Guest Additions, so `net` is
  // absent - and `!g.additions && !g.release && !g.hostname && g.net.length`
  // short-circuits straight into `undefined.length` and throws on exactly the
  // machines most likely to be in the list. Every powered-off VM on the fleet
  // took the card down with it.
  const nics = g?.net ?? []
  if (!g || (!g.additions && !g.release && !g.hostname && nics.length === 0)) return null

  const os = [g.product, g.release].filter(Boolean).join(' ') || null

  return (
    <div className="fleet-vm-guest">
      <div className="fleet-vm-guest-head">
        <span className="eyebrow">Guest</span>
        {g.additions && (
          <span className="fleet-vm-additions" title="Guest Additions version reported by the guest">
            Additions {g.additions}
          </span>
        )}
      </div>

      <dl className="fleet-vm-guest-facts">
        <div>
          <dt>OS</dt>
          <dd title={g.version ?? undefined}>{os ?? '—'}</dd>
        </div>
        <div>
          <dt>Hostname</dt>
          <dd>{g.hostname ?? '—'}</dd>
        </div>
        <div>
          <dt>Logged on</dt>
          <dd>{g.logged_on_users?.length ? g.logged_on_users.join(', ') : '—'}</dd>
        </div>
      </dl>

      {/* One line per adapter, because v4 and v6 on the same line would read as
          two machines. The prefix is shown with the address rather than as a
          dotted mask - the guest reports a prefix length and converting it
          would be a lossy guess about something the operator will paste into
          an nmap target. */}
      {nics.length > 0 && (
        <ul className="fleet-vm-nics">
          {nics.map((nic) => (
            <li key={nic.index}>
              <span className="fleet-vm-nic-name">NIC {nic.index}</span>
              <code>{nic.v4}{nic.v4_prefix !== null ? `/${nic.v4_prefix}` : ''}</code>
              {nic.v6 && <code className="fleet-vm-nic-v6">{nic.v6}</code>}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

/**
 * The IPv4 cell: what the guest reported, or - when it is powered off and has
 * reported nothing - where the project's own config expects it to be.
 *
 * The two are never merged. `vm_info.json` is what the Qiling tooling, ClamAV
 * collector and the SSH metrics all dial, so while a machine is down that is
 * genuinely the address an operator wants to see, and an em dash implied
 * nothing was configured when in fact the whole lab is pointed at it. But it is
 * an expectation, not a measurement, so it is drawn in the muted "configured"
 * style and says so on hover rather than sitting in the live slot pretending
 * to be a reading.
 */
function AddressCell({ vm }: { vm: VmInfo }) {
  const cfg = vm.configured
  if (vm.ip) {
    return (
      <div>
        <span>IPv4</span>
        <strong title={`Reported by the guest${cfg ? ` · vm_info.json expects ${cfg.ip}` : ''}`}>
          {vm.ip}
        </strong>
      </div>
    )
  }
  if (cfg) {
    return (
      <div>
        {/* The marker sits in the LABEL row, not beside the address. Putting it
            after the value pushed a 15-character address past the column and
            ellipsised it, which is the one thing this cell exists to show. */}
        <span>
          IPv4 <em className="fleet-vm-configured">configured</em>
        </span>
        <strong className="is-configured" title={
          'Not reported — this machine is not running.\n' +
          `Expected address from ${cfg.source} (ssh/${cfg.port}).\n` +
          'This is where the tooling is pointed, not a live reading.'
        }>
          {cfg.ip}
        </strong>
      </div>
    )
  }
  return (
    <div>
      <span>IPv4</span>
      <strong>—</strong>
    </div>
  )
}

function MachineCard({
  vm,
  busy,
  mode,
  onMode,
  onAction,
}: {
  vm: VmInfo
  busy: { name: string; action: 'start' | 'stop' } | null
  mode: LaunchMode
  onMode: (name: string, mode: LaunchMode) => void
  onAction: (vm: VmInfo, action: 'start' | 'stop') => void
}) {
  const mine = busy?.name === vm.name
  const locked = busy !== null
  // Decided server-side so this chip and the run log's severity split cannot
  // disagree about what counts as a crash.
  const crashed = vm.crashed === true
  return (
    <Card className={`fleet-vm-card w-full ${crashed ? 'is-crashed' : ''}`}>
      <Card.Header className="fleet-vm-head">
        <div className="min-w-0 flex-1">
          <div className="flex min-w-0 items-center gap-1.5">
            <span className={`fleet-vm-indicator ${vm.running ? 'is-running' : ''} ${crashed ? 'is-crashed' : ''}`} />
            <Card.Title className="truncate font-mono text-[12px]" title={vm.name}>
              {vm.name}
            </Card.Title>
            <Chip size="sm" variant="soft" color={crashed ? 'danger' : vm.running ? 'success' : 'default'}>
              {vm.state}
            </Chip>
          </div>
          <p className="mt-0.5 truncate text-[10px] text-muted">
            {vm.os ?? 'Guest OS not reported'}
          </p>
        </div>

        {/* Both buttons are always present. An operator looking at a running
            machine wants to know Close is one click away, and a control that
            appears and disappears with the power state is a control you have to
            hunt for. The inapplicable one is disabled, not removed. */}
        <div className="fleet-vm-actions">
          {/* Headless stays the default because it is what this lab assumes, but
              it is a choice rather than a constant: a boot that only fails
              visibly on the guest console is exactly when an operator wants a
              window. Disabled while running, since the mode describes the NEXT
              start and there is none to configure. */}
          <select
            value={mode}
            onChange={(e) => onMode(vm.name, e.target.value === 'gui' ? 'gui' : 'headless')}
            disabled={vm.running || locked}
            title={vm.running
              ? 'Launch mode applies to the next start'
              : 'Headless runs with no window; GUI opens the guest console'}
            aria-label={`Launch mode for ${vm.name}`}
            className="fleet-vm-mode"
          >
            <option value="headless">Headless</option>
            <option value="gui">GUI</option>
          </select>
          <button
            onClick={() => onAction(vm, 'start')}
            disabled={locked || vm.running}
            title={vm.running
              ? 'Already running'
              : `Boot this machine ${mode === 'gui' ? 'with a window' : 'headless'}`}
            className="fleet-vm-action start"
          >
            {mine && busy?.action === 'start' ? 'Starting…' : 'Start'}
          </button>
          <button
            onClick={() => onAction(vm, 'stop')}
            disabled={locked || !vm.running}
            title={vm.running ? 'Hard power off' : 'Not running'}
            className="fleet-vm-action stop"
          >
            {mine && busy?.action === 'stop' ? 'Closing…' : 'Close'}
          </button>
        </div>
      </Card.Header>

      <Card.Content className="fleet-vm-body">
        {/* A machine that failed is not the same as a machine that is off, and
            the difference is the whole reason this panel exists during an
            incident. Without this the card reads as an ordinary powered-off VM
            and the one thing worth knowing is the thing you have to go looking
            for in the log. */}
        {crashed && (
          <Alert status="danger">
            <Alert.Title>This machine stopped abnormally</Alert.Title>
            <Alert.Description>
              VirtualBox reports state <code>{vm.state}</code>, which a machine
              only reaches by failing. The last lines of the run log below carry
              the reason; the same text is in the log's own summary.
            </Alert.Description>
          </Alert>
        )}

        {vm.error && (
          <Alert status="danger">
            <Alert.Description>{vm.error}</Alert.Description>
          </Alert>
        )}

        {/* IPv4 and IPv6 sit side by side rather than one replacing the other.
            A dual-stack sandbox has both, and a card showing only the v4 reads
            as "this is the address" when it is one of two. The wide columns are
            sized for the v6 case; the narrow ones hold a core count. */}
        <div className="fleet-vm-facts">
          <AddressCell vm={vm} />
          <div>
            <span>IPv6</span>
            <strong title={vm.ip6 ?? undefined}>{vm.ip6 ?? '—'}</strong>
          </div>
          <div><span>CPU</span><strong>{vm.cpus ? `${vm.cpus}c` : '—'}</strong></div>
          <div>
            <span>Memory</span>
            <strong>{vm.memory_mb
              ? vm.memory_mb >= 1024
                ? `${(vm.memory_mb / 1024).toFixed(1)}G`
                : `${vm.memory_mb}M`
              : '—'}</strong>
          </div>
        </div>

        <GuestBlock vm={vm} />

        <div className="fleet-vm-services">
          <span className="eyebrow">Detected services</span>
          <ServiceChips vm={vm} />
        </div>

        <VmMetricsPanel metrics={vm.metrics} />

        {vm.run_log && <RunLog text={vm.run_log} />}
      </Card.Content>
    </Card>
  )
}

export default function VmListPanel() {
  const { data, error, refresh } = usePoll<VmList>(api.vms, POLL_MS)
  const [busy, setBusy] = useState<{ name: string; action: 'start' | 'stop' } | null>(null)
  const [notice, setNotice] = useState<{ tone: 'ok' | 'bad'; text: string } | null>(null)
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState<StatusFilter>('all')
  const [pageSize, setPageSize] = useState(8)
  // Per machine, not one global setting: half a fleet booted headless for the
  // Qiling tooling and the other half open on a console while somebody watches
  // a boot is a normal thing to want, and a single global combo would force the
  // operator to change it back and forth for every machine.
  const [modes, setModes] = useState<Record<string, LaunchMode>>({})

  const modeFor = (name: string): LaunchMode => modes[name] ?? 'headless'
  const setMode = (name: string, mode: LaunchMode) =>
    setModes((prev) => ({ ...prev, [name]: mode }))

  // Filter before paging, never after: Pager counts what it is handed, so
  // paging first would make "8 of 34" mean something different from what the
  // filter box says it selected.
  const filtered = useMemo(() => {
    const all = data?.vms ?? []
    const needle = query.trim().toLowerCase()
    return all.filter((vm) => {
      if (status === 'running' && !vm.running) return false
      if (status === 'stopped' && vm.running) return false
      if (!needle) return true
      return [vm.name, vm.ip, vm.os, vm.state, vm.adapter]
        .filter(Boolean)
        .some((field) => String(field).toLowerCase().includes(needle))
    })
  }, [data?.vms, query, status])

  const paged = usePaged(filtered, pageSize)

  const onAction = async (vm: VmInfo, action: 'start' | 'stop') => {
    setBusy({ name: vm.name, action })
    setNotice(null)
    // Read the mode the card is showing, so the confirmation and the command
    // cannot disagree if the combo is changed mid-flight.
    const headless = modeFor(vm.name) !== 'gui'
    try {
      const res = await api.vmAction(vm.name, action, headless)
      setNotice({
        tone: res.ok ? 'ok' : 'bad',
        text: res.ok
          ? `${vm.name}: ${action === 'start'
              ? `started (${res.headless === false ? 'gui' : 'headless'})`
              : 'closed'}.`
          // A refused start is the common crash case and the detail is the only
          // thing worth reading, so it is shown verbatim rather than summarised.
          : `${vm.name} could not ${action === 'start' ? 'start' : 'close'}: ${res.detail}`,
      })
      refresh()
    } catch (e) {
      const detail = e instanceof Error ? e.message : String(e)
      setNotice({ tone: 'bad', text: detail })
    } finally {
      setBusy(null)
    }
  }

  const duplicates = data?.counts.duplicates ?? 0
  const crashed = (data?.vms ?? []).filter((vm) => vm.crashed === true)

  return (
    <Card className="w-full">
      <Card.Header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Card.Title className="text-sm font-semibold">Live VirtualBox fleet</Card.Title>
          <p className="mt-1 text-[11px] text-muted">
            {filtered.length === data?.vms.length
              ? 'Paginated inventory, power controls, and live guest metrics.'
              : `${filtered.length} of ${data?.vms.length ?? 0} machines match the filter.`}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {duplicates > 0 && (
            <Chip size="sm" variant="soft" color="warning"
                  title={`Collapsed duplicate registrations: ${data?.duplicate_names.join(', ')}`}>
              {duplicates} duplicate{duplicates === 1 ? '' : 's'} collapsed
            </Chip>
          )}
          {data?.available && (
            <>
              <Chip size="sm" variant="soft" color="success">
                {data.counts.running} running
              </Chip>
              <Chip size="sm" variant="soft">{data.counts.total} registered</Chip>
            </>
          )}
        </div>
      </Card.Header>

      <Card.Content className="flex flex-col gap-3">
        {notice && (
          <Alert status={notice.tone === 'ok' ? 'success' : 'danger'}>
            <Alert.Description>{notice.text}</Alert.Description>
          </Alert>
        )}

        {error && (
          <Alert status="danger">
            <Alert.Title>Cannot read machines</Alert.Title>
            <Alert.Description>{error}</Alert.Description>
          </Alert>
        )}

        {/* Fleet-level, because a crash on page 4 is not visible from page 1.
            The per-card alert says the same thing in place, but a card you are
            not currently looking at says nothing at all. */}
        {crashed.length > 0 && (
          <Alert status="danger">
            <Alert.Title>
              {crashed.length} machine{crashed.length === 1 ? '' : 's'} stopped abnormally
            </Alert.Title>
            <Alert.Description>
              {crashed.map((vm) => `${vm.name} (${vm.state})`).join(', ')}. These
              are not ordinary power-offs; each card carries the tail of its run
              log.
            </Alert.Description>
          </Alert>
        )}

        {data && !data.available && (
          <p className="py-4 text-center text-[12px] text-muted">
            VirtualBox is not available on this host. {data.error ?? ''}
          </p>
        )}

        {data?.available && data.vms.length > 0 && (
          <div className="fleet-vm-toolbar">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by name, address, OS or adapter…"
              aria-label="Filter machines"
              className="fleet-vm-search"
            />
            <div className="fleet-vm-segment" role="group" aria-label="Filter by state">
              {(['all', 'running', 'stopped'] as StatusFilter[]).map((value) => (
                <button
                  key={value}
                  onClick={() => setStatus(value)}
                  aria-pressed={status === value}
                  className={status === value ? 'is-on' : ''}
                >
                  {value}
                </button>
              ))}
            </div>
            <label className="fleet-vm-pagesize">
              <span>Rows</span>
              <select
                value={pageSize}
                onChange={(e) => setPageSize(Number(e.target.value))}
                aria-label="Machines per page"
              >
                {PAGE_SIZES.map((n) => (
                  <option key={n} value={n}>{n}</option>
                ))}
              </select>
            </label>
          </div>
        )}

        {data?.available && data.vms.length === 0 && (
          <p className="py-4 text-center text-[12px] text-muted">
            No machines registered. Create one in VirtualBox, then rescan.
          </p>
        )}

        {data?.available && data.vms.length > 0 && filtered.length === 0 && (
          <p className="py-6 text-center text-[12px] text-muted">
            Nothing matches that filter.
          </p>
        )}

        {filtered.length > 0 && (
          <div className="fleet-vm-grid">
            {paged.slice.map((vm) => (
              <MachineCard
                key={vm.uuid ?? vm.name}
                vm={vm}
                busy={busy}
                mode={modeFor(vm.name)}
                onMode={setMode}
                onAction={onAction}
              />
            ))}
          </div>
        )}

        {filtered.length > 0 && (
          <Pager
            page={paged.page}
            pages={paged.pages}
            first={paged.first}
            last={paged.last}
            total={filtered.length}
            onPrev={paged.prev}
            onNext={paged.next}
          />
        )}
      </Card.Content>
    </Card>
  )
}