import { useState } from 'react'
import { Button } from '@heroui/react/button'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import { Sparkline, type SparkTone } from './Stat'
import { NetStrip } from './NetFacts'
import { ms } from '../lib/format'
import type { Probe } from '../types'

// HeroUI colour vocabulary: accent | danger | default | success | warning.
// up -> success, down -> danger. A TCP connect is still success - the port
// answered - but the label says "port open" so it is not mistaken for a
// healthy application.

export function StatusChip({ state, label }: { state: Probe | string; label?: string }) {
  const up = typeof state === 'string' ? state === 'up' : state.up
  return (
    <Chip color={up ? 'success' : 'danger'} size="sm" variant="soft">
      {label ?? (up ? 'UP' : 'DOWN')}
    </Chip>
  )
}

// Latency is the one number where "slow but up" and "down" are very different
// problems, so the tone reflects the round trip rather than just reachability.
function latencyTone(p: Probe): SparkTone {
  if (!p.up) return 'danger'
  if (p.ms > 500) return 'danger'
  if (p.ms > 200) return 'warning'
  return 'success'
}

// Copy-to-clipboard with inline confirmation. navigator.clipboard is unavailable
// on a non-secure origin and this panel is plain HTTP on loopback, so the
// textarea fallback is the path that actually runs - not a defensive afterthought.
//
// Exported because the Containers panel shows the same fact about the same
// services, and two copy buttons that drift apart is one more thing to keep in
// sync.
export function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value)
      } else {
        const el = document.createElement('textarea')
        el.value = value
        el.setAttribute('readonly', '')
        el.style.position = 'fixed'
        el.style.opacity = '0'
        document.body.appendChild(el)
        el.select()
        document.execCommand('copy')
        document.body.removeChild(el)
      }
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1600)
    } catch {
      setCopied(false)
    }
  }

  return (
    <button
      onClick={(e) => {
        e.stopPropagation()
        void copy()
      }}
      title={`Copy ${label}`}
      className={`rounded border px-1.5 py-0.5 text-[10px] font-medium transition-colors ${
        copied
          ? 'border-success/40 text-success'
          : 'border-default-200 text-default-400 hover:border-accent hover:text-accent'
      }`}
    >
      {copied ? 'copied' : 'copy'}
    </button>
  )
}

export interface ServiceNotice {
  tone: 'success' | 'warning'
  text: string
}

export function ServiceCard({ probe, onAction, busy, message, onContainers }: {
  probe: Probe
  /**
   * Present only for services the panel can supervise (probe.control). The
   * card never decides that itself: the backend's allowlist does, so a card
   * cannot offer a control that would 404.
   */
  onAction?: (action: 'start' | 'stop') => void
  /** The action in flight for this card, if any. */
  busy?: 'start' | 'stop'
  /** The last action's outcome, kept until the next click. */
  message?: ServiceNotice
  /**
   * Present when the card is a compose service (probe.container). Those are
   * started and stopped on the Containers page, so the card links there
   * instead of leaving the reader with a red DOWN and no next step.
   */
  onContainers?: () => void
}) {
  const [open, setOpen] = useState(false)

  // A TCP connect proves the port is listening and nothing more, so it never
  // claims to be a healthy application - the label says which check ran.
  const qualifier = probe.kind === 'tcp' && probe.up ? 'port open' : probe.code
  // 'auth' is its own state: the service answered, it just wants credentials.
  // Collapsing that into UP or DOWN would both be lies.
  const chipLabel = !probe.up
    ? 'DOWN'
    : probe.code === 'auth'
      ? 'AUTH'
      : probe.kind === 'tcp'
        ? 'PORT'
        : 'UP'
  const chipTone = !probe.up
    ? 'danger'
    : probe.code === 'auth'
      ? 'warning'
      : 'success'

  const routes = Object.entries(probe.routes ?? {})
  const detail = Object.entries(probe.detail).filter(([k]) => k !== 'routes')
  const hasMore = Boolean(probe.note) || detail.length > 0 || routes.length > 0
  const trendReady = probe.trend.ms.filter((v) => v !== null).length > 1

  return (
    <Card
      className={`service-card tone-${chipTone} w-full transition-colors ${open ? 'border-accent/30' : ''}`}
      onClick={() => hasMore && setOpen((o) => !o)}
    >
      <Card.Header className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <Card.Title className="truncate">{probe.name}</Card.Title>
          {/* host:port is the fact an operator actually needs - it is what they
              type into a browser, and what they grep for when it is wrong. */}
          <p className="mt-0.5 truncate font-mono text-[11px] text-default-400">
            {probe.host}:{probe.port}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          <Chip color={chipTone} size="sm" variant="soft">
            {chipLabel}
          </Chip>
        </div>
      </Card.Header>

      <Card.Content className="flex flex-col gap-2.5">
        {/* Routing facts under every card: which interface the address is on,
            its CIDR and class, and what the port is. Identifying an endpoint
            should not require a click. */}
        {probe.net && <NetStrip net={probe.net} />}
        {/* What it is for. Kept to two lines so six cards still scan as a list
            rather than as a wall of prose. */}
        <p className="text-xs leading-relaxed text-default-500">{probe.description}</p>

        {/* latency + trend */}
        <div className="flex items-end justify-between gap-3">
          <div className="min-w-0">
            <p className="font-mono text-sm tabular-nums text-foreground">
              {probe.up ? ms(probe.ms) : '—'}
              <span className="ml-1.5 text-[10px] font-normal text-default-400">
                {qualifier}
              </span>
            </p>
          </div>
          {trendReady && (
            <div className="w-24 shrink-0 opacity-80">
              <Sparkline data={probe.trend.ms} tone={latencyTone(probe)} height={26} />
            </div>
          )}
        </div>

        {/* endpoint, copyable */}
        <div className="flex items-center gap-2 rounded-md border border-default-200 bg-default-50/50 px-2 py-1">
          <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-default-600" title={probe.endpoint}>
            {probe.endpoint}
          </code>
          <CopyButton value={probe.endpoint} label="probe URL" />
        </div>

        {/* badges */}
        <div className="flex flex-wrap gap-1.5">
          <Chip size="sm" variant="soft">{probe.kind === 'tcp' ? 'TCP connect' : 'HTTP GET'}</Chip>
          {probe.auth && (
            <Chip size="sm" variant="soft" color="warning" title="Probed with a bearer token">
              token
            </Chip>
          )}
          {probe.ui_url && (
            <a
              href={probe.ui_url}
              target="_blank"
              rel="noreferrer noopener"
              onClick={(e) => e.stopPropagation()}
              className="rounded-full border border-default-200 px-2 py-0.5 text-[10px] font-medium text-default-500 hover:border-accent hover:text-accent"
            >
              open UI ↗
            </a>
          )}
        </div>

        {/* Start / Stop. Only the three Python services get this row - the
            card does not guess, it reads probe.control from the backend's
            allowlist. stopPropagation keeps a control click from also
            expanding the card underneath it. */}
        {onAction && probe.control && (
          <div className="service-control" onClick={(e) => e.stopPropagation()}>
            <Button
              size="sm"
              variant={probe.up ? 'danger-soft' : 'primary'}
              isDisabled={Boolean(busy) || (!probe.up && Boolean(probe.control_blocked))}
              onPress={() => onAction(probe.up ? 'stop' : 'start')}
              aria-busy={busy ? true : undefined}
            >
              {busy === 'start'
                ? 'Starting…'
                : busy === 'stop'
                  ? 'Stopping…'
                  : probe.up
                    ? 'Stop'
                    : 'Start'}
            </Button>
            {/* The reason a disabled Start is disabled belongs next to it,
                not in a tooltip that a disabled button will not show. */}
            <span className="service-control-note">
              {probe.up
                ? `listening on port ${probe.port}`
                : probe.control_blocked || 'not running'}
            </span>
          </div>
        )}

        {/* Containers: the panel cannot start these, so the card says where
            it can. The compose unit is named because the Containers page
            groups by project - without it "go to Containers" is a search. */}
        {probe.container && onContainers && (
          <div className="service-control" onClick={(e) => e.stopPropagation()}>
            <Button
              size="sm"
              variant="outline"
              onPress={onContainers}
            >
              Manage in Containers →
            </Button>
            <span className="service-control-note">
              {probe.container.project} / {probe.container.service}
            </span>
          </div>
        )}

        {message && (
          <p className={`service-notice is-${message.tone}`} title={message.text}>
            {message.text}
          </p>
        )}

        {/* expandable: the service's own words about itself */}
        {open && hasMore && (
          <div
            className="flex flex-col gap-2 border-t border-default-100 pt-2"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Secondary routes first - these are the fault that a green
                /health hides, so they lead the expanded view. */}
            {routes.length > 0 && (
              <div>
                <p className="eyebrow mb-1.5">routes</p>
                <div className="flex flex-wrap gap-1.5">
                  {routes.map(([path, code]) => (
                    <span
                      key={path}
                      title={`${probe.scheme}://${probe.host}:${probe.port}${path} → HTTP ${code}`}
                      className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${
                        code >= 200 && code < 400
                          ? 'border-success/30 text-success'
                          : code === 401 || code === 403
                            ? 'border-warning/30 text-warning'
                            : 'border-danger/30 text-danger'
                      }`}
                    >
                      {path} {code}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {probe.note && (
              <p className="break-words font-mono text-[11px] text-default-500">{probe.note}</p>
            )}
            {detail.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {detail.map(([k, v]) => (
                  <span
                    key={k}
                    className="rounded border border-default-200 px-1.5 py-0.5 font-mono text-[10px] text-default-500"
                  >
                    {k}={typeof v === 'object' ? JSON.stringify(v) : String(v)}
                  </span>
                ))}
              </div>
            )}
            <p className="text-[10px] text-default-400">
              {probe.trend.samples > 1
                ? `${probe.trend.samples} latency samples this session`
                : 'collecting latency history…'}
            </p>
          </div>
        )}
      </Card.Content>
    </Card>
  )
}
