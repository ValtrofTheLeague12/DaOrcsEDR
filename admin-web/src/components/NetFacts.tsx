import Icon from './Icon'
import type { IpFacts, NetFacts, PortFacts } from '../types'

// ---------------------------------------------------------------------------
// IP and port, drawn.
//
// A raw "127.0.0.1:60100" tells an admin nothing they can act on. This renders
// the two halves of that address as the things they actually reason about:
//
//   IP    the octet breakdown, the prefix length as a bit bar (how many bits
//         are network vs host), the scope, and the legacy class - flagged as
//         legacy, because classful addressing died in 1993 and 137.x is the
//         same size as 140.x.
//
//   Port  where it sits on the 0-65535 scale, whether it is a well-known,
//         registered or dynamic port, and whether it is a real IANA
//         registration or a convention this lab invented.
//
// Everything shown is derived from the address itself server-side. Nothing here
// guesses, and anything unknowable renders as an explicit "unknown" rather than
// a plausible default.
// ---------------------------------------------------------------------------

const SCOPE_TONE: Record<IpFacts['scope'], string> = {
  loopback: 'bg-accent/12 text-accent',
  private: 'bg-success/12 text-success',
  'link-local': 'bg-warning/12 text-warning',
  multicast: 'bg-warning/12 text-warning',
  reserved: 'bg-danger/12 text-danger',
  public: 'bg-danger/12 text-danger',
  hostname: 'bg-default-200 text-default-500',
  ipv6: 'bg-default-200 text-default-500',
}

const BAND_TONE: Record<PortFacts['band'], string> = {
  'well-known': 'text-danger',
  registered: 'text-warning',
  dynamic: 'text-accent',
}

const SOURCE_TONE: Record<PortFacts['source'], string> = {
  iana: 'bg-success/12 text-success',
  'de-facto': 'bg-warning/12 text-warning',
  unregistered: 'bg-default-200 text-default-400',
}

const SOURCE_LABEL: Record<PortFacts['source'], string> = {
  iana: 'IANA',
  'de-facto': 'de facto',
  unregistered: 'unregistered',
}

function Badge({
  tone,
  children,
  title,
}: {
  tone: string
  children: React.ReactNode
  title?: string
}) {
  return (
    <span
      title={title}
      className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${tone}`}
    >
      {children}
    </span>
  )
}

/** 32-bit split: filled = network bits, dim = host bits. Ticks at octet edges. */
function PrefixBar({ prefix }: { prefix: number }) {
  const pct = (prefix / 32) * 100
  return (
    <div className="w-full">
      <div
        className="relative h-2 w-full overflow-hidden rounded-full bg-default-200"
        role="img"
        aria-label={`/${prefix} prefix: ${prefix} network bits, ${32 - prefix} host bits`}
      >
        <div
          className="h-full rounded-full bg-accent/70"
          style={{ width: `${pct}%` }}
        />
        {/* octet boundaries at 8/16/24 - where the dots in the address fall */}
        {[8, 16, 24].map((bit) => (
          <span
            key={bit}
            className="absolute top-0 h-full w-px bg-background/70"
            style={{ left: `${(bit / 32) * 100}%` }}
          />
        ))}
        <span
          className="absolute top-0 h-full w-0.5 bg-foreground"
          style={{ left: `${pct}%` }}
        />
      </div>
      <div className="mt-1 flex justify-between font-mono text-[9px] text-default-400">
        <span>network {prefix} bits</span>
        <span>host {32 - prefix} bits</span>
      </div>
    </div>
  )
}

/** Where the port sits on the full 0-65535 range, with the two band edges. */
function PortScale({ port }: { port: number }) {
  const pos = (port / 65535) * 100
  return (
    <div className="w-full">
      <div
        className="relative h-2 w-full overflow-hidden rounded-full bg-default-200"
        role="img"
        aria-label={`port ${port}, ${(port / 65535 * 100).toFixed(1)} percent up the range`}
      >
        <div className="absolute inset-y-0 left-0 bg-danger/25" style={{ width: `${(1024 / 65535) * 100}%` }} />
        <div
          className="absolute inset-y-0 bg-warning/25"
          style={{ left: `${(1024 / 65535) * 100}%`, width: `${((49152 - 1024) / 65535) * 100}%` }}
        />
        <div
          className="absolute inset-y-0 bg-accent/25"
          style={{ left: `${(49152 / 65535) * 100}%`, right: 0 }}
        />
        <span
          className="absolute top-0 h-full w-0.5 bg-foreground"
          style={{ left: `${pos}%` }}
        />
      </div>
      <div className="mt-1 flex justify-between font-mono text-[9px] text-default-400">
        <span>0</span>
        <span>1023</span>
        <span>49151</span>
        <span>65535</span>
      </div>
    </div>
  )
}

export function IpBlock({ ip }: { ip: IpFacts }) {
  return (
    <div className="flex flex-col gap-2.5 rounded-lg border border-default-200 bg-default-50/40 p-3">
      {/* octets */}
      <div className="flex items-center gap-1.5">
        <span className="eyebrow mr-1">address</span>
        {ip.octets ? (
          <>
            {ip.octets.map((o, i) => (
              <span key={i} className="flex items-center gap-1.5">
                {/* The first octet is the one the legacy class was read off, so
                    it gets the emphasis. */}
                <span
                  className={`min-w-[2.25rem] rounded px-1.5 py-0.5 text-center font-mono text-[13px] tabular-nums ${
                    i === 0
                      ? 'bg-accent/15 text-foreground ring-1 ring-accent/30'
                      : 'bg-default-200/70 text-foreground'
                  }`}
                >
                  {o}
                </span>
                {i < 3 && <span className="text-default-400">.</span>}
              </span>
            ))}
          </>
        ) : (
          <span className="font-mono text-[13px] text-foreground">{ip.ip}</span>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <Badge tone={SCOPE_TONE[ip.scope]} title={ip.scope_meaning}>
          {ip.scope}
        </Badge>
        {ip.cidr && (
          <Badge tone="bg-default-200 text-default-600" title="CIDR - network bits / total bits">
            {ip.cidr}
          </Badge>
        )}
        {ip.network && ip.network !== ip.cidr && (
          <Badge tone="bg-default-200 text-default-500" title="Network address for this prefix">
            net {ip.network}
          </Badge>
        )}
        {ip.hosts !== null && (
          <Badge tone="bg-default-200 text-default-500" title="Usable host addresses in this subnet">
            {ip.hosts.toLocaleString()} hosts
          </Badge>
        )}
        {ip.class && (
          <Badge
            tone="bg-default-200 text-default-500"
            title={
              ip.class_legacy
                ? `Classful class ${ip.class.split(' ')[0]} - LEGACY. Classful addressing was replaced by CIDR in 1993, so this does NOT tell you the subnet size.`
                : 'Legacy classful address class'
            }
          >
            class {ip.class.split(' ')[0]}
            <span className="ml-1 font-normal opacity-60">(legacy)</span>
          </Badge>
        )}
      </div>

      {ip.prefix_length !== null ? (
        <PrefixBar prefix={ip.prefix_length} />
      ) : (
        <p className="text-[10px] leading-relaxed text-default-400">
          {ip.note ?? 'Prefix length is not known for this address.'}
        </p>
      )}
    </div>
  )
}

export function PortBlock({ port }: { port: PortFacts }) {
  return (
    <div className="flex flex-col gap-2.5 rounded-lg border border-default-200 bg-default-50/40 p-3">
      <div className="flex items-center gap-2">
        <span className="eyebrow">port</span>
        <span className="font-mono text-[15px] font-semibold tabular-nums text-foreground">
          {port.port}
        </span>
        {port.service && (
          <span className="truncate font-mono text-[12px] text-default-500" title={port.service}>
            {port.service}
          </span>
        )}
        <Badge
          tone={SOURCE_TONE[port.source]}
          title={
            port.source === 'iana'
              ? 'A real IANA registration'
              : port.source === 'de-facto'
                ? 'A convention, not an IANA registration'
                : 'No IANA service name for this port'
          }
        >
          {SOURCE_LABEL[port.source]}
        </Badge>
      </div>

      <div className="flex items-center gap-2">
        <span className={`font-mono text-[11px] font-medium ${BAND_TONE[port.band]}`}>
          {port.band}
        </span>
        <span className="text-[10px] text-default-400">{port.band_meaning}</span>
      </div>

      <PortScale port={port.port} />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Compact strip
//
// The full blocks above are for when a row is expanded. This is the version
// that sits under EVERY service without being clicked, so it has to carry the
// same facts in two lines instead of a screen: which interface the address is
// on, the prefix, the scope, the class and what the port is. The bit bar and
// the port scale stay in the expanded view - they are pretty but they are not
// needed to identify an endpoint at a glance.
// ---------------------------------------------------------------------------

export function NetStrip({ net }: { net: NetFacts }) {
  const ip = net.ip
  const port = net.port
  if (!ip || !port) return null

  return (
    <div className="flex flex-col gap-1.5 border-t border-default-100 pt-2">
      {/* --- address --- */}
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="eyebrow shrink-0">ip</span>
        {ip.octets ? (
          <span className="flex items-center gap-0.5">
            {ip.octets.map((o, i) => (
              <span key={i} className="flex items-center gap-0.5">
                <span
                  className={`min-w-[1.4rem] rounded px-1 py-px text-center font-mono text-[11px] tabular-nums ${
                    i === 0 ? 'bg-accent/15 text-foreground' : 'bg-default-200/70 text-default-600'
                  }`}
                >
                  {o}
                </span>
                {i < 3 && <span className="text-default-300">.</span>}
              </span>
            ))}
          </span>
        ) : (
          <span className="font-mono text-[11px] text-default-600">{ip.ip}</span>
        )}

        <Badge tone={SCOPE_TONE[ip.scope]} title={ip.scope_meaning}>
          {ip.scope}
        </Badge>
        {ip.cidr && (
          <span
            className="rounded bg-default-200 px-1.5 py-0.5 font-mono text-[10px] text-default-600"
            title="CIDR prefix"
          >
            {ip.cidr}
          </span>
        )}
        {ip.class && (
          <span
            className="rounded bg-default-200 px-1.5 py-0.5 text-[10px] text-default-500"
            title="Legacy classful class. Classful addressing was replaced by CIDR in 1993, so this does NOT indicate the subnet size."
          >
            class {ip.class.split(' ')[0]}
          </span>
        )}
        {ip.interface && (
          <span
            className="flex min-w-0 items-center gap-1 text-[10px] text-default-400"
            title={`Bound to this interface (index ${ip.interface_index ?? '?'})`}
          >
            <Icon name="machine" size={10} className="shrink-0" />
            <span className="truncate">{ip.interface}</span>
            {ip.interface_index !== null && (
              <span className="shrink-0 font-mono opacity-60">#{ip.interface_index}</span>
            )}
          </span>
        )}
      </div>

      {/* --- port --- */}
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="eyebrow shrink-0">port</span>
        <span className="font-mono text-[12px] font-semibold tabular-nums text-foreground">
          {port.port}
        </span>
        {port.service && (
          <span className="truncate font-mono text-[11px] text-default-500" title={port.service}>
            {port.service}
          </span>
        )}
        <Badge tone={SOURCE_TONE[port.source]}>{SOURCE_LABEL[port.source]}</Badge>
        <span className={`font-mono text-[10px] ${BAND_TONE[port.band]}`}>{port.band}</span>
      </div>
    </div>
  )
}

export default function NetFactsPanel({ net }: { net: NetFacts }) {
  return (
    <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
      {net.ip && <IpBlock ip={net.ip} />}
      {net.port && <PortBlock port={net.port} />}
    </div>
  )
}