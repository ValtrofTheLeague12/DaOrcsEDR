import { Card, Chip } from '@heroui/react'
import Icon from './Icon'
import Pager, { usePaged } from './Pager'
import type { VirtTool, VirtStatus } from '../types'

// ---------------------------------------------------------------------------
// Hypervisor roster.
//
// Answers "what virtualisation is this box actually running" for every tool
// that could plausibly be on it, not just the one this project happens to use.
//
// The absent tools are shown too, and deliberately so. A lab that reports
// "VirtualBox 7.2.8, 1 VM" and silently omits QEMU reads as "these are all the
// hypervisors that exist" - which is false, and is exactly the wrong conclusion
// to draw while debugging why a disk will not attach. Naming the three that
// were looked for and not found makes the search exhaustive instead of
// partial, and `detail` gives the reason each was ruled out.
//
// `primary` is the tool the lab is wired to, which is not always the only tool
// present. When both VirtualBox and Hyper-V exist, the rest render as
// alternatives rather than the panel quietly choosing on the operator's behalf.
// ---------------------------------------------------------------------------

function ToolRow({ tool, primary }: { tool: VirtTool; primary: boolean }) {
  const running = tool.machines.running
  const total = tool.machines.total
  const paged = usePaged(tool.machines.names)

  return (
    <div
      className={`flex flex-col gap-2 rounded-md border px-3 py-2.5 ${
        tool.installed ? 'border-default-200' : 'border-default-100 opacity-60'
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span
            className={`h-1.5 w-1.5 shrink-0 rounded-full ${
              tool.installed ? 'bg-success' : 'bg-default-400'
            }`}
          />
          <span className={`text-[12px] ${tool.installed ? '' : 'text-default-500'}`}>
            {tool.name}
          </span>
          {primary && (
            <Chip size="sm" variant="soft" color="accent">
              in use
            </Chip>
          )}
        </div>

        <div className="flex items-center gap-1.5">
          {tool.installed && (
            <Chip size="sm" variant="soft" color={total > 0 ? 'success' : 'default'}>
              {total} machine{total === 1 ? '' : 's'}
            </Chip>
          )}
          {running > 0 && (
            <Chip size="sm" variant="soft" color="success">
              {running} running
            </Chip>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
        {tool.version ? (
          <span className="font-mono text-[11px] text-default-500">{tool.version}</span>
        ) : (
          <span className="text-[11px] text-default-400">not installed</span>
        )}
        {tool.exe && (
          <span className="font-mono text-[10px] text-default-400">{tool.exe}</span>
        )}
      </div>

      {tool.installed && total > 0 && (
        <>
          <div className="flex flex-wrap gap-1.5">
            {paged.slice.map((n) => {
              const live = tool.machines.running_names.includes(n)
              return (
                <span
                  key={n}
                  className={`flex items-center gap-1.5 rounded-full px-2 py-0.5 font-mono text-[11px] ${
                    live ? 'bg-success/12 text-success' : 'bg-default-200 text-default-500'
                  }`}
                >
                  <span className={`h-1.5 w-1.5 rounded-full ${live ? 'bg-success' : 'bg-default-400'}`} />
                  {n}
                </span>
              )
            })}
          </div>
          <Pager
            page={paged.page}
            pages={paged.pages}
            first={paged.first}
            last={paged.last}
            total={total}
            onPrev={paged.prev}
            onNext={paged.next}
          />
        </>
      )}

      {tool.detail && (
        <p className="text-[10.5px] leading-relaxed text-default-400">{tool.detail}</p>
      )}
    </div>
  )
}

export default function VirtRoster({ virt }: { virt?: VirtStatus }) {
  // A panel server older than this field simply does not send it. Say so rather
  // than rendering an empty card that looks like "no hypervisors found".
  if (!virt) {
    return (
      <Card className="w-full">
        <Card.Header>
          <Card.Title className="text-sm font-semibold">Hypervisors</Card.Title>
        </Card.Header>
        <Card.Content>
          <p className="py-2 text-[12px] text-default-400">
            Hypervisor detection was not returned by the panel. Restart it to
            pick up the current backend.
          </p>
        </Card.Content>
      </Card>
    )
  }

  return (
    <Card className="w-full">
      <Card.Header className="flex flex-wrap items-center justify-between gap-3">
        <Card.Title className="text-sm font-semibold">Hypervisors</Card.Title>
        <Chip size="sm" variant="soft" color={virt.count > 0 ? 'success' : 'warning'}>
          {virt.count} installed · {virt.detected.length} checked
        </Chip>
      </Card.Header>
      <Card.Content className="flex flex-col gap-2">
        {virt.count === 0 && (
          <div className="mb-1 flex items-start gap-2 rounded-md border border-warning/25 bg-warning/5 px-3 py-2">
            <Icon name="logs" size={13} className="mt-0.5 shrink-0 text-warning" />
            <p className="text-[11px] leading-relaxed text-warning">
              No hypervisor found. The analysis VM has nothing to run on - install
              one of the tools below, or point the panel at a host that has it.
            </p>
          </div>
        )}
        {virt.detected.map((tool) => (
          <ToolRow key={tool.id} tool={tool} primary={tool.id === virt.primary} />
        ))}
      </Card.Content>
    </Card>
  )
}