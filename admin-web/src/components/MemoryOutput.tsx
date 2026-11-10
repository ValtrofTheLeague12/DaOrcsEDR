import { api } from '../api'
import CommandLine from './CommandLine'
import { renderPieces } from '../lib/logColor'
import type { MemoryProfilingJob } from '../types'

/** Split the backend's `a ; b ; c` command record back into separate commands. */
function commands(value: string | null): string[] {
  const parts: string[] = []
  const input = value ?? ''
  let start = 0
  let quoted = false

  for (let index = 0; index < input.length; index += 1) {
    if (input[index] === '"') {
      let backslashes = 0
      for (let previous = index - 1; previous >= 0 && input[previous] === '\\'; previous -= 1) {
        backslashes += 1
      }
      if (backslashes % 2 === 0) quoted = !quoted
    }

    if (!quoted && input.startsWith(' ; ', index)) {
      parts.push(input.slice(start, index).trim())
      start = index + 3
      index += 2
    }
  }
  parts.push(input.slice(start).trim())

  return [...new Set(parts.filter(Boolean))]
}

function withoutCommandEchoes(lines: string[], commandsToOmit: string[]): string[] {
  const omitted = new Set(commandsToOmit.map((command) => command.trim()))
  return lines.filter((line) => {
    const trimmed = line.trimStart()
    return !trimmed.startsWith('$ ') || !omitted.has(trimmed.slice(2).trim())
  })
}

function OutputLines({ lines, empty }: { lines: string[]; empty: string }) {
  if (lines.length === 0) {
    return <p className="p-3 text-[11px] text-default-500">{empty}</p>
  }
  return (
    <div className="max-h-80 overflow-auto p-3 font-mono text-[10px] leading-relaxed">
      {lines.map((line, index) => {
        const command = line.trimStart()
        // VMMap and the analyzer echo each command with a `$ ` prompt. Give
        // those rows the same design as the command list above instead of
        // letting them dissolve into the console text.
        if (command.startsWith('$ ')) {
          return (
            <div key={index} className="my-1">
              <CommandLine value={command.slice(2)} compact />
            </div>
          )
        }
        return (
          <div key={index} className="whitespace-pre-wrap break-words">
            {line ? renderPieces(line) : ' '}
          </div>
        )
      })}
    </div>
  )
}

export default function MemoryOutput({ job }: { job: MemoryProfilingJob }) {
  const running = job.state === 'running'
  const finished = job.state === 'done'
  const vmmapLines = job.log ?? []
  const targetLines = job.target_log ?? []
  const jobCommands = commands(job.command)
  const visibleVmmapLines = withoutCommandEchoes(vmmapLines, jobCommands)
  const visibleTargetLines = withoutCommandEchoes(targetLines, jobCommands)

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-xs font-medium text-default-700">
            {jobCommands.length === 1 ? 'Command' : 'Commands'}
          </p>
          <div className="mt-1.5 flex flex-col gap-1.5">
            {jobCommands.length > 0 ? (
              jobCommands.map((command, index) => (
                <CommandLine key={index} value={command} compact />
              ))
            ) : (
              <code className="block break-all font-mono text-[10px] text-default-500">
                {running ? 'Starting the capture…' : 'No command was recorded.'}
              </code>
            )}
          </div>
        </div>
        {finished && (job.csv_path || job.snapshot_path) && (
          <div className="flex flex-wrap items-center gap-3 text-xs font-medium">
            {job.csv_path && (
              <a
                className="text-accent underline underline-offset-2"
                href={api.memoryProfilingCsvUrl(job.id)}
              >
                Download CSV
              </a>
            )}
            {job.snapshot_path && (
              <a
                className="text-accent underline underline-offset-2"
                href={api.memoryProfilingSnapshotUrl(job.id)}
              >
                Download .mmp
              </a>
            )}
          </div>
        )}
      </div>

      <section className="overflow-hidden rounded-lg border border-default-200 bg-default-50/60">
        <div className="flex items-center justify-between gap-2 border-b border-default-200 px-3 py-2">
          <p className="text-xs font-medium text-default-700">VMMap output</p>
          <span className="font-mono text-[10px] text-default-400">
            {visibleVmmapLines.length} line{visibleVmmapLines.length === 1 ? '' : 's'}
          </span>
        </div>
        <OutputLines
          lines={visibleVmmapLines}
          empty={running ? 'Waiting for VMMap output…' : 'VMMap produced no console output.'}
        />
      </section>

      {visibleTargetLines.length > 0 && (
        <details className="overflow-hidden rounded-lg border border-default-200">
          <summary className="flex cursor-pointer items-center justify-between gap-2 px-3 py-2 text-xs font-medium text-default-600 hover:bg-default-100/60">
            <span>Profiled process output</span>
            <span className="font-mono text-[10px] font-normal text-default-400">
              {visibleTargetLines.length} line{visibleTargetLines.length === 1 ? '' : 's'}
            </span>
          </summary>
          <OutputLines lines={visibleTargetLines} empty="The profiled process produced no output." />
        </details>
      )}

      <p className="text-[10px] text-default-500">
        VMMap writes the full memory map to the CSV and the native .mmp
        snapshot. The text above is what it printed while capturing.
      </p>
    </div>
  )
}
