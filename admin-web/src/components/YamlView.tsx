import { useMemo } from 'react'
import type { YamlKind } from '../types'

// ---------------------------------------------------------------------------
// Read-only YAML source view.
//
// This component does not parse YAML. The backend hands over the file text plus
// `[start, length, kind]` spans derived from PyYAML's own node marks, and the
// only job here is to paint them. A line-at-a-time YAML lexer in the browser
// was the previous approach and it was wrong in ways that matter: a regex
// cannot tell a mapping colon from a colon inside a scalar, and a block
// scalar's body looks like keys to anything that reads line by line.
//
// Shared because two pages now show YAML as source - the compose viewer and the
// pipelines configuration - and they must colour it identically or the same file
// would read differently depending on where you opened it.
// ---------------------------------------------------------------------------

const KIND_CLASS: Record<YamlKind | 'plain', string> = {
  key: 'compose-tok-key',
  string: 'compose-tok-string',
  number: 'compose-tok-number',
  bool: 'compose-tok-bool',
  null: 'compose-tok-null',
  comment: 'compose-tok-comment',
  punct: 'compose-tok-op',
  plain: '',
}

interface Seg {
  t: string
  k: YamlKind | 'plain'
}

/** Cut the text into lines of pre-coloured segments.
 *
 *  A span may cross a newline - a block scalar covers every line of its body -
 *  so the walk is split on newlines as segments are emitted and the tail
 *  continues onto the next line rather than being dropped.
 */
function paint(content: string, spans: [number, number, YamlKind][]): Seg[][] {
  const lines: Seg[][] = [[]]

  const push = (text: string, kind: YamlKind | 'plain') => {
    if (!text) return
    text.split('\n').forEach((part, i) => {
      if (i > 0) lines.push([])
      if (part) lines[lines.length - 1].push({ t: part, k: kind })
    })
  }

  let cursor = 0
  for (const [start, length, kind] of spans) {
    if (start > cursor) push(content.slice(cursor, start), 'plain')
    push(content.slice(start, start + length), kind)
    cursor = start + length
  }
  if (cursor < content.length) push(content.slice(cursor), 'plain')

  // A trailing newline parses to a final empty scalar; editors show the file as
  // ending on the last real line, not an extra blank one.
  if (content.endsWith('\n') && lines.length > 1 && lines[lines.length - 1].length === 0) {
    lines.pop()
  }
  return lines
}

export default function YamlView({
  content,
  spans,
}: {
  content: string
  spans: [number, number, YamlKind][]
}) {
  const lines = useMemo(() => paint(content, spans), [content, spans])
  return (
    <div className="compose-viewer-pane">
      <div className="compose-viewer-code">
        {lines.map((segs, i) => (
          <div className="compose-viewer-line" key={i}>
            <span className="compose-viewer-gutter">{i + 1}</span>
            <span className="compose-viewer-text">
              {segs.map((seg, j) => (
                <span key={j} className={KIND_CLASS[seg.k]}>{seg.t}</span>
              ))}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}