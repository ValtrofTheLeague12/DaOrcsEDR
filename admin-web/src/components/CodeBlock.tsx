import { useMemo } from 'react'

// ---------------------------------------------------------------------------
// Colourised read-only code for text THIS PANEL generates.
//
// Two modes, with their honest scope stated:
//
//   * 'yaml' reads the pipeline wizard's own draft - the shape renderYaml()
//     composes in PipelineWizard, whose lines are comments, `key:` mappings and
//     quoted values, and nothing else. That is not a general YAML lexer, and an
//     arbitrary file fed through it would be lie-coloured in exactly the ways
//     YamlView.tsx's header describes (block scalars, colon-in-scalar). Anything
//     that is not this panel's own output belongs in YamlView, with spans from
//     PyYAML.
//
//   * 'c' / 'cpp' reads the sample factory's composed `int main()` - plain sample
//     code: literals, keywords, comments, a #include. No macros, no templates,
//     nothing that needs a real parser.
//
// All tokens share the compose-tok-* palette the YAML viewer and the compose
// build log already speak, so "comment" or "key" is one colour everywhere in
// the console.
// ---------------------------------------------------------------------------

export type CodeLang = 'c' | 'cpp' | 'yaml'

interface Tok {
  text: string
  /** A compose-tok-* class, or '' for plain text. */
  cls: string
}

const C_KEYWORDS = new Set([
  'auto', 'break', 'case', 'const', 'continue', 'default', 'do', 'else',
  'extern', 'for', 'goto', 'if', 'inline', 'register', 'restrict', 'return',
  'sizeof', 'static', 'struct', 'switch', 'typedef', 'union', 'volatile',
  'while',
])

const C_TYPES = new Set([
  'bool', 'char', 'double', 'float', 'int', 'long', 'short', 'signed',
  'unsigned', 'void', 'size_t', 'ssize_t', 'uint8_t', 'uint16_t', 'uint32_t',
  'uint64_t', 'int8_t', 'int16_t', 'int32_t', 'int64_t', 'FILE', 'time_t',
  'nullptr', 'NULL', 'string',
])

const C_IDENT = /^[A-Za-z_]\w*/
const C_NUMBER = /^(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?[uUlLfF]*)/
const C_STRING = /^(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')/
const C_SPACE = /^\s+/

/** Tokenise one line of C, with the block-comment state carried in. */
function cLineTokens(line: string, inBlock: { v: boolean }): Tok[] {
  const toks: Tok[] = []
  const push = (text: string, cls: string) => {
    if (!text) return
    const last = toks[toks.length - 1]
    // Same-class runs merge: fewer spans, and a token boundary inside a word
    // never splits one colour into two spans for nothing.
    if (last && last.cls === cls) last.text += text
    else toks.push({ text, cls })
  }

  if (inBlock.v) {
    const end = line.indexOf('*/')
    if (end === -1) return [{ text: line, cls: 'compose-tok-comment' }]
    push(line.slice(0, end + 2), 'compose-tok-comment')
    inBlock.v = false
    return [...toks, ...cLineTokens(line.slice(end + 2), inBlock)]
  }

  if (/^\s*#/.test(line)) {
    // The directive itself recedes; an #include path is a literal, which is how
    // the factory's "plain imports" claim reads at a glance.
    const inc = line.match(/^(\s*#(?:include|import))(\s*)(<[^>]*>|"[^"]*")(.*)$/)
    if (inc) {
      push(inc[1], 'compose-tok-null')
      push(inc[2], '')
      push(inc[3], 'compose-tok-string')
      push(inc[4], 'compose-tok-comment')
      return toks
    }
    return [{ text: line, cls: 'compose-tok-comment' }]
  }

  let i = 0
  while (i < line.length) {
    const rest = line.slice(i)
    if (rest.startsWith('/*')) {
      const end = line.indexOf('*/', i + 2)
      if (end === -1) {
        // Unbalanced open: the comment claims the rest, and the caller's line
        // loop must carry the state forward.
        push(rest, 'compose-tok-comment')
        inBlock.v = true
        return toks
      }
      push(rest.slice(0, end + 2 - i), 'compose-tok-comment')
      i = end + 2
      continue
    }
    if (rest.startsWith('//')) {
      push(rest, 'compose-tok-comment')
      return toks
    }
    let m = C_STRING.exec(rest)
    if (m) {
      push(m[0], 'compose-tok-string')
      i += m[0].length
      continue
    }
    m = C_NUMBER.exec(rest)
    if (m) {
      push(m[0], 'compose-tok-number')
      i += m[0].length
      continue
    }
    m = C_IDENT.exec(rest)
    if (m) {
      const word = m[0]
      // Keyword and named type share the accent word tone: the sample code's
      // readability problem is "what is a literal here", not taxonomy.
      push(word, C_KEYWORDS.has(word) || C_TYPES.has(word) ? 'compose-tok-key' : '')
      i += word.length
      continue
    }
    m = C_SPACE.exec(rest)
    if (m) {
      push(m[0], '')
      i += m[0].length
      continue
    }
    push(rest[0], '')
    i += 1
  }
  return toks
}

/** Tokenise one line of the wizard's generated YAML draft. */
function yamlLineTokens(line: string): Tok[] {
  if (!line.trim()) return [{ text: line, cls: '' }]
  if (/^\s*#/.test(line)) return [{ text: line, cls: 'compose-tok-comment' }]
  // A list entry - "  - strings   # why it is here". The dash punctuates, the
  // phase name is a member the operator is choosing, so it wears the accent
  // word tone too, and any trailing comment recedes.
  const li = line.match(/^(\s*)(- )(\S+)(.*)$/)
  if (li) {
    const toks: Tok[] = [
      { text: li[1], cls: '' },
      { text: li[2], cls: 'compose-tok-op' },
      { text: li[3], cls: 'compose-tok-key' },
    ]
    const tail = li[4]
    if (/^\s*#/.test(tail) || tail.trimStart().startsWith('#')) {
      toks.push({ text: tail, cls: 'compose-tok-comment' })
    } else toks.push({ text: tail, cls: '' })
    return toks
  }
  // Indent is plain, the key is the accent word, and the value is coloured by
  // what it holds - a number in quotes reads as a number, which is the fact
  // the wizard wants the operator to see before saving.
  const m = line.match(/^(\s*)([A-Za-z_][\w-]*)(:)(.*)$/)
  if (!m) return [{ text: line, cls: '' }]
  const [, indent, key, colon, restRaw] = m
  const toks: Tok[] = [{ text: indent, cls: '' }, { text: key, cls: 'compose-tok-key' }, { text: colon, cls: 'compose-tok-op' }]
  const rest = restRaw.trimStart()
  toks.push({ text: restRaw.slice(0, restRaw.length - rest.length), cls: '' })
  if (!rest) return toks
  const q = rest.match(/^"(.*)"$/)
  if (q) {
    toks.push({ text: `"${q[1]}"`, cls: /^-?\d+(?:\.\d+)?$/.test(q[1]) ? 'compose-tok-number' : 'compose-tok-string' })
    return toks
  }
  if (/^(?:true|false)$/.test(rest)) toks.push({ text: rest, cls: 'compose-tok-bool' })
  else if (/^null$/.test(rest)) toks.push({ text: rest, cls: 'compose-tok-null' })
  else if (/^-?\d+(?:\.\d+)?$/.test(rest)) toks.push({ text: rest, cls: 'compose-tok-number' })
  else toks.push({ text: rest, cls: 'compose-tok-string' })
  return toks
}

export default function CodeBlock({ code, lang, className = '' }: {
  code: string
  lang: CodeLang
  /** Extra classes for the <pre> - scroll caps and padding come from callers. */
  className?: string
}) {
  const lines = useMemo(() => {
    const out: Tok[][] = []
    const blockComment = { v: false }
    for (const line of code.split('\n')) {
      if (lang === 'yaml') out.push(yamlLineTokens(line))
      else out.push(cLineTokens(line, blockComment))
    }
    return out
  }, [code, lang])

  return (
    <pre className={`factory-code ${className}`} spellCheck={false}>
      {lines.map((toks, n) => (
        <div key={n} className="code-line">
          {toks.length === 0
            ? ' '
            : toks.map((t, k) => (
              <span key={k} className={t.cls}>{t.text}</span>
            ))}
        </div>
      ))}
    </pre>
  )
}
