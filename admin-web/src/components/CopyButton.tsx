import { useCallback, useEffect, useRef, useState } from 'react'
import { Button } from '@heroui/react/button'
import Icon from './Icon'

// ---------------------------------------------------------------------------
// Copy-to-clipboard, one implementation.
//
// navigator.clipboard is unavailable on a non-secure origin, and this console is
// plain HTTP on loopback, so the textarea fallback is not an edge case - it is
// the path that normally runs. Every caller needs both, and a copy button that
// silently does nothing is worse than one that says it failed, so failures fall
// back to leaving the "copied" state off rather than pretending.
//
// The timer is cleared on unmount: a page switch mid-window would otherwise set
// state on a component that is no longer on screen.
// ---------------------------------------------------------------------------

export function useCopy(resetMs = 1600) {
  const [copied, setCopied] = useState(false)
  const timer = useRef<number | null>(null)

  useEffect(
    () => () => {
      if (timer.current !== null) window.clearTimeout(timer.current)
    },
    [],
  )

  const copy = useCallback(
    async (text: string) => {
      try {
        if (navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(text)
        } else {
          const el = document.createElement('textarea')
          el.value = text
          el.style.position = 'fixed'
          el.style.opacity = '0'
          document.body.appendChild(el)
          el.select()
          document.execCommand('copy')
          document.body.removeChild(el)
        }
        setCopied(true)
        if (timer.current !== null) window.clearTimeout(timer.current)
        timer.current = window.setTimeout(() => setCopied(false), resetMs)
        return true
      } catch {
        setCopied(false)
        return false
      }
    },
    [resetMs],
  )

  return { copied, copy }
}

export default function CopyButton({
  text,
  children = 'Copy',
  size = 'sm',
  variant,
  className = '',
}: {
  text: string | (() => string)
  children?: string
  size?: 'sm' | 'md'
  /** Defaults to ghost, and flips to secondary while the state is showing. */
  variant?: 'ghost' | 'outline' | 'secondary'
  className?: string
}) {
  const { copied, copy } = useCopy()
  return (
    <Button
      size={size}
      variant={variant ?? (copied ? 'secondary' : 'ghost')}
      className={className}
      onPress={() => void copy(typeof text === 'function' ? text() : text)}
    >
      <Icon name={copied ? 'check' : 'copy'} size={13} />
      {copied ? 'Copied' : children}
    </Button>
  )
}