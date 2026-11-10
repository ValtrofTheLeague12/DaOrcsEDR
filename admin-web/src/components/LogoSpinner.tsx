import type { CSSProperties } from 'react'
import { LogoMark } from './Logo'

// In-page loading mark. A faint skull sits inside a thin ring; a red arc orbits
// the ring while a scan beam sweeps down the skull, the same pixel-scan language
// as the boot screen. Pure CSS (transform + mask), so it stays smooth while the
// main thread is busy parsing the chunk it is waiting for.
export default function LogoSpinner({ size = 44, label }: { size?: number; label?: string }) {
  const mark = Math.round(size * 0.56)
  return (
    <span
      className="lspin"
      style={{ '--lspin': `${size}px` } as CSSProperties}
      role={label ? 'status' : undefined}
      aria-label={label}
    >
      <span className="lspin-ring" aria-hidden="true" />
      <span className="lspin-orbit" aria-hidden="true" />
      <span className="lspin-face" aria-hidden="true">
        <LogoMark height={mark} className="lspin-base" />
        <LogoMark height={mark} className="lspin-scan" />
      </span>
    </span>
  )
}
