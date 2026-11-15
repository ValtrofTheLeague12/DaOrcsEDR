import { LogoLockup } from './Logo'

// Opening screen. Replaces the bare spinner shown while the console asks the
// server who it is talking to. The skull is revealed row by row (a scanline
// wipe, matching its pixel-art origin), then breathes while the bar sweeps.
export default function BootScreen({ label = 'connecting to analysis server' }: { label?: string }) {
  return (
    <div className="boot" role="status" aria-live="polite">
      <div className="boot-stage">
        <div className="boot-glow" aria-hidden="true" />
        <LogoLockup height={320} className="boot-logo" title="Da Orks" />
      </div>
      <div className="boot-bar" aria-hidden="true"><i /></div>
      <p className="boot-label">{label}<span className="boot-caret" aria-hidden="true" /></p>
    </div>
  )
}
