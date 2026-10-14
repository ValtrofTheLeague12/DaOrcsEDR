import { useEffect, useState } from 'react'

// ---------------------------------------------------------------------------
// A minute-resolution clock, for relative timestamps only.
//
// Exists because "how often should the data refresh" and "how often should
// '2m ago' change" are two different questions, and answering them with one
// interval is what makes a status page feel either sluggish or frantic.
//
// A timestamp is a fixed point in time. What moves is the label describing it.
// Re-fetching the whole payload every 30 seconds purely to notice that
// '30s ago' has become '1m ago' is a network round trip, a JSON parse and a
// re-render spent on arithmetic, and on a page like Artifacts it re-runs a
// MEGAcmd renewal as a side effect. This re-renders the labels on its own
// schedule and touches nothing else.
//
// 60s, not 1s. Every relative time in this codebase renders through
// shortDuration, which floors to whole seconds under 90s and whole minutes
// under 90m - so a 1s tick would fire about sixty times to produce zero visible
// changes.
// ---------------------------------------------------------------------------

export function useMinuteTick(intervalMs = 60000): number {
  const [tick, setTick] = useState(0)

  useEffect(() => {
    // A hidden tab has nobody reading the labels, and browsers throttle
    // background timers anyway. Skipping the tick means a tab left overnight
    // does not re-render on every wake-up.
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') setTick((t) => t + 1)
    }, intervalMs)
    return () => window.clearInterval(id)
  }, [intervalMs])

  return tick
}
