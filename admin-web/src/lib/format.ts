// Formatters shared by every panel. Centralised so a number never renders two
// different ways in two places.

export function bytes(n: number | null | undefined, digits = 1): string {
  if (n === null || n === undefined) return '—'
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB', 'PB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v >= 100 ? 0 : digits)} ${units[i]}`
}

export function compact(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—'
  if (n < 1000) return String(n)
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`
  return `${(n / 1_000_000).toFixed(1)}M`
}

export function pct(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—'
  return `${n >= 10 ? Math.round(n) : n.toFixed(1)}%`
}

export function duration(sec: number | null | undefined): string {
  if (sec === null || sec === undefined || sec <= 0) return '—'
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  const m = Math.floor((sec % 3600) / 60)
  if (d) return `${d}d ${h}h`
  if (h) return `${h}h ${m}m`
  return `${m}m`
}

export function shortDuration(sec: number | null | undefined): string {
  if (sec === null || sec === undefined || sec <= 0) return '—'
  if (sec < 90) return `${Math.round(sec)}s`
  if (sec < 5400) return `${Math.round(sec / 60)}m`
  if (sec < 172800) return `${Math.round(sec / 3600)}h`
  return `${Math.round(sec / 86400)}d`
}

export function ms(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—'
  if (n >= 1000) return `${(n / 1000).toFixed(1)}s`
  return `${Math.round(n)}ms`
}

export function ago(unixSeconds: number | null | undefined): string {
  if (!unixSeconds) return '—'
  return `${shortDuration(Date.now() / 1000 - unixSeconds)} ago`
}