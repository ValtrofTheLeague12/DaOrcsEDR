// Inline SVG icon set.
//
// Hand-rolled rather than a dependency: a console needs ~18 glyphs and an
// icon package would be a large install to render them. All stroke-based,
// 24x24, currentColor, so they inherit theme and size from CSS alone.

export type IconName =
  | 'overview' | 'machine' | 'stats' | 'logs' | 'artifacts' | 'containers'
  | 'analyze' | 'build' | 'model' | 'services' | 'vm' | 'clamd' | 'qiling'
  | 'sun' | 'moon' | 'logout' | 'refresh' | 'search' | 'chevron'

const PATHS: Record<IconName, string> = {
  // heartbeat / pulse
  overview: 'M3 12h4l3-8 4 16 3-8h4',
  // microchip
  machine: 'M9 3v3m6-3v3M9 18v3m6-3v3M3 9h3m-3 6h3m12-6h3m-3 6h3M7 6h10v12H7z M10 10h4v4h-4z',
  // bar chart
  stats: 'M4 20V10m5 10V4m5 16v-7m5 7V8',
  // document with lines
  logs: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z M14 3v5h5 M9 13h6 M9 17h4',
  // package
  artifacts: 'M12 3 3 7.5v9L12 21l9-4.5v-9z M3 7.5 12 12l9-4.5M12 12v9',
  // stacked container
  containers: 'M4 5h16v5H4zM4 14h16v5H4z M7 5v5 M7 14v5',
  // play
  analyze: 'M6 4l14 8-14 8z',
  // hammer
  build: 'M14 4l6 6-3 3-6-6zM11 7L3 15v6h6l8-8',
  // model / chart-line
  model: 'M4 18 9 11l4 4 7-9 M20 6h-5m5 0v5',
  // server rack
  services: 'M4 4h16v6H4zM4 14h16v6H4z M7 7h.01M7 17h.01',
  // monitor
  vm: 'M3 4h18v12H3zM8 20h8M12 16v4',
  // shield-check
  clamd: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z M9 12l2 2 4-4',
  // terminal
  qiling: 'M5 7l5 5-5 5M12 17h7',
  sun: 'M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 2v2m0 16v2M4.2 4.2l1.4 1.4m12.8 12.8 1.4 1.4M2 12h2m16 0h2M4.2 19.8l1.4-1.4M17.4 6.6l1.4-1.4',
  moon: 'M21 13A9 9 0 0 1 11 3a7 7 0 1 0 10 10z',
  logout: 'M15 17l5-5-5-5M20 12H9M12 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h6',
  refresh: 'M21 12a9 9 0 1 1-3-6.7L21 8 M21 3v5h-5',
  search: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3',
  chevron: 'M9 6l6 6-6 6',
}

export default function Icon({
  name,
  size = 16,
  className = '',
}: {
  name: IconName
  size?: number
  className?: string
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={`shrink-0 ${className}`}
      aria-hidden="true"
      focusable="false"
    >
      <path d={PATHS[name]} />
    </svg>
  )
}