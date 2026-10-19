// Inline SVG icon set.
//
// Hand-rolled rather than a dependency: a console needs ~18 glyphs and an
// icon package would be a large install to render them. All stroke-based,
// 24x24, currentColor, so they inherit theme and size from CSS alone.

export type IconName =
  | 'overview' | 'machine' | 'stats' | 'logs' | 'artifacts' | 'containers'
  | 'analyze' | 'build' | 'model' | 'services' | 'vm' | 'clamd' | 'qiling'
  | 'sun' | 'moon' | 'logout' | 'refresh' | 'search' | 'chevron'
  | 'chevron-up' | 'chevron-down'
  | 'file-text' | 'file-code' | 'x' | 'alert-circle' | 'copy'
  | 'image' | 'network' | 'database' | 'link' | 'git-merge' | 'rotate-cw'
  | 'terminal' | 'play' | 'folder' | 'user' | 'activity' | 'rocket' | 'tag' | 'server'
  | 'variable' | 'filter' | 'check' | 'plus' | 'wrench' | 'grip'

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
  // Vertical chevrons. Not rotations of the one above: a stepper that grows and
  // shrinks a list wants arrows pointing up and down, and rotating a right-point
  // chevron by CSS would make the rotation depend on a transform surviving on an
  // element that also carries a font-size.
  'chevron-down': 'M6 9l6 6 6-6',
  'chevron-up': 'M6 15l6-6 6 6',
  // file-text
  'file-text': 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M16 13H8 M16 17H8 M10 9h8',
  // file-code
  'file-code': 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M10 10l4 4-4 4 M14 14l-4-4 4-4',
  // x
  x: 'M18 6L6 18M6 6l12 12',
  // alert-circle
  'alert-circle': 'M12 22C6.48 22 2 17.52 2 12S6.48 2 12 2s10 4.48 10 10-4.48 10-10 10z M12 8v4 M12 16h.01',
  // copy
  copy: 'M16 16h2a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2h-2a2 2 0 0 0-2 2v2 M8 16H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2 M16 16v8a2 2 0 0 1-2 2h-8a2 2 0 0 1-2-2v-8',
  // image
  image: 'M21 19V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2z M3 11l9-9 9 9',
  // network
  network: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  // database
  database: 'M4 6v6a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V6 M4 12v6a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-6',
  // link
  link: 'M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71 M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71',
  // git-merge
  'git-merge': 'M12 3v12 M5 3h14 M5 9h14 M5 15h14',
  // rotate-cw
  'rotate-cw': 'M23 4v6h-6 M1 20v-6h6 M3.51 9a9 9 0 0 1 14.85-3.36L23 10',
  // terminal
  terminal: 'M4 17l4-4 4 4 M17 17h3a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-3',
  // play
  play: 'M5 3l14 9-14 9z',
  // folder
  folder: 'M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z',
  // user
  user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2 M12 9a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
  // activity
  activity: 'M22 12h-4l-3 9L9 3l-3 9H2',
  // rocket
  rocket: 'M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c1.26-1.5.5-3.74-2-5z M12 15h-3 M12 15v5',
  // tag
  tag: 'M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z M6 6a2 2 0 0 1 2.83 0L12 8.83 8.83 12 6 8.83a2 2 0 0 1 0-2.83z',
  // server
  server: 'M6 2h12a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z M6 10h12 M6 14h12 M6 18h7',
  // variable / env var
  variable: 'M8 3a5 5 0 0 0 0 18M16 3a5 5 0 0 1 0 18 M9.5 9l5 6 M14.5 9l-5 6',
  // filter
  filter: 'M3 5h18l-7 8v6l-4 2v-8z',
  // check
  check: 'M20 6L9 17l-5-5',
  // plus - marks a value the system supplied rather than one the user chose
  plus: 'M12 5v14M5 12h14',
  // wrench - maintenance tooling, distinct from `build` (compile) and
  // `refresh` (retry something that just ran)
  wrench: 'M14.7 6.3a4 4 0 0 0 5 5L21 21H3l9.7-9.7a4 4 0 0 1 2-5z',
  // grip - the six-dot drag affordance. Its own glyph rather than chevrons,
  // because a grip says "this whole row moves" where chevrons say "these two
  // buttons move it".
  grip: 'M9 5h.01M9 12h.01M9 19h.01M15 5h.01M15 12h.01M15 19h.01',
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