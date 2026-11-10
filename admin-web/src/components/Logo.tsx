// Da Orks logo, vectorised from the original block-character art.
//
// Paths instead of an <img>: the glyphs use currentColor, so one asset follows
// the light/dark theme, the accent tile and muted empty states without a second
// file. Shade characters (the soft pixel edges) are kept as partial-opacity
// layers. Whole mark is ~1 KB of path data.
type Art = { w: number; h: number; layers: [number, string][] }

const MARK: Art = { w: 30, h: 46, layers: [[1.0, "M0 10h8v2h-8zM0 32h10v2h-10zM1 28h5v4h-5zM1 8h9v2h-9zM1 6h22v2h-22zM1 34h28v2h-28zM2 22h2v2h-2zM2 24h3v4h-3zM2 12h6v2h-6zM3 20h1v2h-1zM4 36h24v2h-24zM5 14h4v2h-4zM7 30h2v2h-2zM7 16h8v2h-8zM7 38h17v2h-17zM8 24h5v2h-5zM8 18h6v2h-6zM8 20h14v4h-14zM8 4h15v2h-15zM9 0h2v2h-2zM9 2h10v2h-10zM9 40h13v2h-13zM10 26h2v2h-2zM12 30h5v4h-5zM12 42h6v2h-6zM13 28h2v2h-2zM14 8h14v2h-14zM14 14h16v2h-16zM15 44h1v2h-1zM15 12h3v2h-3zM15 24h4v2h-4zM15 10h6v2h-6zM16 26h2v2h-2zM16 16h7v2h-7zM17 18h5v2h-5zM19 32h10v2h-10zM20 28h1v2h-1zM20 30h3v2h-3zM23 10h6v2h-6zM24 30h5v2h-5zM24 12h6v2h-6zM25 28h3v2h-3zM26 26h2v2h-2zM27 24h1v2h-1z"], [0.75, "M1 12h1v2h-1zM3 36h1v2h-1zM4 14h1v2h-1zM6 38h1v2h-1zM7 4h1v2h-1zM7 18h1v2h-1zM7 22h1v4h-1zM8 2h1v2h-1zM10 28h1v2h-1zM11 32h1v2h-1zM13 8h1v2h-1zM14 26h1v2h-1zM17 28h1v2h-1zM17 32h1v2h-1zM18 42h1v2h-1zM21 24h1v2h-1zM23 6h1v2h-1zM26 24h1v2h-1zM28 8h1v2h-1z"], [0.5, "M4 22h1v2h-1zM6 30h1v2h-1zM7 20h1v2h-1zM9 14h1v2h-1zM10 32h1v2h-1zM14 18h1v2h-1zM15 28h1v2h-1zM19 30h1v2h-1zM21 28h1v2h-1zM24 38h1v2h-1zM28 28h1v2h-1zM29 16h1v2h-1z"], [0.25, "M0 30h1v2h-1zM1 26h1v2h-1zM3 18h1v2h-1zM9 26h1v2h-1zM11 0h1v2h-1zM13 14h1v2h-1zM14 44h1v2h-1zM22 18h1v2h-1zM27 22h1v2h-1z"]] }
const LOCKUP: Art = { w: 30, h: 54, layers: [[1.0, "M0 10h8v2h-8zM0 32h10v2h-10zM1 28h5v4h-5zM1 8h9v2h-9zM1 6h22v2h-22zM1 34h28v2h-28zM2 48h1v5h-1zM2 22h2v2h-2zM2 24h3v4h-3zM2 12h6v2h-6zM3 20h1v2h-1zM3 48h1v1h-1zM3 52h1v1h-1zM4 49h1v3h-1zM4 36h24v2h-24zM5 14h4v2h-4zM6 48h1v5h-1zM7 48h1v1h-1zM7 50h1v1h-1zM7 30h2v2h-2zM7 16h8v2h-8zM7 38h17v2h-17zM8 48h1v5h-1zM8 24h5v2h-5zM8 18h6v2h-6zM8 20h14v4h-14zM8 4h15v2h-15zM9 0h2v2h-2zM9 2h10v2h-10zM9 40h13v2h-13zM10 26h2v2h-2zM12 48h1v5h-1zM12 30h5v4h-5zM12 42h6v2h-6zM13 48h1v1h-1zM13 52h1v1h-1zM13 28h2v2h-2zM14 48h1v5h-1zM14 8h14v2h-14zM14 14h16v2h-16zM15 44h1v2h-1zM15 12h3v2h-3zM15 24h4v2h-4zM15 10h6v2h-6zM16 48h1v5h-1zM16 26h2v2h-2zM16 16h7v2h-7zM17 48h1v1h-1zM17 50h1v1h-1zM17 18h5v2h-5zM18 49h1v1h-1zM18 51h1v2h-1zM19 32h10v2h-10zM20 28h1v2h-1zM20 48h1v5h-1zM20 30h3v2h-3zM21 50h1v1h-1zM22 48h1v2h-1zM22 51h1v2h-1zM23 10h6v2h-6zM24 48h1v3h-1zM24 52h1v1h-1zM24 30h5v2h-5zM24 12h6v2h-6zM25 48h1v1h-1zM25 50h1v1h-1zM25 52h1v1h-1zM25 28h3v2h-3zM26 48h1v1h-1zM26 50h1v3h-1zM26 26h2v2h-2zM27 24h1v2h-1z"], [0.75, "M1 12h1v2h-1zM3 36h1v2h-1zM4 14h1v2h-1zM6 38h1v2h-1zM7 4h1v2h-1zM7 18h1v2h-1zM7 22h1v4h-1zM8 2h1v2h-1zM10 28h1v2h-1zM11 32h1v2h-1zM13 8h1v2h-1zM14 26h1v2h-1zM17 28h1v2h-1zM17 32h1v2h-1zM18 42h1v2h-1zM21 24h1v2h-1zM23 6h1v2h-1zM26 24h1v2h-1zM28 8h1v2h-1z"], [0.5, "M4 22h1v2h-1zM6 30h1v2h-1zM7 20h1v2h-1zM9 14h1v2h-1zM10 32h1v2h-1zM14 18h1v2h-1zM15 28h1v2h-1zM19 30h1v2h-1zM21 28h1v2h-1zM24 38h1v2h-1zM28 28h1v2h-1zM29 16h1v2h-1z"], [0.25, "M0 30h1v2h-1zM1 26h1v2h-1zM1 48h1v6h-1zM3 18h1v2h-1zM3 50h1v2h-1zM4 52h2v2h-2zM5 48h1v4h-1zM7 52h1v2h-1zM9 26h1v2h-1zM9 48h3v6h-3zM11 0h1v2h-1zM13 14h1v2h-1zM13 50h1v2h-1zM14 44h1v2h-1zM15 48h1v6h-1zM17 52h1v2h-1zM19 48h1v6h-1zM21 48h1v2h-1zM21 52h1v2h-1zM22 18h1v2h-1zM23 48h1v6h-1zM27 22h1v2h-1z"]] }

function Svg({ art, height, className, title }: { art: Art; height: number; className?: string; title?: string }) {
  return (
    <svg
      viewBox={`0 0 ${art.w} ${art.h}`}
      height={height}
      width={(height * art.w) / art.h}
      fill="currentColor"
      shapeRendering="crispEdges"
      className={className}
      role={title ? 'img' : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
    >
      {art.layers.map(([o, d]) => (
        <path key={o} d={d} opacity={o === 1 ? undefined : o} />
      ))}
    </svg>
  )
}

/** The skull alone. Sized by height in px. */
export function LogoMark({ height = 16, className, title }: { height?: number; className?: string; title?: string }) {
  return <Svg art={MARK} height={height} className={className} title={title} />
}

/** Skull plus the pixel "DA ORKS" wordmark. */
export function LogoLockup({ height = 84, className, title }: { height?: number; className?: string; title?: string }) {
  return <Svg art={LOCKUP} height={height} className={className} title={title} />
}
