import Icon, { type IconName } from './Icon'

// Sub-navigation for panels that carry more than one concern.
//
// A panel like Qiling has status, performance, a guest scanner and an emulation
// rootfs. Stacked, that is a long scroll where nothing has emphasis. Tabs keep
// each concern on its own screen while the panel keeps one identity and one
// header, which is why this is not routing.

export interface SubTab {
  id: string
  label: string
  icon: IconName
  /** Optional status dot - used to signal "this one needs attention". */
  tone?: 'ok' | 'warn' | 'bad'
}

export default function SubNav({
  tabs,
  active,
  onChange,
}: {
  tabs: SubTab[]
  active: string
  onChange: (id: string) => void
}) {
  return (
    <div
      role="tablist"
      aria-label="Section"
      className="mb-5 flex flex-wrap gap-1 rounded-xl border border-default-200/70 bg-surface/50 p-1 backdrop-blur"
    >
      {tabs.map((t) => {
        const on = t.id === active
        return (
          <button
            key={t.id}
            role="tab"
            aria-selected={on}
            onClick={() => onChange(t.id)}
            className={`flex items-center gap-2 rounded-lg px-3 py-2 text-[12px] font-medium transition-all ${
              on
                ? 'bg-accent/12 text-foreground shadow-[0_4px_16px_-10px_var(--accent)]'
                : 'text-default-500 hover:bg-default-100 hover:text-foreground'
            }`}
          >
            <Icon name={t.icon} size={14} />
            {t.label}
            {t.tone && (
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  t.tone === 'ok'
                    ? 'bg-success'
                    : t.tone === 'warn'
                      ? 'bg-warning'
                      : 'bg-danger'
                }`}
              />
            )}
          </button>
        )
      })}
    </div>
  )
}