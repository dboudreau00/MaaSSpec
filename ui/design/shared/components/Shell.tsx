import React, { useEffect, useState } from 'react'
import { Moon, Sun } from 'lucide-react'

export type Screen = 'spectra' | 'selectors' | 'feeds' | 'send'
export type Theme = 'dark' | 'light'

type Props = {
  active: Screen
  theme?: Theme
  sendCount?: number
  onToggleTheme?: () => void
  onNavigate?: (s: Screen) => void
  children: React.ReactNode
}

const NAV: { id: Screen; label: string }[] = [
  { id: 'spectra', label: 'Spectra' },
  { id: 'selectors', label: 'Selectors' },
  { id: 'feeds', label: 'Feeds' },
  { id: 'send', label: 'Send' },
]

export function Shell({ active, theme = 'dark', sendCount = 0, onToggleTheme, onNavigate, children }: Props) {
  const [local, setLocal] = useState<Theme>(theme)
  useEffect(() => setLocal(theme), [theme])
  const current = onToggleTheme ? theme : local
  const toggle = onToggleTheme ?? (() => setLocal((t) => (t === 'dark' ? 'light' : 'dark')))

  return (
    <div className={`theme-${current} flex h-screen flex-col bg-bg font-sans text-[13px] leading-[1.45] text-fg`}>
      <header className="flex h-9 shrink-0 items-center gap-2 border-b border-line bg-panel px-3">
        <Logomark />
        <span className="font-semibold tracking-tight">MaaSSpec</span>
        <span className="font-mono text-[11px] text-muted">0.4.0</span>
      </header>
      <div className="flex min-h-0 flex-1 flex-col md:flex-row">
        <nav className="flex shrink-0 items-center gap-0.5 overflow-x-auto border-b border-line bg-panel px-2 py-1 md:w-[132px] md:flex-col md:items-stretch md:border-b-0 md:border-r md:px-1.5 md:py-2">
          {NAV.map((n) => {
            const on = n.id === active
            return (
              <button
                key={n.id}
                onClick={() => onNavigate?.(n.id)}
                className={`flex items-center justify-between gap-3 whitespace-nowrap rounded px-2.5 py-1.5 text-left transition-colors duration-100 ${
                  on ? 'bg-accent-soft text-fg' : 'text-muted hover:bg-raised hover:text-fg'
                }`}
              >
                <span className={on ? 'font-medium' : ''}>{n.label}</span>
                {n.id === 'send' && sendCount > 0 && (
                  <span className="tabular font-mono text-[11px] text-accent">{sendCount}</span>
                )}
              </button>
            )
          })}
          <div className="hidden flex-1 md:block" />
          <button
            onClick={toggle}
            className="ml-auto flex items-center gap-2 whitespace-nowrap rounded px-2.5 py-1.5 text-muted transition-colors duration-100 hover:bg-raised hover:text-fg md:ml-0"
            aria-label="Toggle theme"
          >
            {current === 'dark' ? <Sun size={13} /> : <Moon size={13} />}
            <span>{current === 'dark' ? 'Light' : 'Dark'}</span>
          </button>
        </nav>
        <main className="flex min-h-0 min-w-0 flex-1 flex-col">{children}</main>
      </div>
    </div>
  )
}

/** Mass-spectrum peaks on a baseline: the MaaSSpec mark. */
export function Logomark({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden className="text-accent">
      <path d="M1 14.5h14" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
      <path
        d="M3 14.5v-4M5.5 14.5V3M8 14.5v-6.5M10.5 14.5V5.5M13 14.5v-2.5"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  )
}
