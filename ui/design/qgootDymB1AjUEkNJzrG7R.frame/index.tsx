import React, { useMemo, useState } from 'react'
import { Search } from 'lucide-react'

import { Shell, type Screen, type Theme } from '@shared/components/Shell'
import { ConfidenceBar, CopyButton, Help, Select, Toggle, TypeChip } from '@shared/components/ui'
import { SELECTOR_KINDS, defang, getSpectrum, pivotSelectors, type SelectorRow } from '@shared/data/spectra'

export const args = {
  theme: 'dark',
  kind: 'all',
  selected: 'ipv4|93.184.216.34',
  sharedOnly: false,
}

export const argTypes = {
  theme: { control: 'radio', options: ['dark', 'light'] },
  kind: { control: 'select', options: ['all', 'sha256', 'domain', 'url', 'ipv4', 'ipv4_port', 'email', 'bitcoin'] },
  selected: { control: 'text' },
  sharedOnly: { control: 'boolean' },
}

type Props = Partial<typeof args> & {
  sendCount?: number
  onOpen?: (spectrumId: string) => void
  onNavigate?: (s: Screen) => void
  onToggleTheme?: () => void
}

export default function Selectors(props: Props) {
  const p = { ...args, ...props }
  const [kind, setKind] = useState(p.kind)
  const [sel, setSel] = useState<string | null>(p.selected)
  const [shared, setShared] = useState(p.sharedOnly)
  const [q, setQ] = useState('')

  const all = useMemo(() => pivotSelectors(), [])
  const rows = all.filter(
    (r) =>
      (kind === 'all' || r.kind === kind) &&
      (!shared || r.spectra.length > 1) &&
      (!q.trim() || r.value.toLowerCase().includes(q.trim().toLowerCase())),
  )
  const groups = SELECTOR_KINDS.map((k) => ({
    kind: k,
    items: rows.filter((r) => r.kind === k).sort((a, b) => b.spectra.length - a.spectra.length || b.best - a.best),
  })).filter((g) => g.items.length)
  const current = all.find((r) => key(r) === sel) ?? null

  return (
    <Shell active="selectors" theme={p.theme as Theme} sendCount={p.sendCount} onNavigate={p.onNavigate} onToggleTheme={p.onToggleTheme}>
      <div className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-2 border-b border-line bg-panel px-3 py-2">
        <label className="flex h-7 min-w-[180px] flex-1 items-center gap-1.5 rounded border border-line-strong bg-bg px-2 focus-within:border-accent sm:max-w-[280px]">
          <Search size={13} className="shrink-0 text-faint" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filter values"
            className="min-w-0 flex-1 bg-transparent font-mono text-[12px] outline-none placeholder:font-sans placeholder:text-faint"
          />
        </label>
        <Select
          label="Kind"
          value={kind}
          onChange={setKind}
          mono
          options={[{ value: 'all', label: 'all' }, ...SELECTOR_KINDS.map((k) => ({ value: k, label: k }))]}
        />
        <Toggle label="In more than one spectrum" checked={shared} onChange={setShared} />
        <span className="ml-auto inline-flex items-center gap-1.5 text-[12px] text-muted">
          <span className="tabular font-mono">{rows.length}</span> values
          <Help align="right">
            Selectors are pivoted across all loaded spectra by normalized value. A spectrum's own sha256 counts as a
            selector, except for feed records, whose hash is of the record, not a sample.
          </Help>
        </span>
      </div>

      <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
        <div className="min-h-0 min-w-0 flex-1 overflow-auto">
          {groups.length === 0 ? (
            <p className="px-4 py-3 text-muted">No selectors.</p>
          ) : (
            <table className="w-full min-w-[620px] border-collapse text-left">
              <thead className="sticky top-0 z-10 bg-bg">
                <tr className="border-b border-line text-[11px] text-muted">
                  <th className="px-3 py-1.5 font-normal">value</th>
                  <th className="px-3 py-1.5 font-normal">kind</th>
                  <th className="px-3 py-1.5 text-right font-normal">spectra</th>
                  <th className="px-3 py-1.5 font-normal">best confidence</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((g) => (
                  <React.Fragment key={g.kind}>
                    <tr className="border-b border-line bg-panel">
                      <td colSpan={4} className="px-3 py-1.5">
                        <span className="font-mono text-[12px] font-medium">{g.kind}</span>
                        <span className="tabular ml-2 font-mono text-[11px] text-muted">{g.items.length}</span>
                      </td>
                    </tr>
                    {g.items.map((r) => {
                      const on = key(r) === sel
                      const multi = r.spectra.length > 1
                      return (
                        <tr
                          key={key(r)}
                          onClick={() => setSel(key(r))}
                          className={`cursor-pointer border-b border-line transition-colors duration-100 ${
                            on ? 'bg-accent-soft' : 'hover:bg-raised'
                          }`}
                        >
                          <td className="max-w-[420px] px-3 py-1.5">
                            <span className="flex items-center gap-1">
                              {multi && <span className="mr-1 h-3.5 w-[3px] shrink-0 rounded-full bg-accent" aria-hidden />}
                              <span className="truncate font-mono text-[12px]" title={r.value}>
                                {defang(r.value)}
                              </span>
                              <CopyButton value={r.value} label="Copy selector" />
                            </span>
                          </td>
                          <td className="px-3 py-1.5 font-mono text-[12px] text-muted">{r.kind}</td>
                          <td className="px-3 py-1.5 text-right">
                            {multi ? (
                              <span className="tabular rounded bg-accent px-1.5 py-px font-mono text-[11px] font-medium text-on-accent">
                                {r.spectra.length}
                              </span>
                            ) : (
                              <span className="tabular font-mono text-[12px] text-muted">1</span>
                            )}
                          </td>
                          <td className="px-3 py-1.5">
                            <ConfidenceBar value={r.best} />
                          </td>
                        </tr>
                      )
                    })}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <aside className="flex max-h-[45%] shrink-0 flex-col border-t border-line bg-panel lg:max-h-none lg:w-[380px] lg:border-l lg:border-t-0">
          {current ? (
            <>
              <div className="border-b border-line px-4 py-3">
                <div className="font-mono text-[11px] text-muted">{current.kind}</div>
                <div className="mt-1 flex items-start gap-1">
                  <span className="min-w-0 break-all font-mono text-[13px]">{defang(current.value)}</span>
                  <CopyButton value={current.value} label="Copy selector" />
                </div>
                <div className="mt-1 text-[12px] text-muted">
                  In <span className="tabular font-mono text-fg">{current.spectra.length}</span> of the loaded spectra
                </div>
              </div>
              <ul className="min-h-0 flex-1 overflow-auto">
                {current.spectra.map((sid) => {
                  const s = getSpectrum(sid)
                  const hits = s.findings.filter((f) => f.selectors.some((x) => x.kind === current.kind && x.normalized === current.value))
                  const self = current.kind === 'sha256' && s.sha256 === current.value
                  return (
                    <li key={sid}>
                      <button
                        onClick={() => p.onOpen?.(sid)}
                        className="flex w-full flex-col gap-1 border-b border-line px-4 py-2.5 text-left transition-colors duration-100 hover:bg-raised"
                      >
                        <span className="flex items-center gap-2">
                          <TypeChip type={s.inputType} />
                          <span className="truncate">{s.name}</span>
                        </span>
                        <span className="text-[12px] text-muted">
                          {self && 'Input sha256'}
                          {self && hits.length > 0 && ' · '}
                          {hits.length > 0 && (
                            <span className="font-mono">
                              {hits.map((f) => `${f.id} ${f.type} ${f.confidence.toFixed(2)}`).join(', ')}
                            </span>
                          )}
                        </span>
                      </button>
                    </li>
                  )
                })}
              </ul>
            </>
          ) : (
            <p className="px-4 py-3 text-muted">Select a value to list its spectra.</p>
          )}
        </aside>
      </div>
    </Shell>
  )
}

function key(r: SelectorRow) {
  return `${r.kind}|${r.value}`
}
