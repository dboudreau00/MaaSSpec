import React, { useEffect, useState } from 'react'
import { ArrowLeft, AlertTriangle } from 'lucide-react'

import { Shell, type Screen, type Theme } from '@shared/components/Shell'
import { Chip, ConfidenceBar, CopyButton, Flag, LevelTag, Notice, TypeChip } from '@shared/components/ui'
import { TOOL, formatBytes, getSpectrum, spectra, warnCount } from '@shared/data/spectra'
import { FindingsTable } from './components/FindingsTable'
import { ArtifactTree } from './components/ArtifactTree'

export const args = {
  theme: 'dark',
  spectrumId: 's1',
  tab: 'findings',
  defanged: true,
  grouped: true,
}

export const argTypes = {
  theme: { control: 'radio', options: ['dark', 'light'] },
  spectrumId: { control: 'select', options: ['s1', 's2', 's3', 's4', 's5', 's6'] },
  tab: { control: 'radio', options: ['findings', 'artifacts', 'issues', 'raw'] },
  defanged: { control: 'boolean' },
  grouped: { control: 'boolean' },
}

type Props = Partial<typeof args> & {
  sendCount?: number
  onOpen?: (id: string) => void
  onBack?: () => void
  onNavigate?: (s: Screen) => void
  onToggleTheme?: () => void
}

export default function SpectrumDetail(props: Props) {
  const p = { ...args, ...props }
  const [openId, setOpenId] = useState(p.spectrumId)
  useEffect(() => setOpenId(p.spectrumId), [p.spectrumId])
  const [tab, setTab] = useState(p.tab)
  useEffect(() => setTab(p.tab), [p.tab])
  const [artFilter, setArtFilter] = useState<string | null>(null)

  const id = p.onOpen ? p.spectrumId : openId
  const s = getSpectrum(id)
  const open = (next: string) => {
    setArtFilter(null)
    setTab('findings')
    if (p.onOpen) p.onOpen(next)
    else setOpenId(next)
  }

  const isFeed = s.inputType === 'feed_record'
  const tabs = [
    { id: 'findings', label: 'Findings', count: s.findings.length },
    { id: 'artifacts', label: 'Artifacts', count: s.artifacts.length },
    { id: 'issues', label: 'Issues', count: s.issues.length },
    { id: 'raw', label: 'Raw JSON' },
  ]

  return (
    <Shell active="spectra" theme={p.theme as Theme} sendCount={p.sendCount} onNavigate={p.onNavigate} onToggleTheme={p.onToggleTheme}>
      <div className="flex min-h-0 flex-1">
        {/* List stays visible */}
        <aside className="hidden w-[260px] shrink-0 flex-col border-r border-line bg-panel lg:flex">
          <button
            onClick={p.onBack}
            className="flex items-center gap-1.5 border-b border-line px-3 py-2 text-left text-[12px] text-muted transition-colors duration-100 hover:text-fg"
          >
            <ArrowLeft size={13} /> All spectra
            <span className="tabular ml-auto font-mono text-[11px]">{spectra.length}</span>
          </button>
          <ul className="min-h-0 flex-1 overflow-auto">
            {spectra.map((x) => {
              const on = x.id === s.id
              const w = warnCount(x)
              return (
                <li key={x.id}>
                  <button
                    onClick={() => open(x.id)}
                    className={`flex w-full flex-col gap-1 border-b border-line px-3 py-2 text-left transition-colors duration-100 ${
                      on ? 'bg-accent-soft' : 'hover:bg-raised'
                    }`}
                  >
                    <span className="flex items-center gap-2">
                      <TypeChip type={x.inputType} />
                      {w > 0 && (
                        <span className="inline-flex items-center gap-1 text-[11px] text-warn">
                          <AlertTriangle size={12} /> {w}
                        </span>
                      )}
                    </span>
                    <span className="truncate">{x.name}</span>
                    <span className="flex items-center justify-between text-[11px] text-muted">
                      <span className="truncate">{x.family ? `${x.family.name} ${x.family.confidence.toFixed(2)}` : '—'}</span>
                      <span className="tabular shrink-0 font-mono">{x.findings.length} f</span>
                    </span>
                  </button>
                </li>
              )
            })}
          </ul>
        </aside>

        <section className="flex min-h-0 min-w-0 flex-1 flex-col overflow-auto">
          {/* Header strip */}
          <div className="border-b border-line bg-panel px-4 py-2.5">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <button onClick={p.onBack} className="text-muted transition-colors duration-100 hover:text-fg lg:hidden" aria-label="Back to spectra">
                <ArrowLeft size={14} />
              </button>
              <TypeChip type={s.inputType} />
              <h1 className={`text-[15px] font-semibold ${isFeed ? 'font-mono' : ''}`}>{s.name}</h1>
            </div>
            <dl className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-1.5 text-[12px]">
              <Meta label="sha256">
                <span className="font-mono text-[12px] break-all">{s.sha256}</span>
                <CopyButton value={s.sha256} label="Copy sha256" />
              </Meta>
              <Meta label="size">
                <span className="tabular font-mono">{formatBytes(s.size)}</span>
              </Meta>
              <Meta label="tool">
                <span className="font-mono">
                  {TOOL.name} {TOOL.version}
                </span>
              </Meta>
              <Meta label="analysis id">
                <span className="font-mono">{s.analysisId}</span>
                <CopyButton value={s.analysisId} label="Copy analysis id" />
              </Meta>
            </dl>
          </div>

          {/* Summary strip */}
          <div className="flex flex-wrap items-start gap-x-8 gap-y-3 border-b border-line px-4 py-3">
            <div className="min-w-[200px]">
              <div className="text-[11px] text-muted">Family claim</div>
              {s.family ? (
                <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span className="text-[15px] font-semibold">{s.family.name}</span>
                  <ConfidenceBar value={s.family.confidence} />
                  <span className="font-mono text-[11px] text-muted">{s.family.method}</span>
                </div>
              ) : (
                <div className="mt-0.5 text-muted">No family claim</div>
              )}
            </div>
            <SummaryGroup label="Capabilities" items={s.capabilities} />
            <SummaryGroup label="Risk signals" items={s.riskSignals} />
            <div className="flex flex-col gap-1">
              <span className="inline-flex items-center gap-1.5 text-[12px]">
                <span className="text-muted">c2_count</span>
                <span className="tabular font-mono">{s.c2Count}</span>
              </span>
              <Flag on={s.configExtracted} label="config extracted" />
              <Flag on={s.encryptionObserved} label="encryption observed" />
            </div>
          </div>

          {(s.truncated || isFeed) && (
            <div className="flex flex-col gap-2 border-b border-line px-4 py-2.5">
              {isFeed && (
                <Notice level="warning" word="Unverified">
                  Feed claims, not verified. The sample was not fetched.
                </Notice>
              )}
              {s.truncated && (
                <Notice level="info" word="Scan window">
                  Hash covers the whole file. Inspection covers 8 MiB.
                </Notice>
              )}
            </div>
          )}

          {/* Tabs */}
          <div role="tablist" className="sticky top-0 z-10 flex shrink-0 items-end gap-1 border-b border-line bg-bg px-3">
            {tabs.map((t) => {
              const on = t.id === tab
              const w = t.id === 'issues' ? warnCount(s) : 0
              return (
                <button
                  key={t.id}
                  role="tab"
                  aria-selected={on}
                  onClick={() => setTab(t.id)}
                  className={`-mb-px flex items-center gap-1.5 whitespace-nowrap border-b-2 px-2.5 py-2 transition-colors duration-100 ${
                    on ? 'border-accent text-fg' : 'border-transparent text-muted hover:text-fg'
                  }`}
                >
                  {t.label}
                  {t.count !== undefined && <span className="tabular font-mono text-[11px] text-muted">{t.count}</span>}
                  {w > 0 && <AlertTriangle size={12} className="text-warn" aria-label="has warnings" />}
                </button>
              )
            })}
          </div>

          <div className="min-w-0 flex-1">
            {tab === 'findings' && (
              <FindingsTable
                spectrum={s}
                defanged={p.defanged}
                grouped={p.grouped}
                sourceFilter={artFilter}
                onClearFilter={() => setArtFilter(null)}
              />
            )}
            {tab === 'artifacts' && (
              <ArtifactTree
                spectrum={s}
                onPick={(artId) => {
                  setArtFilter(artId)
                  setTab('findings')
                }}
              />
            )}
            {tab === 'issues' &&
              (s.issues.length === 0 ? (
                <p className="px-4 py-3 text-muted">No issues.</p>
              ) : (
                <ul>
                  {s.issues.map((i, n) => (
                    <li key={n} className="flex flex-wrap items-baseline gap-x-4 gap-y-1 border-b border-line px-4 py-2">
                      <span className="w-[84px] shrink-0">
                        <LevelTag level={i.level} />
                      </span>
                      <span className="w-[120px] shrink-0 font-mono text-[12px] text-muted">{i.module}</span>
                      <span className="min-w-0 flex-1">{i.message}</span>
                      {i.recoverable && (
                        <span className="rounded border border-line-strong px-1.5 text-[11px] text-muted">recoverable</span>
                      )}
                    </li>
                  ))}
                </ul>
              ))}
            {tab === 'raw' && (
              <div className="relative">
                <div className="absolute right-3 top-2">
                  <CopyButton value={JSON.stringify(toRaw(s), null, 2)} label="Copy JSON" />
                </div>
                <pre className="overflow-auto px-4 py-3 font-mono text-[12px] leading-relaxed text-fg">
                  {JSON.stringify(toRaw(s), null, 2)}
                </pre>
              </div>
            )}
          </div>
        </section>
      </div>
    </Shell>
  )
}

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 items-center gap-1.5">
      <dt className="shrink-0 text-muted">{label}</dt>
      <dd className="flex min-w-0 items-center gap-1">{children}</dd>
    </div>
  )
}

function SummaryGroup({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="min-w-0 max-w-[320px]">
      <div className="text-[11px] text-muted">{label}</div>
      <div className="mt-1 flex flex-wrap gap-1">
        {items.length ? items.map((c) => <Chip key={c}>{c}</Chip>) : <span className="text-faint">none</span>}
      </div>
    </div>
  )
}

function toRaw(s: ReturnType<typeof getSpectrum>) {
  const { id: _id, review: _review, ...rest } = s
  return { schema: 'maasspec.spectrum/1', tool: TOOL, ...rest }
}
