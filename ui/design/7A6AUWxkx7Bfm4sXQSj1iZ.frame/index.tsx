import React, { useMemo, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { AlertTriangle, ChevronDown, OctagonX, Plus, Search } from 'lucide-react'

import { Shell, type Screen, type Theme } from '@shared/components/Shell'
import { Button, CopyButton, Help, ReviewMark, Select, Toggle, TypeChip } from '@shared/components/ui'
import { shortHash, spectra as ALL, type Spectrum } from '@shared/data/spectra'

export const args = {
  state: 'default',
  theme: 'dark',
  selected: ['s1', 's4', 's6'],
  addMenuOpen: false,
}

export const argTypes = {
  state: { control: 'radio', options: ['default', 'empty'] },
  theme: { control: 'radio', options: ['dark', 'light'] },
  addMenuOpen: { control: 'boolean' },
}

type Props = Partial<typeof args> & {
  onOpen?: (id: string) => void
  onSelect?: (ids: string[]) => void
  onNavigate?: (s: Screen) => void
  onToggleTheme?: () => void
  onAdd?: (kind: 'open' | 'analyze' | 'import') => void
}

export default function Spectra(props: Props) {
  const { state, theme, selected: selectedArg, addMenuOpen, onOpen, onSelect, onNavigate, onToggleTheme, onAdd } = {
    ...args,
    ...props,
  }
  const [localSel, setLocalSel] = useState<string[]>(selectedArg)
  const selected = onSelect ? selectedArg : localSel
  const setSelected = onSelect ?? setLocalSel
  const [menu, setMenu] = useState(addMenuOpen)
  const [type, setType] = useState('all')
  const [feed, setFeed] = useState('all')
  const [hasFamily, setHasFamily] = useState(false)
  const [hasIssues, setHasIssues] = useState(false)
  const [minConf, setMinConf] = useState('0')
  const [q, setQ] = useState('')
  const [marks, setMarks] = useState<Record<string, string>>(() => Object.fromEntries(ALL.map((s) => [s.id, s.review])))

  const data = state === 'empty' ? [] : ALL
  const rows = useMemo(
    () =>
      data.filter((s) => {
        if (type !== 'all' && s.inputType !== type) return false
        if (feed !== 'all' && s.source !== feed) return false
        if (hasFamily && !s.family) return false
        if (hasIssues && issueCount(s).total === 0) return false
        const mc = Number(minConf)
        if (mc > 0 && !s.findings.some((f) => f.confidence >= mc)) return false
        if (q.trim()) {
          const needle = q.trim().toLowerCase()
          const hay = [s.sha256, ...s.findings.flatMap((f) => f.selectors.map((x) => x.normalized))].join(' ').toLowerCase()
          if (!hay.includes(needle)) return false
        }
        return true
      }),
    [data, type, feed, hasFamily, hasIssues, minConf, q],
  )

  const allOn = rows.length > 0 && rows.every((r) => selected.includes(r.id))
  const toggle = (id: string) =>
    setSelected(selected.includes(id) ? selected.filter((x) => x !== id) : [...selected, id])

  return (
    <Shell active="spectra" theme={theme as Theme} sendCount={selected.length} onNavigate={onNavigate} onToggleTheme={onToggleTheme}>
      {/* Toolbar */}
      <div className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-2 border-b border-line bg-panel px-3 py-2">
        <div className="relative">
          <Button variant="primary" onClick={() => setMenu((m) => !m)}>
            <Plus size={13} /> Add <ChevronDown size={12} />
          </Button>
          <AnimatePresence>
            {menu && (
              <motion.div
                initial={{ opacity: 0, y: -3 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -3 }}
                transition={{ duration: 0.15, ease: [0.23, 1, 0.32, 1] }}
                className="absolute left-0 top-8 z-30 w-[260px] rounded border border-line-strong bg-panel py-1"
              >
                {[
                  { k: 'open' as const, label: 'Open spectra file', hint: '.json, .jsonl' },
                  { k: 'analyze' as const, label: 'Analyze a file', hint: 'static, local' },
                  { k: 'import' as const, label: 'Import feed export', hint: '.json' },
                ].map((i) => (
                  <button
                    key={i.k}
                    onClick={() => {
                      setMenu(false)
                      onAdd?.(i.k)
                    }}
                    className="flex w-full items-center justify-between px-3 py-1.5 text-left transition-colors duration-100 hover:bg-raised"
                  >
                    <span>{i.label}</span>
                    <span className="font-mono text-[11px] text-faint">{i.hint}</span>
                  </button>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
        <span className="hidden h-5 w-px bg-line sm:block" />
        <label className="flex h-7 min-w-[180px] flex-1 items-center gap-1.5 rounded border border-line-strong bg-bg px-2 focus-within:border-accent sm:max-w-[280px]">
          <Search size={13} className="shrink-0 text-faint" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search selectors"
            className="min-w-0 flex-1 bg-transparent font-mono text-[12px] text-fg outline-none placeholder:font-sans placeholder:text-faint"
          />
        </label>
        <Select
          label="Type"
          value={type}
          onChange={setType}
          options={[{ value: 'all', label: 'All' }, ...['sample', 'archive', 'cape_report', 'feed_record'].map((v) => ({ value: v, label: v }))]}
        />
        <Select
          label="Feed"
          value={feed}
          onChange={setFeed}
          options={[{ value: 'all', label: 'All' }, ...['local file', 'malwarebazaar', 'threatfox', 'unpacme'].map((v) => ({ value: v, label: v }))]}
        />
        <Select
          label="Min conf."
          value={minConf}
          onChange={setMinConf}
          mono
          options={['0', '0.35', '0.50', '0.70', '0.90'].map((v) => ({ value: v, label: v === '0' ? 'any' : `≥ ${v}` }))}
        />
        <Toggle label="Has family" checked={hasFamily} onChange={setHasFamily} />
        <Toggle label="Has issues" checked={hasIssues} onChange={setHasIssues} />
        <div className="ml-auto flex items-center gap-2">
          <span className="tabular whitespace-nowrap text-[12px] text-muted">
            {selected.length} selected
          </span>
          <Button disabled={selected.length === 0} onClick={() => onNavigate?.('send')}>
            Send…
          </Button>
        </div>
      </div>

      {/* Table */}
      <div className="min-h-0 flex-1 overflow-auto">
        {data.length === 0 ? (
          <p className="px-4 py-3 text-muted">No spectra loaded.</p>
        ) : (
          <table className="w-full border-collapse text-left">
            <thead className="sticky top-0 z-10 bg-panel">
              <tr className="border-b border-line text-[11px] text-muted">
                <th className="w-8 py-1.5 pl-3 font-normal">
                  <input
                    type="checkbox"
                    aria-label="Select all"
                    checked={allOn}
                    onChange={() => setSelected(allOn ? [] : rows.map((r) => r.id))}
                    className="h-3.5 w-3.5 accent-[var(--mx-accent)]"
                  />
                </th>
                <Th>Input</Th>
                <Th>Name</Th>
                <Th className="hidden md:table-cell">sha256</Th>
                <Th>Family claim</Th>
                <Th right>C2</Th>
                <Th right>Findings</Th>
                <Th>Issues</Th>
                <Th className="hidden lg:table-cell">Source</Th>
                <Th className="hidden xl:table-cell">Generated</Th>
                <Th className="hidden lg:table-cell">
                  <span className="inline-flex items-center gap-1.5">
                    Review
                    <Help align="right">Review marks are stored in this browser only. They are never written into a spectrum and are never sent.</Help>
                  </span>
                </Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => {
                const on = selected.includes(s.id)
                const iss = issueCount(s)
                return (
                  <tr
                    key={s.id}
                    onClick={() => onOpen?.(s.id)}
                    className={`cursor-pointer border-b border-line transition-colors duration-100 ${
                      on ? 'bg-accent-soft' : 'hover:bg-raised'
                    }`}
                  >
                    <td className="py-1.5 pl-3" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        aria-label={`Select ${s.name}`}
                        checked={on}
                        onChange={() => toggle(s.id)}
                        className="h-3.5 w-3.5 accent-[var(--mx-accent)]"
                      />
                    </td>
                    <Td>
                      <TypeChip type={s.inputType} />
                    </Td>
                    <Td>
                      <span className={s.inputType === 'feed_record' || s.inputType === 'cape_report' ? 'font-mono text-[12px]' : ''}>
                        {s.name}
                      </span>
                    </Td>
                    <Td className="hidden md:table-cell">
                      <span className="inline-flex items-center gap-1">
                        <span className="font-mono text-[12px] text-muted">{shortHash(s.sha256)}</span>
                        <CopyButton value={s.sha256} label="Copy sha256" />
                      </span>
                    </Td>
                    <Td>
                      {s.family ? (
                        <span className="whitespace-nowrap">
                          {s.family.name} <span className="tabular font-mono text-[12px] text-muted">{s.family.confidence.toFixed(2)}</span>
                        </span>
                      ) : (
                        <span className="text-faint">—</span>
                      )}
                    </Td>
                    <Td right>
                      <span className={`tabular font-mono text-[12px] ${s.c2Count ? '' : 'text-faint'}`}>{s.c2Count}</span>
                    </Td>
                    <Td right>
                      <span className="tabular font-mono text-[12px]">{s.findings.length}</span>
                    </Td>
                    <Td>
                      {iss.errors > 0 ? (
                        <span className="inline-flex items-center gap-1 whitespace-nowrap text-[12px] text-err">
                          <OctagonX size={13} /> {iss.errors} error{iss.errors > 1 ? 's' : ''}
                        </span>
                      ) : iss.warnings > 0 ? (
                        <span className="inline-flex items-center gap-1 whitespace-nowrap text-[12px] text-warn">
                          <AlertTriangle size={13} /> {iss.warnings} warning{iss.warnings > 1 ? 's' : ''}
                        </span>
                      ) : (
                        <span className="tabular font-mono text-[12px] text-faint">0</span>
                      )}
                    </Td>
                    <Td className="hidden lg:table-cell">
                      <span className="whitespace-nowrap text-muted">{s.source}</span>
                    </Td>
                    <Td className="hidden xl:table-cell">
                      <span className="whitespace-nowrap font-mono text-[12px] text-muted">{s.generated}</span>
                    </Td>
                    <Td className="hidden lg:table-cell">
                      <ReviewMark value={marks[s.id]} onChange={(v) => setMarks((m) => ({ ...m, [s.id]: v }))} />
                    </Td>
                  </tr>
                )
              })}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={11} className="px-4 py-3 text-muted">
                    No spectra match these filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </Shell>
  )
}

function Th({ children, right, className = '' }: { children?: React.ReactNode; right?: boolean; className?: string }) {
  return <th className={`whitespace-nowrap px-3 py-1.5 font-normal ${right ? 'text-right' : ''} ${className}`}>{children}</th>
}

function Td({ children, right, className = '' }: { children?: React.ReactNode; right?: boolean; className?: string }) {
  return <td className={`px-3 py-1.5 align-middle ${right ? 'text-right' : ''} ${className}`}>{children}</td>
}

function issueCount(s: Spectrum) {
  const warnings = s.issues.filter((i) => i.level === 'warning').length
  const errors = s.issues.filter((i) => i.level === 'error').length
  return { warnings, errors, total: warnings + errors }
}
