import React, { useMemo, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { ChevronRight, X } from 'lucide-react'

import { ConfidenceBar, CopyButton, GradeChip, Help, ProvenanceBadge, Toggle } from './ui'
import { FINDING_TYPES, defang, isDefangable } from '../format'
import type { Finding, Spectrum } from '../types'

type Props = {
  spectrum: Spectrum
  sourceFilter: string | null
  onClearFilter: () => void
}

export function FindingsTable({ spectrum, sourceFilter, onClearFilter }: Props) {
  const [defanged, setDefanged] = useState(true)
  const [grouped, setGrouped] = useState(true)
  const [expanded, setExpanded] = useState<string | null>(null)

  const rows = useMemo(() => {
    const list = spectrum.findings.filter((f) => !sourceFilter || f.source === sourceFilter)
    return [...list].sort(byPublicThenConfidence)
  }, [spectrum, sourceFilter])

  const types = [...FINDING_TYPES, ...new Set(rows.map((r) => r.type).filter((t) => !FINDING_TYPES.includes(t)))]
  const groups = grouped
    ? types.map((t) => ({ type: t, items: rows.filter((r) => r.type === t) })).filter((g) => g.items.length)
    : [{ type: null, items: rows }]

  return (
    <div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-line px-4 py-2">
        <Toggle label="Group by type" checked={grouped} onChange={setGrouped} />
        <span className="inline-flex items-center gap-1.5">
          <Toggle label="Defang URLs and domains" checked={defanged} onChange={setDefanged} />
          <Help>
            Defanged values read hxxps:// and [.] so they cannot be followed by accident. Copy follows this toggle. Values
            are never rendered as links.
          </Help>
        </span>
        {sourceFilter && (
          <button
            onClick={onClearFilter}
            className="inline-flex items-center gap-1.5 rounded border border-accent/60 bg-accent-soft px-2 py-0.5 text-[12px] transition-colors duration-100 hover:border-accent"
          >
            <span className="text-muted">source</span>
            <span className="font-mono">{sourceFilter}</span>
            <X size={12} />
          </button>
        )}
        <span className="tabular ml-auto font-mono text-[11px] text-muted">
          {rows.length} of {spectrum.findings.length}
        </span>
      </div>

      {rows.length === 0 ? (
        <p className="px-4 py-3 text-muted">No findings.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[920px] border-collapse text-left">
            <thead>
              <tr className="border-b border-line text-[11px] text-muted">
                <th className="w-7" />
                <Th>id</Th>
                <Th>subtype</Th>
                <Th>value</Th>
                <Th>confidence</Th>
                <Th>
                  <span className="inline-flex items-center gap-1.5">
                    grade
                    <Help>
                      <p>
                        <span className="font-semibold">Letter</span> is source reliability: A completely reliable, B
                        usually reliable, C fairly reliable, D not usually reliable, E unreliable, F cannot be judged.
                      </p>
                      <p className="mt-2">
                        <span className="font-semibold">Number</span> is information credibility: 1 confirmed, 2 probably
                        true, 3 possibly true, 4 doubtful, 5 improbable, 6 cannot be judged.
                      </p>
                      <p className="mt-2 text-muted">Grades are proposals. The analyst sets the final grade in NocTORnal.</p>
                    </Help>
                  </span>
                </Th>
                <Th>provenance</Th>
                <Th>source</Th>
                <Th>tags</Th>
              </tr>
            </thead>
            <tbody>
              {groups.map((g) => (
                <React.Fragment key={g.type ?? 'flat'}>
                  {g.type && (
                    <tr className="border-b border-line bg-panel">
                      <td colSpan={9} className="px-3 py-1.5">
                        <span className="font-mono text-[12px] font-medium">{g.type}</span>
                        <span className="tabular ml-2 font-mono text-[11px] text-muted">{g.items.length}</span>
                      </td>
                    </tr>
                  )}
                  {g.items.map((f) => (
                    <Row
                      key={f.id}
                      f={f}
                      defanged={defanged}
                      open={expanded === f.id}
                      onToggle={() => setExpanded((e) => (e === f.id ? null : f.id))}
                    />
                  ))}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function Row({ f, defanged, open, onToggle }: { f: Finding; defanged: boolean; open: boolean; onToggle: () => void }) {
  const claimed = f.provenance.kind === 'feed'
  const network = f.type === 'c2' || f.type === 'panel'
  const shown = defanged && network ? defang(f.value) : f.value
  const tone = claimed ? 'text-muted' : ''
  return (
    <>
      <tr
        onClick={onToggle}
        className={`cursor-pointer border-b border-line transition-colors duration-100 hover:bg-raised ${open ? 'bg-raised' : ''}`}
      >
        <td className="pl-2">
          <ChevronRight
            size={13}
            className={`text-faint transition-transform duration-150 ${open ? 'rotate-90' : ''}`}
            style={{ transitionTimingFunction: 'cubic-bezier(0.23, 1, 0.32, 1)' }}
          />
        </td>
        <Td>
          <span className="font-mono text-[12px] text-muted">{f.id}</span>
        </Td>
        <Td>
          <span className={`font-mono text-[12px] ${tone}`}>{f.subtype}</span>
        </Td>
        <Td>
          <span className="flex max-w-[380px] items-center gap-1">
            <span className={`truncate font-mono text-[12px] ${tone}`} title={shown}>
              {shown}
            </span>
            <CopyButton value={shown} label="Copy value" />
            {defanged && network && isDefangable(f.value) && <span className="sr-only">defanged</span>}
          </span>
        </Td>
        <Td>
          <ConfidenceBar value={f.confidence} />
        </Td>
        <Td>
          {f.grade && <GradeChip r={f.grade.r} c={f.grade.c} rationale={f.grade.rationale} />}
        </Td>
        <Td>
          <ProvenanceBadge p={f.provenance} />
        </Td>
        <Td>
          <span className="font-mono text-[12px] text-muted">{f.source}</span>
        </Td>
        <Td>
          <span className="flex flex-wrap gap-1">
            {f.private && (
              <span className="rounded border border-line-strong px-1 font-mono text-[11px] text-fg">private</span>
            )}
            {f.tags.map((t) => (
              <span key={t} className="rounded bg-raised px-1 font-mono text-[11px] text-muted">
                {t}
              </span>
            ))}
          </span>
        </Td>
      </tr>
      <AnimatePresence initial={false}>
        {open && (
          <tr className="border-b border-line bg-panel">
            <td />
            <td colSpan={8} className="p-0">
              <motion.div
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.18, ease: [0.23, 1, 0.32, 1] }}
                className="grid gap-x-8 gap-y-4 px-3 py-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]"
              >
                <dl className="grid grid-cols-[120px_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-[12px]">
                  <Dt>extracted_by</Dt>
                  <Dd mono>
                    {f.extractedBy.module} {f.extractedBy.version}
                  </Dd>
                  <Dt>technique</Dt>
                  <Dd mono>{f.extractedBy.technique}</Dd>
                  <Dt>confidence method</Dt>
                  <Dd mono>{f.confidenceMethod}</Dd>
                  <Dt>offset / section</Dt>
                  <Dd mono>{f.location}</Dd>
                  <Dt>grade rationale</Dt>
                  <Dd>
                    {f.grade ? (
                      <>
                        <span className="font-mono">
                          {f.grade.r}/{f.grade.c}
                        </span>{' '}
                        {f.grade.rationale}
                      </>
                    ) : (
                      '—'
                    )}
                  </Dd>
                  {Object.entries(f.context).map(([k, v]) => (
                    <React.Fragment key={k}>
                      <Dt mono>{k}</Dt>
                      <Dd mono>{v}</Dd>
                    </React.Fragment>
                  ))}
                  {f.familyData &&
                    Object.entries(f.familyData).map(([k, v]) => (
                      <React.Fragment key={`fd-${k}`}>
                        <Dt mono>family_data.{k}</Dt>
                        <Dd mono>{v}</Dd>
                      </React.Fragment>
                    ))}
                </dl>
                <div className="min-w-0">
                  <div className="mb-1 text-[11px] text-muted">selectors</div>
                  {f.selectors.length === 0 ? (
                    <p className="text-[12px] text-faint">No selectors.</p>
                  ) : (
                    <table className="w-full border-collapse text-[12px]">
                      <thead>
                        <tr className="text-[11px] text-muted">
                          <th className="py-1 pr-3 text-left font-normal">kind</th>
                          <th className="py-1 pr-3 text-left font-normal">value</th>
                          <th className="py-1 text-left font-normal">normalized</th>
                        </tr>
                      </thead>
                      <tbody>
                        {f.selectors.map((s) => (
                          <tr key={s.kind + s.value} className="border-t border-line">
                            <td className="py-1 pr-3 font-mono text-muted">{s.kind}</td>
                            <td className="max-w-[220px] py-1 pr-3">
                              <span className="flex items-center gap-1">
                                <span className="truncate font-mono">{defanged ? defang(s.value) : s.value}</span>
                                <CopyButton value={s.value} label="Copy selector value" />
                              </span>
                            </td>
                            <td className="max-w-[220px] py-1">
                              <span className="flex items-center gap-1">
                                <span className="truncate font-mono text-muted">{defanged ? defang(s.normalized) : s.normalized}</span>
                                <CopyButton value={s.normalized} label="Copy normalized" />
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </motion.div>
            </td>
          </tr>
        )}
      </AnimatePresence>
    </>
  )
}

function Th({ children }: { children?: React.ReactNode }) {
  return <th className="whitespace-nowrap px-3 py-1.5 font-normal">{children}</th>
}

function Td({ children }: { children?: React.ReactNode }) {
  return <td className="px-3 py-1.5 align-middle">{children}</td>
}

function Dt({ children, mono }: { children: React.ReactNode; mono?: boolean }) {
  return <dt className={`text-muted ${mono ? 'font-mono' : ''}`}>{children}</dt>
}

function Dd({ children, mono }: { children: React.ReactNode; mono?: boolean }) {
  return <dd className={`min-w-0 break-words ${mono ? 'font-mono' : ''}`}>{children}</dd>
}

function byPublicThenConfidence(a: Finding, b: Finding) {
  if (!!a.private !== !!b.private) return a.private ? 1 : -1
  return b.confidence - a.confidence
}
