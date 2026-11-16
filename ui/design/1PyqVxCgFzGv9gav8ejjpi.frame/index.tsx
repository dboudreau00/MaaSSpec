import React, { useEffect, useState } from 'react'
import { AlertTriangle, Check, Loader2, OctagonX, X } from 'lucide-react'

import { Shell, type Screen, type Theme } from '@shared/components/Shell'
import { Button, CopyButton, Help, TypeChip } from '@shared/components/ui'
import { getSpectrum } from '@shared/data/spectra'

export const args = {
  theme: 'dark',
  state: 'ready',
  host: 'https://127.0.0.1:8443',
  ingestKey: true,
  simulateRejection: false,
  selected: ['s1', 's4', 's6'],
}

export const argTypes = {
  theme: { control: 'radio', options: ['dark', 'light'] },
  state: { control: 'radio', options: ['ready', 'sent', 'rejected'] },
  host: { control: 'text' },
  ingestKey: { control: 'boolean' },
  simulateRejection: { control: 'boolean' },
}

type Props = Partial<typeof args> & {
  onSelect?: (ids: string[]) => void
  onNavigate?: (s: Screen) => void
  onToggleTheme?: () => void
}

export default function Send(props: Props) {
  const p = { ...args, ...props }
  const [localSel, setLocalSel] = useState<string[]>(p.selected)
  const selected = p.onSelect ? p.selected : localSel
  const setSelected = p.onSelect ?? setLocalSel
  const [host, setHost] = useState(p.host)
  useEffect(() => setHost(p.host), [p.host])
  const [state, setState] = useState(p.state)
  useEffect(() => setState(p.state), [p.state])

  const hostOk = LOOPBACK.test(host.trim())
  const done = state === 'sent' || state === 'rejected'
  const canSend = hostOk && p.ingestKey && selected.length > 0 && state === 'ready'
  const rows = selected.map((id) => getSpectrum(id))

  return (
    <Shell active="send" theme={p.theme as Theme} sendCount={selected.length} onNavigate={p.onNavigate} onToggleTheme={p.onToggleTheme}>
      <div className="min-h-0 flex-1 overflow-auto">
        {/* Destination */}
        <div className="flex flex-wrap items-end gap-x-6 gap-y-3 border-b border-line bg-panel px-4 py-3">
          <label className="flex min-w-[260px] flex-1 flex-col gap-1 sm:max-w-[360px]">
            <span className="inline-flex items-center gap-1.5 text-[11px] text-muted">
              Destination host
              <Help>
                MaaSSpec only sends to a NocTORnal instance on this machine: http or https on 127.0.0.0/8, ::1 or
                localhost. Each spectrum is POSTed on its own with its analysis id as the Idempotency-Key, so a resend is
                reported as a duplicate rather than ingested twice.
              </Help>
            </span>
            <input
              value={host}
              onChange={(e) => setHost(e.target.value)}
              disabled={done || state === 'sending'}
              aria-invalid={!hostOk}
              className={`h-7 rounded border bg-bg px-2 font-mono text-[12px] text-fg outline-none disabled:opacity-60 ${
                hostOk ? 'border-line-strong focus:border-accent' : 'border-err'
              }`}
            />
          </label>
          <div className="flex h-7 items-center text-[12px]">
            {p.ingestKey ? (
              <span className="inline-flex items-center gap-1.5">
                <Check size={13} className="text-accent" /> Ingest key set
                <span className="font-mono text-[11px] text-muted">NOCTORNAL_INGEST_KEY</span>
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 font-medium text-warn">
                <AlertTriangle size={13} /> Ingest key not set
                <span className="font-mono text-[11px] font-normal text-muted">NOCTORNAL_INGEST_KEY</span>
              </span>
            )}
          </div>
          <div className="ml-auto flex items-center gap-2">
            {done ? (
              <Button onClick={() => setState('ready')}>Reset</Button>
            ) : (
              <Button
                variant="primary"
                disabled={!canSend}
                onClick={() => {
                  setState('sending')
                  setTimeout(() => setState(p.simulateRejection ? 'rejected' : 'sent'), 650)
                }}
              >
                {state === 'sending' && <Loader2 size={13} className="animate-spin" />}
                {state === 'sending' ? 'Sending…' : `Send ${selected.length} ${selected.length === 1 ? 'spectrum' : 'spectra'}`}
              </Button>
            )}
          </div>
          {!hostOk && (
            <p className="flex w-full items-center gap-1.5 text-[12px] text-err">
              <OctagonX size={13} /> <span className="font-medium">Error</span> Destination must be loopback http or https.
            </p>
          )}
        </div>

        <p className="border-b border-line px-4 py-2.5 text-fg">
          Spectra are sent unchanged. Nothing enters a case until a person triages it in NocTORnal.
        </p>

        {rows.length === 0 ? (
          <p className="px-4 py-3 text-muted">No spectra selected.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] border-collapse text-left">
              <thead>
                <tr className="border-b border-line text-[11px] text-muted">
                  <Th>Input</Th>
                  <Th>Family</Th>
                  <Th right>Findings</Th>
                  <Th>Idempotency-Key</Th>
                  <Th>Result</Th>
                  <Th>Batch id</Th>
                  <Th>Accepted</Th>
                  <Th>Duplicate</Th>
                  <th className="w-8" />
                </tr>
              </thead>
              <tbody>
                {rows.map((s, i) => {
                  const r = resultFor(state, i, s.id)
                  return (
                    <tr key={s.id} className={`border-b border-line ${r.kind === 'failed' ? 'bg-err-soft' : ''}`}>
                      <Td>
                        <span className="flex items-center gap-2">
                          <TypeChip type={s.inputType} />
                          <span className={`truncate ${s.inputType === 'feed_record' ? 'font-mono text-[12px]' : ''}`}>{s.name}</span>
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
                        <span className="tabular font-mono text-[12px]">{s.findings.length}</span>
                      </Td>
                      <Td>
                        <span className="inline-flex items-center gap-1">
                          <span className="font-mono text-[12px]">{s.analysisId}</span>
                          <CopyButton value={s.analysisId} label="Copy Idempotency-Key" />
                        </span>
                      </Td>
                      <Td>
                        <ResultCell r={r} />
                      </Td>
                      <Td>
                        <span className="font-mono text-[12px] text-muted">{r.kind === 'ok' ? r.batch : ''}</span>
                      </Td>
                      <Td>
                        <span className="font-mono text-[12px]">{r.kind === 'ok' ? 'yes' : ''}</span>
                      </Td>
                      <Td>
                        <span className={`font-mono text-[12px] ${r.kind === 'ok' && r.duplicate ? 'text-fg' : 'text-muted'}`}>
                          {r.kind === 'ok' ? (r.duplicate ? 'yes' : 'no') : ''}
                        </span>
                      </Td>
                      <td className="pr-2">
                        {state === 'ready' && (
                          <button
                            aria-label={`Remove ${s.name}`}
                            onClick={() => setSelected(selected.filter((x) => x !== s.id))}
                            className="inline-flex h-5 w-5 items-center justify-center rounded text-faint transition-colors duration-100 hover:bg-raised hover:text-fg"
                          >
                            <X size={12} />
                          </button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        {state === 'rejected' && (
          <p className="flex items-center gap-1.5 px-4 py-2.5 text-[12px] text-fg">
            <OctagonX size={13} className="text-err" />
            <span className="font-medium text-err">Stopped</span> at the first rejection. Rows after it were not sent.
          </p>
        )}
      </div>
    </Shell>
  )
}

const LOOPBACK = /^https?:\/\/(127(\.\d{1,3}){3}|localhost|\[::1\])(:\d{1,5})?(\/.*)?$/i

type Result =
  | { kind: 'pending' }
  | { kind: 'sending' }
  | { kind: 'ok'; batch: string; duplicate: boolean }
  | { kind: 'failed'; status: number; message: string }
  | { kind: 'not_sent' }

const BATCH: Record<string, string> = {
  s1: 'bt_7Q2MX4K9',
  s2: 'bt_8R3NY5L0',
  s3: 'bt_9S4PZ6M1',
  s4: 'bt_0T5QA7N2',
  s5: 'bt_1U6RB8P3',
  s6: 'bt_2V7SC9Q4',
}

function resultFor(state: string, index: number, id: string): Result {
  if (state === 'ready') return { kind: 'pending' }
  if (state === 'sending') return { kind: 'sending' }
  if (state === 'rejected') {
    if (index === 0) return { kind: 'ok', batch: BATCH[id], duplicate: false }
    if (index === 1) return { kind: 'failed', status: 422, message: 'schema: findings[0].grade missing credibility' }
    return { kind: 'not_sent' }
  }
  return { kind: 'ok', batch: BATCH[id], duplicate: id === 's4' }
}

function ResultCell({ r }: { r: Result }) {
  switch (r.kind) {
    case 'pending':
      return <span className="text-[12px] text-faint">ready</span>
    case 'sending':
      return (
        <span className="inline-flex items-center gap-1.5 text-[12px] text-muted">
          <Loader2 size={12} className="animate-spin" /> sending
        </span>
      )
    case 'ok':
      return (
        <span className="inline-flex items-center gap-1.5 text-[12px]">
          <Check size={13} className="text-accent" /> sent
        </span>
      )
    case 'failed':
      return (
        <span className="inline-flex flex-col">
          <span className="inline-flex items-center gap-1.5 text-[12px] font-medium text-err">
            <OctagonX size={13} /> Failed <span className="font-mono">HTTP {r.status}</span>
          </span>
          <span className="font-mono text-[11px] text-muted">{r.message}</span>
        </span>
      )
    case 'not_sent':
      return <span className="text-[12px] text-muted">not sent</span>
  }
}

function Th({ children, right }: { children?: React.ReactNode; right?: boolean }) {
  return <th className={`whitespace-nowrap px-3 py-1.5 font-normal ${right ? 'text-right' : ''}`}>{children}</th>
}

function Td({ children, right }: { children?: React.ReactNode; right?: boolean }) {
  return <td className={`px-3 py-1.5 align-middle ${right ? 'text-right' : ''}`}>{children}</td>
}
