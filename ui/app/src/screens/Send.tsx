import React, { useState } from 'react'
import { AlertTriangle, Check, Loader2, OctagonX, X } from 'lucide-react'

import { Button, CopyButton, Help, Notice, TypeChip } from '../components/ui'
import { api, errorText } from '../api'
import type { ApiStatus, SendResult, Spectrum } from '../types'

type Props = {
  status: ApiStatus | null
  statusError: string | null
  spectra: Spectrum[]
  selected: string[]
  onSelect: (ids: string[]) => void
}

type Phase = 'ready' | 'sending' | 'done'

export default function Send({ status, statusError, spectra, selected, onSelect }: Props) {
  const [phase, setPhase] = useState<Phase>('ready')
  const [results, setResults] = useState<Record<string, SendResult>>({})
  const [error, setError] = useState<string | null>(null)

  const rows = selected.flatMap((id) => spectra.find((s) => s.id === id) ?? [])
  const url = status?.ingest.url ?? null
  const keySet = status?.ingest.keySet ?? false
  const stopped = Object.values(results).some((r) => r.status === 'failed')
  const canSend = !!status && !!url && keySet && rows.length > 0 && phase === 'ready'

  const send = async () => {
    const ids = rows.map((s) => s.id)
    setPhase('sending')
    setError(null)
    try {
      const r = await api.send(ids)
      setResults(Object.fromEntries(r.results.map((x) => [x.id, x])))
      setPhase('done')
    } catch (e) {
      setError(errorText(e))
      setPhase('ready')
    }
  }

  const reset = () => {
    setPhase('ready')
    setResults({})
    setError(null)
  }

  return (
    <div className="min-h-0 flex-1 overflow-auto">
      {/* Destination */}
      <div className="flex flex-wrap items-end gap-x-6 gap-y-3 border-b border-line bg-panel px-4 py-3">
        <div className="flex min-w-[260px] flex-1 flex-col gap-1 sm:max-w-[360px]">
          <span className="inline-flex items-center gap-1.5 text-[11px] text-muted">
            Destination
            <Help>
              MaaSSpec sends to the NocTORnal address set in {status?.env.ingestUrl ?? 'the server environment'}. Each
              spectrum is POSTed on its own with its analysis id as the Idempotency-Key, so a resend is reported as a
              duplicate rather than ingested twice.
            </Help>
          </span>
          <div className="flex h-7 items-center text-[12px]">
            {!status ? null : url ? (
              <span className="font-mono text-[12px]">{url}</span>
            ) : (
              <span className="inline-flex items-center gap-1.5 font-medium text-warn">
                <AlertTriangle size={13} /> Destination not set
                <span className="font-mono text-[11px] font-normal text-muted">{status.env.ingestUrl}</span>
              </span>
            )}
          </div>
        </div>
        <div className="flex h-7 items-center text-[12px]">
          {!status ? null : keySet ? (
            <span className="inline-flex items-center gap-1.5">
              <Check size={13} className="text-accent" /> Ingest key set
              <span className="font-mono text-[11px] text-muted">{status.env.ingestKey}</span>
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 font-medium text-warn">
              <AlertTriangle size={13} /> Ingest key not set
              <span className="font-mono text-[11px] font-normal text-muted">{status.env.ingestKey}</span>
            </span>
          )}
        </div>
        <div className="ml-auto flex items-center gap-2">
          {phase === 'done' ? (
            <Button onClick={reset}>Reset</Button>
          ) : (
            <Button variant="primary" disabled={!canSend} onClick={send}>
              {phase === 'sending' && <Loader2 size={13} className="animate-spin" />}
              {phase === 'sending' ? 'Sending…' : `Send ${rows.length} ${rows.length === 1 ? 'spectrum' : 'spectra'}`}
            </Button>
          )}
        </div>
        {(error ?? statusError) && (
          <div className="w-full">
            <Notice level="error" word="Error">
              {error ?? statusError}
            </Notice>
          </div>
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
              {rows.map((s) => {
                const r = results[s.id]
                const ok = r?.status === 'ok'
                return (
                  <tr key={s.id} className={`border-b border-line ${r?.status === 'failed' ? 'bg-err-soft' : ''}`}>
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
                      <ResultCell phase={phase} r={r} />
                    </Td>
                    <Td>
                      <span className="font-mono text-[12px] text-muted">{ok ? (r.batchId ?? '') : ''}</span>
                    </Td>
                    <Td>
                      <span className="font-mono text-[12px]">{ok && r.accepted !== undefined ? (r.accepted ? 'yes' : 'no') : ''}</span>
                    </Td>
                    <Td>
                      <span className={`font-mono text-[12px] ${ok && r.duplicate ? 'text-fg' : 'text-muted'}`}>
                        {ok && r.duplicate !== undefined ? (r.duplicate ? 'yes' : 'no') : ''}
                      </span>
                    </Td>
                    <td className="pr-2">
                      {phase === 'ready' && (
                        <button
                          aria-label={`Remove ${s.name}`}
                          onClick={() => onSelect(selected.filter((x) => x !== s.id))}
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
      {stopped && (
        <p className="flex items-center gap-1.5 px-4 py-2.5 text-[12px] text-fg">
          <OctagonX size={13} className="text-err" />
          <span className="font-medium text-err">Stopped</span> at the first rejection. Rows after it were not sent.
        </p>
      )}
    </div>
  )
}

function ResultCell({ phase, r }: { phase: Phase; r: SendResult | undefined }) {
  if (phase === 'ready') return <span className="text-[12px] text-faint">ready</span>
  if (phase === 'sending')
    return (
      <span className="inline-flex items-center gap-1.5 text-[12px] text-muted">
        <Loader2 size={12} className="animate-spin" /> sending
      </span>
    )
  if (!r) return <span className="text-[12px] text-muted">not sent</span>
  switch (r.status) {
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
            <OctagonX size={13} /> Failed {r.httpStatus !== undefined && <span className="font-mono">HTTP {r.httpStatus}</span>}
          </span>
          {r.message && <span className="font-mono text-[11px] text-muted">{r.message}</span>}
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
