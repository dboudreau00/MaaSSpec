import React, { useEffect, useState } from 'react'
import { AlertTriangle, Check, Loader2 } from 'lucide-react'

import { Button, CopyButton, Toggle } from '@shared/components/ui'

type Props = {
  feed: FeedConfig
  keyState: 'set' | 'unset' | 'none'
  fetched: boolean
  onImport?: () => void
}

export function FeedCard({ feed, keyState, fetched: fetchedArg, onImport }: Props) {
  const [queryId, setQueryId] = useState(feed.queries[0].id)
  const query = feed.queries.find((q) => q.id === queryId) ?? feed.queries[0]
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(feed.queries.flatMap((q) => q.fields.map((f) => [`${q.id}.${f.id}`, f.value]))),
  )
  const canFetch = keyState !== 'unset'
  const [status, setStatus] = useState<'idle' | 'fetching' | 'fetched'>(fetchedArg && canFetch ? 'fetched' : 'idle')
  useEffect(() => setStatus(fetchedArg && canFetch ? 'fetched' : 'idle'), [fetchedArg, canFetch])

  const val = (fid: string) => values[`${query.id}.${fid}`] ?? ''
  const set = (fid: string, v: string) => {
    setValues((s) => ({ ...s, [`${query.id}.${fid}`]: v }))
    setStatus('idle')
  }
  const cmd = buildCommand(feed.id, query, val)

  return (
    <section className="rounded border border-line bg-panel">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-2.5">
        <h2 className="text-[14px] font-semibold">{feed.name}</h2>
        <KeyStatus state={keyState} envVar={feed.envVar} />
      </header>

      <div className="flex flex-col gap-3 px-4 py-3">
        <div className="flex flex-wrap items-end gap-x-4 gap-y-3">
          <Field label="query">
            <select
              value={queryId}
              onChange={(e) => {
                setQueryId(e.target.value)
                setStatus('idle')
              }}
              className="h-7 rounded border border-line-strong bg-bg px-1.5 font-mono text-[12px] text-fg outline-none focus:border-accent"
            >
              {feed.queries.map((q) => (
                <option key={q.id} value={q.id}>
                  {q.label}
                </option>
              ))}
            </select>
          </Field>
          {query.fields.map((f) =>
            f.type === 'toggle' ? (
              <div key={f.id} className="flex h-7 items-center">
                <Toggle label={f.label} checked={val(f.id) === 'true'} onChange={(v) => set(f.id, String(v))} />
              </div>
            ) : f.type === 'select' ? (
              <Field key={f.id} label={f.label}>
                <select
                  value={val(f.id)}
                  onChange={(e) => set(f.id, e.target.value)}
                  className="h-7 rounded border border-line-strong bg-bg px-1.5 font-mono text-[12px] text-fg outline-none focus:border-accent"
                >
                  {f.options?.map((o) => (
                    <option key={o}>{o}</option>
                  ))}
                </select>
              </Field>
            ) : (
              <Field key={f.id} label={f.type === 'number' ? `${f.label} (${f.min ?? 1}–${f.max})` : f.label} grow={f.type === 'text'}>
                <input
                  type={f.type === 'number' ? 'number' : 'text'}
                  min={f.min ?? 1}
                  max={f.max}
                  value={val(f.id)}
                  onChange={(e) => set(f.id, e.target.value)}
                  className={`h-7 min-w-0 rounded border border-line-strong bg-bg px-2 font-mono text-[12px] text-fg outline-none focus:border-accent ${
                    f.type === 'number' ? 'w-[88px]' : 'w-full'
                  }`}
                />
              </Field>
            ),
          )}
        </div>

        <div className="flex items-start gap-2 rounded border border-line bg-bg px-3 py-2">
          <code className="min-w-0 flex-1 break-all font-mono text-[12px] text-muted">
            <span className="select-none text-faint">$ </span>
            {cmd}
          </code>
          <CopyButton value={cmd} label="Copy command" />
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button
            disabled={!canFetch || status === 'fetching'}
            onClick={() => {
              setStatus('fetching')
              setTimeout(() => setStatus('fetched'), 700)
            }}
          >
            {status === 'fetching' ? <Loader2 size={13} className="animate-spin" /> : null}
            Fetch
          </Button>
          {status === 'fetching' && <span className="text-[12px] text-muted">Fetching…</span>}
          {status === 'fetched' && (
            <>
              <span className="inline-flex items-center gap-1.5 text-[12px]">
                <Check size={13} className="text-accent" />
                <span className="tabular font-mono">{feed.received}</span>
              </span>
              <Button variant="primary" onClick={onImport} className="ml-auto">
                Import
              </Button>
            </>
          )}
          {!canFetch && <span className="text-[12px] text-muted">Set {feed.envVar} to fetch.</span>}
        </div>
      </div>
    </section>
  )
}

function KeyStatus({ state, envVar }: { state: 'set' | 'unset' | 'none'; envVar: string | null }) {
  if (state === 'none') return <span className="text-[12px] text-muted">No key needed</span>
  return (
    <span className="inline-flex items-center gap-2 text-[12px]">
      <span className="font-mono text-[11px] text-muted">{envVar}</span>
      {state === 'set' ? (
        <span className="inline-flex items-center gap-1 text-fg">
          <Check size={13} className="text-accent" /> Key set
        </span>
      ) : (
        <span className="inline-flex items-center gap-1 font-medium text-warn">
          <AlertTriangle size={13} /> Key not set
        </span>
      )}
    </span>
  )
}

function Field({ label, children, grow }: { label: string; children: React.ReactNode; grow?: boolean }) {
  return (
    <label className={`flex min-w-0 flex-col gap-1 ${grow ? 'flex-1 basis-[240px]' : ''}`}>
      <span className="text-[11px] text-muted">{label}</span>
      {children}
    </label>
  )
}

function buildCommand(feedId: string, q: Query, val: (id: string) => string) {
  const parts = ['maasspec', 'feed', feedId, q.id]
  for (const f of q.fields) {
    const v = val(f.id)
    if (f.type === 'toggle') {
      if (v === 'true') parts.push(`--${f.id}`)
    } else if (v) parts.push(`--${f.id}`, v.includes(' ') ? `"${v}"` : v)
  }
  parts.push('--out', `${feedId}_${q.id}.jsonl`)
  return parts.join(' ')
}

export type FieldConfig = {
  id: string
  label: string
  type: 'text' | 'number' | 'select' | 'toggle'
  value: string
  options?: string[]
  min?: number
  max?: number
}

type Query = { id: string; label: string; fields: FieldConfig[] }

export type FeedConfig = {
  id: string
  name: string
  envVar: string | null
  received: string
  queries: Query[]
}
