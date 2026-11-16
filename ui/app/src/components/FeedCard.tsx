import React, { useState } from 'react'
import { AlertTriangle, Check, Loader2 } from 'lucide-react'

import { Button, CopyButton, Help, Notice, Toggle } from './ui'
import { api, errorText, type FetchBody } from '../api'
import type { RawSpectrum } from '../types'

type Props = {
  feed: FeedConfig
  envVar: string | null
  keyState: 'set' | 'unset' | 'none'
  onImport: (raw: RawSpectrum[]) => void
}

type Status = 'idle' | 'fetching' | 'fetched' | 'importing'

export function FeedCard({ feed, envVar, keyState, onImport }: Props) {
  const [queryId, setQueryId] = useState(feed.queries[0]?.id ?? '')
  const query = feed.queries.find((q) => q.id === queryId) ?? feed.queries[0]
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(feed.queries.flatMap((q) => q.fields.map((f) => [`${q.id}.${f.id}`, f.value]))),
  )
  const canFetch = keyState !== 'unset'
  const [status, setStatus] = useState<Status>('idle')
  const [fetched, setFetched] = useState<{ fetchId: string; bytes: number } | null>(null)
  const [error, setError] = useState<string | null>(null)

  if (!query) return null

  const reset = () => {
    setStatus('idle')
    setFetched(null)
    setError(null)
  }
  const val = (fid: string) => values[`${query.id}.${fid}`] ?? ''
  const set = (fid: string, v: string) => {
    setValues((s) => ({ ...s, [`${query.id}.${fid}`]: v }))
    reset()
  }
  const cmd = buildCommand(feed.id, query, val)

  const doFetch = async () => {
    const body = buildBody(feed.id, query, val)
    if (typeof body === 'string') {
      setError(body)
      return
    }
    setStatus('fetching')
    setError(null)
    try {
      setFetched(await api.fetchFeed(body))
      setStatus('fetched')
    } catch (e) {
      setError(errorText(e))
      setStatus('idle')
    }
  }

  const doImport = async () => {
    if (!fetched) return
    setStatus('importing')
    setError(null)
    try {
      onImport((await api.importFetched(fetched.fetchId)).spectra)
    } catch (e) {
      setError(errorText(e))
      setStatus('fetched')
    }
  }

  return (
    <section className="rounded border border-line bg-panel">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-2.5">
        <h2 className="text-[14px] font-semibold">{feed.name}</h2>
        <KeyStatus state={keyState} envVar={envVar} />
      </header>

      <div className="flex flex-col gap-3 px-4 py-3">
        <div className="flex flex-wrap items-end gap-x-4 gap-y-3">
          <Field label="query">
            <div className="flex items-center gap-1.5">
              <select
                value={queryId}
                onChange={(e) => {
                  setQueryId(e.target.value)
                  reset()
                }}
                className="h-7 rounded border border-line-strong bg-bg px-1.5 font-mono text-[12px] text-fg outline-none focus:border-accent"
              >
                {feed.queries.map((q) => (
                  <option key={q.id} value={q.id}>
                    {q.label}
                  </option>
                ))}
              </select>
              {query.help && <Help>{query.help}</Help>}
            </div>
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
          <Button disabled={!canFetch || status === 'fetching' || status === 'importing'} onClick={doFetch}>
            {status === 'fetching' ? <Loader2 size={13} className="animate-spin" /> : null}
            Fetch
          </Button>
          {status === 'fetching' && <span className="text-[12px] text-muted">Fetching…</span>}
          {fetched && (status === 'fetched' || status === 'importing') && (
            <>
              <span className="inline-flex items-center gap-1.5 text-[12px]">
                <Check size={13} className="text-accent" />
                <span className="tabular font-mono">{kb(fetched.bytes)} KB received</span>
              </span>
              <Button variant="primary" disabled={status === 'importing'} onClick={doImport} className="ml-auto">
                {status === 'importing' ? <Loader2 size={13} className="animate-spin" /> : null}
                Import
              </Button>
            </>
          )}
          {!canFetch && <span className="text-[12px] text-muted">Set {envVar} to fetch.</span>}
        </div>

        {error && (
          <Notice level="error" word="Error">
            {error}
          </Notice>
        )}
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

function kb(bytes: number) {
  const n = bytes / 1024
  return n >= 100 ? String(Math.round(n)) : n.toFixed(1)
}

const SAFE_WORD = /^[A-Za-z0-9_.:/@%+=,-]+$/

function shellWord(v: string) {
  return SAFE_WORD.test(v) ? v : `"${v.replace(/["\\$`]/g, (c) => '\\' + c)}"`
}

/** The real CLI: the term is positional, then the flags that apply. */
function buildCommand(feedId: string, q: Query, val: (id: string) => string) {
  const parts = ['maasspec', 'feed', 'fetch', feedId, q.id]
  const t = val('term').trim()
  if (t) parts.push(shellWord(t))
  for (const id of ['limit', 'days', 'selector']) {
    const v = val(id).trim()
    if (v && q.fields.some((f) => f.id === id)) parts.push(`--${id}`, shellWord(v))
  }
  if (val('exact') === 'true') parts.push('--exact')
  parts.push('--out', `${feedId}_${q.id}.json`)
  return parts.join(' ')
}

/** Checks only the ranges the form already shows. The server validates the rest. */
function buildBody(feedId: string, q: Query, val: (id: string) => string): FetchBody | string {
  const body: FetchBody = { feed: feedId, query: q.id }
  for (const f of q.fields) {
    const v = val(f.id).trim()
    if (f.id === 'term') {
      if (v) body.term = v
    } else if (f.id === 'limit' || f.id === 'days') {
      const n = Number(v)
      if (v === '' || !Number.isInteger(n) || n < (f.min ?? 1) || n > (f.max ?? 1000))
        return `${f.id} must be a whole number from ${f.min ?? 1} to ${f.max}.`
      body[f.id] = n
    } else if (f.id === 'selector') {
      if (v !== 'time' && v !== '100') return 'selector must be time or 100.'
      body.selector = v
    } else {
      body.exact = v === 'true'
    }
  }
  return body
}

export type FieldConfig = {
  id: 'term' | 'limit' | 'days' | 'selector' | 'exact'
  label: string
  type: 'text' | 'number' | 'select' | 'toggle'
  value: string
  options?: string[]
  min?: number
  max?: number
}

type Query = { id: string; label: string; help: string; fields: FieldConfig[] }

export type FeedConfig = {
  id: string
  name: string
  needsKey: boolean
  queries: Query[]
}
