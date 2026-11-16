import type { Spectrum } from './types'

export const FINDING_TYPES = [
  'c2', 'config', 'credential_pattern', 'crypto_material', 'embedded_artifact',
  'family_indicator', 'behavior', 'wallet', 'panel', 'other',
]

export const INPUT_TYPES = ['sample', 'archive', 'cape_report', 'memory_dump', 'config_dump', 'feed_record']

export const SELECTOR_KINDS = [
  'sha256', 'sha1', 'md5', 'imphash', 'tlsh', 'ssdeep', 'domain', 'url',
  'ipv4', 'ipv4_port', 'email', 'bitcoin', 'cert_serial',
]

export function warnCount(s: Spectrum) {
  return s.issues.filter((i) => i.level === 'warning' || i.level === 'error').length
}

export function shortHash(h: string, n = 12) {
  return h.slice(0, n)
}

export function formatBytes(n: number | null) {
  if (n == null) return 'unknown'
  if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MiB`
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KiB`
  return `${n} B`
}

/** Defang URLs and domains for display. Never used for copy. The whole authority (userinfo, host, port) is dotted. */
export function defang(value: string) {
  const m = value.match(/^(https?)(:\/\/)([^/?#]*)(.*)$/i)
  if (m) return `${m[1].replace(/t/gi, 'x')}${m[2]}${m[3].replace(/\./g, '[.]')}${m[4]}`
  const host = value.match(/^([a-z0-9-]+(?:\.[a-z0-9-]+)+)(:\d{1,5})?$/i)
  if (host && !/^\d+(\.\d+){3}$/.test(host[1])) return `${host[1].replace(/\./g, '[.]')}${host[2] ?? ''}`
  return value
}

/** Everything the spectra search can match, built from the parsed spectrum and never from rendered markup. */
export function spectrumHaystack(s: Spectrum) {
  const parts: string[] = [s.sha256, s.analysisId, s.name, s.family?.name ?? '']
  for (const issue of s.issues) parts.push(issue.message)
  for (const f of s.findings) {
    parts.push(f.type, f.subtype, f.value, ...Object.values(f.context))
    for (const x of f.selectors) parts.push(x.value, x.normalized)
  }
  return parts.join(' ').toLowerCase()
}

export function isDefangable(value: string) {
  return defang(value) !== value
}

export type SelectorRow = {
  kind: string
  value: string
  spectra: string[]
  best: number
}

/** Pivot every selector across loaded spectra, including each spectrum's own sha256. */
export function pivotSelectors(list: Spectrum[]): SelectorRow[] {
  const map = new Map<string, SelectorRow>()
  const add = (kind: string, value: string, sid: string, conf: number) => {
    const key = `${kind}|${value}`
    const row = map.get(key) ?? { kind, value, spectra: [], best: 0 }
    if (!row.spectra.includes(sid)) row.spectra.push(sid)
    row.best = Math.max(row.best, conf)
    map.set(key, row)
  }
  for (const s of list) {
    if (s.inputType !== 'feed_record') add('sha256', s.sha256, s.id, 1)
    for (const f of s.findings) for (const sel of f.selectors) add(sel.kind, sel.normalized, s.id, f.confidence)
  }
  return [...map.values()]
}

/** Known kinds first, in their usual order, then any other kind the spectra carry. */
export function orderKinds(kinds: string[]) {
  const present = new Set(kinds)
  const known = SELECTOR_KINDS.filter((k) => present.has(k))
  const extra = [...present].filter((k) => !SELECTOR_KINDS.includes(k)).sort()
  return [...known, ...extra]
}

export const FEED_IDS = ['malwarebazaar', 'threatfox', 'unpacme']
