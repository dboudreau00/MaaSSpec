import { shortHash } from './format'
import type { Artifact, Finding, Provenance, RawArtifact, RawFinding, RawSpectrum, Spectrum } from './types'

const DASH = '—'

/** Spectrum values are Any in the models; the screens show text. */
function text(v: unknown): string {
  if (v == null) return ''
  if (typeof v === 'string') return v
  return JSON.stringify(v)
}

function textMap(m: Record<string, unknown> | null | undefined): Record<string, string> {
  return Object.fromEntries(Object.entries(m ?? {}).map(([k, v]) => [k, text(v)]))
}

function provenance(tags: string[], fallbackFeed: string): Provenance {
  if (tags.includes('claimed')) {
    const t = tags.find((x) => x.startsWith('feed:'))
    return { kind: 'feed', feed: t ? t.slice('feed:'.length) : fallbackFeed }
  }
  if (tags.includes('sandbox') || tags.includes('cape')) return { kind: 'sandbox' }
  return { kind: 'static' }
}

/** Tags the provenance badge and the private chip already say. */
function isShownElsewhere(t: string) {
  return t === 'claimed' || t === 'feed' || t === 'sandbox' || t === 'cape' || t === 'scope:private' || t.startsWith('feed:')
}

function finding(f: RawFinding, feed: string): Finding {
  const tags = f.tags ?? []
  const g = f.proposed_grade
  const hasGrade = !!g && (g.source_reliability || g.information_credibility)
  return {
    id: f.id,
    type: f.type,
    subtype: f.subtype ?? '',
    value: text(f.value),
    confidence: f.confidence,
    private: tags.includes('scope:private') || undefined,
    grade: hasGrade
      ? { r: g.source_reliability ?? '-', c: g.information_credibility ?? '-', rationale: g.rationale ?? '' }
      : null,
    provenance: provenance(tags, feed),
    source: f.source?.artifact_id ?? '',
    tags: tags.filter((t) => !isShownElsewhere(t)),
    extractedBy: {
      module: f.extracted_by.module,
      version: f.extracted_by.version ?? '',
      technique: f.extracted_by.technique ?? DASH,
    },
    confidenceMethod: f.confidence_method ?? DASH,
    location: [f.source?.offset, f.source?.section].filter(Boolean).join(' ') || DASH,
    selectors: (f.selectors ?? []).map((s) => ({ kind: s.kind, value: s.value, normalized: s.normalized ?? s.value })),
    context: textMap(f.context),
    familyData: f.family_data ? textMap(f.family_data) : undefined,
  }
}

function artifact(a: RawArtifact): Artifact {
  return {
    id: a.id,
    type: a.type,
    parent: a.parent_artifact_id ?? undefined,
    name: a.description ?? '',
    sha256: a.sha256 ?? '',
    size: a.size_bytes ?? null,
    producedBy: a.produced_by ?? '',
  }
}

function generated(iso: string) {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 16).replace('T', ' ')
}

export function adapt(raw: RawSpectrum): Spectrum {
  const isFeed = raw.input.type === 'feed_record'
  const meta = raw.metadata ?? {}
  const feed = isFeed ? text(meta.feed) || raw.input.source_hint || 'feed' : ''
  const rawId = isFeed ? text(meta.feed_record_id) : ''
  const recordId = isFeed ? (/^[a-f0-9]{64}$/i.test(rawId) ? shortHash(rawId) : rawId) || shortHash(raw.input.sha256) : ''
  const sum = raw.summary
  return {
    id: raw.analysis_id,
    analysisId: raw.analysis_id,
    inputType: raw.input.type,
    name: isFeed ? `${feed} : ${recordId}` : raw.input.filename || shortHash(raw.input.sha256),
    sha256: raw.input.sha256,
    size: raw.input.size_bytes ?? null,
    source: isFeed ? feed : 'local file',
    generated: generated(raw.generated_at),
    tool: `${raw.tool.name.toLowerCase()} ${raw.tool.version}`,
    family: sum?.family ? { name: sum.family.name, method: sum.family.method ?? '', confidence: sum.family.confidence } : null,
    capabilities: sum?.primary_capabilities ?? [],
    riskSignals: sum?.risk_signals ?? [],
    c2Count: sum?.c2_count ?? 0,
    configExtracted: sum?.config_extracted ?? false,
    encryptionObserved: sum?.encryption_observed ?? false,
    truncated: meta.scan_window_truncated === true || undefined,
    artifacts: (raw.artifacts ?? []).map(artifact),
    issues: (raw.errors ?? []).map((e) => ({
      level: e.severity,
      module: e.module ?? '',
      message: e.message,
      recoverable: !!e.recoverable,
    })),
    findings: raw.findings.map((f) => finding(f, feed)),
    raw,
  }
}

/** Merge new spectra into the list by analysis id. A repeat id replaces the old row in place. */
export function merge(list: Spectrum[], incoming: Spectrum[]): Spectrum[] {
  const out = [...list]
  for (const s of incoming) {
    const i = out.findIndex((x) => x.id === s.id)
    if (i >= 0) out[i] = s
    else out.push(s)
  }
  return out
}
