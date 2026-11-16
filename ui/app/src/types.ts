// Spectrum as the API returns it: Spectrum.model_dump(mode="json"), snake_case.

export type RawFinding = {
  id: string
  type: string
  subtype?: string | null
  value?: unknown
  normalized?: unknown
  confidence: number
  confidence_method?: string | null
  extracted_by: { module: string; version?: string | null; technique?: string | null }
  source?: { artifact_id?: string | null; offset?: string | null; section?: string | null; method?: string | null } | null
  context?: Record<string, unknown> | null
  selectors?: { kind: string; value: string; normalized?: string | null }[]
  proposed_grade?: {
    source_reliability?: string | null
    information_credibility?: string | null
    rationale?: string | null
  } | null
  tags?: string[]
  family_data?: Record<string, unknown> | null
}

export type RawArtifact = {
  id: string
  type: string
  sha256?: string | null
  size_bytes?: number | null
  description?: string | null
  produced_by?: string | null
  parent_artifact_id?: string | null
}

export type RawSpectrum = {
  maasspec_version: string
  analysis_id: string
  generated_at: string
  tool: { name: string; version: string; commit?: string | null }
  input: {
    type: string
    filename?: string | null
    sha256: string
    size_bytes?: number | null
    source_hint?: string | null
  }
  summary?: {
    family?: { name: string; confidence: number; method?: string | null } | null
    primary_capabilities?: string[]
    c2_count?: number
    config_extracted?: boolean
    encryption_observed?: boolean
    risk_signals?: string[]
  } | null
  findings: RawFinding[]
  artifacts?: RawArtifact[]
  errors?: { severity: 'info' | 'warning' | 'error'; module?: string | null; message: string; recoverable?: boolean | null }[]
  metadata?: Record<string, unknown> | null
}

// View model the screens consume. Built by adapt.ts.

export type Review = 'Unreviewed' | 'Reviewed' | 'Skip'

export type Provenance = { kind: 'static' } | { kind: 'sandbox' } | { kind: 'feed'; feed: string }

export type Finding = {
  id: string
  type: string
  subtype: string
  value: string
  confidence: number
  private?: boolean
  grade: { r: string; c: string; rationale: string } | null
  provenance: Provenance
  source: string
  tags: string[]
  extractedBy: { module: string; version: string; technique: string }
  confidenceMethod: string
  location: string
  selectors: { kind: string; value: string; normalized: string }[]
  context: Record<string, string>
  familyData?: Record<string, string>
}

export type Artifact = {
  id: string
  type: string
  parent?: string
  name: string
  sha256: string
  size: number | null
  producedBy: string
}

export type Issue = {
  level: 'info' | 'warning' | 'error'
  module: string
  message: string
  recoverable: boolean
}

export type Spectrum = {
  id: string
  analysisId: string
  inputType: string
  name: string
  sha256: string
  size: number | null
  source: string
  generated: string
  tool: string
  family: { name: string; method: string; confidence: number } | null
  capabilities: string[]
  riskSignals: string[]
  c2Count: number
  configExtracted: boolean
  encryptionObserved: boolean
  truncated?: boolean
  artifacts: Artifact[]
  issues: Issue[]
  findings: Finding[]
  raw: RawSpectrum
}

// /api/status

export type FeedStatus = { needsKey: boolean; keySet: boolean; queries: Record<string, string> }

export type ApiStatus = {
  version: string
  env: { ingestUrl: string; ingestKey: string; abusech: string }
  ingest: { url: string | null; keySet: boolean }
  feeds: Record<string, FeedStatus>
}

export type SendResult = {
  id: string
  status: 'ok' | 'failed' | 'not_sent'
  batchId?: string
  accepted?: boolean
  duplicate?: boolean
  httpStatus?: number
  message?: string
}
