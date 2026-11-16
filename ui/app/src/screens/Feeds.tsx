import { Help, Notice } from '../components/ui'
import { FeedCard, type FeedConfig, type FieldConfig } from '../components/FeedCard'
import type { ApiStatus, RawSpectrum } from '../types'

type Props = {
  status: ApiStatus | null
  statusError: string | null
  onImport: (raw: RawSpectrum[]) => void
}

export default function Feeds({ status, statusError, onImport }: Props) {
  const feeds = status ? buildFeeds(status) : []
  const abusechSet = !!status && Object.values(status.feeds).every((f) => !f.needsKey || f.keySet)
  return (
    <div className="min-h-0 flex-1 overflow-auto">
      <div className="mx-auto flex max-w-[760px] flex-col gap-3 px-3 py-4 sm:px-4">
        <div className="flex items-center gap-1.5 text-[12px] text-muted">
          <span>Fetch is read-only.</span>
          <Help>
            Fetch requests feed metadata only. No sample is downloaded, unpacked or executed. Import converts the
            received records into spectra with Feed claim provenance and opens them in Spectra.
          </Help>
        </div>
        {statusError && (
          <Notice level="error" word="Error">
            {statusError}
          </Notice>
        )}
        {status &&
          feeds.map((f) => (
            <FeedCard
              key={f.id}
              feed={f}
              envVar={f.needsKey ? status.env.abusech : null}
              keyState={f.needsKey ? (abusechSet ? 'set' : 'unset') : 'none'}
              onImport={onImport}
            />
          ))}
      </div>
    </div>
  )
}

const NAMES: Record<string, string> = { malwarebazaar: 'MalwareBazaar', threatfox: 'ThreatFox', unpacme: 'UnpacMe' }

const LABELS: Record<string, string> = { 'unpacme.feed': 'public feed', 'unpacme.results': 'results by unpack id' }

const term = (label: string): FieldConfig => ({ id: 'term', label, type: 'text', value: '' })
const limit: FieldConfig = { id: 'limit', label: 'limit', type: 'number', value: '100', min: 1, max: 1000 }

const FIELDS: Record<string, FieldConfig[]> = {
  'malwarebazaar.recent': [{ id: 'selector', label: 'selector', type: 'select', options: ['time', '100'], value: 'time' }],
  'malwarebazaar.hash': [term('hash')],
  'malwarebazaar.tag': [term('tag'), limit],
  'malwarebazaar.signature': [term('signature'), limit],
  'threatfox.recent': [{ id: 'days', label: 'days', type: 'number', value: '1', min: 1, max: 7 }],
  'threatfox.hash': [term('hash')],
  'threatfox.malware': [term('malware'), limit],
  'threatfox.search': [term('term'), { id: 'exact', label: 'exact match', type: 'toggle', value: 'false' }],
  'unpacme.results': [term('unpack id')],
}

function buildFeeds(status: ApiStatus): FeedConfig[] {
  return Object.entries(status.feeds).map(([id, f]) => ({
    id,
    name: NAMES[id] ?? id,
    needsKey: f.needsKey,
    queries: Object.entries(f.queries).map(([q, help]) => ({
      id: q,
      label: LABELS[`${id}.${q}`] ?? q,
      help,
      fields: FIELDS[`${id}.${q}`] ?? [],
    })),
  }))
}
