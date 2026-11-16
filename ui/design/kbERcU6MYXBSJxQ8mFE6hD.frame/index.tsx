import React from 'react'

import { Shell, type Screen, type Theme } from '@shared/components/Shell'
import { Help } from '@shared/components/ui'
import { FeedCard, type FeedConfig } from './components/FeedCard'

export const args = {
  theme: 'dark',
  state: 'idle',
  malwarebazaarKey: false,
  threatfoxKey: true,
}

export const argTypes = {
  theme: { control: 'radio', options: ['dark', 'light'] },
  state: { control: 'radio', options: ['idle', 'fetched'] },
  malwarebazaarKey: { control: 'boolean' },
  threatfoxKey: { control: 'boolean' },
}

type Props = Partial<typeof args> & {
  sendCount?: number
  onImport?: (feed: string) => void
  onNavigate?: (s: Screen) => void
  onToggleTheme?: () => void
}

export default function Feeds(props: Props) {
  const p = { ...args, ...props }
  return (
    <Shell active="feeds" theme={p.theme as Theme} sendCount={p.sendCount} onNavigate={p.onNavigate} onToggleTheme={p.onToggleTheme}>
      <div className="min-h-0 flex-1 overflow-auto">
        <div className="mx-auto flex max-w-[760px] flex-col gap-3 px-3 py-4 sm:px-4">
          <div className="flex items-center gap-1.5 text-[12px] text-muted">
            <span>Fetch is read-only.</span>
            <Help>
              Fetch requests feed metadata only. No sample is downloaded, unpacked or executed. Import converts the
              received records into spectra with Feed claim provenance and opens them in Spectra.
            </Help>
          </div>
          {FEEDS.map((f) => (
            <FeedCard
              key={f.id}
              feed={f}
              keyState={f.id === 'unpacme' ? 'none' : (f.id === 'malwarebazaar' ? p.malwarebazaarKey : p.threatfoxKey) ? 'set' : 'unset'}
              fetched={p.state === 'fetched'}
              onImport={() => p.onImport?.(f.id)}
            />
          ))}
        </div>
      </div>
    </Shell>
  )
}

const FEEDS: FeedConfig[] = [
  {
    id: 'malwarebazaar',
    name: 'MalwareBazaar',
    envVar: 'MB_AUTH_KEY',
    received: '1.8 MB received',
    queries: [
      { id: 'recent', label: 'recent', fields: [{ id: 'selector', label: 'selector', type: 'select', options: ['time', '100'], value: 'time' }] },
      { id: 'hash', label: 'hash', fields: [{ id: 'hash', label: 'hash', type: 'text', value: 'a3f19c0e7b2d4815c6e0f9a7d3b21c4e8f5a6b7c9d0e1f2a3b4c5d6e7f809a1b' }] },
      {
        id: 'tag',
        label: 'tag',
        fields: [
          { id: 'tag', label: 'tag', type: 'text', value: 'ExampleRAT' },
          { id: 'limit', label: 'limit', type: 'number', value: '100', max: 1000 },
        ],
      },
      {
        id: 'signature',
        label: 'signature',
        fields: [
          { id: 'signature', label: 'signature', type: 'text', value: 'Example.Loader' },
          { id: 'limit', label: 'limit', type: 'number', value: '100', max: 1000 },
        ],
      },
    ],
  },
  {
    id: 'threatfox',
    name: 'ThreatFox',
    envVar: 'THREATFOX_AUTH_KEY',
    received: '412 KB received',
    queries: [
      { id: 'recent', label: 'recent', fields: [{ id: 'days', label: 'days', type: 'number', value: '3', min: 1, max: 7 }] },
      { id: 'hash', label: 'hash', fields: [{ id: 'hash', label: 'hash', type: 'text', value: '4f8c2e6ab1d73095e2a64c8f07b5d9e3a6c1f4803d9e2b57c4a8016fe7b35d29' }] },
      { id: 'malware', label: 'malware', fields: [{ id: 'malware', label: 'malware', type: 'text', value: 'win.example_rat' }] },
      {
        id: 'search',
        label: 'search',
        fields: [
          { id: 'term', label: 'term', type: 'text', value: '93.184.216.34' },
          { id: 'exact', label: 'exact match', type: 'toggle', value: 'true' },
        ],
      },
    ],
  },
  {
    id: 'unpacme',
    name: 'UnpacMe',
    envVar: null,
    received: '96 KB received',
    queries: [
      { id: 'public', label: 'public feed', fields: [] },
      { id: 'results', label: 'results by unpack id', fields: [{ id: 'id', label: 'unpack id', type: 'text', value: '9f3c2a71' }] },
    ],
  },
]
