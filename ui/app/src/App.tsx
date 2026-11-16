import { useEffect, useState } from 'react'

import { Shell, type Screen, type Theme } from './components/Shell'
import { adapt, merge } from './adapt'
import { api, errorText, setUnauthorizedHandler } from './api'
import { loadMarks, saveMarks } from './marks'
import type { ApiStatus, RawSpectrum, Review, Spectrum } from './types'
import Spectra from './screens/Spectra'
import SpectrumDetail from './screens/SpectrumDetail'
import Selectors from './screens/Selectors'
import Feeds from './screens/Feeds'
import Send from './screens/Send'

const NO_ACCESS = 'Open the URL printed by maasspec serve.'

export default function App({ hasToken }: { hasToken: boolean }) {
  const [theme, setTheme] = useState<Theme>('dark')
  const [screen, setScreen] = useState<Screen | 'detail'>('spectra')
  const [openId, setOpenId] = useState<string | null>(null)
  const [spectra, setSpectra] = useState<Spectrum[]>([])
  const [selected, setSelected] = useState<string[]>([])
  const [marks, setMarks] = useState<Record<string, Review>>(loadMarks)
  const [status, setStatus] = useState<ApiStatus | null>(null)
  const [statusError, setStatusError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [denied, setDenied] = useState(!hasToken)

  useEffect(() => {
    if (!hasToken) return
    setUnauthorizedHandler(() => setDenied(true))
    api.status().then(setStatus).catch((e) => setStatusError(errorText(e)))
    api
      .spectra()
      .then((r) => setSpectra(r.spectra.map(adapt)))
      .catch((e) => setLoadError(errorText(e)))
      .finally(() => setLoading(false))
  }, [hasToken])

  if (denied) return <p className="px-4 py-3 text-muted">{NO_ACCESS}</p>

  const add = (raw: RawSpectrum[]) => setSpectra((list) => merge(list, raw.map(adapt)))
  const mark = (id: string, m: Review) =>
    setMarks((cur) => {
      const next = { ...cur, [id]: m }
      saveMarks(next)
      return next
    })
  const open = (id: string) => {
    setOpenId(id)
    setScreen('detail')
  }

  const current = spectra.find((s) => s.id === openId)
  const view = screen === 'detail' && !current ? 'spectra' : screen

  return (
    <Shell
      active={view === 'detail' ? 'spectra' : view}
      theme={theme}
      version={status?.version ?? ''}
      sendCount={selected.length}
      onToggleTheme={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
      onNavigate={setScreen}
    >
      {view === 'detail' && current ? (
        <SpectrumDetail spectrum={current} spectra={spectra} onOpen={open} onBack={() => setScreen('spectra')} />
      ) : view === 'selectors' ? (
        <Selectors spectra={spectra} onOpen={open} />
      ) : view === 'feeds' ? (
        <Feeds
          status={status}
          statusError={statusError}
          onImport={(raw) => {
            add(raw)
            setScreen('spectra')
          }}
        />
      ) : view === 'send' ? (
        <Send status={status} statusError={statusError} spectra={spectra} selected={selected} onSelect={setSelected} />
      ) : (
        <Spectra
          spectra={spectra}
          loading={loading}
          loadError={loadError}
          selected={selected}
          marks={marks}
          onSelect={setSelected}
          onMark={mark}
          onOpen={open}
          onSend={() => setScreen('send')}
          onAdd={add}
        />
      )}
    </Shell>
  )
}
