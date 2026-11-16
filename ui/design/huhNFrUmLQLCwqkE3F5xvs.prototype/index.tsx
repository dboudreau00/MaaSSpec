import React, { useState } from 'react'

import Spectra from '@os/7A6AUWxkx7Bfm4sXQSj1iZ'
import SpectrumDetail from '@os/9squQUDscDCvFzh8Gkz6VH'
import Selectors from '@os/qgootDymB1AjUEkNJzrG7R'
import Feeds from '@os/kbERcU6MYXBSJxQ8mFE6hD'
import Send from '@os/1PyqVxCgFzGv9gav8ejjpi'

const SPECTRA = '7A6AUWxkx7Bfm4sXQSj1iZ'
const DETAIL = '9squQUDscDCvFzh8Gkz6VH'
const SELECTORS = 'qgootDymB1AjUEkNJzrG7R'
const FEEDS = 'kbERcU6MYXBSJxQ8mFE6hD'
const SEND = '1PyqVxCgFzGv9gav8ejjpi'

export const viewport = 'web'

export const args = {
  theme: 'dark',
  sendOutcome: 'accepted',
  threatfoxKey: true,
}

export const argTypes = {
  theme: { control: 'radio', options: ['dark', 'light'] },
  sendOutcome: { control: 'radio', options: ['accepted', 'rejected'] },
  threatfoxKey: { control: 'boolean' },
}

type Props = Partial<typeof args> & { start?: string }

type ScreenName = 'spectra' | 'selectors' | 'feeds' | 'send'
const SCREEN_TO_FRAME: Record<ScreenName, string> = { spectra: SPECTRA, selectors: SELECTORS, feeds: FEEDS, send: SEND }

export default function MaaSSpec(props: Props) {
  const { theme, sendOutcome, threatfoxKey, start } = { ...args, ...props }
  const [frame, setFrame] = useState(() => start ?? SPECTRA)
  const [themeOverride, setThemeOverride] = useState<string | null>(null)
  const [selected, setSelected] = useState<string[]>(['s1', 's4', 's6'])
  const [openId, setOpenId] = useState('s1')

  const t = themeOverride ?? theme
  const common = {
    theme: t,
    onToggleTheme: () => setThemeOverride(t === 'dark' ? 'light' : 'dark'),
    onNavigate: (s: ScreenName) => setFrame(SCREEN_TO_FRAME[s]),
  }
  const open = (id: string) => {
    setOpenId(id)
    setFrame(DETAIL)
  }

  if (frame === DETAIL)
    return <SpectrumDetail {...common} spectrumId={openId} sendCount={selected.length} onOpen={setOpenId} onBack={() => setFrame(SPECTRA)} />
  if (frame === SELECTORS) return <Selectors {...common} sendCount={selected.length} onOpen={open} />
  if (frame === FEEDS)
    return <Feeds {...common} sendCount={selected.length} threatfoxKey={threatfoxKey} onImport={() => setFrame(SPECTRA)} />
  if (frame === SEND)
    return <Send {...common} selected={selected} onSelect={setSelected} simulateRejection={sendOutcome === 'rejected'} />
  return <Spectra {...common} selected={selected} onSelect={setSelected} onOpen={open} />
}
