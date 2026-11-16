import type { ApiStatus, RawSpectrum, SendResult } from './types'

const TOKEN_KEY = 'maasspec.token'

let token = ''
let onUnauthorized: () => void = () => {}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export function errorText(e: unknown) {
  return e instanceof Error ? e.message : 'Unexpected error.'
}

/** Read the token from the URL fragment, keep it in memory and sessionStorage, clear the fragment. */
export function initToken() {
  const m = /(?:^#|&)t=([^&]*)/.exec(location.hash)
  let fromHash = ''
  if (m && m[1]) {
    try {
      fromHash = decodeURIComponent(m[1])
    } catch {
      fromHash = m[1]
    }
  }
  if (fromHash) {
    token = fromHash
    try {
      sessionStorage.setItem(TOKEN_KEY, token)
    } catch {
      // Storage can be blocked. The token stays in memory.
    }
  } else {
    try {
      token = sessionStorage.getItem(TOKEN_KEY) ?? ''
    } catch {
      token = ''
    }
  }
  if (location.hash) history.replaceState(null, '', location.pathname + location.search)
  return token !== ''
}

export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, {
      ...init,
      headers: { ...init.headers, 'X-MaaSSpec-Token': token },
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
    })
  } catch {
    throw new ApiError(0, 'The server did not answer.')
  }
  if (res.status === 401) {
    onUnauthorized()
    throw new ApiError(401, 'Unauthorized.')
  }
  let body: unknown = null
  let readable = true
  try {
    body = await res.json()
  } catch {
    readable = false
  }
  if (!res.ok) {
    const msg = readable && body && typeof (body as { error?: unknown }).error === 'string' ? (body as { error: string }).error : ''
    throw new ApiError(res.status, msg || `The server answered HTTP ${res.status}.`)
  }
  if (!readable) throw new ApiError(res.status, 'The server sent a reply that is not JSON.')
  return body as T
}

const json = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

const bytes = (file: File): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/octet-stream' },
  body: file,
})

type Spectra = { spectra: RawSpectrum[] }

export type FetchBody = {
  feed: string
  query: string
  term?: string
  limit?: number
  days?: number
  selector?: string
  exact?: boolean
}

export const api = {
  status: () => request<ApiStatus>('/api/status'),
  spectra: () => request<Spectra>('/api/spectra'),
  parse: (file: File) => request<Spectra>('/api/spectra/parse', bytes(file)),
  analyze: (file: File) => request<Spectra>(`/api/analyze?filename=${encodeURIComponent(file.name)}`, bytes(file)),
  importFile: (feed: string, file: File) => request<Spectra>(`/api/import?feed=${encodeURIComponent(feed)}`, bytes(file)),
  fetchFeed: (body: FetchBody) => request<{ fetchId: string; bytes: number }>('/api/feeds/fetch', json(body)),
  importFetched: (fetchId: string) => request<Spectra>('/api/feeds/import', json({ fetchId })),
  send: (ids: string[]) => request<{ results: SendResult[] }>('/api/send', json({ ids })),
}
