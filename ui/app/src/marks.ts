import type { Review } from './types'

const KEY = 'maasspec.review'
const VALUES: Review[] = ['Unreviewed', 'Reviewed', 'Skip']

/** Review marks live in this browser only, keyed by analysis id. They are never sent. */
export function loadMarks(): Record<string, Review> {
  try {
    const raw = JSON.parse(localStorage.getItem(KEY) ?? '{}') as Record<string, unknown>
    return Object.fromEntries(Object.entries(raw).filter(([, v]) => VALUES.includes(v as Review))) as Record<string, Review>
  } catch {
    return {}
  }
}

export function saveMarks(marks: Record<string, Review>) {
  try {
    localStorage.setItem(KEY, JSON.stringify(marks))
  } catch {
    // Storage can be blocked. Marks then last until the page closes.
  }
}
