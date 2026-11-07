/** ISO timestamp → "3m ago / 2h ago / yesterday / 4d ago".
 *  A date that cannot be read gives '—', the empty value the page uses elsewhere. */
export function relTime(iso: string): string {
  const mins = (Date.now() - new Date(iso).getTime()) / 60_000
  if (!Number.isFinite(mins)) return '—'
  if (mins < 1)    return 'just now'
  // Each unit is picked from its rounded count, so 59m45s reads 1h, not 60m.
  const m = Math.round(mins)
  if (m < 60) return `${m}m ago`
  const h = Math.round(mins / 60)
  if (h < 24) return `${h}h ago`
  const d = Math.round(mins / 1440)
  return d === 1 ? 'yesterday' : `${d}d ago`
}
