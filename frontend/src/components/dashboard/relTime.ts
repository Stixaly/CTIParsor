/** ISO timestamp → "3m ago / 2h ago / yesterday / 4d ago".
 *  A date that cannot be read gives '—', the empty value the page uses elsewhere. */
export function relTime(iso: string): string {
  const mins = (Date.now() - new Date(iso).getTime()) / 60_000
  if (!Number.isFinite(mins)) return '—'
  if (mins < 1)    return 'just now'
  if (mins < 60)   return `${Math.round(mins)}m ago`
  if (mins < 1440) return `${Math.round(mins / 60)}h ago`
  const d = Math.round(mins / 1440)
  return d === 1 ? 'yesterday' : `${d}d ago`
}
