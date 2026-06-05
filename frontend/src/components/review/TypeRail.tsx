import { useMemo } from 'react'
import type { Entity } from '../../types'
import { typeDot, typeLabel } from './tokens'

interface Props {
  entities: Entity[]
  activeTypes: string[]
  toggleType: (t: string) => void
  onAcceptAllOfType: (t: string) => void
  onRejectAllOfType: (t: string) => void   // bulk-reject all pending of this type
}

export default function TypeRail({
  entities, activeTypes, toggleType,
  onAcceptAllOfType, onRejectAllOfType,
}: Props) {
  const counts = useMemo(() => {
    const m: Record<string, { total: number; pending: number }> = {}
    entities.forEach(e => {
      if (!m[e.entity_type]) m[e.entity_type] = { total: 0, pending: 0 }
      m[e.entity_type].total++
      if (e.accepted === null) m[e.entity_type].pending++
    })
    return m
  }, [entities])

  const types = Object.keys(counts).sort((a, b) => counts[b].total - counts[a].total)

  return (
    <nav className="type-rail">
      <div className="rail-title">Filter</div>
      {types.map(t => {
        const c = counts[t]
        const active = activeTypes.includes(t)
        return (
          <div key={t} className={`rail-row ${active ? 'rail-on' : ''}`}>
            {/* Type chip — click to filter the document view */}
            <button
              className="rail-chip"
              onClick={() => toggleType(t)}
              title={typeLabel(t)}
            >
              <span className="rail-dot" style={{ background: typeDot(t) }} />
              <span className="rail-label">{typeLabel(t)}</span>
              <span className="rail-count">{c.total}</span>
            </button>

            {/* Bulk action buttons — only visible when there are pending entities */}
            {c.pending > 0 && (
              <div className="rail-bulk">
                <button
                  className="rail-accept"
                  title={`Accept all ${c.pending} pending ${typeLabel(t)}`}
                  onClick={() => onAcceptAllOfType(t)}
                >
                  ✓ {c.pending}
                </button>
                <button
                  className="rail-reject"
                  title={`Reject all ${c.pending} pending ${typeLabel(t)}`}
                  onClick={() => onRejectAllOfType(t)}
                >
                  ✗
                </button>
              </div>
            )}
          </div>
        )
      })}
    </nav>
  )
}
