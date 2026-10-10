import { useMemo } from 'react'
import type { Entity } from '../../types'
import { heldPending, typeDot, typeLabel } from './tokens'

interface Props {
  entities: Entity[]
  activeTypes: string[]
  toggleType: (t: string) => void
  onAcceptAllOfType: (t: string) => void
  onRejectAllOfType: (t: string) => void   // bulk-reject all pending of this type
  /** Closes the rail when a narrow window shows it as a drawer; the button
   *  is only displayed there (index.css, RESPONSIVE). */
  onClose?: () => void
}

export default function TypeRail({
  entities, activeTypes, toggleType,
  onAcceptAllOfType, onRejectAllOfType, onClose,
}: Props) {
  const counts = useMemo(() => {
    // `held`: pending rows the pipeline held back (ADR-0082) — a type's
    // accept skips them, so its button counts only the others.
    const m: Record<string, { total: number; pending: number; held: number }> = {}
    entities.forEach(e => {
      if (!m[e.entity_type]) m[e.entity_type] = { total: 0, pending: 0, held: 0 }
      m[e.entity_type].total++
      if (e.accepted === null) m[e.entity_type].pending++
      if (heldPending(e)) m[e.entity_type].held++
    })
    return m
  }, [entities])

  const types = Object.keys(counts).sort((a, b) => counts[b].total - counts[a].total)

  return (
    <nav className="type-rail">
      <div className="rail-title">
        Filter
        {onClose && (
          <button className="drawer-close" onClick={onClose} aria-label="Close filters">×</button>
        )}
      </div>
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
                {c.pending > c.held && (
                  <button
                    className="rail-accept"
                    title={`Accept all ${c.pending - c.held} pending ${typeLabel(t)}`
                      + (c.held ? ` (${c.held} held for review: accept those on their own cards)` : '')}
                    onClick={() => onAcceptAllOfType(t)}
                  >
                    ✓ {c.pending - c.held}
                  </button>
                )}
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
