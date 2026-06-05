import { useState } from 'react'
import { createPortal } from 'react-dom'
import type { Entity } from '../../types'
import { typeDot, typeLabel, typeSoft, typeInk, TYPE_GROUPS, confPct } from './tokens'

interface Props {
  entity: Entity
  x: number
  y: number
  onAccept: (id: string) => void
  onReject: (id: string) => void
  onReset: (id: string) => void
  onOpen: (id: string) => void
  onChangeType: (id: string, t: string) => void
  onEnterChip: () => void
  onLeaveChip: () => void
}

export default function InlineHoverChip({
  entity, x, y,
  onAccept, onReject, onReset, onOpen, onChangeType,
  onEnterChip, onLeaveChip,
}: Props) {
  const [typeMenu, setTypeMenu] = useState(false)
  const accepted = entity.accepted === true
  const rejected = entity.accepted === false

  return createPortal(
    <div
      className="chip"
      style={{ left: x, top: y - 12 }}
      onMouseEnter={onEnterChip}
      onMouseLeave={onLeaveChip}
    >
      <div className="chip-meta">
        <span className="chip-dot" style={{ background: typeDot(entity.entity_type) }} />
        <span className="chip-type">{typeLabel(entity.entity_type)}</span>
        <span className="chip-conf">{confPct(entity.confidence)}%</span>
      </div>
      <div className="chip-actions">
        <button
          className={`chip-btn ok ${accepted ? 'is-on' : ''}`}
          title="Accept (A)"
          onClick={() => accepted ? onReset(entity.id) : onAccept(entity.id)}
        >✓</button>
        <button
          className={`chip-btn no ${rejected ? 'is-on' : ''}`}
          title="Reject (R)"
          onClick={() => rejected ? onReset(entity.id) : onReject(entity.id)}
        >✗</button>
        <button
          className="chip-btn neutral"
          title="Change type"
          onClick={() => setTypeMenu(v => !v)}
        >☰</button>
        <button
          className="chip-btn neutral"
          title="Focus in margin"
          onClick={() => onOpen(entity.id)}
        >→</button>
      </div>

      {typeMenu && (
        <div className="chip-typemenu">
          <div className="menu-title">Change type</div>
          {/* Use TYPE_GROUPS (pipeline-internal underscore names only) instead of
              Object.keys(TYPE_STYLE) — TYPE_STYLE also contains STIX canonical
              hyphenated aliases (e.g. "threat-actor") that the API rejects with 400. */}
          {TYPE_GROUPS.map(grp => (
            <div key={grp.label}>
              <div className="menu-group-label">{grp.label}</div>
              <div className="menu-grid">
                {grp.types.map(t => (
                  <button
                    key={t}
                    className={`type-pill ${t === entity.entity_type ? 'current' : ''}`}
                    style={{ background: typeSoft(t), color: typeInk(t) }}
                    onClick={() => { onChangeType(entity.id, t); setTypeMenu(false) }}
                  >
                    {typeLabel(t)}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>,
    document.body,
  )
}
