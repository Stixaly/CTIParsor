import { useState, useLayoutEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import type { Entity } from '../../types'
import { typeDot, typeLabel, typeSoft, typeInk, TYPE_GROUPS, confPct } from './tokens'

const EDGE = 8   // px kept free between the chip (or its menu) and the window edge

interface Props {
  entity: Entity
  /** Centre of the mark, and its top edge. */
  x: number
  y: number
  /** The mark's bottom edge — where the chip goes when there is no room above. */
  bottom?: number
  onAccept: (id: string) => void
  onReject: (id: string) => void
  onReset: (id: string) => void
  onOpen: (id: string) => void
  onChangeType: (id: string, t: string) => void
  onEnterChip: () => void
  onLeaveChip: () => void
}

export default function InlineHoverChip({
  entity, x, y, bottom,
  onAccept, onReject, onReset, onOpen, onChangeType,
  onEnterChip, onLeaveChip,
}: Props) {
  const [typeMenu, setTypeMenu] = useState(false)
  const accepted = entity.accepted === true
  const rejected = entity.accepted === false

  // The chip sat centred above the mark whatever the window: half of it off
  // screen at a side edge, all of it above the top one.  Measured before
  // paint, then kept inside the window (or moved under the mark).
  const chipRef = useRef<HTMLDivElement>(null)
  const [place, setPlace] = useState({ left: x, below: false, arrow: 0 })
  useLayoutEffect(() => {
    const el = chipRef.current
    if (!el) return
    const w = el.offsetWidth
    const half = w / 2
    const left = Math.max(EDGE + half, Math.min(window.innerWidth - EDGE - half, x))
    const below = y - 12 - el.offsetHeight < EDGE
    // The arrow still points at the mark when the chip has been pushed aside.
    const arrow = Math.max(12, Math.min(w - 12, x - (left - half)))
    setPlace(p => (p.left === left && p.below === below && p.arrow === arrow
      ? p : { left, below, arrow }))
  }, [x, y, entity.id])

  // "Change type" opens downward with no height limit: in a low window its
  // last rows were out of reach.  It now opens toward the larger space and
  // scrolls within it.
  const menuRef = useRef<HTMLDivElement>(null)
  const [menu, setMenu] = useState<{ up: boolean; maxHeight: number } | null>(null)
  useLayoutEffect(() => {
    if (!typeMenu || !chipRef.current) { setMenu(null); return }
    const r = chipRef.current.getBoundingClientRect()
    const spaceBelow = window.innerHeight - r.bottom - 6 - EDGE
    const spaceAbove = r.top - 6 - EDGE
    const needed = menuRef.current?.scrollHeight ?? 0
    const up = needed > spaceBelow && spaceAbove > spaceBelow
    setMenu({ up, maxHeight: Math.max(120, up ? spaceAbove : spaceBelow) })
  }, [typeMenu, place])

  return createPortal(
    <div
      ref={chipRef}
      className={`chip ${place.below ? 'chip-below' : ''}`}
      style={{
        left: place.left,
        top: place.below ? (bottom ?? y + 20) + 12 : y - 12,
        ...(place.arrow ? { '--chip-arrow': `${place.arrow}px` } : {}),
      } as React.CSSProperties}
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
        <div
          ref={menuRef}
          className={`chip-typemenu ${menu?.up ? 'chip-typemenu-up' : ''}`}
          style={menu ? { maxHeight: menu.maxHeight } : undefined}
        >
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
