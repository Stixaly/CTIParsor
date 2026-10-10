import { useState, useEffect, useLayoutEffect, useRef } from 'react'
import type { Entity } from '../../types'
import { typeDot, typeLabel, typeSoft, typeInk, confPct, heldPending, heldTitle, SOURCE_LABEL, TYPE_GROUPS } from './tokens'

interface Props {
  entity: Entity
  y?: number
  flow?: boolean
  collapsed: boolean
  focused: boolean
  /** Called when the user clicks the entity value — scrolls to the entity in the document. */
  onClick: () => void
  onToggleCollapse: () => void
  onAccept: () => void
  onReject: () => void
  onReset: () => void
  onChangeType: (t: string) => void
  /** Whether the entity is currently selected (checkbox is ticked). */
  selected?: boolean
  /** Called when the user clicks the selection checkbox. */
  onToggleSelect?: () => void
}

export default function MarginaliaCard({
  entity: e, y, flow, collapsed, focused,
  onClick, onToggleCollapse, onAccept, onReject, onReset, onChangeType,
  selected = false, onToggleSelect,
}: Props) {
  const accepted = e.accepted === true
  const rejected = e.accepted === false
  const [menuOpen, setMenuOpen] = useState(false)
  // The "⋯" button's box when the menu opened; the menu is placed from it.
  const [anchor, setAnchor] = useState<DOMRect | null>(null)
  const [menuPos, setMenuPos] = useState<{ top: number; right: number; maxHeight: number } | null>(null)
  const btnRef    = useRef<HTMLButtonElement>(null)
  const popupRef  = useRef<HTMLDivElement>(null)
  const src = SOURCE_LABEL[e.source] ?? { label: e.source, hint: '' }

  const openMenu = (ev: React.MouseEvent) => {
    ev.stopPropagation()
    if (menuOpen) { setMenuOpen(false); return }
    if (!btnRef.current) return
    setAnchor(btnRef.current.getBoundingClientRect())
    setMenuPos(null)
    setMenuOpen(true)
  }

  // Placed from the menu's measured height, before paint.  It used to assume
  // 340 px while the CSS allows 360, so opening downward with 340–360 px left
  // ran off the bottom, and a window under ~370 px cut it at both ends.  It
  // now opens toward the larger space and scrolls within it.
  useLayoutEffect(() => {
    if (!menuOpen || !anchor || !popupRef.current) return
    const EDGE = 8
    const needed = popupRef.current.scrollHeight
    const below = window.innerHeight - anchor.bottom - 4 - EDGE
    const above = anchor.top - 4 - EDGE
    const down = needed <= below || below >= above
    const maxHeight = Math.max(80, Math.min(360, down ? below : above))
    const height = Math.min(needed, maxHeight)
    const top = down ? anchor.bottom + 4 : anchor.top - 4 - height
    // right: kept ≥ 0 — a negative value would push the popup off-screen on
    // narrow viewports.
    setMenuPos({ top: Math.max(EDGE, top), right: Math.max(0, window.innerWidth - anchor.right), maxHeight })
  }, [menuOpen, anchor])

  useEffect(() => {
    if (!menuOpen) return
    const close = () => setMenuOpen(false)
    const closeOnScroll = (e: Event) => {
      if (popupRef.current?.contains(e.target as Node)) return
      setMenuOpen(false)
    }
    document.addEventListener('click', close)
    document.addEventListener('scroll', closeOnScroll, true)
    window.addEventListener('resize', close)
    return () => {
      document.removeEventListener('click', close)
      document.removeEventListener('scroll', closeOnScroll, true)
      window.removeEventListener('resize', close)
    }
  }, [menuOpen])

  const cls = [
    'marg',
    focused   ? 'focused'   : '',
    accepted  ? 'accepted'  : '',
    rejected  ? 'rejected'  : '',
    collapsed ? 'marg-collapsed' : '',
    selected  ? 'marg-selected'  : '',
    flow      ? 'marg-flow-item' : 'marg-abs',
  ].filter(Boolean).join(' ')

  const style = (!flow && y !== undefined) ? { top: y } : undefined

  return (
    <div className={cls} style={style} data-marg-id={e.id}>
      <div className="marg-row">

        {/* ── Selection checkbox ──────────────────────────────────────── */}
        {onToggleSelect && (
          <button
            className={`marg-check ${selected ? 'marg-check-on' : ''}`}
            onClick={ev => { ev.stopPropagation(); onToggleSelect() }}
            title={selected ? 'Deselect' : 'Select for bulk action'}
            aria-checked={selected}
            role="checkbox"
          >
            {selected ? '✓' : ''}
          </button>
        )}

        {/* ── Colour bar ─────────────────────────────────────────────── */}
        <span className="marg-bar" style={{ background: typeDot(e.entity_type) }} />

        <div className="marg-body">
          {/* ── Header: type badge + MITRE ID + confidence + collapse ── */}
          <div
            className="marg-head"
            onClick={ev => { ev.stopPropagation(); onToggleCollapse() }}
          >
            <span
              className="marg-type"
              style={{ color: typeInk(e.entity_type), background: typeSoft(e.entity_type) }}
            >
              {typeLabel(e.entity_type)}
            </span>
            {e.mitre_id && <span className="marg-mitre">{e.mitre_id}</span>}
            {/* ADR-0058 — who decided: the worker's auto-accept, or a control
                row it left for an analyst so auto-accept can be measured. */}
            {e.control_sample && e.accepted === null && (
              <span
                className="marg-origin marg-origin-control"
                title="Control sample: auto-accept left this one for you. Your verdict measures how often auto-accept is right."
              >
                confirm
              </span>
            )}
            {/* ADR-0082 — the pipeline could not decide it: why, and that it
                waits for this card's ✓. */}
            {heldPending(e) && (
              <span className="marg-origin marg-origin-held" title={heldTitle(e.held_reason!)}>
                held
              </span>
            )}
            {e.decision_origin === 'auto_policy' && e.accepted === true && (
              <span className="marg-origin" title="Accepted automatically (high confidence), not by an analyst">
                auto
              </span>
            )}
            <span className="marg-conf">{confPct(e.confidence)}</span>
            <span className="marg-collapse-ind">{collapsed ? '›' : '˅'}</span>
          </div>

          {/* ── Entity value — clicking scrolls to the entity in the doc ── */}
          <button
            className="marg-value marg-value-link"
            title={`Go to "${e.value}" in the document`}
            onClick={ev => { ev.stopPropagation(); onClick() }}
          >
            {e.value}
          </button>

          {/* ── Expanded body ─────────────────────────────────────────── */}
          {!collapsed && (
            <>
              {e.context && (
                <div className="marg-note">{e.context}</div>
              )}
              <div className="marg-foot">
                <span className="marg-src" title={src.hint}>{src.label}</span>
                <div className="marg-actions">
                  <button
                    className={`mbtn ok ${accepted ? 'on' : ''}`}
                    onClick={ev => { ev.stopPropagation(); accepted ? onReset() : onAccept() }}
                    title="Accept (A)"
                  >✓</button>
                  <button
                    className={`mbtn no ${rejected ? 'on' : ''}`}
                    onClick={ev => { ev.stopPropagation(); rejected ? onReset() : onReject() }}
                    title="Reject (R)"
                  >✗</button>
                  <button
                    ref={btnRef}
                    className="mbtn"
                    onClick={openMenu}
                    title="Change type"
                  >⋯</button>
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {/* ── Type-picker popup ─────────────────────────────────────────── */}
      {menuOpen && (
        <div
          ref={popupRef}
          className="type-picker-popup"
          style={menuPos
            ? { top: menuPos.top, right: menuPos.right, maxHeight: menuPos.maxHeight }
            // First layout pass: measured, not shown.
            : { top: 0, right: 0, visibility: 'hidden' }}
          onClick={ev => ev.stopPropagation()}
        >
          <div className="type-picker-title">Change type</div>
          {TYPE_GROUPS.map(grp => (
            <div key={grp.label} className="type-picker-group">
              <div className="type-picker-group-label">{grp.label}</div>
              <div className="type-picker-pills">
                {grp.types.map(t => (
                  <button
                    key={t}
                    className={`type-pill ${t === e.entity_type ? 'current' : ''}`}
                    style={{ background: typeSoft(t), color: typeInk(t) }}
                    onClick={() => { onChangeType(t); setMenuOpen(false) }}
                  >
                    {typeLabel(t)}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
