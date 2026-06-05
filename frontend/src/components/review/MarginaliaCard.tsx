import { useState, useEffect, useRef } from 'react'
import type { Entity } from '../../types'
import { typeDot, typeLabel, typeSoft, typeInk, confPct, SOURCE_LABEL, TYPE_GROUPS } from './tokens'

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
  const [menuPos, setMenuPos] = useState<{ top: number; right: number } | null>(null)
  const btnRef    = useRef<HTMLButtonElement>(null)
  const popupRef  = useRef<HTMLDivElement>(null)
  const src = SOURCE_LABEL[e.source] ?? { label: e.source, hint: '' }

  const openMenu = (ev: React.MouseEvent) => {
    ev.stopPropagation()
    if (menuOpen) { setMenuOpen(false); return }
    if (btnRef.current) {
      const r = btnRef.current.getBoundingClientRect()
      const MENU_H = 340
      const top = window.innerHeight - r.bottom > MENU_H
        ? r.bottom + 4
        : r.top - MENU_H - 4
      // Clamp both axes: top away from the top edge, right away from the left edge
      // (a negative right value would push the popup off-screen on narrow viewports).
      setMenuPos({ top: Math.max(8, top), right: Math.max(0, window.innerWidth - r.right) })
    }
    setMenuOpen(true)
  }

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
      {menuOpen && menuPos && (
        <div
          ref={popupRef}
          className="type-picker-popup"
          style={{ top: menuPos.top, right: menuPos.right }}
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
