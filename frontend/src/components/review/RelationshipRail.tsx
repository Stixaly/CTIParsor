import { useState, useRef, useEffect } from 'react'
import type { Relationship } from '../../types'
import { REL_TYPES, confPct, verbsForPair } from './tokens'

interface Props {
  rels: Relationship[]
  onAccept: (id: string) => void
  onReject: (id: string) => void
  onReset: (id: string) => void
  onJump: (value: string) => void
  onChangeType: (id: string, type: string) => void
  showInDoc: boolean
  setShowInDoc: (v: boolean) => void
  onNewRelationship: (x: number, y: number) => void
  /** Optional: look up the STIX entity_type for a given entity value string.
   *  When provided, the verb edit select shows only spec-valid verbs first. */
  getEntityType?: (value: string) => string | undefined
}

type Filter = 'pending' | 'all' | 'accepted' | 'rejected'

function RelCard({ r, onAccept, onReject, onReset, onJump, onChangeType, getEntityType }: {
  r: Relationship
  onAccept: (id: string) => void
  onReject: (id: string) => void
  onReset: (id: string) => void
  onJump: (v: string) => void
  onChangeType: (id: string, t: string) => void
  getEntityType?: (value: string) => string | undefined
}) {
  const [editing, setEditing] = useState(false)

  // Resolve entity types for constraint-aware verb filtering
  const srcType = getEntityType?.(r.source_value)
  const tgtType = getEntityType?.(r.target_value)
  const { valid, others, constrained } = srcType && tgtType
    ? verbsForPair(srcType, tgtType)
    : { valid: REL_TYPES, others: [], constrained: false }

  return (
    <div className={`rel-card ${r.accepted === true ? 'rok' : ''} ${r.accepted === false ? 'rno' : ''}`}>
      <div className="rel-line">
        <button className="rel-node" onClick={() => onJump(r.source_value)}>
          {r.source_value}
        </button>
        {editing ? (
          <select
            className="rel-edge-select"
            value={r.relationship_type}
            onChange={e => { onChangeType(r.id, e.target.value); setEditing(false) }}
            onBlur={() => setEditing(false)}
            autoFocus
          >
            {/* When a known src→tgt pair is selected, show only spec-valid verbs */}
            {constrained
              ? valid.map(t => <option key={t} value={t}>{t}</option>)
              : REL_TYPES.map(t => <option key={t} value={t}>{t}</option>)
            }
          </select>
        ) : (
          <button
            className="rel-edge"
            onClick={() => setEditing(true)}
            title="Click to change relationship type"
          >
            {r.relationship_type} <span className="rel-edge-edit">✎</span>
          </button>
        )}
        <button className="rel-node" onClick={() => onJump(r.target_value)}>
          {r.target_value}
        </button>
        <span className="rel-conf">{confPct(r.confidence)}%</span>
        <div className="rel-actions">
          <button
            className={`mbtn ok ${r.accepted === true ? 'on' : ''}`}
            onClick={() => r.accepted === true ? onReset(r.id) : onAccept(r.id)}
            title="Accept"
          >✓</button>
          <button
            className={`mbtn no ${r.accepted === false ? 'on' : ''}`}
            onClick={() => r.accepted === false ? onReset(r.id) : onReject(r.id)}
            title="Reject"
          >✗</button>
        </div>
      </div>
      {r.evidence_text && (
        <div className="rel-evidence">"{r.evidence_text}"</div>
      )}
    </div>
  )
}

export default function RelationshipRail({
  rels, onAccept, onReject, onReset, onJump, onChangeType,
  showInDoc, setShowInDoc, onNewRelationship, getEntityType,
}: Props) {
  const [filter, setFilter] = useState<Filter>('pending')
  const [collapsed, setCollapsed] = useState(false)
  const [height, setHeight] = useState(300)
  const [dragging, setDragging] = useState(false)
  const startRef = useRef({ y: 0, h: 0 })
  // Tracks the active drag listeners so we can remove them if the component
  // unmounts during a resize (prevents setState-after-unmount and listener leaks).
  const activeResizeRef = useRef<{ move: (ev: PointerEvent) => void; up: () => void } | null>(null)

  useEffect(() => () => {
    if (activeResizeRef.current) {
      window.removeEventListener('pointermove', activeResizeRef.current.move)
      window.removeEventListener('pointerup',   activeResizeRef.current.up)
    }
  }, [])

  const onResizeDown = (e: React.PointerEvent) => {
    setDragging(true)
    startRef.current = { y: e.clientY, h: height }
    const move = (ev: PointerEvent) => {
      const dy = startRef.current.y - ev.clientY
      const nh = Math.max(56, Math.min(window.innerHeight - 140, startRef.current.h + dy))
      setHeight(nh)
    }
    const up = () => {
      setDragging(false)
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
      activeResizeRef.current = null
    }
    activeResizeRef.current = { move, up }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
  }

  const counts = {
    all:      rels.length,
    pending:  rels.filter(r => r.accepted === null).length,
    accepted: rels.filter(r => r.accepted === true).length,
    rejected: rels.filter(r => r.accepted === false).length,
  }

  const filtered = rels.filter(r => {
    if (filter === 'all')      return true
    if (filter === 'pending')  return r.accepted === null
    if (filter === 'accepted') return r.accepted === true
    if (filter === 'rejected') return r.accepted === false
    return true
  })

  const actualHeight = collapsed ? 42 : height

  return (
    <section
      className={`rel-rail ${collapsed ? 'rel-collapsed' : ''} ${dragging ? 'rel-dragging' : ''}`}
      style={{ height: actualHeight }}
    >
      {!collapsed && (
        <div className="rel-resize" onPointerDown={onResizeDown} title="Drag to resize">
          <span className="rel-resize-grip" />
        </div>
      )}

      <header className="rel-head">
        <button
          className="rel-toggle"
          onClick={() => setCollapsed(c => !c)}
          title={collapsed ? 'Expand' : 'Collapse'}
        >
          {collapsed ? '▴' : '▾'}
        </button>
        <div className="rel-title">Relationships</div>

        <button
          className={`rel-eye ${showInDoc ? 'on' : ''}`}
          onClick={() => setShowInDoc(!showInDoc)}
          title={showInDoc ? 'Hide evidence highlights' : 'Show evidence highlights in document'}
        >
          {showInDoc ? (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
              <circle cx="12" cy="12" r="3" fill="currentColor" />
            </svg>
          ) : (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24" />
              <path d="M1 1l22 22" />
            </svg>
          )}
        </button>

        <div className="rel-tabs">
          {(['pending', 'all', 'accepted', 'rejected'] as const).map(f => (
            <button
              key={f}
              className={`rel-tab ${filter === f ? 'on' : ''}`}
              onClick={() => setFilter(f)}
            >
              {f} <span className="rel-count">{counts[f]}</span>
            </button>
          ))}
        </div>

        <button
          className="rel-new"
          onClick={e => onNewRelationship(e.clientX, e.clientY)}
          title="Add a relationship"
        >
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
            <path d="M12 5v14M5 12h14" />
          </svg>
          New
        </button>
      </header>

      {!collapsed && (
        <div className="rel-list">
          {filtered.map(r => (
            <RelCard
              key={r.id}
              r={r}
              onAccept={onAccept}
              onReject={onReject}
              onReset={onReset}
              onJump={onJump}
              onChangeType={onChangeType}
              getEntityType={getEntityType}
            />
          ))}
          {filtered.length === 0 && (
            <div className="rel-empty">All caught up. Nothing in "{filter}."</div>
          )}
        </div>
      )}
    </section>
  )
}
