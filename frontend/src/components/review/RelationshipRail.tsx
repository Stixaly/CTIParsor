import { useState, useRef, useEffect } from 'react'
import type { Relationship, TemporalAssertion } from '../../types'
import { REL_TYPES, confPct, relNeedsReview, typeDot, typeLabel, verbsForPair } from './tokens'

export type BulkAction = 'accept' | 'reject' | 'reset'

/** One bound an analyst sets or clears (ADR-0063 §9).  Only the bound that
 *  changed is sent: re-sending the other would turn the model's date into the
 *  analyst's. */
export type DatePatch = { start_time?: string | null; stop_time?: string | null }

interface Props {
  rels: Relationship[]
  onAccept: (id: string) => void
  onReject: (id: string) => void
  onReset: (id: string) => void
  onJump: (value: string) => void
  onChangeType: (id: string, type: string) => void
  onChangeDates: (id: string, patch: DatePatch) => void
  showInDoc: boolean
  setShowInDoc: (v: boolean) => void
  onNewRelationship: (x: number, y: number) => void
  /** Optional: look up the STIX entity_type for a given entity value string.
   *  When provided, the verb edit select shows only spec-valid verbs first. */
  getEntityType?: (value: string) => string | undefined
  /** Decide every relationship of a group in one call (ADR-0065).  Without
   *  it the groups show no group buttons. */
  onBulk?: (ids: string[], action: BulkAction) => void
}

/** A stored date as the rail shows it: a partial value as it is ("2023",
 *  "2023-03"), a timestamp down to the minute. */
function shortDate(v: string | null | undefined): string {
  if (!v) return ''
  return v.length > 10 && v[10] === 'T' ? v.slice(0, 16).replace('T', ' ') : v
}

const DATE_HINT = '2023, 2023-03, 2023-03-12 or March 2023'

/** Why a date is not verified, in the analyst's words (pipeline/temporal.py). */
const TIME_REASON: Record<string, string> = {
  not_found: 'the quote is not in the report',
  boundary: 'found only inside an identifier (a CVE number, a version)',
  unparsed: 'not a date the pipeline reads',
  value_mismatch: "the model's reading contradicts the quote",
  numeric_order: 'day/month order unknown',
  no_anchor: 'relative date, and no publication date is known',
  weak_anchor: 'relative date, and only the file timestamp is known',
  year_from_context: 'the quote gives no year',
  contradicts: 'contradicts another date of this relationship',
  legacy: 'stored before dates kept their precision — precision unknown',
  no_quote: 'the model gave a date without quoting it',
  invalid_date: 'not a calendar date',
  implausible_year: 'not a plausible year',
}

function timeTitle(t: TemporalAssertion): string {
  const parts = [`${t.role} · ${t.status}`]
  if (t.reason) parts.push(TIME_REASON[t.reason] ?? t.reason)
  if (t.alternatives?.length) parts.push(`possible readings: ${t.alternatives.join(', ')}`)
  if (t.anchor === 'document' && t.anchor_value) {
    parts.push(`resolved against ${t.anchor_value} (${t.anchor_source ?? 'document date'})`)
  }
  if (t.qualifier && t.qualifier !== 'none') parts.push(`qualifier: ${t.qualifier}`)
  return parts.join('\n')
}

function TimesList({ times }: { times: TemporalAssertion[] }) {
  return (
    <ul className="rel-times" aria-label="Dates of this relationship">
      {times.map(t => (
        <li key={t.id} className={`rel-time st-${t.status}`} title={timeTitle(t)}>
          <span className="rel-time-role">{t.role}{t.first_last ? ` (${t.first_last})` : ''}</span>
          <span className="rel-time-text">
            {t.time_text ? `“${t.time_text}”` : t.origin === 'analyst' ? 'set by analyst' : 'stored earlier'}
          </span>
          <span className="rel-time-value">
            {t.value ? shortDate(t.value) : t.alternatives?.length ? `${t.alternatives.join(' | ')} ?` : '—'}
            {t.precision ? ` · ${t.precision}` : ''}
          </span>
          <span className="rel-time-status">{t.status}</span>
        </li>
      ))}
    </ul>
  )
}

/** A bound typed at the analyst's precision, committed on Enter or blur —
 *  never per keystroke, where "2023-0" would be sent and refused. */
function DateField({ value, label, onCommit }: {
  value: string | null | undefined
  label: string
  onCommit: (v: string | null) => void
}) {
  const [draft, setDraft] = useState(value ?? '')
  useEffect(() => setDraft(value ?? ''), [value])
  const commit = () => {
    const v = draft.trim()
    if (v !== (value ?? '')) onCommit(v || null)
  }
  return (
    <input
      type="text"
      className="rel-date-input partial"
      aria-label={label}
      placeholder={label}
      title={DATE_HINT}
      value={draft}
      onChange={e => setDraft(e.target.value)}
      onBlur={commit}
      onKeyDown={e => {
        if (e.key === 'Enter') commit()
        if (e.key === 'Escape') setDraft(value ?? '')
      }}
    />
  )
}

type Filter = 'pending' | 'all' | 'accepted' | 'rejected'

function RelCard({ r, onAccept, onReject, onReset, onJump, onChangeType, onChangeDates, getEntityType }: {
  r: Relationship
  onAccept: (id: string) => void
  onReject: (id: string) => void
  onReset: (id: string) => void
  onJump: (v: string) => void
  onChangeType: (id: string, t: string) => void
  onChangeDates: (id: string, patch: DatePatch) => void
  getEntityType?: (value: string) => string | undefined
}) {
  const [editing, setEditing] = useState(false)
  const [editingDates, setEditingDates] = useState(false)

  // Resolve entity types for constraint-aware verb filtering
  const srcType = getEntityType?.(r.source_value)
  const tgtType = getEntityType?.(r.target_value)
  const { valid, others, constrained } = srcType && tgtType
    ? verbsForPair(srcType, tgtType)
    : { valid: REL_TYPES, others: [], constrained: false }
  // ADR-0058: the pipeline stores every relationship accepted, as `default`.
  // That is nobody's decision, so ✓ confirms it instead of resetting it.
  const byDefault = r.accepted === true && r.decision_origin === 'default'
  const acceptedByPerson = r.accepted === true && !byDefault

  return (
    <div className={`rel-card ${acceptedByPerson ? 'rok' : ''} ${r.accepted === false ? 'rno' : ''}`}>
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
        {byDefault && (
          <span
            className="marg-origin"
            title="Kept by default: the pipeline stores every relationship accepted, and it ships unless rejected. Nobody has reviewed it."
          >
            default
          </span>
        )}
        <div className="rel-actions">
          <button
            className={`mbtn ok ${acceptedByPerson ? 'on' : ''}`}
            onClick={() => acceptedByPerson ? onReset(r.id) : onAccept(r.id)}
            title={byDefault ? 'Confirm (accepted by default, not reviewed)' : 'Accept'}
          >✓</button>
          <button
            className={`mbtn no ${r.accepted === false ? 'on' : ''}`}
            onClick={() => r.accepted === false ? onReset(r.id) : onReject(r.id)}
            title="Reject"
          >✗</button>
        </div>
      </div>
      {editingDates ? (
        <div className="rel-dates-edit">
          <DateField value={r.start_time} label="start"
                     onCommit={v => onChangeDates(r.id, { start_time: v })} />
          <span className="rel-dates-arrow">→</span>
          <DateField value={r.stop_time} label="end"
                     onCommit={v => onChangeDates(r.id, { stop_time: v })} />
          <button className="rel-dates-done" onClick={() => setEditingDates(false)} title="Done">✓</button>
          <span className="rel-dates-hint">{DATE_HINT}</span>
        </div>
      ) : (
        <button
          className="rel-dates"
          onClick={() => setEditingDates(true)}
          title="Click to set when this relationship began and ended, at the precision you know"
        >
          {r.start_time || r.stop_time
            ? `${shortDate(r.start_time) || '?'} → ${shortDate(r.stop_time) || '?'}`
            : '+ dates'}
        </button>
      )}
      {r.times && r.times.length > 0 && <TimesList times={r.times} />}
      {r.evidence_text && (
        <div className="rel-evidence">"{r.evidence_text}"</div>
      )}
    </div>
  )
}

// Tallest the rail may be: the window minus the chrome above the document
// (~140 px) and ~100 px of document left readable.  Applied to the default,
// to a drag and to every window resize — it used to be applied only while
// dragging, so a rail sized on a tall window covered a smaller one entirely.
const RAIL_MIN = 56
const railMax = () => Math.max(RAIL_MIN, window.innerHeight - 240)
const clampRail = (h: number) => Math.max(RAIL_MIN, Math.min(railMax(), h))

const FILTER_LABEL: Record<Filter, string> = {
  pending: 'to review', all: 'all', accepted: 'accepted', rejected: 'rejected',
}

/** Rows sharing a target, biggest group first — the unit the analyst decides
 *  in one click (ADR-0065).  Matched case-insensitively, as Stage 4 resolves
 *  endpoints. */
function groupByTarget(rels: Relationship[]): Array<{ key: string; target: string; rows: Relationship[] }> {
  const groups = new Map<string, { key: string; target: string; rows: Relationship[] }>()
  for (const r of rels) {
    const key = r.target_value.trim().toLowerCase()
    const g = groups.get(key)
    if (g) g.rows.push(r)
    else groups.set(key, { key, target: r.target_value, rows: [r] })
  }
  return [...groups.values()].sort((a, b) =>
    b.rows.length - a.rows.length || a.target.localeCompare(b.target))
}

export default function RelationshipRail({
  rels, onAccept, onReject, onReset, onJump, onChangeType, onChangeDates,
  showInDoc, setShowInDoc, onNewRelationship, getEntityType, onBulk,
}: Props) {
  const [filter, setFilter] = useState<Filter>('pending')
  const [grouped, setGrouped] = useState(true)
  const [collapsed, setCollapsed] = useState(false)
  // The height asked for (default or dragged); what is shown is that height
  // clamped to the current window, so it comes back when the window grows.
  const [height, setHeight] = useState(300)
  const [, setViewportH] = useState(() => window.innerHeight)
  const [dragging, setDragging] = useState(false)
  const startRef = useRef({ y: 0, h: 0 })
  // Tracks the active drag listeners so we can remove them if the component
  // unmounts during a resize (prevents setState-after-unmount and listener leaks).
  const activeResizeRef = useRef<{ move: (ev: PointerEvent) => void; up: () => void } | null>(null)

  useEffect(() => {
    const onResize = () => setViewportH(window.innerHeight)
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])

  useEffect(() => () => {
    if (activeResizeRef.current) {
      window.removeEventListener('pointermove', activeResizeRef.current.move)
      window.removeEventListener('pointerup',   activeResizeRef.current.up)
    }
  }, [])

  const onResizeDown = (e: React.PointerEvent) => {
    setDragging(true)
    startRef.current = { y: e.clientY, h: clampRail(height) }
    const move = (ev: PointerEvent) => {
      const dy = startRef.current.y - ev.clientY
      setHeight(clampRail(startRef.current.h + dy))
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

  // "To review" is what no analyst has decided: pending rows and the rows the
  // pipeline stored accepted by default (ADR-0058).  It used to count only
  // pending rows, and the pipeline never stores one, so the tab read 0 on
  // every report while all its relationships went out unreviewed.
  const inFilter = (r: Relationship, f: Filter) => {
    if (f === 'pending')  return relNeedsReview(r)
    if (f === 'accepted') return r.accepted === true && !relNeedsReview(r)
    if (f === 'rejected') return r.accepted === false
    return true
  }
  const counts = {
    all:      rels.length,
    pending:  rels.filter(r => inFilter(r, 'pending')).length,
    accepted: rels.filter(r => inFilter(r, 'accepted')).length,
    rejected: rels.filter(r => inFilter(r, 'rejected')).length,
  }

  const filtered = rels.filter(r => inFilter(r, filter))

  const card = (r: Relationship) => (
    <RelCard
      key={r.id}
      r={r}
      onAccept={onAccept}
      onReject={onReject}
      onReset={onReset}
      onJump={onJump}
      onChangeType={onChangeType}
      onChangeDates={onChangeDates}
      getEntityType={getEntityType}
    />
  )

  const actualHeight = collapsed ? 42 : clampRail(height)

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
              title={f === 'pending'
                ? 'Not decided by an analyst: pending, or kept by default — these ship unless rejected'
                : undefined}
            >
              {FILTER_LABEL[f]} <span className="rel-count">{counts[f]}</span>
            </button>
          ))}
        </div>

        <button
          className={`rel-tab ${grouped ? 'on' : ''}`}
          aria-pressed={grouped}
          onClick={() => setGrouped(g => !g)}
          title="Group the relationships that share a target, to decide each group at once"
        >
          by target
        </button>

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
          {grouped
            ? groupByTarget(filtered).map(g => g.rows.length < 2 ? card(g.rows[0]) : (
                <div key={g.key} className="rel-group" role="group" aria-label={`Relationships to ${g.target}`}>
                  <div className="rel-group-head">
                    {(() => {
                      const t = getEntityType?.(g.target)
                      return t ? (
                        <>
                          <span className="rc-chip-dot" style={{ background: typeDot(t) }} />
                          <span className="rel-group-type">{typeLabel(t)}</span>
                        </>
                      ) : null
                    })()}
                    <button className="rel-node" onClick={() => onJump(g.target)}>{g.target}</button>
                    <span className="rel-group-count">{g.rows.length} relationships</span>
                    {onBulk && (
                      <div className="rel-actions">
                        <button
                          className="mbtn ok rel-group-btn"
                          onClick={() => onBulk(g.rows.map(r => r.id), 'accept')}
                          title={`Accept these ${g.rows.length} relationships`}
                        >✓ all</button>
                        <button
                          className="mbtn no rel-group-btn"
                          onClick={() => onBulk(g.rows.map(r => r.id), 'reject')}
                          title={`Reject these ${g.rows.length} relationships`}
                        >✗ all</button>
                      </div>
                    )}
                  </div>
                  {g.rows.map(card)}
                </div>
              ))
            : filtered.map(card)}
          {filtered.length === 0 && (
            <div className="rel-empty">All caught up. Nothing in "{FILTER_LABEL[filter]}."</div>
          )}
        </div>
      )}
    </section>
  )
}
