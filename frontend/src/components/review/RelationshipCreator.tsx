import { useState, useEffect, useLayoutEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import type { Entity } from '../../types'
import { typeDot, typeLabel, REL_TYPES, suggestRelType, TYPE_GROUPS, verbsForPair } from './tokens'

interface CreatorPayload {
  srcId?: string
  tgtId?: string
  x: number
  y: number
  evidenceText?: string
}

interface Props {
  entities: Entity[]
  initial: CreatorPayload
  onCancel: () => void
  onCreate: (payload: { src: string; tgt: string; type: string; evidence: string }) => void
  /** Called when the user asks to add a new entity inline from the picker.
   *  Returns the newly-created Entity so the picker can auto-select it. */
  onAddEntity: (value: string, entityType: string) => Promise<Entity>
}

// ── Entity picker ──────────────────────────────────────────────────────────────

function RcEntityPicker({
  label, entity, query, setQuery, options, onPick, onClear, onAddEntity,
}: {
  label: string
  entity: Entity | undefined
  query: string
  setQuery: (q: string) => void
  options: Entity[]
  onPick: (id: string) => void
  onClear: () => void
  onAddEntity: (value: string, entityType: string) => Promise<Entity>
}) {
  const [open,        setOpen]        = useState(false)
  const [showForm,    setShowForm]    = useState(false)
  const [newType,     setNewType]     = useState('malware')
  const [adding,      setAdding]      = useState(false)
  const [addError,    setAddError]    = useState('')

  // Reset the mini-form whenever the picker is reset (query cleared)
  useEffect(() => {
    if (!query) { setShowForm(false); setAddError('') }
  }, [query])

  const handleInlineAdd = async () => {
    const val = query.trim()
    if (!val) return
    setAdding(true)
    setAddError('')
    try {
      const created = await onAddEntity(val, newType)
      onPick(created.id)
      setShowForm(false)
      setOpen(false)
    } catch (err) {
      setAddError(err instanceof Error ? err.message : 'Failed to create entity')
    } finally {
      setAdding(false)
    }
  }

  return (
    <div className="rc-picker">
      <div className="rc-label">{label}</div>

      {entity ? (
        /* ── Selected chip ─────────────────────────────────────────────── */
        <div className="rc-chip">
          <span className="rc-chip-dot" style={{ background: typeDot(entity.entity_type) }} />
          <span className="rc-chip-type">{typeLabel(entity.entity_type)}</span>
          <span className="rc-chip-val">{entity.value}</span>
          <button className="rc-chip-x" onClick={onClear}>×</button>
        </div>
      ) : (
        /* ── Search input + dropdown ────────────────────────────────────── */
        <div className="rc-search">
          <input
            className="rc-input"
            placeholder="Search entities…"
            value={query}
            autoFocus={label === 'Source'}
            onChange={e => { setQuery(e.target.value); setOpen(true); setShowForm(false) }}
            onFocus={() => setOpen(true)}
            onBlur={() => setTimeout(() => setOpen(false), 160)}
          />

          {/* Results list — shown when open and there are matches */}
          {open && options.length > 0 && (
            <div className="rc-options">
              {options.map(o => (
                <button
                  key={o.id}
                  className="rc-option"
                  onMouseDown={() => { onPick(o.id); setOpen(false) }}
                >
                  <span className="rc-chip-dot" style={{ background: typeDot(o.entity_type) }} />
                  <span className="rc-chip-type">{typeLabel(o.entity_type)}</span>
                  <span className="rc-chip-val">{o.value}</span>
                  {o.mitre_id && <span className="rc-chip-type">{o.mitre_id}</span>}
                </button>
              ))}
            </div>
          )}

          {/* No-matches state — show "Add new entity" option */}
          {open && options.length === 0 && query.trim() && (
            <div className="rc-options">
              <button
                className="rc-option rc-option-add"
                onMouseDown={() => { setShowForm(true); setOpen(false) }}
              >
                <span className="rc-option-add-icon">＋</span>
                Add &ldquo;{query.trim()}&rdquo; as new entity
              </button>
            </div>
          )}

          {/* ── Inline mini-form — appears after clicking "Add" ────────── */}
          {showForm && (
            <div className="rc-mini-form">
              <div className="rc-mini-form-label">
                Choose type for &ldquo;{query.trim()}&rdquo;
              </div>
              <div className="rc-mini-form-row">
                <select
                  className="rc-mini-select"
                  value={newType}
                  onChange={e => setNewType(e.target.value)}
                >
                  {TYPE_GROUPS.map(grp => (
                    <optgroup key={grp.label} label={grp.label}>
                      {grp.types.map(t => (
                        <option key={t} value={t}>{typeLabel(t)}</option>
                      ))}
                    </optgroup>
                  ))}
                </select>
                <button
                  className="btn-primary"
                  style={{ fontSize: 11, padding: '5px 10px', flexShrink: 0 }}
                  onClick={handleInlineAdd}
                  disabled={adding}
                >
                  {adding ? '…' : 'Add'}
                </button>
                <button
                  className="btn-ghost"
                  style={{ fontSize: 11, padding: '5px 8px', flexShrink: 0 }}
                  onClick={() => { setShowForm(false); setAddError('') }}
                >
                  ✕
                </button>
              </div>
              {addError && (
                <div className="rc-mini-form-error">{addError}</div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Placement ──────────────────────────────────────────────────────────────────

const EDGE = 12   // px kept free around the card

/** The card's height with nothing scrolled or capped: its header and actions,
 *  and the body's blocks.  Summed block by block, not read from scrollHeight,
 *  so an open picker dropdown (absolutely positioned, meant to overflow the
 *  card) does not count. */
function naturalHeight(pop: HTMLElement): number {
  let h = 2   // borders
  for (const part of Array.from(pop.children) as HTMLElement[]) {
    if (!part.classList.contains('rc-body')) { h += part.offsetHeight; continue }
    const cs = getComputedStyle(part)
    h += parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom)
    for (const block of Array.from(part.children) as HTMLElement[]) {
      const s = getComputedStyle(block)
      h += block.offsetHeight + parseFloat(s.marginTop) + parseFloat(s.marginBottom)
    }
  }
  return h
}

// ── Main creator popover ───────────────────────────────────────────────────────

export default function RelationshipCreator({
  entities, initial, onCancel, onCreate, onAddEntity,
}: Props) {
  const [srcId, setSrcId] = useState(initial.srcId ?? '')
  const [tgtId, setTgtId] = useState(initial.tgtId ?? '')
  const [type, setType] = useState(() => {
    const s = entities.find(e => e.id === initial.srcId)
    const t = entities.find(e => e.id === initial.tgtId)
    return (s && t) ? suggestRelType(s.entity_type, t.entity_type) : 'related-to'
  })
  const [srcQuery, setSrcQuery] = useState('')
  const [tgtQuery, setTgtQuery] = useState('')

  // Auto-suggest relationship type whenever source or target changes
  useEffect(() => {
    const s = entities.find(e => e.id === srcId)
    const t = entities.find(e => e.id === tgtId)
    if (s && t) setType(suggestRelType(s.entity_type, t.entity_type))
  }, [srcId, tgtId, entities])

  /** Filter entity list for a picker:
   *  - exclude the entity already selected in the other picker
   *  - exclude rejected entities (accepted === false)
   *  - case-insensitive match on value, entity_type or ATT&CK id ("T1059")
   *  - at most 50 results; the list scrolls.  It used to stop at 8, so
   *    "ttp" listed 8 of a report's techniques and the rest could only be
   *    reached by typing their exact name. */
  const filterEntities = (q: string, excludeId: string) => {
    const qq = q.toLowerCase()
    return entities
      .filter(e =>
        e.id !== excludeId &&
        e.accepted !== false &&          // hide rejected — they're irrelevant as link endpoints
        (qq === '' ||
         e.value.toLowerCase().includes(qq) ||
         e.entity_type.includes(qq) ||
         (e.mitre_id ?? '').toLowerCase().includes(qq))
      )
      .slice(0, 50)
  }

  const src     = entities.find(e => e.id === srcId)
  const tgt     = entities.find(e => e.id === tgtId)
  const canCreate = !!src && !!tgt && !!type && srcId !== tgtId

  const submit = () => {
    if (!canCreate || !src || !tgt) return
    onCreate({ src: src.value, tgt: tgt.value, type, evidence: initial.evidenceText ?? '' })
  }

  // Placement used to assume a 440 × 420 card: on a 390 px window it ran
  // 70 px off the right edge, and a card grown taller (evidence, the inline
  // "add entity" form) ran off the bottom.  Measure it instead.
  const popRef = useRef<HTMLDivElement>(null)
  const [natural, setNatural] = useState(0)
  const [viewport, setViewport] = useState({ w: window.innerWidth, h: window.innerHeight })

  // After every render (the chosen entities change the body), before paint.
  useLayoutEffect(() => {
    if (popRef.current) setNatural(naturalHeight(popRef.current))
  })
  // …and when the window or the card changes size without a render of this
  // component (a picker's inline "add entity" form is the picker's state).
  useEffect(() => {
    const pop = popRef.current
    if (!pop) return
    const measure = () => setNatural(naturalHeight(pop))
    const onResize = () => { setViewport({ w: window.innerWidth, h: window.innerHeight }); measure() }
    window.addEventListener('resize', onResize)
    const ro = typeof ResizeObserver === 'function' ? new ResizeObserver(measure) : null
    ro?.observe(pop)
    const body = pop.querySelector('.rc-body')
    if (body) ro?.observe(body)
    return () => { window.removeEventListener('resize', onResize); ro?.disconnect() }
  }, [])

  const width = Math.min(440, viewport.w - 2 * EDGE)
  const room  = viewport.h - 2 * EDGE
  const tall  = natural > room   // taller than the window: the body scrolls
  const height = Math.min(natural || 420, room)
  const style = {
    left: Math.max(EDGE, Math.min(viewport.w - EDGE - width, initial.x - width / 2)),
    top:  Math.max(EDGE, Math.min(viewport.h - EDGE - height, initial.y + 14)),
  }

  return createPortal(
    <>
      <div className="rc-backdrop" onClick={onCancel} />
      <div
        ref={popRef}
        className={`rc-pop ${tall ? 'rc-pop-tall' : ''}`}
        style={style}
        onClick={e => e.stopPropagation()}
      >

        <div className="rc-head">
          <span className="rc-head-title">New relationship</span>
          <button className="rc-close" onClick={onCancel}>×</button>
        </div>

        <div className="rc-body">
          <RcEntityPicker
            label="Source"
            entity={src}
            query={srcQuery}
            setQuery={setSrcQuery}
            options={filterEntities(srcQuery, tgtId)}
            onPick={id => { setSrcId(id); setSrcQuery('') }}
            onClear={() => setSrcId('')}
            onAddEntity={onAddEntity}
          />

          <div className="rc-type-row">
            {/* Verb select — shows only spec-valid verbs for this pair first */}
            {(() => {
              const { valid, others, constrained } = src && tgt
                ? verbsForPair(src.entity_type, tgt.entity_type)
                : { valid: REL_TYPES, others: [], constrained: false }
              return (
                <select
                  className="rc-type"
                  value={type}
                  onChange={e => setType(e.target.value)}
                  title={constrained
                    ? `Showing valid STIX 2.1 verbs for ${typeLabel(src!.entity_type)} → ${typeLabel(tgt!.entity_type)}`
                    : undefined
                  }
                >
                  {/* Show only spec-valid verbs for a known pair; all verbs otherwise.
                      `valid` already contains the right set in both cases (spec verbs
                      when constrained, all REL_TYPES when unconstrained), so a single
                      map suffices — the old two-branch conditional was dead code. */}
                  {valid.map(v => <option key={v} value={v}>{v}</option>)}
                </select>
              )
            })()}
            <span className="rc-arrow">↓</span>
          </div>
          {src && tgt && (() => {
            const { valid, constrained } = verbsForPair(src.entity_type, tgt.entity_type)
            return constrained && valid.length === 1 && valid[0] === 'indicates' ? (
              <div className="rc-hint">
                An IoC and a technique are linked through the IoC's Indicator: the
                bundle says “indicator indicates attack-pattern” (ADR-0065).
              </div>
            ) : null
          })()}

          <RcEntityPicker
            label="Target"
            entity={tgt}
            query={tgtQuery}
            setQuery={setTgtQuery}
            options={filterEntities(tgtQuery, srcId)}
            onPick={id => { setTgtId(id); setTgtQuery('') }}
            onClear={() => setTgtId('')}
            onAddEntity={onAddEntity}
          />

          {initial.evidenceText && (
            <div className="rc-evidence">
              <div className="rc-evidence-label">Evidence (from selection)</div>
              <div className="rc-evidence-text">&ldquo;{initial.evidenceText}&rdquo;</div>
            </div>
          )}
        </div>

        <div className="rc-actions">
          <button className="btn-ghost" onClick={onCancel}>Cancel</button>
          <button
            className={`btn-primary ${!canCreate ? 'rc-disabled' : ''}`}
            disabled={!canCreate}
            onClick={submit}
          >
            Create relationship
          </button>
        </div>
      </div>
    </>,
    document.body,
  )
}
