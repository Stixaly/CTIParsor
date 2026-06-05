import { useState, useEffect } from 'react'
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
   *  - case-insensitive match on value or entity_type
   *  - limit to 8 results */
  const filterEntities = (q: string, excludeId: string) => {
    const qq = q.toLowerCase()
    return entities
      .filter(e =>
        e.id !== excludeId &&
        e.accepted !== false &&          // hide rejected — they're irrelevant as link endpoints
        (qq === '' ||
         e.value.toLowerCase().includes(qq) ||
         e.entity_type.includes(qq))
      )
      .slice(0, 8)
  }

  const src     = entities.find(e => e.id === srcId)
  const tgt     = entities.find(e => e.id === tgtId)
  const canCreate = !!src && !!tgt && !!type && srcId !== tgtId

  const submit = () => {
    if (!canCreate || !src || !tgt) return
    onCreate({ src: src.value, tgt: tgt.value, type, evidence: initial.evidenceText ?? '' })
  }

  const style = {
    left: Math.max(20, Math.min(window.innerWidth  - 460, initial.x - 220)),
    top:  Math.max(20, Math.min(window.innerHeight - 420, initial.y + 14)),
  }

  return createPortal(
    <>
      <div className="rc-backdrop" onClick={onCancel} />
      <div className="rc-pop" style={style} onClick={e => e.stopPropagation()}>

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
