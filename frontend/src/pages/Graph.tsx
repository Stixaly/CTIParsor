/**
 * Graph.tsx — native d3-force STIX relationship graph.
 *
 * Data source: fetchEntities + fetchRelationships (not the bundle).
 * That source carries `accepted`, supports editing, and reflects edits
 * immediately on cache-invalidate — no "Rebuild & reload" round-trip needed.
 *
 * Relationships reference entities by VALUE (source_value / target_value),
 * not by id.  We build a value→entityId map and skip edges whose endpoints
 * don't resolve.
 */

import { useState, useMemo, useRef, useCallback, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft, Download, Eye, Link2, X, Search, RotateCcw,
  Maximize2, Tag, Network, AlignCenter, CircleDot, Check, Trash2,
  Plus, ChevronRight, ChevronLeft,
} from 'lucide-react'

import {
  fetchJob, fetchEntities, fetchRelationships,
  createRelationship, updateRelationship, deleteRelationship, fetchBundle,
  createEntity,
} from '../api/client'
import type { Entity, Relationship } from '../types'
import { typeDot, typeSoft, typeInk, typeLabel, REL_TYPES, suggestRelType, confPct, TYPE_GROUPS, verbsForPair } from '../components/review/tokens'
import GraphCanvas, { type GraphCanvasHandle } from '../components/graph/GraphCanvas'
import { type GraphNode, type GraphEdge, getTier } from '../components/graph/graphLayout'

// ── Deduped relationship-type list for <select> ───────────────────────────────
const REL_TYPES_UNIQ = [...new Set(REL_TYPES)]

// ── Mono font shorthand ───────────────────────────────────────────────────────
const MONO: React.CSSProperties = { fontFamily: "'JetBrains Mono', ui-monospace, monospace" }
const SERIF: React.CSSProperties = { fontFamily: "'Source Serif 4', Georgia, serif" }

// ─────────────────────────────────────────────────────────────────────────────
// Sub-components
// ─────────────────────────────────────────────────────────────────────────────

// ── Search ────────────────────────────────────────────────────────────────────

function GraphSearch({ nodes, onPick }: { nodes: GraphNode[]; onPick: (id: string) => void }) {
  const [q, setQ]       = useState('')
  const [open, setOpen] = useState(false)
  const results = useMemo(() => {
    if (!q.trim()) return []
    const s = q.toLowerCase()
    return nodes
      .filter(n => n.name.toLowerCase().includes(s) || typeLabel(n.type).toLowerCase().includes(s))
      .slice(0, 8)
  }, [q, nodes])

  return (
    <div style={{ position: 'relative' }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 6,
        background: 'var(--bg-soft)', border: '1px solid var(--rule)',
        borderRadius: 7, padding: '5px 8px',
      }}>
        <Search size={12} style={{ color: 'var(--ink-4)', flexShrink: 0 }} />
        <input
          value={q}
          onChange={e => { setQ(e.target.value); setOpen(true) }}
          onFocus={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 150)}
          placeholder="Search nodes…"
          style={{
            flex: 1, border: 'none', background: 'transparent',
            fontSize: 11, color: 'var(--ink)', outline: 'none',
            fontFamily: 'inherit',
          }}
        />
        {q && (
          <button onClick={() => setQ('')}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--ink-4)', padding: 0, display: 'flex' }}>
            <X size={11} />
          </button>
        )}
      </div>
      {open && results.length > 0 && (
        <div style={{
          position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 40,
          background: 'var(--bg-elev)', border: '1px solid var(--rule)',
          borderRadius: 8, marginTop: 3, boxShadow: 'var(--shadow-pop)',
          overflow: 'hidden',
        }}>
          {results.map(n => (
            <button key={n.id} onMouseDown={() => { onPick(n.id); setQ(''); setOpen(false) }}
              style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: 7,
                padding: '6px 10px', border: 'none', background: 'none',
                cursor: 'pointer', textAlign: 'left', fontSize: 12,
              }}
              onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-soft)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
            >
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: typeDot(n.type), flexShrink: 0 }} />
              <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--ink)' }}>{n.name}</span>
              <span style={{ fontSize: 10, color: 'var(--ink-4)', ...MONO }}>{typeLabel(n.type)}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Type Legend ───────────────────────────────────────────────────────────────

function TypeLegend({
  typeCounts, visibleTypes, onToggle, onSolo, onReset,
}: {
  typeCounts: Record<string, number>
  visibleTypes: Set<string>
  onToggle: (t: string) => void
  onSolo: (t: string) => void
  onReset: () => void
}) {
  const types = Object.keys(typeCounts)
    .sort((a, b) => getTier(a) - getTier(b) || typeCounts[b] - typeCounts[a])

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
        <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--ink-3)' }}>
          Types
        </span>
        {visibleTypes.size > 0 && (
          <button onClick={onReset}
            style={{ fontSize: 10, color: 'var(--accent)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
            Reset
          </button>
        )}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
        {types.map(t => {
          const on  = visibleTypes.size === 0 || visibleTypes.has(t)
          const dot = typeDot(t)
          return (
            <button
              key={t}
              onClick={() => onToggle(t)}
              onDoubleClick={() => onSolo(t)}
              title="Click to toggle · double-click to solo"
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '3px 5px', borderRadius: 5,
                border: 'none', background: 'none', cursor: 'pointer',
                opacity: on ? 1 : 0.35, textAlign: 'left', width: '100%',
                transition: 'opacity .12s',
              }}
              onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-soft)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
            >
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: dot, flexShrink: 0 }} />
              <span style={{ flex: 1, fontSize: 11, color: 'var(--ink-2)' }}>{typeLabel(t)}</span>
              <span style={{ fontSize: 10, color: 'var(--ink-4)', ...MONO }}>{typeCounts[t]}</span>
            </button>
          )
        })}
      </div>
    </div>
  )
}

// ── Confidence bar ────────────────────────────────────────────────────────────

function ConfBar({ value }: { value: number }) {
  const pct  = confPct(value)
  const tone = pct >= 85 ? 'var(--ok)' : pct >= 65 ? 'var(--warn)' : 'var(--no)'
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
      <span style={{
        display: 'inline-block', width: 44, height: 4, borderRadius: 2,
        background: 'var(--rule-soft)', overflow: 'hidden', flexShrink: 0,
      }}>
        <span style={{ display: 'block', width: `${pct}%`, height: '100%', background: tone, borderRadius: 2 }} />
      </span>
      <span style={{ fontSize: 10, color: tone, ...MONO }}>{pct}</span>
    </span>
  )
}

// ── Detail Panel ──────────────────────────────────────────────────────────────

function DetailPanel({
  node, edges, byId, onClose, onPick,
}: {
  node: GraphNode
  edges: GraphEdge[]
  byId: Map<string, GraphNode>
  onClose: () => void
  onPick: (id: string) => void
}) {
  const incident = edges.filter(e => e.source === node.id || e.target === node.id)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Header */}
      <div style={{
        padding: '14px 16px 12px', borderBottom: '1px solid var(--rule)',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 4 }}>
          <span style={{ width: 12, height: 12, borderRadius: '50%', background: typeDot(node.type), flexShrink: 0, marginTop: 2 }} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: typeInk(node.type), background: typeSoft(node.type), display: 'inline-block', padding: '1px 6px', borderRadius: 4, marginBottom: 4 }}>
              {typeLabel(node.type)}
            </div>
            <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--ink)', lineHeight: 1.3, wordBreak: 'break-word', ...SERIF }}>
              {node.name}
            </div>
          </div>
          <button onClick={onClose}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--ink-4)', display: 'flex', flexShrink: 0, padding: 2 }}>
            <X size={14} />
          </button>
        </div>
        {node.mitre_id && (
          <div style={{ fontSize: 10, color: 'var(--ink-3)', ...MONO }}>{node.mitre_id}</div>
        )}
      </div>

      {/* Scrollable body */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px' }}>
        {/* Properties */}
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--ink-3)', marginBottom: 7 }}>
            Properties
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {(([
              ['Value',      node.name],
              ['Confidence', ''],
              ['Source',     node.source],
              ...(node.context ? [['Context', node.context]] : []),
            ] as [string, string][])).map(([k, v]) => (
              <div key={k} style={{ display: 'flex', gap: 8, fontSize: 11 }}>
                <dt style={{ color: 'var(--ink-4)', flexShrink: 0, width: 72, paddingTop: 1 }}>{k}</dt>
                <dd style={{ margin: 0, color: 'var(--ink)', wordBreak: 'break-word', flex: 1 }}>
                  {k === 'Confidence' ? <ConfBar value={node.confidence} /> : v}
                </dd>
              </div>
            ))}
          </div>
        </div>

        {/* Relationships */}
        <div>
          <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--ink-3)', marginBottom: 7 }}>
            Relationships · {incident.length}
          </div>
          {incident.length === 0 && (
            <p style={{ fontSize: 11, color: 'var(--ink-4)', margin: 0 }}>No relationships</p>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {incident.map(e => {
              const out   = e.source === node.id
              const other = byId.get(out ? e.target : e.source)
              if (!other) return null
              return (
                <button key={e.id} onClick={() => onPick(other.id)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    padding: '5px 7px', borderRadius: 6, border: 'none',
                    background: 'var(--bg-soft)', cursor: 'pointer', textAlign: 'left',
                    fontSize: 11,
                  }}
                  onMouseEnter={ev => (ev.currentTarget.style.background = 'var(--bg)')}
                  onMouseLeave={ev => (ev.currentTarget.style.background = 'var(--bg-soft)')}
                >
                  <span style={{ color: out ? 'var(--accent)' : 'var(--ink-3)', flexShrink: 0, fontSize: 13 }}>
                    {out ? '→' : '←'}
                  </span>
                  <span style={{ color: 'var(--ink-3)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', ...MONO, fontSize: 10 }}>
                    {e.rel}
                  </span>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: typeDot(other.type), flexShrink: 0 }} />
                  <span style={{ color: 'var(--ink)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 100 }}>
                    {other.name}
                  </span>
                  {e.accepted === null && (
                    <span style={{ fontSize: 9, color: 'var(--warn)', ...MONO, flexShrink: 0 }}>pending</span>
                  )}
                </button>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Relationship Editor ───────────────────────────────────────────────────────

function RelEditor({
  jobId, nodes, edges, byId, onClose, onPick,
  onAccept, onReject, onReset, onDelete, onCreate, onAddEntity,
}: {
  jobId: string
  nodes: GraphNode[]
  edges: GraphEdge[]
  byId: Map<string, GraphNode>
  onClose: () => void
  onPick: (id: string) => void
  onAccept: (id: string) => void
  onReject: (id: string) => void
  onReset:  (id: string) => void
  onDelete: (id: string) => void
  onCreate: (srcValue: string, tgtValue: string, rel: string, evidence: string) => void
  onAddEntity: (value: string, type: string) => Promise<void>
}) {
  const [filter, setFilter] = useState('')
  const [adding, setAdding] = useState(false)

  const pending = edges.filter(e => e.accepted === null).length
  const shown   = edges.filter(e => {
    if (!filter.trim()) return true
    const s = filter.toLowerCase()
    return (byId.get(e.source)?.name ?? '').toLowerCase().includes(s)
        || (byId.get(e.target)?.name ?? '').toLowerCase().includes(s)
        || e.rel.includes(s)
  })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Header */}
      <div style={{ padding: '13px 16px 10px', borderBottom: '1px solid var(--rule)', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Link2 size={14} style={{ color: 'var(--accent)', flexShrink: 0 }} />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--ink)' }}>Edit relationships</div>
            <div style={{ fontSize: 10, color: 'var(--ink-3)', ...MONO }}>
              {edges.length} links · {pending} pending
            </div>
          </div>
          <button onClick={onClose}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--ink-4)', display: 'flex', padding: 2 }}>
            <X size={14} />
          </button>
        </div>
      </div>

      {/* Toolbar */}
      <div style={{
        padding: '8px 12px', borderBottom: '1px solid var(--rule-soft)',
        display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0,
      }}>
        <div style={{
          display: 'flex', alignItems: 'center', gap: 5, flex: 1,
          background: 'var(--bg-soft)', border: '1px solid var(--rule)',
          borderRadius: 6, padding: '4px 8px',
        }}>
          <Search size={11} style={{ color: 'var(--ink-4)' }} />
          <input value={filter} onChange={e => setFilter(e.target.value)}
            placeholder="Filter links…"
            style={{ flex: 1, border: 'none', background: 'transparent', fontSize: 11, color: 'var(--ink)', outline: 'none', fontFamily: 'inherit' }}
          />
        </div>
        <button onClick={() => setAdding(a => !a)} className="btn-primary"
          style={{ fontSize: 11, padding: '4px 9px', gap: 4, display: 'flex', alignItems: 'center' }}>
          <Plus size={11} /> New
        </button>
      </div>

      {/* Add form */}
      {adding && (
        <AddRelForm
          nodes={nodes}
          byId={byId}
          onAddEntity={onAddEntity}
          onCreate={(sv, tv, rel, ev) => { onCreate(sv, tv, rel, ev); setAdding(false) }}
          onCancel={() => setAdding(false)}
        />
      )}

      {/* List */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 10px' }}>
        {shown.length === 0 && (
          <p style={{ fontSize: 11, color: 'var(--ink-4)', textAlign: 'center', padding: '24px 0' }}>
            No relationships
          </p>
        )}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {shown.map(e => {
            const src  = byId.get(e.source)
            const tgt  = byId.get(e.target)
            if (!src || !tgt) return null
            const pend = e.accepted === null
            const rej  = e.accepted === false
            return (
              <div key={e.id} style={{
                background: pend ? 'color-mix(in oklab, var(--warn) 6%, var(--bg-elev))' : 'var(--bg-elev)',
                border: `1px solid ${pend ? 'color-mix(in oklab, var(--warn) 30%, var(--rule))' : rej ? 'color-mix(in oklab, var(--no) 30%, var(--rule))' : 'var(--rule)'}`,
                borderRadius: 8, padding: '8px 10px',
                opacity: rej ? 0.5 : 1,
              }}>
                {/* Endpoints + type */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 6, flexWrap: 'wrap' }}>
                  <button onClick={() => onPick(e.source)}
                    style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '2px 7px', borderRadius: 4, border: 'none', cursor: 'pointer', background: typeSoft(src.type), color: typeInk(src.type), fontSize: 10.5, fontWeight: 500 }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: typeDot(src.type) }} />
                    {src.name.length > 18 ? src.name.slice(0, 16) + '…' : src.name}
                  </button>
                  <span style={{ fontSize: 10, color: 'var(--ink-4)', ...MONO, flex: 1, textAlign: 'center' }}>{e.rel}</span>
                  <button onClick={() => onPick(e.target)}
                    style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '2px 7px', borderRadius: 4, border: 'none', cursor: 'pointer', background: typeSoft(tgt.type), color: typeInk(tgt.type), fontSize: 10.5, fontWeight: 500 }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: typeDot(tgt.type) }} />
                    {tgt.name.length > 18 ? tgt.name.slice(0, 16) + '…' : tgt.name}
                  </button>
                </div>
                {/* Footer: confidence + actions */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <ConfBar value={e.confidence} />
                  <div style={{ display: 'flex', gap: 3 }}>
                    {pend && (
                      <>
                        <button onClick={() => onAccept(e.id)} title="Accept"
                          style={{ width: 24, height: 24, display: 'flex', alignItems: 'center', justifyContent: 'center', borderRadius: 5, border: 'none', cursor: 'pointer', background: 'color-mix(in oklab, var(--ok) 14%, var(--bg-soft))', color: 'var(--ok)' }}>
                          <Check size={11} />
                        </button>
                        <button onClick={() => onReject(e.id)} title="Reject"
                          style={{ width: 24, height: 24, display: 'flex', alignItems: 'center', justifyContent: 'center', borderRadius: 5, border: 'none', cursor: 'pointer', background: 'color-mix(in oklab, var(--no) 12%, var(--bg-soft))', color: 'var(--no)' }}>
                          <X size={11} />
                        </button>
                      </>
                    )}
                    {rej && (
                      <button onClick={() => onReset(e.id)} title="Restore"
                        style={{ width: 24, height: 24, display: 'flex', alignItems: 'center', justifyContent: 'center', borderRadius: 5, border: 'none', cursor: 'pointer', background: 'var(--bg-soft)', color: 'var(--ink-3)' }}>
                        <RotateCcw size={11} />
                      </button>
                    )}
                    {!pend && !rej && (
                      <span style={{ fontSize: 9, color: 'var(--ok)', ...MONO, display: 'flex', alignItems: 'center', gap: 3 }}>
                        <Check size={9} /> accepted
                      </span>
                    )}
                    <button onClick={() => onDelete(e.id)} title="Delete"
                      style={{ width: 24, height: 24, display: 'flex', alignItems: 'center', justifyContent: 'center', borderRadius: 5, border: 'none', cursor: 'pointer', background: 'var(--bg-soft)', color: 'var(--no)' }}>
                      <Trash2 size={11} />
                    </button>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

// ── GraphNodePicker ───────────────────────────────────────────────────────────
// Searchable entity picker for the graph relationship editor.
// Mirrors the RcEntityPicker from RelationshipCreator (Review page) but
// operates on GraphNode[] and tracks selections by entity value + type.

function GraphNodePicker({
  label, pickedValue, pickedType, query, setQuery,
  options, onPick, onClear, onAddEntity,
}: {
  label: string
  pickedValue: string | null
  pickedType:  string | null
  query: string
  setQuery: (q: string) => void
  options: GraphNode[]
  onPick: (value: string, type: string) => void
  onClear: () => void
  onAddEntity: (value: string, type: string) => Promise<void>
}) {
  const [open,     setOpen]     = useState(false)
  const [showForm, setShowForm] = useState(false)
  const [newType,  setNewType]  = useState('malware')
  const [adding,   setAdding]   = useState(false)
  const [addError, setAddError] = useState('')

  useEffect(() => { if (!query) { setShowForm(false); setAddError('') } }, [query])

  const handleAdd = async () => {
    const val = query.trim()
    if (!val) return
    setAdding(true)
    setAddError('')
    try {
      await onAddEntity(val, newType)
      onPick(val, newType)
      setShowForm(false)
      setOpen(false)
    } catch (err) {
      setAddError(err instanceof Error ? err.message : 'Failed to create entity')
    } finally {
      setAdding(false)
    }
  }

  const inputStyle: React.CSSProperties = {
    width: '100%', fontSize: 11, padding: '5px 7px', borderRadius: 6,
    border: '1px solid var(--rule)', background: 'var(--bg-soft)',
    color: 'var(--ink)', fontFamily: 'inherit', outline: 'none', boxSizing: 'border-box',
  }

  return (
    <div style={{ position: 'relative' }}>
      <div style={{ fontSize: 10, color: 'var(--ink-4)', marginBottom: 2, fontWeight: 500 }}>
        {label}
      </div>

      {pickedValue ? (
        /* ── Selected chip ──────────────────────────────────────────────── */
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '5px 7px', background: 'var(--bg-soft)',
          border: '1px solid var(--rule)', borderRadius: 6, fontSize: 11,
        }}>
          <span style={{ width: 7, height: 7, borderRadius: '50%',
                         background: typeDot(pickedType ?? ''), flexShrink: 0 }} />
          <span style={{ color: 'var(--ink-3)', fontSize: 9.5, flexShrink: 0 }}>
            {typeLabel(pickedType ?? '')}
          </span>
          <span style={{ flex: 1, color: 'var(--ink)', overflow: 'hidden',
                         textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {pickedValue}
          </span>
          <button onClick={onClear}
            style={{ background: 'none', border: 'none', cursor: 'pointer',
                     color: 'var(--ink-4)', padding: 0, fontSize: 14, lineHeight: 1 }}>
            ×
          </button>
        </div>
      ) : (
        /* ── Search input + dropdown ──────────────────────────────────────── */
        <>
          <input
            value={query}
            style={inputStyle}
            placeholder="Search entities…"
            onChange={e => { setQuery(e.target.value); setOpen(true); setShowForm(false) }}
            onFocus={() => setOpen(true)}
            onBlur={() => setTimeout(() => setOpen(false), 160)}
          />

          {/* Results list */}
          {open && options.length > 0 && (
            <div style={{
              position: 'absolute', top: 'calc(100% + 3px)', left: 0, right: 0, zIndex: 40,
              background: 'var(--bg-elev)', border: '1px solid var(--rule)',
              borderRadius: 6, boxShadow: 'var(--shadow-pop)', maxHeight: 180, overflowY: 'auto',
            }}>
              {options.map(n => (
                <button key={n.id}
                  onMouseDown={() => { onPick(n.name, n.type); setOpen(false) }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 6, width: '100%',
                    padding: '5px 9px', border: 'none', background: 'transparent',
                    cursor: 'pointer', textAlign: 'left', fontSize: 11, color: 'var(--ink)',
                  }}
                  onMouseEnter={ev => (ev.currentTarget.style.background = 'var(--accent-soft)')}
                  onMouseLeave={ev => (ev.currentTarget.style.background = 'transparent')}
                >
                  <span style={{ width: 7, height: 7, borderRadius: '50%',
                                 background: typeDot(n.type), flexShrink: 0 }} />
                  <span style={{ color: 'var(--ink-3)', fontSize: 9.5, flexShrink: 0, marginRight: 2 }}>
                    {typeLabel(n.type)}
                  </span>
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {n.name}
                  </span>
                </button>
              ))}
            </div>
          )}

          {/* No-matches → "Add new entity" */}
          {open && options.length === 0 && query.trim() && (
            <div style={{
              position: 'absolute', top: 'calc(100% + 3px)', left: 0, right: 0, zIndex: 40,
              background: 'var(--bg-elev)', border: '1px solid var(--rule)',
              borderRadius: 6, boxShadow: 'var(--shadow-pop)',
            }}>
              <button
                onMouseDown={() => { setShowForm(true); setOpen(false) }}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6, width: '100%',
                  padding: '6px 9px', border: 'none', background: 'transparent',
                  cursor: 'pointer', textAlign: 'left', fontSize: 11,
                  color: 'var(--accent)', fontStyle: 'italic',
                }}
              >
                <span style={{ fontStyle: 'normal', fontSize: 13 }}>＋</span>
                Add &ldquo;{query.trim()}&rdquo; as new entity
              </button>
            </div>
          )}

          {/* Inline mini-form for type selection */}
          {showForm && (
            <div style={{
              marginTop: 4, padding: '7px 9px',
              background: 'color-mix(in oklab, var(--accent) 5%, var(--bg-soft))',
              border: '1px solid color-mix(in oklab, var(--accent) 25%, var(--rule))',
              borderRadius: 6,
            }}>
              <div style={{ fontSize: 10, color: 'var(--ink-3)', marginBottom: 5 }}>
                Type for &ldquo;{query.trim()}&rdquo;
              </div>
              <div style={{ display: 'flex', gap: 5, alignItems: 'center' }}>
                <select value={newType} onChange={e => setNewType(e.target.value)}
                  style={{ ...inputStyle, flex: 1 }}>
                  {TYPE_GROUPS.map(grp => (
                    <optgroup key={grp.label} label={grp.label}>
                      {grp.types.map(t => (
                        <option key={t} value={t}>{typeLabel(t)}</option>
                      ))}
                    </optgroup>
                  ))}
                </select>
                <button className="btn-primary" onClick={handleAdd} disabled={adding}
                  style={{ fontSize: 10, padding: '4px 9px', flexShrink: 0 }}>
                  {adding ? '…' : 'Add'}
                </button>
                <button className="btn-ghost" onClick={() => { setShowForm(false); setAddError('') }}
                  style={{ fontSize: 10, padding: '4px 7px', flexShrink: 0 }}>
                  ✕
                </button>
              </div>
              {addError && (
                <div style={{ fontSize: 10, color: 'var(--no)', marginTop: 4 }}>{addError}</div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}


// ── AddRelForm ────────────────────────────────────────────────────────────────
// Now uses GraphNodePicker (searchable + "Add new entity" inline) instead of
// plain <select> dropdowns.  Tracks source/target by entity VALUE string
// (matching the API's source_value/target_value fields) and by type (for
// automatic relationship type suggestion).

function AddRelForm({
  nodes, byId, onCreate, onCancel, onAddEntity,
}: {
  nodes: GraphNode[]
  byId: Map<string, GraphNode>
  onCreate: (srcValue: string, tgtValue: string, rel: string, evidence: string) => void
  onCancel: () => void
  onAddEntity: (value: string, type: string) => Promise<void>
}) {
  const sorted = useMemo(
    () => [...nodes].sort((a, b) => getTier(a.type) - getTier(b.type)),
    [nodes],
  )

  const [srcValue, setSrcValue] = useState<string | null>(null)
  const [srcType,  setSrcType]  = useState<string | null>(null)
  const [tgtValue, setTgtValue] = useState<string | null>(null)
  const [tgtType,  setTgtType]  = useState<string | null>(null)
  const [srcQuery, setSrcQuery] = useState('')
  const [tgtQuery, setTgtQuery] = useState('')
  const [rel,      setRel]      = useState('related-to')
  const [evidence, setEvidence] = useState('')

  // Auto-suggest relationship type whenever both endpoints are known
  useEffect(() => {
    if (srcType && tgtType) setRel(suggestRelType(srcType, tgtType))
  }, [srcType, tgtType])

  const filterNodes = (q: string, excludeValue: string | null) => {
    const qq = q.toLowerCase()
    return sorted.filter(n =>
      n.name !== excludeValue &&
      (qq === '' || n.name.toLowerCase().includes(qq) || n.type.includes(qq))
    ).slice(0, 8)
  }

  const canAdd = srcValue && tgtValue && rel && srcValue !== tgtValue

  const add = () => {
    if (!canAdd || !srcValue || !tgtValue) return
    onCreate(srcValue, tgtValue, rel, evidence)
  }

  const selStyle: React.CSSProperties = {
    width: '100%', fontSize: 11, padding: '5px 7px', borderRadius: 6,
    border: '1px solid var(--rule)', background: 'var(--bg-soft)',
    color: 'var(--ink)', fontFamily: 'inherit',
  }

  return (
    <div style={{
      padding: '10px 12px', borderBottom: '1px solid var(--rule-soft)',
      background: 'color-mix(in oklab, var(--accent) 5%, var(--bg-elev))',
    }}>
      <div style={{
        fontSize: 10, fontWeight: 600, color: 'var(--ink-3)',
        letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 8,
      }}>
        New relationship
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        <GraphNodePicker
          label="Source"
          pickedValue={srcValue}
          pickedType={srcType}
          query={srcQuery}
          setQuery={setSrcQuery}
          options={filterNodes(srcQuery, tgtValue)}
          onPick={(v, t) => { setSrcValue(v); setSrcType(t); setSrcQuery('') }}
          onClear={() => { setSrcValue(null); setSrcType(null) }}
          onAddEntity={onAddEntity}
        />
        {/* Verb select — filtered to spec-valid verbs when both types are known */}
        {(() => {
          const { valid, others, constrained } = srcType && tgtType
            ? verbsForPair(srcType, tgtType)
            : { valid: REL_TYPES, others: [], constrained: false }
          return (
            <select value={rel} onChange={e => setRel(e.target.value)} style={{
              ...selStyle,
              color: constrained && !valid.includes(rel) ? 'var(--warn)' : selStyle.color,
            }}>
              {/* Show only spec-valid verbs for a known pair; all verbs otherwise */}
              {valid.map(r => <option key={r} value={r}>{r}</option>)}
            </select>
          )
        })()}
        <GraphNodePicker
          label="Target"
          pickedValue={tgtValue}
          pickedType={tgtType}
          query={tgtQuery}
          setQuery={setTgtQuery}
          options={filterNodes(tgtQuery, srcValue)}
          onPick={(v, t) => { setTgtValue(v); setTgtType(t); setTgtQuery('') }}
          onClear={() => { setTgtValue(null); setTgtType(null) }}
          onAddEntity={onAddEntity}
        />
        <input
          value={evidence} onChange={e => setEvidence(e.target.value)}
          placeholder="Evidence text (optional)"
          style={selStyle}
        />
      </div>
      <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
        <button onClick={onCancel} className="btn-ghost"
          style={{ flex: 1, fontSize: 11, padding: '5px 0', justifyContent: 'center' }}>
          Cancel
        </button>
        <button onClick={add} disabled={!canAdd} className="btn-primary"
          style={{ flex: 1, fontSize: 11, padding: '5px 0', justifyContent: 'center' }}>
          Add link
        </button>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Graph page
// ─────────────────────────────────────────────────────────────────────────────

type LayoutMode = 'force' | 'hierarchical' | 'radial'

export default function Graph() {
  const { jobId }  = useParams<{ jobId: string }>()
  const navigate   = useNavigate()
  const qc         = useQueryClient()
  const canvasRef  = useRef<GraphCanvasHandle>(null)

  // ── Data fetching ──────────────────────────────────────────────────────────

  const { data: job }           = useQuery({ queryKey: ['job', jobId],           queryFn: () => fetchJob(jobId!),           enabled: !!jobId })
  const { data: rawEntities  = [], isLoading: entLoading  } = useQuery({ queryKey: ['entities',      jobId], queryFn: () => fetchEntities(jobId!),      enabled: !!jobId })
  const { data: rawRelations = [], isLoading: relLoading  } = useQuery({ queryKey: ['relationships', jobId], queryFn: () => fetchRelationships(jobId!),  enabled: !!jobId })

  // ── Derive graph data ──────────────────────────────────────────────────────
  // Relationships reference entities by VALUE (source_value / target_value).
  // We build a value→entityId map; edges whose endpoints don't resolve are
  // skipped in v1 (the README recommends this for simplicity).

  const { nodes, edges, byId, deg, adj, typeCounts, unmatchedCount } = useMemo(() => {
    // Show only non-rejected entities
    const visible = rawEntities.filter((e: Entity) => e.accepted !== false)

    // value (lowercase) → entity id
    const valueToId = new Map<string, string>()
    visible.forEach((e: Entity) => valueToId.set(e.value.toLowerCase(), e.id))

    const nodes: GraphNode[] = visible.map((e: Entity) => ({
      id: e.id, type: e.entity_type, name: e.value,
      confidence: e.confidence, source: e.source,
      mitre_id: e.mitre_id, context: e.context ?? '',
      accepted: e.accepted,
    }))
    const byId = new Map(nodes.map(n => [n.id, n]))

    // Degree map
    const deg: Record<string, number> = {}
    nodes.forEach(n => { deg[n.id] = 0 })

    // Resolve edges
    let unmatchedCount = 0
    const edges: GraphEdge[] = []
    rawRelations.forEach((r: Relationship) => {
      const srcId = valueToId.get(r.source_value.toLowerCase())
      const tgtId = valueToId.get(r.target_value.toLowerCase())
      if (!srcId || !tgtId) { unmatchedCount++; return }
      edges.push({
        id: r.id, source: srcId, target: tgtId,
        rel: r.relationship_type,
        confidence: r.confidence,
        accepted: r.accepted,
        evidence: r.evidence_text ?? '',
      })
      deg[srcId] = (deg[srcId] || 0) + 1
      deg[tgtId] = (deg[tgtId] || 0) + 1
    })

    // Adjacency
    const adj: Record<string, Set<string>> = {}
    nodes.forEach(n => { adj[n.id] = new Set() })
    edges.forEach(e => { adj[e.source]?.add(e.target); adj[e.target]?.add(e.source) })

    // Type counts
    const typeCounts: Record<string, number> = {}
    nodes.forEach(n => { typeCounts[n.type] = (typeCounts[n.type] || 0) + 1 })

    return { nodes, edges, byId, deg, adj, typeCounts, unmatchedCount }
  }, [rawEntities, rawRelations])

  // ── UI state ───────────────────────────────────────────────────────────────

  const [selectedId,   setSelectedId]   = useState<string | null>(null)
  const [hoverId,      setHoverId]       = useState<string | null>(null)
  const [layout,       setLayout]        = useState<LayoutMode>('force')
  const [visibleTypes, setVisibleTypes]  = useState<Set<string>>(new Set())  // empty = show all
  const [editMode,     setEditMode]      = useState(false)
  const [showLabels,   setShowLabels]    = useState(false)
  const [focusSignal,  setFocusSignal]   = useState<{ id: string; seq: number } | null>(null)
  const focusSeq = useRef(0)

  // Right panel: detail shows on select; editor shows in editMode
  const rightPanel = editMode ? 'editor' : selectedId ? 'detail' : null
  const selectedNode = selectedId ? byId.get(selectedId) ?? null : null

  // ── Legend toggle helpers ──────────────────────────────────────────────────

  const toggleType = useCallback((t: string) => {
    setVisibleTypes(prev => {
      // If currently "show all" (empty set), start from all types
      const base = prev.size === 0 ? new Set(Object.keys(typeCounts)) : new Set(prev)
      if (base.has(t)) base.delete(t); else base.add(t)
      // If all types visible again, collapse back to empty-set convention
      return base.size === Object.keys(typeCounts).length ? new Set() : base
    })
  }, [typeCounts])

  const soloType = useCallback((t: string) => {
    setVisibleTypes(new Set([t]))
  }, [])

  const resetTypes = useCallback(() => setVisibleTypes(new Set()), [])

  // ── Focus a searched node ──────────────────────────────────────────────────

  const focusNode = useCallback((id: string) => {
    setSelectedId(id)
    focusSeq.current++
    setFocusSignal({ id, seq: focusSeq.current })
  }, [])

  // ── Relationship mutations ─────────────────────────────────────────────────

  const invalidateRels = () => qc.invalidateQueries({ queryKey: ['relationships', jobId] })

  const updateRelMut = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: object }) =>
      updateRelationship(jobId!, id, patch),
    onSuccess: invalidateRels,
  })
  const deleteRelMut = useMutation({
    mutationFn: (id: string) => deleteRelationship(jobId!, id),
    onSuccess: invalidateRels,
  })
  const createRelMut = useMutation({
    mutationFn: (body: Parameters<typeof createRelationship>[1]) =>
      createRelationship(jobId!, body),
    onSuccess: invalidateRels,
  })

  // ── Download STIX bundle ───────────────────────────────────────────────────

  const handleDownload = async () => {
    try {
      const bundle = await fetchBundle(jobId!)
      const blob   = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' })
      const url    = URL.createObjectURL(blob)
      const a      = document.createElement('a')
      a.href     = url
      a.download = `${(job?.original_filename ?? 'bundle').replace(/\.[^.]+$/, '')}_stix.json`
      document.body.appendChild(a); a.click()
      document.body.removeChild(a)
      // Defer revocation — revoking synchronously after click() breaks Firefox.
      setTimeout(() => URL.revokeObjectURL(url), 100)
    } catch { alert('Bundle not yet available') }
  }

  // ── Clear stale selectedId when its node is removed from the graph ────────
  // If the user accepts/rejects entities in the Review page and then opens the
  // Graph, previously-selected nodes may no longer exist in `byId`.  Without
  // this guard the right panel renders empty (selectedNode = null) with no
  // way to dismiss it because the close button lives inside DetailPanel.

  useEffect(() => {
    if (selectedId && !byId.has(selectedId)) setSelectedId(null)
  }, [byId, selectedId])

  // ── Loading state ──────────────────────────────────────────────────────────

  const isLoading = entLoading || relLoading

  // ─────────────────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────────────────

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg)' }}>

      {/* ── Top chrome ────────────────────────────────────────────────── */}
      <div className="top-chrome">
        <button onClick={() => navigate('/dashboard')} className="back" title="Back">
          <ArrowLeft size={15} />
        </button>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--ink)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {job?.original_filename ?? `Job ${jobId}`}
          </div>
          <div style={{ fontSize: 11, color: 'var(--ink-4)' }}>STIX 2.1 relationship graph</div>
        </div>
        <button onClick={() => navigate(`/review/${jobId}`)} className="btn-ghost">
          <Eye size={13} /> Review
        </button>
        <button
          onClick={() => { setEditMode(v => !v); if (selectedId) setSelectedId(null) }}
          className={editMode ? 'btn-primary' : 'btn-ghost'}
        >
          <Link2 size={13} /> Edit links
        </button>
        <button onClick={handleDownload} className="btn-ghost">
          <Download size={13} /> Download STIX
        </button>
      </div>

      {/* ── Main area ─────────────────────────────────────────────────── */}
      {/* position: relative is required so the absolutely-positioned
          "collapsed detail tab" button is contained within this area
          rather than being positioned relative to the viewport. */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden', position: 'relative' }}>

        {/* ── Left legend rail ─────────────────────────────────────────── */}
        <div style={{
          width: 200, flexShrink: 0,
          borderRight: '1px solid var(--rule)',
          background: 'var(--bg)',
          display: 'flex', flexDirection: 'column',
          padding: '14px 12px',
          gap: 14, overflowY: 'auto',
        }}>
          <GraphSearch nodes={nodes} onPick={focusNode} />

          {/* Stats */}
          <div style={{ display: 'flex', gap: 6 }}>
            {[
              { n: nodes.length,  label: 'nodes' },
              { n: edges.length,  label: 'edges' },
            ].map(({ n, label }) => (
              <div key={label} style={{
                flex: 1, background: 'var(--bg-soft)', borderRadius: 7,
                padding: '6px 8px', textAlign: 'center',
              }}>
                <div style={{ fontSize: 18, fontWeight: 600, color: 'var(--ink)', ...SERIF }}>{n}</div>
                <div style={{ fontSize: 10, color: 'var(--ink-3)' }}>{label}</div>
              </div>
            ))}
          </div>

          {unmatchedCount > 0 && (
            <div style={{ fontSize: 10, color: 'var(--warn)', background: 'color-mix(in oklab, var(--warn) 8%, transparent)', borderRadius: 5, padding: '4px 7px' }}>
              {unmatchedCount} link{unmatchedCount > 1 ? 's' : ''} reference unknown entities
            </div>
          )}

          <TypeLegend
            typeCounts={typeCounts}
            visibleTypes={visibleTypes}
            onToggle={toggleType}
            onSolo={soloType}
            onReset={resetTypes}
          />
        </div>

        {/* ── Canvas area (flex-1) ──────────────────────────────────────── */}
        <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
          {isLoading ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--ink-4)', gap: 8 }}>
              <svg width={18} height={18} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
                style={{ animation: 'spin 1s linear infinite' }}>
                <path d="M21 12a9 9 0 11-6.2-8.6" />
              </svg>
              Loading graph…
            </div>
          ) : nodes.length === 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--ink-4)', gap: 8 }}>
              <Network size={40} style={{ opacity: 0.3 }} />
              <p style={{ margin: 0, fontSize: 13 }}>No entities to display</p>
              <p style={{ margin: 0, fontSize: 11 }}>Accept some entities in the Review page first.</p>
            </div>
          ) : (
            <GraphCanvas
              ref={canvasRef}
              nodes={nodes}
              edges={edges}
              byId={byId}
              deg={deg}
              adj={adj}
              layout={layout}
              visibleTypes={visibleTypes}
              selectedId={selectedId}
              hoverId={hoverId}
              showLabels={showLabels}
              onSelect={id => {
                setSelectedId(id)
                if (id && editMode) setEditMode(false)
              }}
              onHover={setHoverId}
              focusSignal={focusSignal}
            />
          )}

          {/* ── Floating layout toolbar ─────────────────────────────────── */}
          {!isLoading && nodes.length > 0 && (
            <div style={{
              position: 'absolute', bottom: 20, left: '50%', transform: 'translateX(-50%)',
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'var(--bg-elev)', border: '1px solid var(--rule)',
              borderRadius: 10, padding: '5px 8px',
              boxShadow: 'var(--shadow-card)',
            }}>
              {/* Layout mode segmented */}
              <div style={{ display: 'flex', borderRadius: 7, overflow: 'hidden', border: '1px solid var(--rule)' }}>
                {([
                  { id: 'force',        icon: <Network size={12} />,      label: 'Force'     },
                  { id: 'hierarchical', icon: <AlignCenter size={12} />,  label: 'Hierarchy' },
                  { id: 'radial',       icon: <CircleDot size={12} />,    label: 'Radial'    },
                ] as const).map(opt => (
                  <button key={opt.id} onClick={() => setLayout(opt.id)}
                    title={opt.label}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 4,
                      padding: '4px 9px', fontSize: 11, border: 'none',
                      cursor: 'pointer', transition: 'background .12s',
                      background: layout === opt.id ? 'var(--accent)' : 'transparent',
                      color:      layout === opt.id ? 'white'         : 'var(--ink-3)',
                    }}>
                    {opt.icon}
                    <span style={{ display: 'none' }}>{opt.label}</span>
                  </button>
                ))}
              </div>

              {/* Fit to screen */}
              <button onClick={() => canvasRef.current?.fit()}
                title="Fit to screen"
                style={{ display: 'flex', alignItems: 'center', padding: '4px 7px', borderRadius: 6, border: '1px solid var(--rule)', background: 'var(--bg-soft)', cursor: 'pointer', color: 'var(--ink-3)' }}>
                <Maximize2 size={12} />
              </button>

              {/* Labels toggle */}
              <button onClick={() => setShowLabels(v => !v)}
                title={showLabels ? 'Hide all labels' : 'Show all labels'}
                style={{
                  display: 'flex', alignItems: 'center', gap: 4, padding: '4px 9px',
                  borderRadius: 6, border: '1px solid var(--rule)',
                  background: showLabels ? 'var(--accent-soft)' : 'var(--bg-soft)',
                  color:      showLabels ? 'var(--accent)'      : 'var(--ink-3)',
                  cursor: 'pointer', fontSize: 11,
                }}>
                <Tag size={12} /> Labels
              </button>
            </div>
          )}
        </div>

        {/* ── Right panel ──────────────────────────────────────────────── */}
        {rightPanel && (
          <div style={{
            width: 300, flexShrink: 0,
            borderLeft: '1px solid var(--rule)',
            background: 'var(--bg-elev)',
            display: 'flex', flexDirection: 'column',
            overflow: 'hidden',
          }}>
            {rightPanel === 'detail' && selectedNode && (
              <DetailPanel
                node={selectedNode}
                edges={edges}
                byId={byId}
                onClose={() => setSelectedId(null)}
                onPick={focusNode}
              />
            )}
            {rightPanel === 'editor' && (
              <RelEditor
                jobId={jobId!}
                nodes={nodes}
                edges={edges}
                byId={byId}
                onClose={() => setEditMode(false)}
                onPick={focusNode}
                onAccept={id => updateRelMut.mutate({ id, patch: { accepted: true } })}
                onReject={id => updateRelMut.mutate({ id, patch: { accepted: false } })}
                onReset={id  => updateRelMut.mutate({ id, patch: { accepted: null } })}
                onDelete={id => deleteRelMut.mutate(id)}
                onCreate={(srcValue, tgtValue, rel, evidence) =>
                  createRelMut.mutate({
                    source_value: srcValue,
                    relationship_type: rel,
                    target_value: tgtValue,
                    confidence: 1.0,
                    evidence_text: evidence || null,
                  })
                }
                onAddEntity={async (value, entity_type) => {
                  // Pass source: 'manual' so MarginaliaCard and the Review page
                  // display the correct source badge instead of a blank/undefined.
                  await createEntity(jobId!, { value, entity_type, confidence: 1.0, source: 'manual', context: '' })
                  // Invalidate both entity + relationship queries so the graph
                  // redraws with the new node
                  qc.invalidateQueries({ queryKey: ['entities',      jobId] })
                  qc.invalidateQueries({ queryKey: ['relationships', jobId] })
                }}
              />
            )}
          </div>
        )}

        {/* Collapsed detail tab (shows when node selected but right panel is editor) */}
        {editMode && selectedId && (
          <button
            onClick={() => { setEditMode(false) }}
            title="Show node detail"
            style={{
              position: 'absolute', right: 301, top: '50%', transform: 'translateY(-50%)',
              background: 'var(--bg-elev)', border: '1px solid var(--rule)',
              borderRight: 'none', borderRadius: '6px 0 0 6px',
              padding: '8px 5px', cursor: 'pointer', color: 'var(--ink-3)',
              display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3,
            }}>
            <ChevronLeft size={12} />
          </button>
        )}
      </div>
    </div>
  )
}
