import { useState, useMemo, useEffect } from 'react'
import { enrichmentView, type Entity } from '../../types'
import { ENRICH_FILTERS, heldPending, typeDot, typeLabel, type EnrichFilter } from './tokens'
import MarginaliaCard from './MarginaliaCard'
import { toggleInSet } from '../../hooks/sets'

type SortMode = 'position' | 'type'

interface Props {
  entities: Entity[]
  focusedId: string | null
  setFocusedId: (id: string) => void
  /** `bulk` = decided with others in one click (group or selection). */
  onAccept: (id: string, bulk?: boolean) => void
  onReject: (id: string, bulk?: boolean) => void
  onReset: (id: string) => void
  onChangeType: (id: string, t: string) => void
  sortMode: SortMode
  setSortMode: (m: SortMode) => void
  /** Closes the panel when a narrow window shows it as a drawer; the button
   *  is only displayed there (index.css, RESPONSIVE). */
  onClose?: () => void
}

export default function Marginalia({
  entities, focusedId, setFocusedId,
  onAccept, onReject, onReset, onChangeType,
  sortMode, setSortMode, onClose,
}: Props) {
  // ── STIX bundle filter (ADR-0090) ──────────────────────────────────────
  // It filters what the column lists; the groups, the sort and the selection
  // all work on what it leaves.  Shown only when some row has a bundle status.
  const [enrichFilter, setEnrichFilter] = useState<EnrichFilter>('all')
  const hasEnrich = entities.some(e => e.enrichment_status != null)
  const enrichCounts: Record<EnrichFilter, number> = {
    all:       entities.length,
    new:       entities.filter(e => enrichmentView(e.enrichment_status) === 'new').length,
    in_stix:   entities.filter(e => enrichmentView(e.enrichment_status) === 'in_stix').length,
    stix_only: entities.filter(e => enrichmentView(e.enrichment_status) === 'stix_only').length,
  }
  const shown = useMemo(
    () => enrichFilter === 'all'
      ? entities
      : entities.filter(e => enrichmentView(e.enrichment_status) === enrichFilter),
    [entities, enrichFilter],
  )

  // ── card collapse state ────────────────────────────────────────────────
  const [collapsed,    setCollapsed]    = useState<Set<string>>(new Set())
  const [allCollapsed, setAllCollapsed] = useState(false)

  const toggleCard = (id: string) => {
    setCollapsed(prev => toggleInSet(prev, id))
  }
  const toggleAll = () => {
    if (allCollapsed) {
      setCollapsed(new Set()); setAllCollapsed(false)
    } else {
      setCollapsed(new Set(shown.map(e => e.id))); setAllCollapsed(true)
    }
  }

  // ── group visibility ───────────────────────────────────────────────────
  const [hiddenGroups, setHiddenGroups] = useState<Set<string>>(new Set())

  const toggleGroupVisibility = (type: string) =>
    setHiddenGroups(prev => toggleInSet(prev, type))

  // ── per-group quick bulk ───────────────────────────────────────────────
  const acceptGroup = (grpEntities: Entity[]) =>
    grpEntities.filter(e => e.accepted !== true).forEach(e => onAccept(e.id, true))
  const rejectGroup = (grpEntities: Entity[]) =>
    grpEntities.filter(e => e.accepted !== false).forEach(e => onReject(e.id, true))

  // ── checkbox selection ─────────────────────────────────────────────────
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => toggleInSet(prev, id))
  }

  const clearSelection = () => setSelectedIds(new Set())

  // Visible entities (flat list for "select all visible")
  const visibleIds = useMemo(
    () => new Set(shown.map(e => e.id)),
    [shown],
  )

  const allVisibleSelected =
    visibleIds.size > 0 &&
    [...visibleIds].every(id => selectedIds.has(id))

  const toggleSelectAll = () => {
    if (allVisibleSelected) {
      clearSelection()
    } else {
      setSelectedIds(new Set(visibleIds))
    }
  }

  // A held row (ADR-0082) is accepted on its own card only.
  const bulkAcceptSelected = () => {
    const held = new Set(entities.filter(heldPending).map(e => e.id))
    selectedIds.forEach(id => { if (!held.has(id)) onAccept(id, true) })
    clearSelection()
  }

  const bulkRejectSelected = () => {
    selectedIds.forEach(id => onReject(id, true))
    clearSelection()
  }

  // Clear selection when the entity list changes (e.g. after a filter change)
  useEffect(() => {
    setSelectedIds(prev => {
      const valid = new Set([...prev].filter(id => visibleIds.has(id)))
      return valid.size === prev.size ? prev : valid
    })
  }, [visibleIds])

  // ── sort / group ───────────────────────────────────────────────────────
  const [positionOrder, setPositionOrder] = useState<string[]>([])

  useEffect(() => {
    if (sortMode !== 'position') return
    // The document is inside `.stage-wrapper` which is the actual scroll
    // container — not the window.  Using window.scrollY was wrong and caused
    // incorrect sort order whenever the review panel had been scrolled.
    const wrapper = document.querySelector<HTMLElement>('.stage-wrapper')
    const wrapperScrollTop = wrapper?.scrollTop ?? 0
    const order = shown
      .map(e => {
        const node = document.querySelector<HTMLElement>(`mark[data-eid="${e.id}"]`)
        const y = node
          ? node.getBoundingClientRect().top + wrapperScrollTop
          : Infinity
        return { id: e.id, y }
      })
      .sort((a, b) => a.y - b.y)
      .map(x => x.id)
    setPositionOrder(order)
  }, [shown, sortMode])

  const typeOrder = useMemo(() => {
    const cnts: Record<string, number> = {}
    shown.forEach(e => { cnts[e.entity_type] = (cnts[e.entity_type] || 0) + 1 })
    return Object.keys(cnts).sort((a, b) => cnts[b] - cnts[a])
  }, [shown])

  const grouped = useMemo(() => {
    if (sortMode === 'position') {
      const order = positionOrder.length > 0 ? positionOrder : shown.map(e => e.id)
      const byId = new Map(shown.map(e => [e.id, e]))
      const sorted = order.map(id => byId.get(id)).filter((e): e is Entity => Boolean(e))
      return [{ type: '_all', entities: sorted }]
    }
    return typeOrder.map(t => ({
      type: t,
      entities: shown.filter(e => e.entity_type === t).sort((a, b) => b.confidence - a.confidence),
    }))
  }, [shown, sortMode, typeOrder, positionOrder])

  const selCount = selectedIds.size

  return (
    <aside className={`marginalia mode-${sortMode}`}>

      {/* ── Header ────────────────────────────────────────────────────── */}
      <div className="marg-header">
        <div className="marg-header-left">
          {/* Select-all checkbox */}
          <button
            className={`marg-check marg-check-header ${allVisibleSelected ? 'marg-check-on' : ''}`}
            onClick={toggleSelectAll}
            title={allVisibleSelected ? 'Deselect all' : 'Select all'}
            role="checkbox"
            aria-checked={allVisibleSelected}
          >
            {allVisibleSelected ? '✓' : selCount > 0 ? '—' : ''}
          </button>
          <span className="marg-header-title">
            Margin notes <em>({entities.length})</em>
          </span>
          <button className="marg-header-btn" onClick={toggleAll}>
            {allCollapsed ? 'Expand all' : 'Collapse all'}
          </button>
        </div>
        <div className="marg-sort">
          {(['position', 'type'] as const).map(v => (
            <button
              key={v}
              className={`marg-sort-btn ${sortMode === v ? 'on' : ''}`}
              onClick={() => setSortMode(v)}
              title={`Sort by ${v}`}
            >
              {v === 'position' ? 'Order' : 'Type'}
            </button>
          ))}
        </div>
        {onClose && (
          <button className="drawer-close" onClick={onClose} aria-label="Close entities panel">×</button>
        )}
      </div>

      {/* ── STIX bundle filter (ADR-0090): enrich jobs only ────────────── */}
      {hasEnrich && (
        <div className="marg-sort" role="group" aria-label="Filter by STIX bundle" style={{ marginBottom: 8 }}>
          {ENRICH_FILTERS.map(f => (
            <button
              key={f.value}
              className={`marg-sort-btn ${enrichFilter === f.value ? 'on' : ''}`}
              onClick={() => setEnrichFilter(f.value)}
              aria-pressed={enrichFilter === f.value}
            >
              {f.label} {enrichCounts[f.value]}
            </button>
          ))}
        </div>
      )}

      {/* ── Bulk selection action bar ──────────────────────────────────── */}
      {selCount > 0 && (
        <div className="marg-sel-bar">
          <span className="marg-sel-count">{selCount} selected</span>
          <button
            className="marg-sel-btn marg-sel-ok"
            onClick={bulkAcceptSelected}
            title={`Accept ${selCount} selected entities`}
          >
            ✓ Accept
          </button>
          <button
            className="marg-sel-btn marg-sel-no"
            onClick={bulkRejectSelected}
            title={`Reject ${selCount} selected entities`}
          >
            ✗ Reject
          </button>
          <button
            className="marg-sel-btn marg-sel-clear"
            onClick={clearSelection}
            title="Clear selection"
          >
            ✕
          </button>
        </div>
      )}

      {/* ── Card list ─────────────────────────────────────────────────── */}
      <div className="marg-flow">
        {grouped.map(grp => (
          <div key={grp.type} className="marg-group">
            {grp.type !== '_all' && (() => {
              const hidden        = hiddenGroups.has(grp.type)
              const acceptedCount = grp.entities.filter(e => e.accepted === true).length
              const rejectedCount = grp.entities.filter(e => e.accepted === false).length
              return (
                <div className="marg-group-head">
                  <button
                    className="marg-group-collapse"
                    onClick={() => toggleGroupVisibility(grp.type)}
                    title={hidden ? 'Show group' : 'Hide group'}
                  >
                    {hidden ? '›' : '˅'}
                  </button>
                  <span className="marg-group-dot" style={{ background: typeDot(grp.type) }} />
                  <span className="marg-group-name">{typeLabel(grp.type)}</span>
                  <span className="marg-group-n">{grp.entities.length}</span>

                  {!hidden && acceptedCount < grp.entities.length && (
                    <button
                      className="marg-group-action marg-group-ok"
                      onClick={() => acceptGroup(grp.entities)}
                      title={`Accept all ${grp.entities.length - acceptedCount} ${typeLabel(grp.type)}`}
                    >
                      ✓ {grp.entities.length - acceptedCount}
                    </button>
                  )}
                  {!hidden && rejectedCount < grp.entities.length && (
                    <button
                      className="marg-group-action marg-group-no"
                      onClick={() => rejectGroup(grp.entities)}
                      title={`Reject all ${grp.entities.length - rejectedCount} ${typeLabel(grp.type)}`}
                    >
                      ✗ {grp.entities.length - rejectedCount}
                    </button>
                  )}
                </div>
              )
            })()}

            {!hiddenGroups.has(grp.type) && grp.entities.map(e => (
              <MarginaliaCard
                key={e.id}
                entity={e}
                flow
                collapsed={collapsed.has(e.id)}
                onToggleCollapse={() => toggleCard(e.id)}
                focused={focusedId === e.id}
                onClick={() => setFocusedId(e.id)}
                onAccept={() => onAccept(e.id)}
                onReject={() => onReject(e.id)}
                onReset={() => onReset(e.id)}
                onChangeType={t => onChangeType(e.id, t)}
                selected={selectedIds.has(e.id)}
                onToggleSelect={() => toggleSelect(e.id)}
              />
            ))}
          </div>
        ))}
      </div>
    </aside>
  )
}
