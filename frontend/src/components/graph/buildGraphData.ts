/**
 * Pure derivation of graph data (nodes, edges, adjacency, counts) from the
 * raw entities + relationships the API returns.
 *
 * Extracted from Graph.tsx so it can be unit-tested without rendering React.
 *
 * Relationships reference entities by VALUE (source_value / target_value), not
 * by id — mirroring the STIX bundle's by-value relationship model.  We build a
 * value→entityId map; edges whose endpoints don't resolve are skipped and
 * counted in `unmatchedCount`.
 */
import type { BundleLedger, Entity, LedgerRelationship, Relationship } from '../../types'
import type { GraphNode, GraphEdge } from './graphLayout'

export interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
  byId: Map<string, GraphNode>
  deg: Record<string, number>
  adj: Record<string, Set<string>>
  typeCounts: Record<string, number>
  unmatchedCount: number
  /** Review graph with a ledger: what the stored bundle did with each
   *  relationship row, by row id (ADR-0061).  Absent rows were not in the
   *  build (added since, or no ledger). */
  fate?: Map<string, LedgerRelationship>
}

const relKey = (s: string, v: string, t: string) =>
  `${s.trim().toLowerCase()}\u0000${v.trim().toLowerCase()}\u0000${t.trim().toLowerCase()}`

export function buildGraphData(
  rawEntities: Entity[],
  rawRelations: Relationship[],
  ledger?: BundleLedger | null,
): GraphData {
  // Ledger entries by row value, so each drawn row can say whether it ships.
  // Several entries can share a key (duplicate rows); one that shipped wins.
  const ledgerByKey = new Map<string, LedgerRelationship>()
  for (const l of ledger?.relationships ?? []) {
    const k = relKey(l.source_value, l.relationship_type, l.target_value)
    const prev = ledgerByKey.get(k)
    if (!prev || (prev.outcome === 'dropped' && l.outcome !== 'dropped')) ledgerByKey.set(k, l)
  }
  const fate = ledger ? new Map<string, LedgerRelationship>() : undefined

  // Show only non-rejected entities.
  const visible = rawEntities.filter(e => e.accepted !== false)

  // value (lowercase) → entity id.  Last writer wins on duplicate values, the
  // same ambiguity the backend has when resolving relationships by value.
  const valueToId = new Map<string, string>()
  visible.forEach(e => valueToId.set(e.value.toLowerCase(), e.id))

  const nodes: GraphNode[] = visible.map(e => ({
    id: e.id, type: e.entity_type, name: e.value,
    confidence: e.confidence, source: e.source,
    mitre_id: e.mitre_id, context: e.context ?? '',
    accepted: e.accepted,
  }))
  const byId = new Map(nodes.map(n => [n.id, n]))

  // Degree map (initialised to 0 for every node).
  const deg: Record<string, number> = {}
  nodes.forEach(n => { deg[n.id] = 0 })

  // Resolve edges by value → id; skip + count unresolved endpoints.
  // Rejected edges stay in `edges` (the link editor lists them, so they can be
  // reset) but not in `deg` / `adj`: those size the nodes, drive the layouts
  // and the neighbour highlight, and a link that is no longer drawn must not.
  let unmatchedCount = 0
  const edges: GraphEdge[] = []
  const adj: Record<string, Set<string>> = {}
  nodes.forEach(n => { adj[n.id] = new Set() })
  rawRelations.forEach(r => {
    const srcId = valueToId.get(r.source_value.toLowerCase())
    const tgtId = valueToId.get(r.target_value.toLowerCase())
    if (!srcId || !tgtId) { unmatchedCount++; return }
    const l = ledgerByKey.get(relKey(r.source_value, r.relationship_type, r.target_value))
    if (l && fate) fate.set(r.id, l)
    edges.push({
      id: r.id, source: srcId, target: tgtId,
      rel: r.relationship_type,
      confidence: r.confidence,
      accepted: r.accepted,
      evidence: r.evidence_text ?? '',
      ...(l?.outcome === 'dropped' ? { kind: 'dropped' as const } : {}),
      ...(l && l.outcome !== 'dropped' && l.changes.length > 0 ? { changed: true } : {}),
    })
    if (r.accepted === false) return
    deg[srcId] = (deg[srcId] || 0) + 1
    deg[tgtId] = (deg[tgtId] || 0) + 1
    adj[srcId]?.add(tgtId)
    adj[tgtId]?.add(srcId)
  })

  // Per-type node counts for the legend.
  const typeCounts: Record<string, number> = {}
  nodes.forEach(n => { typeCounts[n.type] = (typeCounts[n.type] || 0) + 1 })

  return { nodes, edges, byId, deg, adj, typeCounts, unmatchedCount, fate }
}
