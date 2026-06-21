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
import type { Entity, Relationship } from '../../types'
import type { GraphNode, GraphEdge } from './graphLayout'

export interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
  byId: Map<string, GraphNode>
  deg: Record<string, number>
  adj: Record<string, Set<string>>
  typeCounts: Record<string, number>
  unmatchedCount: number
}

export function buildGraphData(
  rawEntities: Entity[],
  rawRelations: Relationship[],
): GraphData {
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
  let unmatchedCount = 0
  const edges: GraphEdge[] = []
  rawRelations.forEach(r => {
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

  // Adjacency (undirected) for layout algorithms.
  const adj: Record<string, Set<string>> = {}
  nodes.forEach(n => { adj[n.id] = new Set() })
  edges.forEach(e => { adj[e.source]?.add(e.target); adj[e.target]?.add(e.source) })

  // Per-type node counts for the legend.
  const typeCounts: Record<string, number> = {}
  nodes.forEach(n => { typeCounts[n.type] = (typeCounts[n.type] || 0) + 1 })

  return { nodes, edges, byId, deg, adj, typeCounts, unmatchedCount }
}
