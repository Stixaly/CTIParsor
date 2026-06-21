import { describe, it, expect } from 'vitest'
import { buildGraphData } from './buildGraphData'
import type { Entity, Relationship } from '../../types'

let _id = 0
const entity = (value: string, entity_type: string, accepted: boolean | null = true): Entity => ({
  id: `e${++_id}`, job_id: 'j', value, entity_type, context: '', confidence: 1,
  mitre_id: null, accepted, source: 'test',
})
const rel = (source_value: string, target_value: string, accepted: boolean | null = true): Relationship => ({
  id: `r${++_id}`, job_id: 'j', source_value, relationship_type: 'uses',
  target_value, confidence: 1, accepted, evidence_text: null,
})

describe('buildGraphData', () => {
  it('builds nodes from non-rejected entities only', () => {
    const ents = [entity('APT29', 'threat_actor'), entity('Rejected', 'malware', false)]
    const { nodes, typeCounts } = buildGraphData(ents, [])
    expect(nodes.map(n => n.name)).toEqual(['APT29'])
    expect(typeCounts).toEqual({ threat_actor: 1 })
  })

  it('resolves edges by value (case-insensitively) and computes degree/adjacency', () => {
    const a = entity('APT29', 'threat_actor')
    const m = entity('WellMess', 'malware')
    const r = rel('apt29', 'wellmess')   // lower-case — must still resolve
    const { edges, deg, adj, unmatchedCount } = buildGraphData([a, m], [r])
    expect(unmatchedCount).toBe(0)
    expect(edges).toHaveLength(1)
    expect(edges[0].source).toBe(a.id)
    expect(edges[0].target).toBe(m.id)
    expect(deg[a.id]).toBe(1)
    expect(deg[m.id]).toBe(1)
    expect(adj[a.id].has(m.id)).toBe(true)
    expect(adj[m.id].has(a.id)).toBe(true)
  })

  it('skips and counts edges whose endpoints do not resolve', () => {
    const a = entity('APT29', 'threat_actor')
    const r = rel('APT29', 'GhostEntity')   // target not an entity
    const { edges, unmatchedCount } = buildGraphData([a], [r])
    expect(edges).toHaveLength(0)
    expect(unmatchedCount).toBe(1)
  })

  it('does not create an edge to a rejected entity', () => {
    const a = entity('APT29', 'threat_actor')
    const m = entity('WellMess', 'malware', false)   // rejected → not a node
    const r = rel('APT29', 'WellMess')
    const { nodes, edges, unmatchedCount } = buildGraphData([a, m], [r])
    expect(nodes).toHaveLength(1)
    expect(edges).toHaveLength(0)
    expect(unmatchedCount).toBe(1)
  })

  it('returns empty structures for empty input', () => {
    const g = buildGraphData([], [])
    expect(g.nodes).toEqual([])
    expect(g.edges).toEqual([])
    expect(g.unmatchedCount).toBe(0)
    expect(g.byId.size).toBe(0)
  })
})
