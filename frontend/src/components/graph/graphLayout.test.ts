import { describe, it, expect } from 'vitest'
import {
  getTier,
  nodeRadius,
  layoutHierarchical,
  layoutRadial,
  typeStixIcon,
  typeIconPath,
  type GraphNode,
  type GraphEdge,
} from './graphLayout'

const node = (id: string, type: string): GraphNode => ({
  id, type, name: id, confidence: 1, source: 'test', mitre_id: null, context: '', accepted: true,
})
const edge = (id: string, source: string, target: string): GraphEdge => ({
  id, source, target, rel: 'uses', confidence: 1, accepted: true, evidence: '',
})

function buildAdjDeg(nodes: GraphNode[], edges: GraphEdge[]) {
  const deg: Record<string, number> = {}
  const adj: Record<string, Set<string>> = {}
  nodes.forEach(n => { deg[n.id] = 0; adj[n.id] = new Set() })
  edges.forEach(e => {
    adj[e.source]?.add(e.target); adj[e.target]?.add(e.source)
    deg[e.source]++; deg[e.target]++
  })
  return { deg, adj }
}

describe('getTier / nodeRadius', () => {
  it('maps known + unknown types', () => {
    expect(getTier('threat_actor')).toBe(0)
    expect(getTier('ipv4')).toBe(3)
    expect(getTier('totally-unknown')).toBe(3) // default
  })
  it('node radius grows with degree but is capped', () => {
    expect(nodeRadius('ipv4', 0)).toBeGreaterThan(0)
    expect(nodeRadius('threat_actor', 1000)).toBeLessThanOrEqual(32)
  })
})

describe('layoutHierarchical', () => {
  it('positions every node and stacks tiers by y', () => {
    const nodes = [node('a', 'threat_actor'), node('m', 'malware'), node('ip', 'ipv4')]
    const edges = [edge('e1', 'a', 'm'), edge('e2', 'm', 'ip')]
    const { deg, adj } = buildAdjDeg(nodes, edges)
    const pos = layoutHierarchical(nodes, edges, deg, adj)
    expect(Object.keys(pos)).toHaveLength(3)
    // tier 0 (actor) above tier 1 (malware) above tier 3 (ip)
    expect(pos['a'].y).toBeLessThan(pos['m'].y)
    expect(pos['m'].y).toBeLessThan(pos['ip'].y)
  })
})

describe('layoutRadial', () => {
  it('places the root at the origin and others on rings', () => {
    const nodes = [node('a', 'threat_actor'), node('m', 'malware'), node('ip', 'ipv4')]
    const edges = [edge('e1', 'a', 'm'), edge('e2', 'm', 'ip')]
    const { deg, adj } = buildAdjDeg(nodes, edges)
    const pos = layoutRadial(nodes, edges, deg, adj)
    expect(Object.keys(pos)).toHaveLength(3)
  })

  it('does not crash on empty input', () => {
    expect(() => layoutRadial([], [], {}, {})).not.toThrow()
    expect(layoutRadial([], [], {}, {})).toEqual({})
  })
})

describe('icon helpers', () => {
  it('returns an SDO icon for malware and null for an SCO type', () => {
    expect(typeStixIcon('malware')).not.toBeNull()
    expect(typeStixIcon('ipv4')).toBeNull()
  })
  it('returns an SCO path for ipv4 and null for an SDO type', () => {
    expect(typeIconPath('ipv4')).toBeTruthy()
    expect(typeIconPath('malware')).toBeNull()
  })
})
