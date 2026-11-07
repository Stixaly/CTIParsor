import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render } from '@testing-library/react'
import GraphCanvas from './GraphCanvas'
import { parallelOffsets, type EdgeKind, type GraphEdge, type GraphNode } from './graphLayout'

// The bow of parallel edges is computed by parallelOffsets; the real function
// runs, the spy only records which edges it was given.
vi.mock('./graphLayout', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./graphLayout')>()
  return { ...actual, parallelOffsets: vi.fn(actual.parallelOffsets) }
})

const node = (id: string, type: string): GraphNode => ({
  id, type, name: id, confidence: 1, source: 'test', mitre_id: null, context: '', accepted: true,
})
const edge = (id: string, source: string, target: string, over: Partial<GraphEdge> = {}): GraphEdge => ({
  id, source, target, rel: 'uses', confidence: 1, accepted: true, evidence: '', ...over,
})

const NODES = [node('a', 'malware'), node('b', 'malware')]
const BY_ID = new Map(NODES.map(n => [n.id, n]))

function renderCanvas(edges: GraphEdge[], hiddenKinds?: Set<EdgeKind>) {
  return render(
    <GraphCanvas
      nodes={NODES}
      edges={edges}
      byId={BY_ID}
      deg={{ a: 2, b: 2 }}
      adj={{ a: new Set(['b']), b: new Set(['a']) }}
      layout="hierarchical"
      hiddenTypes={new Set()}
      selectedId={null}
      hoverId={null}
      showLabels={false}
      onSelect={() => {}}
      onHover={() => {}}
      focusSignal={null}
      hiddenKinds={hiddenKinds}
    />,
  )
}

// The edges the last render handed to parallelOffsets.
const offsetEdgeIds = () =>
  vi.mocked(parallelOffsets).mock.lastCall![0].map(e => e.id)

beforeEach(() => {
  vi.mocked(parallelOffsets).mockClear()
})

// #453 — a hidden edge must not bow the visible edges of its pair.
describe('GraphCanvas — parallel edge offsets (#453)', () => {
  it('computes the offsets over the edges drawn, not over a hidden twin', () => {
    renderCanvas(
      [edge('uses', 'a', 'b'), edge('dropped-twin', 'a', 'b', { kind: 'dropped' })],
      new Set(['dropped']),
    )
    expect(offsetEdgeIds()).toEqual(['uses'])
  })

  it('still spreads two visible parallel edges (control)', () => {
    const { container } = renderCanvas(
      [edge('uses', 'a', 'b'), edge('delivers', 'a', 'b')],
      new Set(['dropped']),
    )
    expect(offsetEdgeIds()).toEqual(['uses', 'delivers'])
    expect(container.querySelectorAll('path[data-edge]')).toHaveLength(2)
  })
})
