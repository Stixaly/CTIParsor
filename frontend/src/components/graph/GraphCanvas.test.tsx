import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, render } from '@testing-library/react'
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

function renderCanvas(edges: GraphEdge[], hiddenKinds?: Set<EdgeKind>, onSelect: (id: string | null) => void = () => {}) {
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
      onSelect={onSelect}
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

// #568 — a baseline edge's arrow takes its own stroke colour, not the faint default.
describe('GraphCanvas — arrow colour of baseline edges (#568)', () => {
  it('points a baseline edge at an arrow marker in its stroke colour', () => {
    const { container } = renderCanvas([edge('shipped', 'a', 'b', { kind: 'baseline' })])
    const path = container.querySelector('path[data-edge="shipped"]')!
    expect(path.getAttribute('marker-end')).toBe('url(#gv-arrow-baseline)')
    expect(container.querySelector('marker#gv-arrow-baseline path')?.getAttribute('fill')).toBe('var(--ink-2)')
  })
})

// #570 — only the primary button starts a drag or clears the selection.
describe('GraphCanvas — pointer buttons (#570)', () => {
  const press = (target: EventTarget, button: number, type = 'pointerdown') =>
    target.dispatchEvent(new MouseEvent(type, { button, bubbles: true, clientX: 10, clientY: 10 }))

  it('does not clear the selection on a right-click on the background', () => {
    const onSelect = vi.fn()
    const { container } = renderCanvas([], undefined, onSelect)
    press(container.querySelector('svg')!, 2)
    expect(onSelect).not.toHaveBeenCalled()
  })

  it('clears the selection on a primary click on the background (control)', () => {
    const onSelect = vi.fn()
    const { container } = renderCanvas([], undefined, onSelect)
    press(container.querySelector('svg')!, 0)
    expect(onSelect).toHaveBeenCalledWith(null)
  })

  it('does not select a node on a middle-click', () => {
    const onSelect = vi.fn()
    const { container } = renderCanvas([], undefined, onSelect)
    press(container.querySelector('[data-node="a"]')!, 1)
    press(window, 1, 'pointerup')
    expect(onSelect).not.toHaveBeenCalled()
  })

  it('selects a node on a primary click (control)', () => {
    const onSelect = vi.fn()
    const { container } = renderCanvas([], undefined, onSelect)
    press(container.querySelector('[data-node="a"]')!, 0)
    press(window, 0, 'pointerup')
    expect(onSelect).toHaveBeenCalledWith('a')
  })
})

// #832 — a drag or a pan that ends in pointercancel, or on unmount, lets go.
describe('GraphCanvas — a drag cut short (#832)', () => {
  // A pointer event on the window or an element, inside act so React flushes the repaint.
  const pointer = (type: string, target: EventTarget, clientX = 10, clientY = 10) =>
    act(() => { target.dispatchEvent(new MouseEvent(type, { button: 0, bubbles: true, clientX, clientY })) })
  const nodeTransform = (container: HTMLElement) =>
    container.querySelector('[data-node="a"]')!.getAttribute('transform')
  const viewTransform = (container: HTMLElement) =>
    container.querySelector('svg > g')!.getAttribute('transform')

  it('stops moving the node after pointercancel', () => {
    const { container } = renderCanvas([])
    const before = nodeTransform(container)
    pointer('pointerdown', container.querySelector('[data-node="a"]')!)
    pointer('pointermove', window, 40, 40)
    const dragged = nodeTransform(container)
    expect(dragged).not.toBe(before)

    pointer('pointercancel', window)
    pointer('pointermove', window, 90, 90)

    expect(nodeTransform(container)).toBe(dragged)
  })

  it('stops the node drag’s window listeners when the canvas unmounts mid-drag', () => {
    const add = vi.spyOn(window, 'addEventListener')
    const remove = vi.spyOn(window, 'removeEventListener')
    const { container, unmount } = renderCanvas([])
    pointer('pointerdown', container.querySelector('[data-node="a"]')!)
    const moves = add.mock.calls.filter(([type]) => type === 'pointermove')
    const moveListener = moves[moves.length - 1][1]

    unmount()

    expect(remove).toHaveBeenCalledWith('pointermove', moveListener)
    add.mockRestore()
    remove.mockRestore()
  })

  it('stops panning the background after pointercancel', () => {
    const { container } = renderCanvas([])
    pointer('pointerdown', container.querySelector('svg')!)
    pointer('pointermove', window, 30, 30)
    const panned = viewTransform(container)

    pointer('pointercancel', window)
    pointer('pointermove', window, 90, 90)

    expect(viewTransform(container)).toBe(panned)
  })
})
