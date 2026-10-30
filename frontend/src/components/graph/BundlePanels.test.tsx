import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { BundleNodeDetail, EdgeDetail } from './BundlePanels'
import { buildBundleGraph } from './buildBundleGraph'
import type { StixBundle, StixObject } from '../../types'

const AUTHOR = 'identity--ctiparsor'
const obj = (id: string, type: string, extra: Record<string, unknown> = {}): StixObject =>
  ({ id, type, created_by_ref: AUTHOR, ...extra })

// Two relationships of one actor: one CTIParsor built (a quote and a Markdown
// justification), one the analyst's own bundle carried (a free description, no quote).
const bundle: StixBundle = {
  id: 'bundle--1', type: 'bundle',
  objects: [
    obj('threat-actor--a', 'threat-actor', { name: 'APT29' }),
    obj('malware--w', 'malware', { name: 'WINELOADER' }),
    obj('relationship--1', 'relationship', {
      source_ref: 'threat-actor--a', relationship_type: 'uses', target_ref: 'malware--w', confidence: 85,
      x_evidence_text: 'APT29 deployed WINELOADER in 2023',
      description: '### APT29 uses WINELOADER\n\n> APT29 deployed WINELOADER in 2023\n\n**Why:** the report names both.',
    }),
    obj('relationship--2', 'relationship', {
      source_ref: 'threat-actor--a', relationship_type: 'related-to', target_ref: 'malware--w',
      description: 'Analyst note: same actor',
    }),
  ],
}

function renderEdge(edgeId: string) {
  const g = buildBundleGraph(bundle, null, [], [])
  const edge = g.edges.find(e => e.id === edgeId)!
  return render(
    <EdgeDetail edge={edge} info={g.edgeInfo.get(edgeId)} byId={g.byId} onClose={vi.fn()} onPick={vi.fn()}
      onPickEdge={vi.fn()} labelOf={s => s} />,
  )
}

describe('EdgeDetail — quote and justification (ADR-0093)', () => {
  it('shows the quote as plain text and the description as Markdown, in two blocks', () => {
    renderEdge('relationship--1')

    expect(screen.getByText('Quoted evidence').nextElementSibling?.textContent)
      .toBe('APT29 deployed WINELOADER in 2023')
    const description = screen.getByText('Description').parentElement!
    expect(description.querySelector('.md-preview')).toHaveClass('md-compact')
    expect(screen.getByText('Why:').tagName).toBe('STRONG')
  })

  it('shows no quote for a relationship that has only a description', () => {
    renderEdge('relationship--2')

    expect(screen.queryByText('Quoted evidence')).not.toBeInTheDocument()
    expect(screen.getByText('Analyst note: same actor')).toBeInTheDocument()
  })
})

describe('BundleNodeDetail — an object’s description is Markdown, whole (ADR-0093)', () => {
  const nodeBundle = (description: string): StixBundle => ({
    id: 'bundle--2', type: 'bundle',
    objects: [obj('malware--w', 'malware', { name: 'WINELOADER', description })],
  })
  function renderNode(description: string) {
    const g = buildBundleGraph(nodeBundle(description), null, [], [])
    return render(
      <BundleNodeDetail node={g.byId.get('malware--w')!} info={g.nodeInfo.get('malware--w')} edges={g.edges}
        byId={g.byId} onClose={vi.fn()} onPickEdge={vi.fn()} />,
    )
  }

  it('draws the description as Markdown, and keeps it out of the STIX properties', () => {
    const { container } = renderNode('Mentioned in *R*:\n\n> A sentence.')

    expect(screen.getByText('Description')).toBeInTheDocument()
    expect(container.querySelector('blockquote')?.textContent?.trim()).toBe('A sentence.')
    expect(container.querySelector('em')?.textContent).toBe('R')
    expect(screen.getByText('STIX properties').parentElement?.textContent).not.toContain('description')
  })

  it('does not cut a long description', () => {
    const { container } = renderNode('Long note. '.repeat(60) + 'THE END.')

    expect(container.querySelector('.md-preview')?.textContent).toContain('THE END.')
  })
})
