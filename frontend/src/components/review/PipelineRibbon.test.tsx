import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import PipelineRibbon from './PipelineRibbon'
import type { JobEnrichment } from '../../types'

const counts = { pending: 2, accepted: 3, rejected: 1, rels: 4 }
const stageInfo = {
  chars: 0, approxChunks: 0, iocCount: 0, nerCount: 0, llmCount: 0, ttpCount: 0, relCount: 0,
}

const enrichment: JobEnrichment = {
  intake: null, validated: true,
  counts: {
    entities: { matched: 3, baseline_in_text: 2, baseline_only: 4, new: 5 },
    relationships: { baseline_only: 1, new: 2 },
  },
}

const renderRibbon = (over: { enrichment?: JobEnrichment } = {}) =>
  render(<PipelineRibbon filename="report.pdf" counts={counts} stageInfo={stageInfo} {...over} />)

describe('PipelineRibbon — enrich counts (ADR-0090)', () => {
  it('words the entities line: in STIX, of which extracted and found in text, STIX only, new', () => {
    renderRibbon({ enrichment })
    expect(screen.getByText(
      'Already in STIX: 5 (3 extracted · 2 found in text) · STIX only: 4 · + New: 5')).toBeTruthy()
  })

  it('words the relationships line the same way', () => {
    renderRibbon({ enrichment })
    expect(screen.getByText(
      'Relationships: in STIX 0 (0 extracted · 0 found in text) · STIX only: 1 · + New: 2')).toBeTruthy()
  })

  it('counts a status the job does not hold as 0', () => {
    renderRibbon({ enrichment: { intake: null, validated: true, counts: { entities: {}, relationships: {} } } })
    expect(screen.getByText(
      'Already in STIX: 0 (0 extracted · 0 found in text) · STIX only: 0 · + New: 0')).toBeTruthy()
  })

  it('shows no enrich line without enrichment', () => {
    const { container } = renderRibbon()
    expect(screen.queryByText(/Already in STIX/)).toBeNull()
    expect(screen.queryByText(/Relationships: in STIX/)).toBeNull()
    expect(container.querySelector('.ribbon-enrich')).toBeNull()
  })
})
