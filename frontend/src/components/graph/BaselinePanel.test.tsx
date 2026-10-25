import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { BaselinePanel } from './BaselinePanel'
import { buildBundleGraph } from './buildBundleGraph'
import { makeLabelOf } from './BundlePanels'
import type { BundleLedger, Job, StixBundle, StixObject } from '../../types'

const AUTHOR = 'identity--ctiparsor'
const obj = (id: string, type: string, extra: Record<string, unknown> = {}): StixObject =>
  ({ id, type, created_by_ref: AUTHOR, ...extra })

// APT29 is the analyst's (kept as received), WINELOADER and the link from
// WINELOADER are CTIParsor's, the report is re-issued.
const bundle: StixBundle = {
  id: 'bundle--1', type: 'bundle',
  objects: [
    { id: AUTHOR, type: 'identity', name: 'CTIParsor' },
    obj('threat-actor--b', 'threat-actor', { name: 'APT29' }),
    obj('malware--c', 'malware', { name: 'WINELOADER' }),
    obj('relationship--k', 'relationship', { source_ref: 'threat-actor--b', relationship_type: 'uses', target_ref: 'malware--c' }),
    obj('relationship--x', 'relationship', { source_ref: 'malware--c', relationship_type: 'related-to', target_ref: 'threat-actor--b' }),
    obj('report--r', 'report', { name: 'Analyst report', object_refs: ['threat-actor--b'] }),
  ],
}

const ledger: BundleLedger = {
  version: 1,
  objects: {
    'threat-actor--b': { origin: 'baseline', status: 'matched' },
    'malware--c': { origin: 'entity' },
    'relationship--k': { origin: 'baseline', status: 'only' },
    'relationship--x': { origin: 'extracted' },
    'report--r': { origin: 'baseline_report_upsert', added_refs: 2, removed_refs: ['indicator--gone'] },
  },
  entities: [
    { value: 'APT28 (CTI)', entity_type: 'threat_actor', outcome: 'merged', reason: 'baseline_match', stix_id: 'threat-actor--b' },
    { value: 'WINELOADER', entity_type: 'malware', outcome: 'emitted', stix_id: 'malware--c' },
  ],
  relationships: [],
  removed: [
    { stix_id: 'threat-actor--dup', kind: 'object', reason: 'baseline_match', replaced_by: 'threat-actor--b' },
    { stix_id: 'indicator--gone', kind: 'baseline', reason: 'baseline_rejected' },
  ],
}

const job: Job = {
  id: 'job-1', original_filename: 'report.pdf', status: 'completed',
  created_at: '2026-10-25', updated_at: '2026-10-25', pipeline_mode: 'enrich',
  enrichment: {
    intake: {
      sha256: 'abc', bundle_id: 'bundle--1', counts: {}, warnings: [], reports: [],
      scope_report_id: 'report--r', needs_report_choice: false, min_tlp: null, min_pap: null,
      excluded: [
        { id: 'malware--aaaaaaaa-0000', type: 'malware', reason: 'baseline_invalid', detail: 'no name' },
        { id: 'indicator--bbbbbbbb-0000', type: 'indicator', reason: 'baseline_refs_closure', detail: 'refers to malware--x' },
      ],
      excluded_total: 3,
    },
    validated: true,
    counts: { entities: {}, relationships: {} },
  },
}

function renderPanel(onPickNode = vi.fn(), onPickEdge = vi.fn()) {
  const data = buildBundleGraph(bundle, ledger, [], [])
  render(
    <BaselinePanel job={job} ledger={ledger} data={data} labelOf={makeLabelOf(data.byId, bundle.objects)}
      onClose={() => {}} onPickNode={onPickNode} onPickEdge={onPickEdge} />,
  )
  return { onPickNode, onPickEdge }
}

describe('BaselinePanel — the bundle against the analyst’s STIX bundle (ADR-0090)', () => {
  it('counts what CTIParsor added, and lists only what is not from the analyst’s bundle', () => {
    renderPanel()
    expect(screen.getByRole('button', { name: /Added by CTIParsor/ }).textContent).toMatch(/Added by CTIParsor\s*2$/)
    expect(screen.getByText('WINELOADER')).toBeTruthy()
    expect(screen.getByText('related-to')).toBeTruthy()
    expect(screen.queryByText('uses')).toBeNull()
  })

  it('names each match: the CTIParsor object, then the baseline object that ships', () => {
    const { onPickNode } = renderPanel()
    expect(screen.getByRole('button', { name: /Matched to your objects/ }).textContent).toMatch(/objects\s*1$/)
    fireEvent.click(screen.getByText('APT28 (CTI) → your APT29'))
    expect(onPickNode).toHaveBeenCalledWith('threat-actor--b')
  })

  it('lists what was left out with its reason, and the intake exclusions with “and N more”', () => {
    renderPanel()
    // one baseline removal + three excluded at intake
    expect(screen.getByRole('button', { name: /Left out of your bundle/ }).textContent).toMatch(/bundle\s*4$/)
    expect(screen.getByText('you rejected every row of it, so it is left out of this bundle')).toBeTruthy()
    expect(screen.getByText('invalid STIX object')).toBeTruthy()
    expect(screen.getByText('references an excluded object')).toBeTruthy()
    expect(screen.getByTitle('no name')).toBeTruthy()
    expect(screen.getByText('and 1 more')).toBeTruthy()
  })

  it('states that a rejection leaves a report OpenCTI already holds with its reference', () => {
    renderPanel()
    expect(screen.getByText(/A rejection removes the object from this bundle only/)).toBeTruthy()
    expect(screen.getByText(/OpenCTI’s upsert never removes a reference/)).toBeTruthy()
  })

  it('names the re-issued report and counts its references', () => {
    renderPanel()
    expect(screen.getByText('Analyst report')).toBeTruthy()
    expect(screen.getByText('2 references added · 1 reference dropped from this bundle’s copy (OpenCTI keeps them)')).toBeTruthy()
  })

  it('collapses a section on its header, and picks a drawn node from its row', () => {
    const { onPickNode } = renderPanel()
    const header = screen.getByRole('button', { name: /Added by CTIParsor/ })
    expect(header.getAttribute('aria-expanded')).toBe('true')
    fireEvent.click(header)
    expect(header.getAttribute('aria-expanded')).toBe('false')
    expect(screen.queryByText('WINELOADER')).toBeNull()
    fireEvent.click(header)
    fireEvent.click(screen.getByText('WINELOADER'))
    expect(onPickNode).toHaveBeenCalledWith('malware--c')
  })
})

describe('BaselinePanel — naming what left', () => {
  it('names a left-out object by the review row it came from, and the object a closure points at', () => {
    const closure: BundleLedger = {
      ...ledger,
      removed: [
        { stix_id: 'malware--gone', kind: 'baseline', reason: 'baseline_rejected' },
        { stix_id: 'relationship--gone', kind: 'baseline', reason: 'baseline_refs_closure:malware--gone' },
      ],
    }
    const data = buildBundleGraph(bundle, closure, [], [])
    render(
      <BaselinePanel job={job} ledger={closure} data={data} labelOf={makeLabelOf(data.byId, bundle.objects)}
        onClose={() => {}} onPickNode={() => {}} onPickEdge={() => {}}
        entities={[{ id: 'e1', job_id: 'j', value: 'WellMess', entity_type: 'malware', context: '', confidence: 1,
                     mitre_id: null, accepted: false, source: 'baseline_stix', baseline_stix_id: 'malware--gone' }]}
        relationships={[{ id: 'r1', job_id: 'j', source_value: 'APT29', relationship_type: 'uses', target_value: 'WellMess',
                          confidence: 1, accepted: true, evidence_text: null, baseline_stix_id: 'relationship--gone' }]} />,
    )
    expect(screen.getByText('WellMess')).toBeTruthy()
    expect(screen.getByText('APT29 uses WellMess')).toBeTruthy()
    expect(screen.getByText(/\(WellMess\)$/)).toBeTruthy()
  })
})
