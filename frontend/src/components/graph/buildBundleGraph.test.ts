import { describe, it, expect } from 'vitest'
import { buildBundleGraph, stixLabel } from './buildBundleGraph'
import { buildGraphData } from './buildGraphData'
import type {
  BundleLedger, Entity, LedgerEntity, LedgerRelationship, Relationship, StixBundle, StixObject,
} from '../../types'

let _id = 0
const entity = (value: string, entity_type: string, accepted: boolean | null = true): Entity => ({
  id: `e${++_id}`, job_id: 'j', value, entity_type, context: '', confidence: 1,
  mitre_id: null, accepted, source: 'test',
})
const rel = (source_value: string, relationship_type: string, target_value: string,
             accepted: boolean | null = true): Relationship => ({
  id: `r${++_id}`, job_id: 'j', source_value, relationship_type, target_value,
  confidence: 0.9, accepted, evidence_text: null,
})
const lrel = (source_value: string, relationship_type: string, target_value: string,
              extra: Partial<LedgerRelationship>): LedgerRelationship => ({
  source_value, relationship_type, target_value, outcome: 'emitted', changes: [], ...extra,
})
const lent = (value: string, entity_type: string, extra: Partial<LedgerEntity>): LedgerEntity => ({
  value, entity_type, outcome: 'emitted', ...extra,
})

const AUTHOR = 'identity--author'
const obj = (id: string, type: string, extra: Record<string, unknown> = {}): StixObject =>
  ({ id, type, created_by_ref: AUTHOR, ...extra })
const sro = (id: string, s: string, verb: string, t: string, extra: Record<string, unknown> = {}): StixObject =>
  obj(id, 'relationship', { source_ref: s, relationship_type: verb, target_ref: t, ...extra })

// APT29 --uses--> WINELOADER (a row), WINELOADER --uses--> Mimikatz rewritten
// to related-to, the Indicator based-on its domain, a policy pin, the report.
function fixture() {
  const bundle: StixBundle = {
    id: 'bundle--1', type: 'bundle',
    objects: [
      { id: AUTHOR, type: 'identity', name: 'CTIParsor' },
      obj('marking-definition--tlp', 'marking-definition', { name: 'TLP:CLEAR' }),
      obj('threat-actor--a', 'threat-actor', { name: 'APT29' }),
      obj('malware--w', 'malware', { name: 'WINELOADER' }),
      obj('tool--m', 'tool', { name: 'Mimikatz' }),
      { id: 'domain-name--d', type: 'domain-name', value: 'evil.example' },
      obj('indicator--i', 'indicator', { name: 'Indicator: evil.example', pattern: "[domain-name:value = 'evil.example']" }),
      sro('relationship--1', 'threat-actor--a', 'uses', 'malware--w'),
      sro('relationship--2', 'malware--w', 'related-to', 'tool--m'),
      sro('relationship--3', 'indicator--i', 'based-on', 'domain-name--d'),
      sro('relationship--4', 'threat-actor--a', 'uses', 'tool--m', { x_policy_rule: 'threat-actor uses tool' }),
      obj('report--r', 'report', { name: 'r', object_refs: ['threat-actor--a'] }),
    ],
  }
  const entities = [
    entity('APT29', 'threat_actor'), entity('WINELOADER', 'malware'), entity('Mimikatz', 'tool'),
    entity('evil.example', 'domain'), entity('Atlantis', 'location'),
  ]
  const relations = [
    rel('APT29', 'uses', 'WINELOADER'),
    rel('WINELOADER', 'uses', 'Mimikatz'),
    rel('APT29', 'targets', 'Atlantis'),
    rel('APT29', 'related-to', 'apt29'),
  ]
  const ledger: BundleLedger = {
    version: 1,
    objects: {
      'threat-actor--a': { origin: 'entity' }, 'malware--w': { origin: 'entity' },
      'tool--m': { origin: 'entity' }, 'domain-name--d': { origin: 'entity' },
      'indicator--i': { origin: 'ioc_indicator', ioc_value: 'evil.example' },
      'relationship--1': { origin: 'extracted' }, 'relationship--2': { origin: 'extracted' },
      'relationship--3': { origin: 'ioc_based_on' }, 'relationship--4': { origin: 'policy_pin' },
      'report--r': { origin: 'report' }, [AUTHOR]: { origin: 'author_identity' },
      'marking-definition--tlp': { origin: 'marking' },
    },
    entities: [
      lent('APT29', 'threat_actor', { stix_id: 'threat-actor--a' }),
      lent('WINELOADER', 'malware', { stix_id: 'malware--w' }),
      lent('Mimikatz', 'tool', { stix_id: 'tool--m' }),
      lent('evil.example', 'domain', { stix_id: 'domain-name--d' }),
      lent('Atlantis', 'location', { outcome: 'dropped', reason: 'no_iso_country' }),
    ],
    relationships: [
      lrel('APT29', 'uses', 'WINELOADER', { stix_id: 'relationship--1', final_type: 'uses' }),
      lrel('WINELOADER', 'uses', 'Mimikatz', {
        stix_id: 'relationship--2', final_type: 'related-to',
        changes: [{ kind: 'verb', from: 'uses', to: 'related-to', reason: 'not_suggested' }],
      }),
      lrel('APT29', 'targets', 'Atlantis', { outcome: 'dropped', reason: 'unresolved_target' }),
      lrel('APT29', 'related-to', 'apt29', { outcome: 'dropped', reason: 'self_loop', stix_ref: 'threat-actor--a' }),
    ],
    removed: [],
  }
  return { bundle, entities, relations, ledger }
}

describe('buildBundleGraph', () => {
  it('draws the objects that ship and lists the bundle metadata apart', () => {
    const { bundle, entities, relations, ledger } = fixture()
    const g = buildBundleGraph(bundle, ledger, entities, relations)
    const real = g.nodes.filter(n => !n.ghost).map(n => n.id).sort()
    expect(real).toEqual(['domain-name--d', 'indicator--i', 'malware--w', 'threat-actor--a', 'tool--m'])
    expect(g.meta.map(o => o.type).sort()).toEqual(['identity', 'marking-definition', 'report'])
  })

  it('classifies each link by why it exists and flags rewritten rows', () => {
    const { bundle, entities, relations, ledger } = fixture()
    const g = buildBundleGraph(bundle, ledger, entities, relations)
    const kind = Object.fromEntries(g.edges.map(e => [e.id, e.kind]))
    expect(kind['relationship--1']).toBe('extracted')
    expect(kind['relationship--3']).toBe('mapping')
    expect(kind['relationship--4']).toBe('policy')
    expect(g.edges.find(e => e.id === 'relationship--2')?.changed).toBe(true)
    expect(g.edges.find(e => e.id === 'relationship--1')?.changed).toBe(false)
    expect(g.edgeInfo.get('relationship--1')?.rows[0].rel?.source_value).toBe('APT29')
    expect(g.diff.filter(d => d.kind === 'changed').map(d => d.edgeId)).toEqual(['relationship--2'])
  })

  it('shows a dropped entity as a ghost node and its dropped row as a ghost edge', () => {
    const { bundle, entities, relations, ledger } = fixture()
    const g = buildBundleGraph(bundle, ledger, entities, relations)
    const ghost = g.nodes.find(n => n.ghost)!
    expect(ghost.name).toBe('Atlantis')
    expect(g.nodeInfo.get(ghost.id)?.ghostReason).toBe('no_iso_country')
    const dropped = g.edges.filter(e => e.kind === 'dropped')
    expect(dropped).toHaveLength(1)
    expect(dropped[0].source).toBe('threat-actor--a')
    expect(dropped[0].target).toBe(ghost.id)
    // ghosts do not size the node they hang from
    expect(g.deg['threat-actor--a']).toBe(2)
  })

  it('lists a quoted rule that does not compile with the compiler’s message (ADR-0067)', () => {
    const { bundle, entities, relations, ledger } = fixture()
    ledger.removed = [{ stix_id: 'indicator--y', kind: 'object', reason: 'rule_does_not_compile',
                        name: 'Yara rule: R', error: 'line 10: syntax error' }]
    const g = buildBundleGraph(bundle, ledger, entities, relations)
    const item = g.diff.find(d => d.reason === 'rule_does_not_compile')!
    expect(item.kind).toBe('removed')
    expect(item.title).toBe('Yara rule: R')
    expect(item.error).toBe('line 10: syntax error')
    expect(item.nodeId).toBeUndefined()
  })

  it('lists a self-loop without drawing it', () => {
    const { bundle, entities, relations, ledger } = fixture()
    const g = buildBundleGraph(bundle, ledger, entities, relations)
    const loop = g.diff.find(d => d.reason === 'self_loop')!
    expect(loop.kind).toBe('dropped')
    expect(loop.edgeId).toBeUndefined()
    expect(loop.nodeId).toBe('threat-actor--a')
  })

  it('reports review changes the stored bundle predates', () => {
    const { bundle, entities, ledger } = fixture()
    const relations = [
      rel('APT29', 'uses', 'WINELOADER', false),       // rejected after the build
      rel('WINELOADER', 'uses', 'Mimikatz'),
      rel('APT29', 'targets', 'Atlantis'),
      rel('APT29', 'related-to', 'apt29'),
      rel('Mimikatz', 'related-to', 'evil.example'),   // added after the build
    ]
    const g = buildBundleGraph(bundle, ledger, [...entities, entity('NewOne', 'malware')], relations)
    const stale = g.diff.filter(d => d.kind === 'stale')
    expect(stale.map(d => d.reason).sort()).toEqual(['added_since_build', 'added_since_build', 'removed_since_build'])
    expect(stale.find(d => d.reason === 'removed_since_build')?.edgeId).toBe('relationship--1')
    expect(g.nodes.find(n => n.name === 'NewOne')?.ghost).toBe(true)
  })

  it('reports a date changed since the build, and nothing when the dates match (ADR-0063)', () => {
    const { bundle, entities, relations, ledger } = fixture()
    const built = { ...ledger, relationships: ledger.relationships.map(l => l.stix_id === 'relationship--1'
      ? { ...l, times: [{ kind: 'time' as const, id: 't1', role: 'start' as const, value: '2023-03',
                          status: 'verified' as const, outcome: 'withheld' as const }] }
      : l) }
    const withDate = (value: string) => relations.map((r, i) => i === 0
      ? { ...r, times: [{ id: 't1', role: 'start' as const, value, status: 'verified' as const,
                           origin: 'llm' as const }] }
      : r)
    const same = buildBundleGraph(bundle, built, entities, withDate('2023-03'))
    expect(same.diff.filter(d => d.kind === 'stale')).toEqual([])
    const edited = buildBundleGraph(bundle, built, entities, withDate('2023-02'))
    const stale = edited.diff.filter(d => d.kind === 'stale')
    expect(stale.map(d => [d.reason, d.edgeId])).toEqual([['dates_changed_since_build', 'relationship--1']])
    // A withheld date is not a rewrite of the row.
    expect(edited.edges.find(e => e.id === 'relationship--1')?.changed).toBe(false)
  })

  it('draws an object’s own reference properties as embedded links', () => {
    const bundle: StixBundle = { id: 'b', type: 'bundle', objects: [
      { id: 'domain-name--d', type: 'domain-name', value: 'evil.example', resolves_to_refs: ['ipv4-addr--i'] },
      { id: 'ipv4-addr--i', type: 'ipv4-addr', value: '1.2.3.4' },
    ] }
    const g = buildBundleGraph(bundle, null, [], [])
    expect(g.edges).toHaveLength(1)
    expect(g.edges[0]).toMatchObject({ kind: 'embedded', rel: 'resolves_to_refs', source: 'domain-name--d' })
  })

  it('without a ledger, classifies from the SRO’s own provenance and invents no ghosts', () => {
    const { bundle, entities, relations } = fixture()
    const g = buildBundleGraph(bundle, null, entities, relations)
    expect(g.hasLedger).toBe(false)
    expect(g.nodes.some(n => n.ghost)).toBe(false)
    expect(g.edges.find(e => e.id === 'relationship--4')?.kind).toBe('policy')
    expect(g.edges.find(e => e.id === 'relationship--1')?.kind).toBe('unknown')
    expect(g.diff).toEqual([])
  })
})

describe('stixLabel', () => {
  it('names objects that have no name', () => {
    expect(stixLabel({ id: 'file--1', type: 'file', hashes: { 'SHA-256': 'abc' } })).toBe('abc')
    expect(stixLabel({ id: 'autonomous-system--1', type: 'autonomous-system', number: 15169 })).toBe('AS15169')
    expect(stixLabel({ id: 'windows-registry-key--1', type: 'windows-registry-key', key: 'HKEY_X' })).toBe('HKEY_X')
  })
})

describe('buildGraphData with a ledger', () => {
  it('marks each review row with what the bundle made of it', () => {
    const { entities, relations, ledger } = fixture()
    const g = buildGraphData(entities, relations, ledger)
    const byRow = Object.fromEntries(g.edges.map(e => [e.id, e]))
    const [uses, rewritten, dropped] = relations
    expect(byRow[uses.id].kind).toBeUndefined()
    expect(byRow[rewritten.id].changed).toBe(true)
    expect(byRow[dropped.id].kind).toBe('dropped')
    expect(g.fate?.get(dropped.id)?.reason).toBe('unresolved_target')
  })

  it('has no fate map without a ledger', () => {
    const { entities, relations } = fixture()
    expect(buildGraphData(entities, relations).fate).toBeUndefined()
  })
})
