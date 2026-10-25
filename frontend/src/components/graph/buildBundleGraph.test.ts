import { describe, it, expect } from 'vitest'
import { buildBundleGraph, stixLabel } from './buildBundleGraph'
import { buildGraphData } from './buildGraphData'
import type {
  BundleLedger, Entity, LedgerEntity, LedgerRelationship, Relationship, StixBundle,
  StixObject,
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

  it('flags the objects the analyst’s STIX bundle supplied (ADR-0090)', () => {
    const { bundle, entities, relations, ledger } = fixture()
    bundle.objects.push(obj('threat-actor--b', 'threat-actor', { name: 'APT28' }))
    ledger.objects['threat-actor--b'] = { origin: 'baseline', status: 'only' }
    const g = buildBundleGraph(bundle, ledger, entities, relations)
    const flag = Object.fromEntries(g.nodes.filter(n => !n.ghost).map(n => [n.id, !!n.baseline]))
    expect(flag['threat-actor--b']).toBe(true)
    expect(flag['threat-actor--a']).toBe(false)
    expect(g.nodes.filter(n => n.ghost).every(n => !n.baseline)).toBe(true)
  })

  it('draws a relationship of the analyst’s STIX bundle as from the bundle, not unclassified (ADR-0090)', () => {
    const { bundle, entities, relations, ledger } = fixture()
    ledger.objects['relationship--1'] = { origin: 'baseline' }
    const g = buildBundleGraph(bundle, ledger, entities, relations)
    expect(g.edges.find(e => e.id === 'relationship--1')?.kind).toBe('baseline')
    expect(g.kindCounts.baseline).toBe(1)
    expect(g.kindCounts.unknown).toBeUndefined()
  })

  it('lists an object the analyst’s STIX bundle lost as an object, with its reason (ADR-0090)', () => {
    const { bundle, entities, relations, ledger } = fixture()
    ledger.removed = [{ stix_id: 'indicator--gone', reason: 'baseline_rejected', kind: 'baseline' }]
    const g = buildBundleGraph(bundle, ledger, entities, relations)
    const item = g.diff.find(d => d.reason === 'baseline_rejected')!
    expect(item.kind).toBe('removed')
    expect(item.subject).toBe('object')
    expect(item.nodeId).toBeUndefined()
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

describe('buildBundleGraph — rows imported from the analyst’s bundle (ADR-0090)', () => {
  // The analyst's malware ships as received; their IP left with a rejection;
  // neither row went through Stage 4, so the ledger has no entity entry for them.
  const imported = (value: string, entity_type: string, baseline_stix_id: string,
                    enrichment_status: 'baseline_only' | 'baseline_in_text', accepted = true): Entity =>
    ({ ...entity(value, entity_type, accepted), enrichment_status, baseline_stix_id })
  const bundle: StixBundle = {
    id: 'bundle--1', type: 'bundle',
    objects: [
      obj('malware--w', 'malware', { name: 'WellMess' }),
      obj('intrusion-set--a', 'intrusion-set', { name: 'APT29' }),
      sro('relationship--k', 'intrusion-set--a', 'uses', 'malware--w'),
    ],
  }
  const ledger: BundleLedger = {
    version: 1,
    objects: {
      'malware--w': { origin: 'baseline', status: 'only' },
      'intrusion-set--a': { origin: 'baseline', status: 'only' },
      'relationship--k': { origin: 'baseline', status: 'only' },
    },
    entities: [], relationships: [],
    removed: [{ stix_id: 'ipv4-addr--ip', kind: 'baseline', reason: 'baseline_rejected' }],
  }
  const importedRel = (accepted: boolean): Relationship => ({
    ...rel('APT29', 'uses', 'WellMess', accepted), enrichment_status: 'baseline_only', baseline_stix_id: 'relationship--k',
  })

  it('joins an imported row to its bundle object by id: no ghost, nothing stale', () => {
    const g = buildBundleGraph(bundle, ledger,
      [imported('WellMess', 'malware', 'malware--w', 'baseline_only')], [importedRel(true)])!
    expect(g.nodes.some(n => n.ghost)).toBe(false)
    expect(g.diff.filter(d => d.kind === 'stale')).toEqual([])
  })

  it('leaves an imported object the ledger removed to the removed list, not a ghost', () => {
    const g = buildBundleGraph(bundle, ledger,
      [imported('198.18.12.77', 'ipv4', 'ipv4-addr--ip', 'baseline_only', false)], [])!
    expect(g.nodes.some(n => n.ghost)).toBe(false)
    expect(g.diff.filter(d => d.kind === 'stale')).toEqual([])
    expect(g.diff.filter(d => d.kind === 'removed').map(d => d.reason)).toEqual(['baseline_rejected'])
  })

  it('calls an imported row rejected after the build stale while its object still ships', () => {
    const g = buildBundleGraph(bundle, ledger,
      [imported('WellMess', 'malware', 'malware--w', 'baseline_only', false)], [importedRel(false)])!
    const stale = g.diff.filter(d => d.kind === 'stale')
    expect(stale.map(d => [d.subject, d.reason])).toEqual([
      ['entity', 'removed_since_build'], ['relationship', 'removed_since_build']])
    expect(stale[1].edgeId).toBe('relationship--k')
  })

  it('leaves an accepted imported row the ledger removed by closure to the removed list, not a ghost', () => {
    const closed: BundleLedger = { ...ledger, removed: [
      { stix_id: 'ipv4-addr--ip', kind: 'baseline', reason: 'baseline_refs_closure:indicator--x' }] }
    const g = buildBundleGraph(bundle, closed,
      [imported('198.18.12.77', 'ipv4', 'ipv4-addr--ip', 'baseline_only')], [])!
    expect([...g.nodeInfo.values()].some(i => i.object === null)).toBe(false)
    expect(g.nodes.some(n => n.ghost)).toBe(false)
    expect(g.diff.filter(d => d.kind === 'stale')).toEqual([])
    const removed = g.diff.filter(d => d.kind === 'removed')
    expect(removed).toHaveLength(1)
    expect(removed[0]).toMatchObject({ reason: 'baseline_refs_closure:indicator--x', title: '198.18.12.77' })
  })

  it('calls an imported row re-accepted after a rejection stale, drawn as a ghost (a rebuild would ship it)', () => {
    const g = buildBundleGraph(bundle, ledger,
      [imported('198.18.12.77', 'ipv4', 'ipv4-addr--ip', 'baseline_only')], [])!
    const ghost = g.nodes.find(n => n.ghost)!
    expect(ghost.name).toBe('198.18.12.77')
    expect(g.nodeInfo.get(ghost.id)?.ghostReason).toBe('added_since_build')
    const stale = g.diff.filter(d => d.kind === 'stale')
    expect(stale).toEqual([expect.objectContaining({
      subject: 'entity', reason: 'added_since_build', title: '198.18.12.77', nodeId: ghost.id })])
    expect(g.diff.filter(d => d.kind === 'removed').map(d => d.reason)).toEqual(['baseline_rejected'])
  })

  it('calls an accepted imported relationship the bundle does not ship stale, with no ledger record', () => {
    const unshipped: Relationship = { ...importedRel(true), baseline_stix_id: 'relationship--gone' }
    const g = buildBundleGraph(bundle, ledger, [], [unshipped])!
    expect(g.diff.filter(d => d.kind === 'stale')).toEqual([expect.objectContaining({
      subject: 'relationship', reason: 'added_since_build', title: 'APT29 uses WellMess' })])
  })

  it('titles removed objects of the analyst’s bundle from their row, else by type and id (ADR-0090)', () => {
    const removedLedger: BundleLedger = { ...ledger, removed: [
      { stix_id: 'ipv4-addr--ip', kind: 'baseline', reason: 'baseline_rejected' },
      { stix_id: 'relationship--9f8e7d6c-aaaa', kind: 'baseline', reason: 'baseline_refs_closure:x' },
      { stix_id: 'ipv4-addr--0123456789abcdef', kind: 'baseline', reason: 'baseline_rejected' },
      { stix_id: 'relationship--ffeeddcc-bbbb', kind: 'baseline', reason: 'baseline_rejected' },
    ] }
    const withRow = { ...importedRel(true), baseline_stix_id: 'relationship--9f8e7d6c-aaaa' }
    const g = buildBundleGraph(bundle, removedLedger,
      [imported('198.18.12.77', 'ipv4', 'ipv4-addr--ip', 'baseline_only', false)], [withRow])!
    const removed = g.diff.filter(d => d.kind === 'removed')
    expect(removed.map(d => [d.subject, d.title])).toEqual([
      ['object', '198.18.12.77'],
      ['relationship', 'APT29 uses WellMess'],
      ['object', 'IPv4 01234567'],
      ['relationship', 'relationship ffeeddcc'],
    ])
  })
})
