import { describe, it, expect } from 'vitest'
import {
  describeTime, edgeKindOf, EDGE_KIND_ORDER, EDGE_KIND_STYLE, EDGE_ORIGIN_LABEL, entityReason,
  isFromBaseline, isRenamed, OBJECT_ORIGIN_LABEL, reasonRef, relationshipReason,
} from './provenance'

describe('describeTime — what the export did with a date (ADR-0063)', () => {
  it('names the native property an exported date fills', () => {
    expect(describeTime({ kind: 'time', id: 'a', role: 'start', value: '2023-06-20T14:32:00+02:00',
                          precision: 'instant', status: 'verified', outcome: 'exported',
                          field: 'start_time' }))
      .toBe('start 2023-06-20T14:32:00+02:00 (instant) fills start_time')
  })

  it('says a projection adds the time and zone', () => {
    expect(describeTime({ kind: 'time', id: 'b', role: 'end', value: '2023-06-20', precision: 'day',
                          status: 'verified', outcome: 'projected', field: 'stop_time' }))
      .toContain('projected on the whole day in UTC')
  })

  it('explains why a date stays out of the native bounds', () => {
    expect(describeTime({ kind: 'time', id: 'c', role: 'start', value: '2023-03', precision: 'month',
                          status: 'verified', outcome: 'withheld', reason: 'precision_below_policy' }))
      .toBe('start 2023-03 (month) kept in x_temporal_assertions only: '
            + 'its precision is coarser than the export policy allows a native timestamp')
  })
})

describe('baseline vocabulary — the analyst’s STIX bundle (ADR-0090)', () => {
  it('is true for a baseline object and the re-issued report, and for nothing CTIParsor built', () => {
    expect(isFromBaseline('baseline')).toBe(true)
    expect(isFromBaseline('baseline_report_upsert')).toBe(true)
    expect(isFromBaseline('entity')).toBe(false)
    expect(isFromBaseline('extracted')).toBe(false)
    expect(isFromBaseline(undefined)).toBe(false)
  })

  it('says where a baseline object and the re-issued report come from', () => {
    expect(OBJECT_ORIGIN_LABEL.baseline).toBe('From your STIX bundle, as received')
    expect(OBJECT_ORIGIN_LABEL.baseline_report_upsert).toContain('re-issued')
  })

  it('explains a match, a rejection and a report with nothing left to list', () => {
    expect(entityReason('baseline_match')).toContain('ships in its place')
    expect(entityReason('baseline_rejected')).toContain('left out of this bundle')
    expect(entityReason('baseline_refs_closure')).toContain('cannot ship')
    expect(entityReason('baseline_report_empty')).toContain('not re-issued')
  })

  it('explains a bare ATT&CK id named after its technique, and counts it a rename', () => {
    expect(entityReason('attack_id_named')).toContain('named after its technique')
    expect(isRenamed('attack_id_named')).toBe(true)
    expect(isRenamed('alias_canonical')).toBe(true)
    expect(isRenamed('same_value')).toBe(false)
    expect(isRenamed(undefined)).toBe(false)
  })

  it('explains a name that denotes objects of several types', () => {
    expect(relationshipReason('ambiguous_name')).toContain('several types')
    expect(entityReason('ambiguous_name')).toContain('which one the IoC indicates')
  })

  it('explains a relationship that the baseline merge made a loop or a duplicate', () => {
    expect(relationshipReason('self_loop_after_baseline_merge')).toContain('same object')
    expect(relationshipReason('duplicate_after_baseline_merge')).toContain('already ships')
  })

  it('draws a relationship of the analyst’s bundle as its own kind, not as unclassified', () => {
    expect(edgeKindOf('baseline')).toBe('baseline')
    expect(EDGE_ORIGIN_LABEL.baseline).toBe('Relationship of your STIX bundle, as received')
    expect(EDGE_KIND_STYLE.baseline.label).toBe('From your STIX bundle')
    expect(EDGE_KIND_STYLE.baseline.stroke).not.toBe(EDGE_KIND_STYLE.extracted.stroke)
    expect(EDGE_KIND_ORDER.indexOf('baseline')).toBe(EDGE_KIND_ORDER.indexOf('extracted') + 1)
  })

  it('lists every edge kind once in the legend order', () => {
    expect([...EDGE_KIND_ORDER].sort()).toEqual(Object.keys(EDGE_KIND_STYLE).sort())
  })
})

describe('one type per name, by source rank (ADR-0092)', () => {
  it('explains a type that another source of the same name outranks, and how to keep it', () => {
    expect(entityReason('outranked_type')).toContain('ranks higher')
    expect(entityReason('outranked_type')).toContain('on its own')
  })
})

describe('reasons that name the object behind them (ADR-0090)', () => {
  it('reads the reason before the colon and keeps the id after it', () => {
    expect(entityReason('baseline_refs_closure:malware--1')).toBe(entityReason('baseline_refs_closure'))
    expect(reasonRef('baseline_refs_closure:malware--1')).toBe('malware--1')
    expect(reasonRef('baseline_rejected')).toBeNull()
    expect(reasonRef(undefined)).toBeNull()
  })
})
