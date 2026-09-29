import { describe, it, expect } from 'vitest'
import { describeTime } from './provenance'

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
