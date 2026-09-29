import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import RelationshipRail from './RelationshipRail'
import type { Relationship, TemporalAssertion } from '../../types'

const rel = (over: Partial<Relationship> = {}): Relationship => ({
  id: 'r1',
  job_id: 'job-1',
  source_value: 'APT29',
  relationship_type: 'uses',
  target_value: 'WellMess',
  confidence: 0.9,
  accepted: null,
  evidence_text: null,
  ...over,
} as Relationship)

const noop = () => {}
const noopNum = (_x: number, _y: number) => {}

function renderRail(rels: Relationship[], onChangeDates = noop as any) {
  return render(
    <RelationshipRail
      rels={rels}
      onAccept={noop}
      onReject={noop}
      onReset={noop}
      onJump={noop}
      onChangeType={noop}
      onChangeDates={onChangeDates}
      showInDoc={false}
      setShowInDoc={noop}
      onNewRelationship={noopNum}
    />,
  )
}

describe('RelationshipRail — relationship dates (ADR-0063)', () => {
  it('shows a "+ dates" prompt when no dates are set', () => {
    renderRail([rel()])
    expect(screen.getByText('+ dates')).toBeTruthy()
  })

  it('shows each bound at its own precision, never padded', () => {
    renderRail([rel({ start_time: '2022-11', stop_time: '2023-03-01T10:00:00+00:00' })])
    expect(screen.getByText('2022-11 → 2023-03-01 10:00')).toBeTruthy()
  })

  it('shows a partial range with "?" for the missing bound', () => {
    renderRail([rel({ start_time: '2022', stop_time: null })])
    expect(screen.getByText('2022 → ?')).toBeTruthy()
  })

  it('clicking the dates badge reveals a start and an end field that take any precision', async () => {
    const user = userEvent.setup()
    renderRail([rel()])
    await user.click(screen.getByText('+ dates'))
    expect(screen.getByLabelText('start')).toBeTruthy()
    expect(screen.getByLabelText('end')).toBeTruthy()
    expect(document.querySelectorAll('input[type="date"]').length).toBe(0)
  })

  it('commits on Enter, sends only the bound that changed, never per keystroke', async () => {
    const user = userEvent.setup()
    const onChangeDates = vi.fn()
    renderRail([rel({ id: 'r1', start_time: null, stop_time: '2023-03' })], onChangeDates)
    await user.click(screen.getByText('? → 2023-03'))
    await user.type(screen.getByLabelText('start'), '2022-11')
    expect(onChangeDates).not.toHaveBeenCalled()
    await user.keyboard('{Enter}')
    expect(onChangeDates).toHaveBeenCalledTimes(1)
    expect(onChangeDates).toHaveBeenCalledWith('r1', { start_time: '2022-11' })
  })

  it('clearing a bound sends null for that bound only; leaving it untouched sends nothing', async () => {
    const user = userEvent.setup()
    const onChangeDates = vi.fn()
    renderRail([rel({ id: 'r1', start_time: '2021', stop_time: '2023' })], onChangeDates)
    await user.click(screen.getByText('2021 → 2023'))
    await user.click(screen.getByLabelText('end'))
    await user.tab()                                   // blur without a change
    expect(onChangeDates).not.toHaveBeenCalled()
    await user.clear(screen.getByLabelText('start'))
    await user.tab()
    expect(onChangeDates).toHaveBeenCalledWith('r1', { start_time: null })
  })

  it('lists every date with its status, and says why one is not verified', () => {
    const times: TemporalAssertion[] = [
      { id: 'a', role: 'start', time_text: 'since March 2023', value: '2023-03', precision: 'month',
        status: 'verified', origin: 'llm' },
      { id: 'b', role: 'within', time_text: 'last month', alternatives: ['2026-08'],
        status: 'unresolved', reason: 'weak_anchor', origin: 'llm' },
    ]
    renderRail([rel({ times })])
    expect(screen.getByText('“since March 2023”')).toBeTruthy()
    expect(screen.getByText('verified')).toBeTruthy()
    const unresolved = screen.getByText('unresolved').closest('li') as HTMLElement
    expect(unresolved.title).toContain('only the file timestamp is known')
    expect(unresolved.title).toContain('2026-08')
  })

  it('clicking Done exits edit mode', async () => {
    const user = userEvent.setup()
    renderRail([rel()])
    await user.click(screen.getByText('+ dates'))
    expect(screen.getByLabelText('start')).toBeTruthy()
    await user.click(screen.getByTitle('Done'))
    expect(screen.queryByLabelText('start')).toBeNull()
    expect(screen.getByText('+ dates')).toBeTruthy()
  })
})
