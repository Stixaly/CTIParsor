import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import RelationshipRail from './RelationshipRail'
import type { Relationship } from '../../types'

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

describe('RelationshipRail — start_time / stop_time editing', () => {
  it('shows a "+ dates" prompt when no dates are set', () => {
    renderRail([rel()])
    expect(screen.getByText('+ dates')).toBeTruthy()
  })

  it('shows the date range when start_time/stop_time are set', () => {
    renderRail([rel({ start_time: '2022-11-04T00:00:00+00:00', stop_time: '2023-03-01T00:00:00+00:00' })])
    expect(screen.getByText('2022-11-04 → 2023-03-01')).toBeTruthy()
  })

  it('shows a partial range with "?" for the missing bound', () => {
    renderRail([rel({ start_time: '2022-11-04T00:00:00+00:00', stop_time: null })])
    expect(screen.getByText('2022-11-04 → ?')).toBeTruthy()
  })

  it('clicking the dates badge reveals two date inputs', async () => {
    const user = userEvent.setup()
    renderRail([rel()])
    await user.click(screen.getByText('+ dates'))
    const dateInputs = document.querySelectorAll('input[type="date"]')
    expect(dateInputs.length).toBe(2)
  })

  it('changing the start date input calls onChangeDates with the new start and existing stop', async () => {
    const user = userEvent.setup()
    const onChangeDates = vi.fn()
    renderRail(
      [rel({ id: 'r1', start_time: null, stop_time: '2023-03-01T00:00:00+00:00' })],
      onChangeDates,
    )
    await user.click(screen.getByText('? → 2023-03-01'))
    const [startInput] = document.querySelectorAll('input[type="date"]')
    await user.type(startInput as HTMLInputElement, '2022-11-04')
    expect(onChangeDates).toHaveBeenCalledWith('r1', '2022-11-04', '2023-03-01T00:00:00+00:00')
  })

  it('clicking Done exits edit mode', async () => {
    const user = userEvent.setup()
    renderRail([rel()])
    await user.click(screen.getByText('+ dates'))
    expect(document.querySelectorAll('input[type="date"]').length).toBe(2)
    await user.click(screen.getByTitle('Done'))
    expect(document.querySelectorAll('input[type="date"]').length).toBe(0)
    expect(screen.getByText('+ dates')).toBeTruthy()
  })
})
