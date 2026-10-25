import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import RelationshipRail, { ENDS_BY_NAME_TITLE, type DatePatch } from './RelationshipRail'
import { IMPORTED_TITLE } from './MarginaliaCard'
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

function renderRail(rels: Relationship[], onChangeDates: (id: string, patch: DatePatch) => void = noop) {
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

// ── ADR-0065 — what is left to review, grouped by target ─────────────────────

function renderFull(rels: Relationship[], over: Record<string, unknown> = {}) {
  const props = {
    rels,
    onAccept: vi.fn(), onReject: vi.fn(), onReset: vi.fn(), onJump: vi.fn(),
    onChangeType: vi.fn(), onChangeDates: vi.fn(),
    showInDoc: false, setShowInDoc: vi.fn(), onNewRelationship: vi.fn(),
    onBulk: vi.fn(),
    ...over,
  }
  render(<RelationshipRail {...props} />)
  return props
}

describe('RelationshipRail — review groups (ADR-0065)', () => {
  const byDefault = (id: string, src: string, tgt: string) =>
    rel({ id, source_value: src, target_value: tgt, accepted: true, decision_origin: 'default' })

  it('lists rows the pipeline accepted by default under "to review", with a chip', () => {
    renderFull([byDefault('r1', 'APT29', 'WellMess'),
                rel({ id: 'r2', accepted: true, decision_origin: 'human' })])
    expect(screen.getByRole('button', { name: /to review 1/ })).toBeTruthy()
    expect(screen.getByRole('button', { name: /accepted 1/ })).toBeTruthy()
    expect(screen.getByText('default')).toBeTruthy()
  })

  it('groups the rows sharing a target and decides a group in one call', async () => {
    const user = userEvent.setup()
    const props = renderFull([
      byDefault('r1', 'APT29', 'WellMess'),
      byDefault('r2', 'Cozy Bear', 'wellmess'),     // same target, other case
      byDefault('r3', 'APT29', 'Ukraine'),
    ])
    const group = screen.getByRole('group', { name: 'Relationships to WellMess' })
    expect(group.textContent).toContain('2 relationships')
    await user.click(screen.getByTitle('Accept these 2 relationships'))
    expect(props.onBulk).toHaveBeenCalledWith(['r1', 'r2'], 'accept')
    // A row alone under its target gets no group header.
    expect(screen.queryByRole('group', { name: 'Relationships to Ukraine' })).toBeNull()
  })

  it('can be shown flat again', async () => {
    const user = userEvent.setup()
    renderFull([byDefault('r1', 'A', 'X'), byDefault('r2', 'B', 'X')])
    await user.click(screen.getByRole('button', { name: 'by target' }))
    expect(screen.queryByRole('group')).toBeNull()
  })

  it('✓ on a row accepted by default confirms it instead of resetting it', async () => {
    const user = userEvent.setup()
    const props = renderFull([byDefault('r1', 'APT29', 'WellMess')])
    await user.click(screen.getByTitle('Confirm (accepted by default, not reviewed)'))
    expect(props.onAccept).toHaveBeenCalledWith('r1')
    expect(props.onReset).not.toHaveBeenCalled()
  })
})

describe('RelationshipRail — claims held for review (ADR-0082)', () => {
  it('says a held claim waits for this card, and why', () => {
    renderRail([rel({ held_reason: 'quote not found in the text' })])
    const badge = screen.getByText('held')
    expect(badge.getAttribute('title')).toContain('quote not found in the text')
    expect(badge.getAttribute('title')).toContain('Not in the bundle until you accept it')
  })

  it('shows no badge once the claim is decided, nor on a claim nobody held', () => {
    renderRail([rel({ id: 'r1', held_reason: 'verification call failed', accepted: true }),
                rel({ id: 'r2', target_value: 'SUNBURST' })])
    expect(screen.queryByText('held')).toBeNull()
  })
})

// ── ADR-0090 — relationships from the analyst's STIX 2.1 bundle ──────────────

describe('RelationshipRail — the STIX bundle filter (ADR-0090)', () => {
  it('shows the bundle filter only when some row has a bundle status', () => {
    renderFull([rel({ id: 'r1' })])
    expect(screen.queryByRole('group', { name: 'Filter by STIX bundle' })).toBeNull()
  })

  it('combines the bundle filter with the tabs: both apply', async () => {
    const user = userEvent.setup()
    renderFull([
      rel({ id: 'r1', target_value: 'WellMess', enrichment_status: 'new' }),
      rel({ id: 'r2', target_value: 'Ukraine', enrichment_status: 'matched' }),
      rel({ id: 'r3', target_value: 'Emotet', enrichment_status: 'new', accepted: true, decision_origin: 'human' }),
    ])
    // "to review" (the default tab) with "+ New": r1 only.
    await user.click(screen.getByRole('button', { name: /^\+ New/ }))
    expect(screen.getByRole('button', { name: 'WellMess' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Ukraine' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Emotet' })).toBeNull()

    // "accepted" with "+ New": r3 only.
    await user.click(screen.getByRole('button', { name: /^accepted/ }))
    expect(screen.getByRole('button', { name: 'Emotet' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'WellMess' })).toBeNull()

    // "accepted" with "In STIX": nothing, and the rail says so.  The tab has
    // rows; the bundle segment is what empties the list.
    await user.click(screen.getByRole('button', { name: /^In STIX/ }))
    expect(screen.getByText('No relationship matches these filters.')).toBeTruthy()
    expect(screen.queryByText(/All caught up/)).toBeNull()
  })

  it('says all is caught up when the tab alone leaves nothing', async () => {
    const user = userEvent.setup()
    renderFull([rel({ id: 'r1', enrichment_status: 'new', accepted: true, decision_origin: 'human' })])
    // "to review" is empty here, and no row is in it for any segment.
    await user.click(screen.getByRole('button', { name: /^In STIX/ }))
    expect(screen.getByText('All caught up. Nothing in "to review."')).toBeTruthy()
    expect(screen.queryByText('No relationship matches these filters.')).toBeNull()
  })
})

describe('RelationshipRail — a relationship the bundle supplied (ADR-0090)', () => {
  const imported = (over: Partial<Relationship> = {}) =>
    rel({ id: 'r-imp', enrichment_status: 'baseline_in_text', accepted: true,
          decision_origin: 'baseline_stix', ...over })

  it('keeps its verb and dates read-only, and says why', () => {
    renderFull([imported({ start_time: '2021', stop_time: null })])
    fireEvent.click(screen.getByRole('button', { name: /^accepted/ }))
    const verb = screen.getByRole('button', { name: /^uses/ })
    expect(verb).toBeDisabled()
    expect(verb.getAttribute('title')).toBe(IMPORTED_TITLE)
    const dates = screen.getByRole('button', { name: '2021 → ?' })
    expect(dates).toBeDisabled()
    expect(dates.getAttribute('title')).toBe(IMPORTED_TITLE)
    // Accept and reject stay.
    expect(screen.getByTitle('Accept')).toBeEnabled()
    expect(screen.getByTitle('Reject')).toBeEnabled()
  })

  it('shows no dates control on an imported relationship that has none', () => {
    renderFull([imported()])
    fireEvent.click(screen.getByRole('button', { name: /^accepted/ }))
    expect(screen.queryByText('+ dates')).toBeNull()
    expect(screen.queryByRole('button', { name: /→/ })).toBeNull()
  })

  it('leaves the verb and dates of a row that is not imported editable', () => {
    renderFull([rel({ id: 'r1', enrichment_status: 'new' })])
    expect(screen.getByRole('button', { name: /^uses/ })).toBeEnabled()
    expect(screen.getByRole('button', { name: '+ dates' })).toBeEnabled()
  })

  it('says a matched relationship whose two ends came from the bundle names got them so', () => {
    renderFull([rel({ id: 'r1', enrichment_status: 'matched', accepted: null })],
               { getEntityEnrichment: (v: string) => (v === 'APT29' || v === 'WellMess' ? 'baseline_only' : null) })
    expect(screen.getByText('in STIX').getAttribute('title')).toBe(ENDS_BY_NAME_TITLE)
  })

  it('keeps the standard title when only one end came from the bundle names', () => {
    renderFull([rel({ id: 'r1', enrichment_status: 'matched', accepted: null })],
               { getEntityEnrichment: (v: string) => (v === 'APT29' ? 'baseline_only' : 'matched') })
    expect(screen.getByText('in STIX').getAttribute('title')).toBe('Already in the supplied STIX bundle')
  })
})
