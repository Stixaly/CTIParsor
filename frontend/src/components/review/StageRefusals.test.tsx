import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { StageRecord } from '../../types'
import StageRefusals from './StageRefusals'

const RAN: StageRecord = { stage: '2', label: 'regex IoCs', status: 'ran', reason: '' }

const REFUSED: StageRecord = {
  stage: '3', label: 'LLM enrichment', status: 'skipped',
  reason: 'TLP:AMBER forbids sending the report to anthropic (api.anthropic.com): only a local provider may process it (ADR-0097)',
  egress: { tlp: 'AMBER', provider: 'anthropic', host: 'api.anthropic.com', local: false, allowed: false },
}

const skipped = (stage: string, reason = 'disabled'): StageRecord =>
  ({ stage, label: `stage ${stage}`, status: 'skipped', reason })

describe('StageRefusals', () => {
  it('folds an ordinary skip into a closed one-line summary', () => {
    const { container } = render(
      <StageRefusals stages={[RAN, { stage: '1f', label: 'figures', status: 'skipped', reason: 'no PDF' }]} />)
    const panel = screen.getByRole('region', { name: 'Stages that did not run' })
    expect(panel).toHaveTextContent('Stage 1f — figures: skipped — no PDF')
    expect(panel).not.toHaveTextContent('regex IoCs')
    expect(panel).not.toHaveTextContent('LLM extraction')       // an ordinary skip is not an egress refusal
    expect(panel).not.toHaveTextContent('Mark the report CLEAR')
    const details = container.querySelector('details')
    expect(details).not.toBeNull()
    expect(details!.open).toBe(false)
    expect(details!.querySelector('summary')).toHaveTextContent('1 stage skipped (1f)')
  })

  it('keeps a dozen skips to one summary line', () => {
    const many = ['1f', '2c', '2d', '2e', '3', '3d', '3f', '3e', '3doc', '3r', '2f', '4c'].map(s => skipped(s))
    const { container } = render(<StageRefusals stages={many} />)
    expect(container.querySelectorAll('details li')).toHaveLength(12)
    expect(Array.from(container.querySelectorAll('li')).filter(li => !li.closest('details'))).toHaveLength(0)
    expect(container.querySelector('summary')).toHaveTextContent('12 stages skipped (1f, 2c, 2d')
  })

  it('keeps a failed stage in view', () => {
    const { container } = render(
      <StageRefusals stages={[{ stage: '2e', label: 'GLiNER', status: 'failed', reason: 'model missing' }]} />)
    expect(screen.getByRole('region')).toHaveTextContent('Stage 2e — GLiNER: failed — model missing')
    expect(container.querySelector('details')).toBeNull()
  })

  it('highlights an egress refusal in view, says what to do, and folds the rest', () => {
    const { container } = render(<StageRefusals stages={[RAN, REFUSED, skipped('3d', 'Stage 3 did not run')]} />)
    expect(screen.getByRole('region')).toHaveTextContent(
      'Stage 3 — LLM enrichment: skipped — TLP:AMBER forbids sending the report to anthropic (api.anthropic.com)')
    const refusal = container.querySelector('[data-egress-refusal="true"]')
    expect(refusal).not.toBeNull()
    expect(refusal!.closest('details')).toBeNull()
    expect(screen.getByRole('region')).toHaveTextContent(/Mark the report CLEAR or GREEN.*configure a local model/)
    expect(container.querySelector('summary')).toHaveTextContent('1 stage skipped (3d)')
  })

  it('shows nothing when every stage ran, or when there is no report', () => {
    const { container, rerender } = render(<StageRefusals stages={[RAN]} />)
    expect(container).toBeEmptyDOMElement()
    rerender(<StageRefusals stages={undefined} />)
    expect(container).toBeEmptyDOMElement()
  })
})
