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

describe('StageRefusals', () => {
  it('lists a skipped stage with its reason', () => {
    render(<StageRefusals stages={[RAN, { stage: '1f', label: 'figures', status: 'skipped', reason: 'no PDF' }]} />)
    const panel = screen.getByRole('region', { name: 'Stages that did not run' })
    expect(panel).toHaveTextContent('Stage 1f — figures: skipped — no PDF')
    expect(panel).not.toHaveTextContent('regex IoCs')
    expect(panel).not.toHaveTextContent('LLM extraction')       // an ordinary skip is not an egress refusal
    expect(panel).not.toHaveTextContent('Mark the report CLEAR')
  })

  it('lists a failed stage', () => {
    render(<StageRefusals stages={[{ stage: '2e', label: 'GLiNER', status: 'failed', reason: 'model missing' }]} />)
    expect(screen.getByRole('region')).toHaveTextContent('Stage 2e — GLiNER: failed — model missing')
  })

  it('highlights an egress refusal and says what to do', () => {
    const { container } = render(<StageRefusals stages={[RAN, REFUSED]} />)
    expect(screen.getByRole('region')).toHaveTextContent(
      'Stage 3 — LLM enrichment: skipped — TLP:AMBER forbids sending the report to anthropic (api.anthropic.com)')
    expect(container.querySelector('[data-egress-refusal="true"]')).not.toBeNull()
    expect(screen.getByRole('region')).toHaveTextContent(/Mark the report CLEAR or GREEN.*configure a local model/)
  })

  it('shows nothing when every stage ran, or when there is no report', () => {
    const { container, rerender } = render(<StageRefusals stages={[RAN]} />)
    expect(container).toBeEmptyDOMElement()
    rerender(<StageRefusals stages={undefined} />)
    expect(container).toBeEmptyDOMElement()
  })
})
