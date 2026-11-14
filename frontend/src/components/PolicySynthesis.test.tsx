import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { LastRunPanel } from './PolicySynthesis'

function renderPanel(evidenceOn: boolean, onSelectWindow = vi.fn()) {
  render(
    <LastRunPanel
      run={undefined}
      mode="fair-share"
      evidenceOn={evidenceOn}
      windowSize={3}
      onSelectBudgetMode={vi.fn()}
      onToggleEvidence={vi.fn()}
      onSelectWindow={onSelectWindow}
    />,
  )
  return onSelectWindow
}

// #825: the window segment group was dimmed by CSS only, so a keyboard user could
// still reach and press its buttons while the evidence gate was off.
describe('LastRunPanel — evidence window controls (#825)', () => {
  it('disables the window buttons while the evidence gate is off', () => {
    const onSelectWindow = renderPanel(false)
    for (const name of ['Strict', 'Normal', 'Wide']) {
      expect(screen.getByRole('button', { name })).toBeDisabled()
    }
    fireEvent.click(screen.getByRole('button', { name: 'Wide' }))
    expect(onSelectWindow).not.toHaveBeenCalled()
  })

  it('enables the window buttons while the evidence gate is on', () => {
    renderPanel(true)
    expect(screen.getByRole('button', { name: 'Wide' })).toBeEnabled()
  })
})
