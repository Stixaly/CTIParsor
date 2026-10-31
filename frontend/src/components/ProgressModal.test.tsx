import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import ProgressModal from './ProgressModal'

// The progress dialog with the keyboard (WCAG 2.4.3): the focus moves in,
// stays in, and goes back to what opened it.  No server: the event stream says
// nothing, and the live graph is not drawn.
vi.mock('../hooks/useSSE', () => ({
  useSSE: () => ({ events: [], done: false, partialGraphEvents: [] }),
}))
vi.mock('./graph/GraphCanvas', () => ({ default: () => null }))

/** A button outside the dialog that has the focus, as "View progress" or Create job has when the dialog opens. */
function focusedButton(label: string): HTMLButtonElement {
  const button = document.createElement('button')
  button.textContent = label
  document.body.appendChild(button)
  button.focus()
  return button
}

describe('ProgressModal — the focus', () => {
  it('moves to Close when the dialog opens, and Tab and Shift+Tab keep it inside', () => {
    render(<ProgressModal jobId="job-1" filename="a.txt" onClose={() => {}} />)
    const close = screen.getByTitle('Dismiss — pipeline continues in background')
    expect(close).toHaveFocus()
    // fireEvent returns false when the dialog prevented the browser's own move.
    expect(fireEvent.keyDown(document, { key: 'Tab' })).toBe(false)
    expect(fireEvent.keyDown(document, { key: 'Tab', shiftKey: true })).toBe(false)
    expect(close).toHaveFocus()
  })

  it('closes on Escape', () => {
    const onClose = vi.fn()
    render(<ProgressModal jobId="job-1" filename="a.txt" onClose={onClose} />)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('goes back on close to the element that had it when the dialog opened', () => {
    const viewProgress = focusedButton('View progress →')
    const { unmount } = render(<ProgressModal jobId="job-1" filename="a.txt" onClose={() => {}} />)
    expect(viewProgress).not.toHaveFocus()
    unmount()
    expect(viewProgress).toHaveFocus()
    viewProgress.remove()
  })

  it('goes to returnFocusTo when that element is gone', () => {
    const createJob = focusedButton('Create job')
    const newReport = document.createElement('button')
    document.body.appendChild(newReport)
    const { unmount } = render(
      <ProgressModal jobId="job-1" filename="a.txt" onClose={() => {}} returnFocusTo={{ current: newReport }} />,
    )
    createJob.remove()                      // the new-report dialog closed with it
    unmount()
    expect(newReport).toHaveFocus()
    newReport.remove()
  })
})
