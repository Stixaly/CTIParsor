import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import ProgressModal from './ProgressModal'

// What the dialog says about a run that did not succeed: a failed stage is not
// ticked green (#347), and a stream lost after repeated errors is not a
// success (#293).
const sse = vi.hoisted(() => ({ value: { events: [] as object[], done: false, lost: false, partialGraphEvents: [] } }))
vi.mock('../hooks/useSSE', () => ({ useSSE: () => sse.value }))
vi.mock('./graph/GraphCanvas', () => ({ default: () => null }))

beforeEach(() => {
  sse.value = { events: [], done: false, lost: false, partialGraphEvents: [] }
})

describe('ProgressModal — the outcome', () => {
  it('does not tick the stage a failed run stopped in', () => {
    sse.value = {
      events: [{ stage: 1, chars: 10, chunks: 1 }, { stage: 2, entities: 3 }, { stage: 3 },
        { status: 'failed' }],
      done: true, lost: false, partialGraphEvents: [],
    }
    const { container } = render(<ProgressModal jobId="j" filename="a.txt" onClose={() => {}} />)
    expect(screen.getByText(/Pipeline failed/)).toBeInTheDocument()
    expect(screen.queryByText(/Complete — ready for review/)).not.toBeInTheDocument()
    // Stages 1 and 2 finished before the failure; stage 3 did not.
    const ticks = container.querySelectorAll('.lucide-circle-check-big, .lucide-check-circle-2, .lucide-circle-check')
    expect(ticks.length).toBe(2)
  })

  it('says the stream was lost instead of announcing a success', () => {
    sse.value = { events: [{ stage: 1, chars: 10, chunks: 1 }], done: true, lost: true, partialGraphEvents: [] }
    const { container } = render(<ProgressModal jobId="j" filename="a.txt" onClose={() => {}} />)
    expect(screen.getByText(/Lost the connection to the progress stream/)).toBeInTheDocument()
    expect(screen.queryByText(/Complete — ready for review/)).not.toBeInTheDocument()
    expect(container.querySelectorAll('.lucide-circle-check-big, .lucide-check-circle-2, .lucide-circle-check').length)
      .toBe(0)
  })

  it('ticks every stage that ran once the run succeeded', () => {
    sse.value = {
      events: [{ stage: 1, chars: 10, chunks: 1 }, { stage: 2, entities: 3 }, { status: 'completed' }],
      done: true, lost: false, partialGraphEvents: [],
    }
    const { container } = render(<ProgressModal jobId="j" filename="a.txt" onClose={() => {}} />)
    expect(screen.getByText(/Complete — ready for review/)).toBeInTheDocument()
    // Two stage ticks plus the footer's.
    expect(container.querySelectorAll('.lucide-circle-check-big, .lucide-check-circle-2, .lucide-circle-check').length)
      .toBe(3)
  })
})
