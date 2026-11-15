import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import type { Job } from '../../types'
import ActivityCard from './ActivityCard'
import { relTime } from './relTime'

// The rail of a running report follows the stage the progress stream last sent.
const sse = vi.hoisted(() => ({ latestStage: undefined as { stage?: number | string } | undefined }))
vi.mock('../../hooks/useSSE', () => ({ useSSE: () => ({ latestStage: sse.latestStage }) }))

const JOB: Job = {
  id: 'job-1', original_filename: 'apt29.pdf', status: 'processing',
  created_at: '2026-09-28T08:00:00Z', updated_at: '2026-09-28T08:00:00Z',
}

const railWidth = (container: HTMLElement) =>
  container.querySelector<HTMLElement>('div[style*="transition"]')?.style.width

describe('ActivityCard — the remove button (#875)', () => {
  it('has no remove button without an onDelete handler', () => {
    render(<ActivityCard job={JOB} relTime={relTime} onViewProgress={() => {}} />)
    expect(screen.queryByRole('button', { name: 'Remove job' })).not.toBeInTheDocument()
  })

  it('calls onDelete from the remove button when one is given', () => {
    const onDelete = vi.fn()
    render(<ActivityCard job={JOB} relTime={relTime} onViewProgress={() => {}} onDelete={onDelete} />)
    fireEvent.click(screen.getByRole('button', { name: 'Remove job' }))
    expect(onDelete).toHaveBeenCalledTimes(1)
  })
})

describe('ActivityCard — the rail of a sub-stage (#882)', () => {
  it('places the figures stage "1f" after Ingestion, not as NaN', () => {
    sse.latestStage = { stage: '1f' }
    const { container } = render(<ActivityCard job={JOB} relTime={relTime} onViewProgress={() => {}} />)
    expect(railWidth(container)).toBe('30%')
    expect(container.innerHTML).not.toContain('NaN')
  })

  it('still places a numeric stage (control)', () => {
    sse.latestStage = { stage: 2 }
    const { container } = render(<ActivityCard job={JOB} relTime={relTime} onViewProgress={() => {}} />)
    expect(railWidth(container)).toBe('40%')
  })
})
