import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import MarkdownPreview from './MarkdownPreview'

// The preview fetches no image: each request would tell the report's author the analyst's address.
describe('MarkdownPreview — images', () => {
  it('draws no img for an external image, and shows its alt text in a placeholder', () => {
    const { container } = render(<MarkdownPreview source="Beacon: ![logo](https://tracker.example/p.png)" />)

    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByText('logo')).toBeInTheDocument()
    expect(screen.getByText('external image not loaded')).toBeInTheDocument()
  })

  it('keeps the src of a data: image', () => {
    const src = 'data:image/png;base64,iVBORw0KGgo='
    const { container } = render(<MarkdownPreview source={`![pixel](${src})`} />)

    const img = container.querySelector('img')
    expect(img).toHaveAttribute('src', src)
    expect(img).toHaveAttribute('alt', 'pixel')
  })

  it('does not draw an img from raw HTML either', () => {
    const { container } = render(<MarkdownPreview source={'<img src="https://tracker.example/p.png" alt="x">'} />)

    expect(container.querySelector('img')).toBeNull()
  })

  it('leaves links as they are', () => {
    render(<MarkdownPreview source="[APT29 report](https://example.org/apt29)" />)

    expect(screen.getByRole('link', { name: 'APT29 report' })).toHaveAttribute('href', 'https://example.org/apt29')
  })
})
