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

// The graph's side panels draw the same Markdown small and tight; the report preview is unchanged.
describe('MarkdownPreview — compact', () => {
  it('marks a compact preview md-compact and gives it no page padding', () => {
    const { container } = render(<MarkdownPreview source="**Why:** reported" compact />)

    const root = container.querySelector('.md-preview')
    expect(root).toHaveClass('md-compact')
    expect((root as HTMLElement).style.padding).toBe('')
  })

  it('leaves the default preview unmarked, with its page padding', () => {
    const { container } = render(<MarkdownPreview source="**Why:** reported" />)

    const root = container.querySelector('.md-preview')
    expect(root).not.toHaveClass('md-compact')
    expect(root).toHaveStyle({ padding: '32px 56px 60px' })
  })
})

// The report's text as pipeline/markdown_text.py escapes it (escape_inline, ADR-0093): a URL, a
// domain and an address are defanged, and `==` is backslash-escaped for OpenCTI's flexible markers.
// The strings are that function's output, copied as it gives them. The preview shows them as text.
describe('MarkdownPreview — report text (ADR-0093)', () => {
  it('shows defanged indicators and == as text, with no link', () => {
    const source = [
      'beacons to hxxp://evil.example/gate.php',
      'see www\\[.\\]evil.example',
      'mail ops\\[@\\]evil.example',
      'uint16(0) \\=\\= 0x5A4D and x \\=\\= 1',
    ].join('\n\n')
    const { container } = render(<MarkdownPreview compact source={source} />)

    expect(container.querySelector('a')).toBeNull()
    const text = container.textContent ?? ''
    expect(text).toContain('hxxp://evil.example/gate.php')
    expect(text).toContain('www[.]evil.example')
    expect(text).toContain('ops[@]evil.example')
    expect(text).toContain('uint16(0) == 0x5A4D and x == 1')
  })
})
