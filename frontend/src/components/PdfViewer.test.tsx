import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { useEffect } from 'react'
import PdfViewer from './PdfViewer'

// #347: after a load error <Document> was unmounted for good; a new URL must
// get a new attempt.  react-pdf is replaced by a Document that fails on "bad".
vi.mock('react-pdf', () => ({
  pdfjs: { GlobalWorkerOptions: {} },
  Page: () => null,
  Document: ({ file, onLoadError, onLoadSuccess }: {
    file: string; onLoadError: (e: Error) => void; onLoadSuccess: (pdf: object) => void
  }) => {
    useEffect(() => {
      if (file === 'bad.pdf') onLoadError(new Error('Invalid PDF structure'))
      else onLoadSuccess({ numPages: 0, getPage: () => Promise.reject(new Error('no page')) })
    }, [file, onLoadError, onLoadSuccess])
    return <div data-testid="document">{file}</div>
  },
}))

describe('PdfViewer', () => {
  it('tries again when the URL changes after a load error', async () => {
    const { rerender } = render(<PdfViewer url="bad.pdf" filename="a.pdf" entities={[]} />)
    expect(await screen.findByText('Invalid PDF structure')).toBeInTheDocument()
    expect(screen.queryByTestId('document')).not.toBeInTheDocument()

    rerender(<PdfViewer url="good.pdf" filename="a.pdf" entities={[]} />)
    expect(await screen.findByTestId('document')).toHaveTextContent('good.pdf')
    expect(screen.queryByText('Invalid PDF structure')).not.toBeInTheDocument()
  })
})
