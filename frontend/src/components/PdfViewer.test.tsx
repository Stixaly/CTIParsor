import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useEffect } from 'react'
import PdfViewer from './PdfViewer'

// #347: after a load error <Document> was unmounted for good; a new URL must
// get a new attempt.  react-pdf is replaced by a Document that fails on "bad".
// Every other document has one page, which reports its rotation and scale (#562).
vi.mock('react-pdf', () => ({
  pdfjs: { GlobalWorkerOptions: {} },
  Page: ({ scale, rotate }: { scale: number; rotate: number }) => (
    <div data-testid="page" data-scale={scale} data-rotate={rotate} />
  ),
  Document: ({ file, children, onLoadError, onLoadSuccess }: {
    file: string; children?: React.ReactNode; onLoadError: (e: Error) => void; onLoadSuccess: (pdf: object) => void
  }) => {
    useEffect(() => {
      if (file === 'bad.pdf') onLoadError(new Error('Invalid PDF structure'))
      else onLoadSuccess({
        numPages: 1,
        getPage: () => Promise.resolve({ getViewport: () => ({ width: 600, height: 800 }) }),
      })
    }, [file, onLoadError, onLoadSuccess])
    return <div data-testid="document">{file}{children}</div>
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

  // #562: a rotation or a manual zoom belongs to the document it was set on.
  it('opens a new document unrotated and fitted to the width (#562)', async () => {
    const user = userEvent.setup()
    const { rerender } = render(<PdfViewer url="first.pdf" filename="first.pdf" entities={[]} />)
    await user.click(await screen.findByTitle('Rotate'))
    await user.click(screen.getByTitle('Zoom in'))
    expect(await screen.findByTestId('page')).toHaveAttribute('data-rotate', '90')
    expect(screen.queryByTitle('Fitted to the width')).not.toBeInTheDocument()

    rerender(<PdfViewer url="second.pdf" filename="second.pdf" entities={[]} />)

    await waitFor(() => expect(screen.getByTestId('page')).toHaveAttribute('data-rotate', '0'))
    expect(screen.getByTitle('Fitted to the width')).toBeInTheDocument()
  })
})
