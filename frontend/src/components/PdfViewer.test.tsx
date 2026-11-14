import { describe, it, expect, vi } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useEffect } from 'react'
import PdfViewer from './PdfViewer'

// #347: after a load error <Document> was unmounted for good; a new URL must
// get a new attempt.  react-pdf is replaced by a Document that fails on "bad".
// Every other document has one page, which reports its rotation and scale (#562).
// slow.pdf answers its page 1 only when the test resolves it (#828).
const slowPage = vi.hoisted(() => ({ resolve: null as ((p: unknown) => void) | null }))

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
      else if (file === 'slow.pdf') onLoadSuccess({
        numPages: 3,
        getPage: () => new Promise(r => { slowPage.resolve = r }),
      })
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

  // #828: page 1 of a document the url has left must not write its page count over the new one.
  it('ignores the page count of a document that was replaced while its page 1 was read (#828)', async () => {
    const { rerender } = render(<PdfViewer url="slow.pdf" filename="slow.pdf" entities={[]} />)
    await waitFor(() => expect(slowPage.resolve).not.toBeNull())

    rerender(<PdfViewer url="good.pdf" filename="good.pdf" entities={[]} />)
    expect(await screen.findByText('1 / 1')).toBeInTheDocument()

    await act(async () => { slowPage.resolve?.({ getViewport: () => ({ width: 1200, height: 1500 }) }) })

    expect(screen.getByText('1 / 1')).toBeInTheDocument()
    expect(screen.queryByText('1 / 3')).not.toBeInTheDocument()
  })
})
