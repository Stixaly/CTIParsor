import { describe, it, expect } from 'vitest'
import type { UrlTransform } from 'react-markdown'
import { isAllowedImageSrc, markdownUrlTransform } from './markdownImages'

// The node argument of a urlTransform: only its tagName is read here.
const node = (tagName: string) => ({ tagName }) as Parameters<UrlTransform>[2]

describe('isAllowedImageSrc', () => {
  it('allows an inline data: image, whatever the case', () => {
    expect(isAllowedImageSrc('data:image/png;base64,iVBORw0KGgo=')).toBe(true)
    expect(isAllowedImageSrc('DATA:IMAGE/png;base64,iVBORw0KGgo=')).toBe(true)
  })

  it('refuses every other src, so nothing is requested', () => {
    expect(isAllowedImageSrc('https://x/p.png')).toBe(false)
    expect(isAllowedImageSrc('http://x/p.png')).toBe(false)
    expect(isAllowedImageSrc('//x/p.png')).toBe(false)
    expect(isAllowedImageSrc('img.png')).toBe(false)
    expect(isAllowedImageSrc('')).toBe(false)
    expect(isAllowedImageSrc(undefined)).toBe(false)
    expect(isAllowedImageSrc('data:text/html,<p>x</p>')).toBe(false)
    expect(isAllowedImageSrc('javascript:alert(1)')).toBe(false)
  })
})

describe('markdownUrlTransform', () => {
  it('keeps a data: image for img src, and leaves links to the default', () => {
    expect(markdownUrlTransform('data:image/png;base64,iVBORw0KGgo=', 'src', node('img')))
      .toBe('data:image/png;base64,iVBORw0KGgo=')
    // A data: URL on a link is still dropped by react-markdown's default.
    expect(markdownUrlTransform('data:image/png;base64,iVBORw0KGgo=', 'href', node('a'))).toBe('')
  })
})
