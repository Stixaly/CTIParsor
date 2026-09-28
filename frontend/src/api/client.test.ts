import { describe, it, expect } from 'vitest'
import { errorDetail } from './client'

describe('errorDetail', () => {
  it('unwraps a FastAPI detail', () => {
    expect(errorDetail(new Error('400: {"detail":"Port 11434 is not allowed."}')))
      .toBe('Port 11434 is not allowed.')
  })

  it('keeps a plain-text body', () => {
    expect(errorDetail(new Error('502: Bad Gateway'))).toBe('Bad Gateway')
  })

  it('names the status when the body is empty (the dev proxy, API down)', () => {
    expect(errorDetail(new Error('500: '))).toBe('HTTP 500')
  })
})
