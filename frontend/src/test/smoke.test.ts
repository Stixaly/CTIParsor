import { describe, it, expect } from 'vitest'

describe('vitest setup', () => {
  it('runs', () => {
    expect(1 + 1).toBe(2)
  })

  it('has a jsdom document', () => {
    expect(typeof document).toBe('object')
    document.body.innerHTML = '<span>hi</span>'
    expect(document.querySelector('span')?.textContent).toBe('hi')
  })
})
