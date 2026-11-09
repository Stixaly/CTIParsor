import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import EvidenceGateBanner from './EvidenceGateBanner'

// Regression tests for #628: the percentage and the "of X ATT&CK-tagged" label
// must compare tagged rules only, since ruleTotal includes untagged (YARA) rules.

const base = { corroboratedCount: 0, brandCount: 0 }

describe('EvidenceGateBanner (#628)', () => {
  it('never shows a percentage above 100% when untagged rules are present', () => {
    // 5 rules with evidence, 4 of them untagged -> 1 tagged rule with evidence over 2 tagged.
    const { container } = render(
      <EvidenceGateBanner ruleTotal={5} tagTotal={2} untaggedCount={4} {...base} />,
    )
    const text = container.textContent ?? ''
    expect(text).toContain('50%')
    expect(text).not.toMatch(/\d{3,}%/)
    expect(text).toMatch(/[0-9]+%/)
    const pcts = (text.match(/\d+%/g) ?? []).map(s => parseInt(s, 10))
    expect(pcts.every(p => p >= 0 && p <= 100)).toBe(true)
    // tagTotal (2) > taggedWithEvidence (1): the label must be shown.
    expect(screen.getByText(/of 2 ATT&CK-tagged/)).toBeTruthy()
  })

  it('clamps the percentage to 100 when tagged evidence exceeds tagTotal', () => {
    const { container } = render(
      <EvidenceGateBanner ruleTotal={9} tagTotal={2} untaggedCount={1} {...base} />,
    )
    // taggedWithEvidence = 8, tagTotal = 2 -> raw 400%, clamped to 100%.
    expect(container.textContent).toContain('100%')
    expect(container.textContent).not.toContain('400%')
    // tagTotal (2) < taggedWithEvidence (8): no tagged-total label.
    expect(screen.queryByText(/ATT&CK-tagged/)).toBeNull()
  })

  it('shows "of 4 ATT&CK-tagged" and 75% when there are no untagged rules', () => {
    const { container } = render(
      <EvidenceGateBanner ruleTotal={3} tagTotal={4} untaggedCount={0} {...base} />,
    )
    expect(screen.getByText(/of 4 ATT&CK-tagged/)).toBeTruthy()
    expect(container.textContent).toContain('75%')
  })

  it('omits the percentage when there are no tagged rules', () => {
    const { container } = render(
      <EvidenceGateBanner ruleTotal={2} tagTotal={0} untaggedCount={2} {...base} />,
    )
    expect(container.textContent).not.toContain('%')
    expect(screen.queryByText(/ATT&CK-tagged/)).toBeNull()
  })
})
