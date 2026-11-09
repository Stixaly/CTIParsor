import { describe, expect, it } from 'vitest'
import { bundleFilename } from './downloadBundle'

// Regression tests for #630: blank or extension-only source filenames must not
// produce a hidden "_stix.json" download.
describe('bundleFilename (#630)', () => {
  it('falls back to "bundle" when the filename is undefined', () => {
    expect(bundleFilename(undefined)).toBe('bundle_stix.json')
  })

  it('falls back to "bundle" when the filename is null', () => {
    expect(bundleFilename(null)).toBe('bundle_stix.json')
  })

  it('falls back to "bundle" when the filename is empty', () => {
    expect(bundleFilename('')).toBe('bundle_stix.json')
  })

  it('falls back to "bundle" when the filename is only whitespace', () => {
    expect(bundleFilename('   ')).toBe('bundle_stix.json')
  })

  it('strips the extension from a normal filename', () => {
    expect(bundleFilename('report.pdf')).toBe('report_stix.json')
  })

  it('falls back to "bundle" when the filename is only an extension', () => {
    expect(bundleFilename('.pdf')).toBe('bundle_stix.json')
  })
})
