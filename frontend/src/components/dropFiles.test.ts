import { describe, it, expect } from 'vitest'
import { splitDrop } from './dropFiles'

// A drop of a report and a STIX bundle: the bundle is told apart by its content, not its name.

const BUNDLE = JSON.stringify({ type: 'bundle', id: 'bundle--1', objects: [] })
const PDF = () => new File(['%PDF-1.4'], 'apt29.pdf', { type: 'application/pdf' })
const bundle = (name = 'apt29-bundle.json') => new File([BUNDLE], name, { type: 'application/json' })
const plainJson = (name = 'config.json') => new File(['{"type":"settings"}'], name, { type: 'application/json' })
// A bundle written with a byte order mark, as Windows tools save UTF-16 text.
const utf16le = (text: string, name: string) => new File([Uint8Array.from([
  0xff, 0xfe, ...Array.from(text, c => c.charCodeAt(0)).flatMap(u => [u & 0xff, u >> 8]),
])], name, { type: 'application/json' })
// Whitespace first, then the bundle's type at the very end of a file over 64 KB.
const longJson = (tail: string, name: string) => new File(
  ['{"objects":[', ' '.repeat(100 * 1024), tail], name, { type: 'application/json' })

describe('splitDrop — a report and a bundle dropped together', () => {
  it('takes the PDF as the report and the bundle as the bundle', async () => {
    const pdf = PDF()
    const b = bundle()
    expect(await splitDrop([pdf, b])).toEqual({ report: pdf, bundle: b, ignored: [] })
  })

  it('takes a bundle dropped on its own as the bundle, with no report', async () => {
    const b = bundle()
    expect(await splitDrop([b])).toEqual({ report: null, bundle: b, ignored: [] })
  })

  it('ignores a JSON file that is not a bundle, names it, and keeps the PDF', async () => {
    const pdf = PDF()
    const json = plainJson()
    expect(await splitDrop([json, pdf])).toEqual({
      report: pdf, bundle: null, ignored: [{ file: json, why: 'not_a_bundle' }] })
  })

  it('keeps the first of two bundles, names the second, and reads no report from either', async () => {
    const first = bundle('first.json')
    const second = bundle('second.json')
    expect(await splitDrop([first, second])).toEqual({
      report: null, bundle: first, ignored: [{ file: second, why: 'second_bundle' }] })
  })

  it('looks at every file: a non-bundle JSON after the bundle is named as not a bundle', async () => {
    const first = bundle()
    const json = plainJson()
    expect(await splitDrop([first, json])).toEqual({
      report: null, bundle: first, ignored: [{ file: json, why: 'not_a_bundle' }] })
  })

  it('takes the first non-JSON file as the report, as before', async () => {
    const first = new File(['# one'], 'one.md', { type: 'text/markdown' })
    const second = new File(['# two'], 'two.md', { type: 'text/markdown' })
    expect(await splitDrop([first, second])).toEqual({ report: first, bundle: null, ignored: [] })
  })

  it('takes a .json whose marker says bundle as the bundle without parsing it: the server reports the error', async () => {
    const broken = new File(['{"type": "bundle"'], 'broken.json', { type: 'application/json' })
    expect(await splitDrop([broken])).toEqual({ report: null, bundle: broken, ignored: [] })
  })

  it('takes a UTF-16LE bundle with its byte order mark as the bundle', async () => {
    const b = utf16le(BUNDLE, 'windows.json')
    expect(await splitDrop([b])).toEqual({ report: null, bundle: b, ignored: [] })
  })

  it('takes a large .json whose "type": "bundle" is at the end as the bundle', async () => {
    const big = longJson(',"type":"bundle"}', 'big.json')
    expect(big.size).toBeGreaterThan(64 * 1024)
    expect(await splitDrop([big])).toEqual({ report: null, bundle: big, ignored: [] })
  })

  it('does not take a large .json without a bundle marker as the bundle, whatever its name', async () => {
    const big = longJson(',"type":"settings"}', 'huge.json')
    expect(await splitDrop([big])).toEqual({
      report: null, bundle: null, ignored: [{ file: big, why: 'not_a_bundle' }] })
  })

  it('does not take a PDF renamed .json as a bundle', async () => {
    const renamed = new File(['%PDF-1.4 "type": "bundle"'], 'apt29.json', { type: 'application/pdf' })
    expect(await splitDrop([renamed])).toEqual({
      report: null, bundle: null, ignored: [{ file: renamed, why: 'not_a_bundle' }] })
  })

  it('does not take a JSON array as a bundle', async () => {
    const array = new File(['[{"type":"bundle"}]'], 'array.json', { type: 'application/json' })
    expect(await splitDrop([array])).toEqual({
      report: null, bundle: null, ignored: [{ file: array, why: 'not_a_bundle' }] })
  })
})
