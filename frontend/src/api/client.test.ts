import { afterEach, describe, it, expect, vi } from 'vitest'
import { BundleRefusedError, errorDetail, fetchAttackIndex, fetchBundle, finalizeJob } from './client'

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

// The schemas refused the bundle: the API answers 409 with an object `detail`.
const REFUSED = JSON.stringify({ detail: { validation: 'invalid', errors: ['bad id', 'bad ref', 'bad type', 'bad date'] } })

function answer(status: number, body: string) {
  vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({
    ok: false, status, statusText: 'Error', text: () => Promise.resolve(body),
  })))
}

const failure = (p: Promise<unknown>) => p.catch((e: unknown) => e) as Promise<Error>

describe('a bundle the STIX schemas refused', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('is a BundleRefusedError with its errors and a message that starts with the status', async () => {
    answer(409, REFUSED)
    const err = await failure(fetchBundle('j1'))
    expect(err).toBeInstanceOf(BundleRefusedError)
    expect((err as BundleRefusedError).errors).toEqual(['bad id', 'bad ref', 'bad type', 'bad date'])
    expect(err.message).toBe('409: the STIX 2.1 schemas refused this bundle — bad id')
  })

  it('is the same whichever route refuses it', async () => {
    answer(409, REFUSED)
    expect(await failure(finalizeJob('j1'))).toBeInstanceOf(BundleRefusedError)
  })

  it('leaves every other error as it was', async () => {
    answer(404, '{"detail":"Bundle not yet available"}')
    const missing = await failure(fetchBundle('j1'))
    expect(missing).not.toBeInstanceOf(BundleRefusedError)
    expect(missing.message).toBe('404: {"detail":"Bundle not yet available"}')

    answer(422, JSON.stringify({ detail: [{ msg: 'field required' }] }))
    expect(await failure(fetchBundle('j1'))).not.toBeInstanceOf(BundleRefusedError)

    answer(500, 'Internal Server Error')
    expect((await failure(fetchBundle('j1'))).message).toBe('500: Internal Server Error')
  })

  it('tells the analyst the verdict and the first three errors', () => {
    const err = new BundleRefusedError(409, ['bad id', 'bad ref', 'bad type', 'bad date'])
    expect(err.summary()).toBe(
      'The STIX 2.1 schemas refused this bundle:\n• bad id\n• bad ref\n• bad type\n… and 1 more')
    expect(new BundleRefusedError(409, []).summary()).toBe('The STIX 2.1 schemas refused this bundle:')
  })

  it('reads in errorDetail, as an error and as a raw body', () => {
    expect(errorDetail(new BundleRefusedError(409, ['bad id'])))
      .toBe('the STIX 2.1 schemas refused this bundle — bad id')
    expect(errorDetail(new Error(`409: ${REFUSED}`)))
      .toBe('the STIX 2.1 schemas refused this bundle — bad id')
  })
})

describe('fetchAttackIndex', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('reads the release from X-Attack-Release (ADR-0087)', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({
      ok: true, status: 200, headers: new Headers({ 'X-Attack-Release': '20.0' }),
      json: () => Promise.resolve({ tactics: [], techniques: [{ id: 'T1698', name: 'Indirect Prompt Injection', domain: 'enterprise-attack' }] }),
    })))
    const index = await fetchAttackIndex()
    expect(vi.mocked(fetch)).toHaveBeenCalledWith('/api/attack/index')
    expect(index.release).toBe('20.0')
    expect(index.techniques.map(t => t.id)).toEqual(['T1698'])
  })

  it('throws on an error status, like every other call', async () => {
    answer(404, '{"detail":"ATT&CK 20.0 has no mitre_index.json"}')
    expect((await failure(fetchAttackIndex())).message)
      .toBe('404: {"detail":"ATT&CK 20.0 has no mitre_index.json"}')
  })
})
