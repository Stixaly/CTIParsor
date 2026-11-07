import { afterEach, describe, it, expect, vi } from 'vitest'
import {
  BundleRefusedError, bulkUpdateEntities, bulkUpdateRelationships, createEntity, createRelationship, acceptAllPendingEntities,
  deleteEntity, deleteJob, deleteRelationship, detectionsExportUrl, downloadExportSelection, errorDetail, fetchAttackIndex,
  fetchBaselineIntake, fetchBaselineStatus, fetchBundle, fetchBundleLedger, fetchCoverage, fetchCoverageReportRules,
  fetchCoverageRules, fetchDetectionProposals, fetchEntities, fetchJob, fetchRelationships, finalizeJob, finalizeJobQuick,
  inspectBaseline, sourceUrl, updateEntity, updateJobStatus, updateRelationship, uploadFile,
} from './client'
import { enrichmentView, isImported } from '../types'

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

describe('enrichment views (ADR-0090)', () => {
  it('shows the four stored statuses as three views', () => {
    expect(enrichmentView('new')).toBe('new')
    expect(enrichmentView('matched')).toBe('in_stix')
    expect(enrichmentView('baseline_in_text')).toBe('in_stix')
    expect(enrichmentView('baseline_only')).toBe('stix_only')
  })

  it('has no view for a row without a status', () => {
    expect(enrichmentView(null)).toBeNull()
    expect(enrichmentView(undefined)).toBeNull()
  })

  it('marks the rows the analyst bundle supplied', () => {
    expect(isImported('baseline_in_text')).toBe(true)
    expect(isImported('baseline_only')).toBe(true)
    expect(isImported('matched')).toBe(false)
    expect(isImported('new')).toBe(false)
    expect(isImported(null)).toBe(false)
    expect(isImported(undefined)).toBe(false)
  })
})

describe('baseline intake (ADR-0090)', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('reads the baseline status from its own path', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({
      ok: true, status: 200, json: () => Promise.resolve({ enabled: true, max_bytes: 10, max_objects: 5 }),
    })))
    const status = await fetchBaselineStatus()
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe('/api/baselines/status')
    expect(status.enabled).toBe(true)
  })

  it('posts the bundle as multipart, with the report id only when given', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({
      ok: true, status: 200, json: () => Promise.resolve({ sha256: 'abc' }),
    })))
    const file = new File(['{}'], 'bundle.json')
    await inspectBaseline(file, 'report--1')
    const [url, init] = vi.mocked(fetch).mock.calls[0]
    expect(url).toBe('/api/baselines/inspect')
    expect(init?.method).toBe('POST')
    expect((init?.body as FormData).get('file')).toBeInstanceOf(File)
    expect((init?.body as FormData).get('report_id')).toBe('report--1')

    await inspectBaseline(file)
    const [, bare] = vi.mocked(fetch).mock.calls[1]
    expect((bare?.body as FormData).has('report_id')).toBe(false)
  })

  it('gives the server detail as the error text', async () => {
    answer(400, '{"detail":"x"}')
    const err = await failure(inspectBaseline(new File(['{}'], 'bundle.json')))
    expect(errorDetail(err)).toBe('x')
  })
})

describe('uploadFile (ADR-0090)', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('sends the baseline bundle and its report only when given', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({
      ok: true, status: 200, json: () => Promise.resolve({ job_id: 'j1', filename: 'r.txt' }),
    })))
    const report = new File(['report'], 'r.txt')
    await uploadFile(report)
    let body = vi.mocked(fetch).mock.calls[0][1]?.body as FormData
    expect(body.has('baseline_stix')).toBe(false)
    expect(body.has('baseline_report_id')).toBe(false)

    await uploadFile(report, { baselineStix: new File(['{}'], 'b.json'), baselineReportId: 'report--1' })
    body = vi.mocked(fetch).mock.calls[1][1]?.body as FormData
    expect((body.get('baseline_stix') as File).name).toBe('b.json')
    expect(body.get('baseline_report_id')).toBe('report--1')
  })

  it('gives the server detail as the error text', async () => {
    answer(400, '{"detail":"x"}')
    const err = await failure(uploadFile(new File(['report'], 'r.txt')))
    expect(errorDetail(err)).toBe('x')
  })
})

// Every id that is built into a path is one encoded segment (#551): a value
// with a slash, a query mark or a hash must not change the route.
describe('path segments are encoded (#551)', () => {
  afterEach(() => vi.unstubAllGlobals())

  const SLASHED = 'a/b c?d#e'
  const ENC = 'a%2Fb%20c%3Fd%23e'

  function serveOk() {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({
      ok: true, status: 200, json: () => Promise.resolve({}), text: () => Promise.resolve(''),
    })))
  }

  it.each<[string, () => unknown, string]>([
    ['fetchJob', () => fetchJob(SLASHED), `/api/jobs/${ENC}`],
    ['updateJobStatus', () => updateJobStatus(SLASHED, 'x'), `/api/jobs/${ENC}`],
    ['finalizeJob', () => finalizeJob(SLASHED), `/api/jobs/${ENC}/finalize`],
    ['finalizeJobQuick', () => finalizeJobQuick(SLASHED), `/api/jobs/${ENC}/finalize?quick=true`],
    ['deleteJob', () => deleteJob(SLASHED), `/api/jobs/${ENC}`],
    ['fetchBundle', () => fetchBundle(SLASHED), `/api/jobs/${ENC}/bundle`],
    ['fetchBundleLedger', () => fetchBundleLedger(SLASHED), `/api/jobs/${ENC}/bundle/ledger`],
    ['fetchBaselineIntake', () => fetchBaselineIntake(SLASHED), `/api/jobs/${ENC}/baseline/intake`],
    ['fetchEntities', () => fetchEntities(SLASHED), `/api/jobs/${ENC}/entities`],
    ['updateEntity', () => updateEntity(SLASHED, SLASHED, {}), `/api/jobs/${ENC}/entities/${ENC}`],
    ['deleteEntity', () => deleteEntity(SLASHED, SLASHED), `/api/jobs/${ENC}/entities/${ENC}`],
    ['createEntity', () => createEntity(SLASHED, { value: 'v', entity_type: 't' }), `/api/jobs/${ENC}/entities`],
    ['acceptAllPendingEntities', () => acceptAllPendingEntities(SLASHED), `/api/jobs/${ENC}/entities/accept-pending`],
    ['bulkUpdateEntities', () => bulkUpdateEntities(SLASHED, 'malware', 'accept'), `/api/jobs/${ENC}/entities/bulk`],
    ['fetchRelationships', () => fetchRelationships(SLASHED), `/api/jobs/${ENC}/relationships`],
    ['createRelationship', () => createRelationship(SLASHED, { source_value: 'a', relationship_type: 'r', target_value: 'b' }), `/api/jobs/${ENC}/relationships`],
    ['updateRelationship', () => updateRelationship(SLASHED, SLASHED, {}), `/api/jobs/${ENC}/relationships/${ENC}`],
    ['deleteRelationship', () => deleteRelationship(SLASHED, SLASHED), `/api/jobs/${ENC}/relationships/${ENC}`],
    ['bulkUpdateRelationships', () => bulkUpdateRelationships(SLASHED, [], 'accept'), `/api/jobs/${ENC}/relationships/bulk`],
    ['fetchCoverage', () => fetchCoverage(SLASHED), `/api/jobs/${ENC}/coverage`],
    ['fetchCoverageRules', () => fetchCoverageRules(SLASHED, SLASHED), `/api/jobs/${ENC}/coverage/${ENC}/rules`],
    ['fetchCoverageRules, untagged', () => fetchCoverageRules('j1', '(untagged)'), '/api/jobs/j1/coverage/(untagged)/rules'],
    ['fetchCoverageReportRules', () => fetchCoverageReportRules(SLASHED), `/api/jobs/${ENC}/coverage/rules`],
    ['fetchDetectionProposals', () => fetchDetectionProposals(SLASHED), `/api/jobs/${ENC}/detections/proposals?limit=200`],
  ])('%s requests one encoded segment per id', async (_name, call, url) => {
    serveOk()
    await call()
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe(url)
  })

  it('builds the source and the detection export links the same way', () => {
    expect(sourceUrl(SLASHED)).toBe(`/api/jobs/${ENC}/source`)
    expect(detectionsExportUrl(SLASHED)).toBe(`/api/jobs/${ENC}/detections/export`)
  })
})

// A failed export POST carries the `<status>: ` prefix like every other call,
// or errorDetail cuts the JSON body at its first ': ' (#547).
describe('downloadExportSelection errors (#547)', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('reads the FastAPI detail, as every other error does', async () => {
    answer(400, '{"detail":"Too many rules"}')
    const err = await failure(downloadExportSelection('j1', ['r1']))
    expect(err.message).toBe('400: {"detail":"Too many rules"}')
    expect(errorDetail(err)).toBe('Too many rules')
  })
})
