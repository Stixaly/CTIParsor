import { fetchBundle } from '../api/client'

/**
 * Build the download filename from the job's source filename: the extension is
 * stripped and `_stix.json` appended. A blank name, or one that is only an
 * extension (e.g. ".pdf"), falls back to "bundle" (#630) so the file never
 * ends up as a hidden `_stix.json`.
 */
export function bundleFilename(originalFilename?: string | null): string {
  const base = (originalFilename ?? '').trim().replace(/\.[^.]+$/, '').trim()
  return `${base || 'bundle'}_stix.json`
}

/**
 * Fetch a job's finalized STIX 2.1 bundle and trigger a browser download as a
 * pretty-printed JSON file named `<report>_stix.json`.
 *
 * Shared by the Review and Graph pages so the download behaviour stays in one
 * place. Throws if the bundle isn't available yet, or a `BundleRefusedError` when
 * the STIX schemas refused it; callers handle the error (e.g. surface an alert).
 *
 * @param jobId            The job whose bundle to download.
 * @param originalFilename The job's source filename; its extension is stripped
 *                         and `_stix.json` appended. Falls back to "bundle".
 */
export async function downloadBundle(
  jobId: string,
  originalFilename?: string | null,
): Promise<void> {
  const bundle = await fetchBundle(jobId)
  const blob   = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' })
  const url    = URL.createObjectURL(blob)
  const a      = document.createElement('a')
  a.href     = url
  a.download = bundleFilename(originalFilename)
  document.body.appendChild(a); a.click()
  document.body.removeChild(a)
  // Defer revocation — revoking synchronously after click() breaks Firefox.
  setTimeout(() => URL.revokeObjectURL(url), 100)
}
