// The files of one drop, told apart by content (ADR-0090): the report, and the
// STIX bundle the analyst wants enriched.  The server refuses a .json as the
// report, so a .json that is not a bundle is no report either: it is ignored.

// A bundle is sniffed from its first and last bytes only, never read whole: its
// "type": "bundle" is near the start, or after a long list of objects at the end.
const HEAD_BYTES = 64 * 1024
const TAIL_BYTES = 4 * 1024
const BUNDLE_TYPE = /"type"\s*:\s*"bundle"/

const isJson = (f: File) => /\.json$/i.test(f.name) || f.type === 'application/json'

/** The encoding a byte order mark names; utf-8 without one. */
function encodingOf(head: Uint8Array): string {
  if (head[0] === 0xff && head[1] === 0xfe) return 'utf-16le'
  if (head[0] === 0xfe && head[1] === 0xff) return 'utf-16be'
  return 'utf-8'
}

async function isStixBundle(f: File): Promise<boolean> {
  const head = new Uint8Array(await f.slice(0, HEAD_BYTES).arrayBuffer())
  const decode = new TextDecoder(encodingOf(head))
  const headText = decode.decode(head)
  if (headText.trimStart()[0] !== '{') return false
  if (BUNDLE_TYPE.test(headText)) return true
  if (f.size <= HEAD_BYTES) return false
  // An even offset keeps the UTF-16 code units whole.
  const tailStart = (f.size - TAIL_BYTES) & ~1
  return BUNDLE_TYPE.test(decode.decode(await f.slice(tailStart).arrayBuffer()))
}

/** A .json of the drop that is not used, and why. */
export interface IgnoredFile {
  file: File
  why: 'not_a_bundle' | 'second_bundle'
}

/** The first bundle is the bundle; the first file that is not JSON is the report.
 *  A .json that is not a bundle, or a bundle after the first, is `ignored` with
 *  why, so the modal can say it was not used. */
export async function splitDrop(files: File[]): Promise<{
  report: File | null; bundle: File | null; ignored: IgnoredFile[]
}> {
  let report: File | null = null
  let bundle: File | null = null
  const ignored: IgnoredFile[] = []
  for (const f of files) {
    if (isJson(f)) {
      if (!await isStixBundle(f)) ignored.push({ file: f, why: 'not_a_bundle' })
      else if (bundle === null) bundle = f
      else ignored.push({ file: f, why: 'second_bundle' })
    } else if (report === null) {
      report = f
    }
  }
  return { report, bundle, ignored }
}
