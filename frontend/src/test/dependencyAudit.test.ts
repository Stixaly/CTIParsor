import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as url from 'node:url'

/**
 * Highest version of each package that is known to be vulnerable.
 * An installed copy passes only if its version is strictly greater.
 * Ranges come from the npm advisory database (`npm audit --json`).
 */
const MAX_VULNERABLE_VERSION: Readonly<Record<string, string>> = {
  // GHSA-67mh-4wv8-2f99 - dev server accepts cross-origin requests
  'esbuild': '0.24.2',
  // Path traversal in optimized deps `.map`, `server.fs.deny` bypass,
  // launch-editor NTLMv2 hash disclosure on Windows
  'vite': '6.4.2',
  // Inherits the vite advisories through its own nested copy
  'vite-node': '2.2.0-beta.2',
  // Arbitrary file read and execution while the Vitest UI server listens
  'vitest': '3.2.5',
  '@vitest/mocker': '3.0.0-beta.4',
  // CVE-2025-68470 bypass: open redirect via backslash in <Link>/useNavigate,
  // and arbitrary constructor injection in deserializeErrors() during SSR
  // hydration. The advisory range starts at 6.0.0; no 5.x copy is installed
  // in this tree, so an "at or below" check is an accurate superset.
  'react-router': '7.17.0',
  'react-router-dom': '7.17.0',
}

/** Packages that must be present, so an empty walk cannot pass vacuously. */
const MUST_BE_INSTALLED: readonly string[] = ['vite', 'vitest', 'react-router', 'react-router-dom']

export interface InstalledCopy {
  name: string
  version: string
  /** Path relative to the frontend root, POSIX separators. */
  path: string
}

export function parseVersion(version: string): { release: number[]; prerelease: string[] } {
  if (version === '') {
    return { release: [0], prerelease: [] }
  }

  let v = version
  const plusIdx = v.indexOf('+')
  if (plusIdx !== -1) {
    v = v.slice(0, plusIdx)
  }

  const dashIdx = v.indexOf('-')
  let releasePart = v
  let prereleasePart = ''
  if (dashIdx !== -1) {
    releasePart = v.slice(0, dashIdx)
    prereleasePart = v.slice(dashIdx + 1)
  }

  const release = releasePart.split('.').map(part => {
    const n = Number.parseInt(part, 10)
    return Number.isNaN(n) ? 0 : n
  })

  const prerelease = prereleasePart === '' ? [] : prereleasePart.split('.')

  return { release, prerelease }
}

export function compareVersions(a: string, b: string): number {
  const pa = parseVersion(a)
  const pb = parseVersion(b)

  const maxLen = Math.max(pa.release.length, pb.release.length)
  for (let i = 0; i < maxLen; i++) {
    const ra = i < pa.release.length ? pa.release[i] : 0
    const rb = i < pb.release.length ? pb.release[i] : 0
    if (ra < rb) return -1
    if (ra > rb) return 1
  }

  if (pa.prerelease.length === 0 && pb.prerelease.length === 0) return 0
  if (pa.prerelease.length === 0) return 1
  if (pb.prerelease.length === 0) return -1

  const maxPreLen = Math.max(pa.prerelease.length, pb.prerelease.length)
  for (let i = 0; i < maxPreLen; i++) {
    if (i >= pa.prerelease.length) return -1
    if (i >= pb.prerelease.length) return 1

    const idA = pa.prerelease[i]
    const idB = pb.prerelease[i]

    const isNumA = /^\d+$/.test(idA)
    const isNumB = /^\d+$/.test(idB)

    if (isNumA && isNumB) {
      const nA = parseInt(idA, 10)
      const nB = parseInt(idB, 10)
      if (nA < nB) return -1
      if (nA > nB) return 1
    } else if (isNumA) {
      return -1
    } else if (isNumB) {
      return 1
    } else {
      if (idA < idB) return -1
      if (idA > idB) return 1
    }
  }

  return 0
}

export function findFrontendRoot(): string {
  let dir = path.dirname(url.fileURLToPath(import.meta.url))
  const root = path.parse(dir).root

  while (true) {
    if (fs.existsSync(path.join(dir, 'package.json')) && fs.existsSync(path.join(dir, 'node_modules'))) {
      return dir
    }
    if (dir === root) {
      break
    }
    dir = path.dirname(dir)
  }

  throw new Error('frontend root not found: no ancestor directory has both package.json and node_modules')
}

export function collectInstalledCopies(root: string): InstalledCopy[] {
  const copies: InstalledCopy[] = []
  const MAX_DEPTH = 12

  function walkNodeModules(nmDir: string, depth: number): void {
    if (depth > MAX_DEPTH) return

    let entries: fs.Dirent[]
    try {
      entries = fs.readdirSync(nmDir, { withFileTypes: true })
    } catch {
      return
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue
      if (entry.name.startsWith('.')) continue

      if (entry.name.startsWith('@')) {
        const scopeDir = path.join(nmDir, entry.name)
        let scopeEntries: fs.Dirent[]
        try {
          scopeEntries = fs.readdirSync(scopeDir, { withFileTypes: true })
        } catch {
          continue
        }

        for (const subEntry of scopeEntries) {
          if (!subEntry.isDirectory()) continue
          if (subEntry.name.startsWith('.')) continue

          const pkgName = `${entry.name}/${subEntry.name}`
          const pkgDir = path.join(scopeDir, subEntry.name)
          processPackage(pkgName, pkgDir, root, copies)
          walkPackageNodeModules(pkgDir, depth + 1)
        }
      } else {
        const pkgName = entry.name
        const pkgDir = path.join(nmDir, entry.name)
        processPackage(pkgName, pkgDir, root, copies)
        walkPackageNodeModules(pkgDir, depth + 1)
      }
    }
  }

  function processPackage(name: string, pkgDir: string, rootDir: string, out: InstalledCopy[]): void {
    const pkgJsonPath = path.join(pkgDir, 'package.json')
    if (!fs.existsSync(pkgJsonPath)) return

    let content: string
    try {
      content = fs.readFileSync(pkgJsonPath, 'utf-8')
    } catch {
      return
    }

    let data: unknown
    try {
      data = JSON.parse(content)
    } catch {
      return
    }

    if (typeof data !== 'object' || data === null) return
    const obj = data as Record<string, unknown>
    if (typeof obj.name !== 'string' || typeof obj.version !== 'string') return

    const relPath = path.relative(rootDir, pkgDir).split(path.sep).join('/')
    out.push({ name, version: obj.version, path: relPath })
  }

  function walkPackageNodeModules(pkgDir: string, depth: number): void {
    const nestedNm = path.join(pkgDir, 'node_modules')
    if (fs.existsSync(nestedNm)) {
      walkNodeModules(nestedNm, depth)
    }
  }

  const topNm = path.join(root, 'node_modules')
  if (fs.existsSync(topNm)) {
    walkNodeModules(topNm, 1)
  }

  return copies
}

describe('dependency audit', () => {
  const root = findFrontendRoot()
  const copies = collectInstalledCopies(root)

  it('finds an installed copy of every watched package', () => {
    for (const name of MUST_BE_INSTALLED) {
      expect(copies.some(c => c.name === name), `missing required package: ${name}`).toBe(true)
    }
  })

  it('has no copy of a package at a known-vulnerable version, at any depth', () => {
    const offenders = copies.filter(c => {
      const maxVuln = MAX_VULNERABLE_VERSION[c.name]
      if (maxVuln === undefined) return false
      return compareVersions(c.version, maxVuln) <= 0
    })

    const formatted = offenders.map(c => `${c.name}@${c.version} at ${c.path}`)
    expect(formatted).toEqual([])
  })

  describe('compareVersions', () => {
    it('compareVersions("6.4.3", "6.4.2") is 1', () => {
      expect(compareVersions('6.4.3', '6.4.2')).toBe(1)
    })

    it('compareVersions("6.4.2", "6.4.3") is -1', () => {
      expect(compareVersions('6.4.2', '6.4.3')).toBe(-1)
    })

    it('compareVersions("6.4.2", "6.4.2") is 0', () => {
      expect(compareVersions('6.4.2', '6.4.2')).toBe(0)
    })

    it('compareVersions("1.2", "1.2.0") is 0', () => {
      expect(compareVersions('1.2', '1.2.0')).toBe(0)
    })

    it('compareVersions("2.2.0-beta.2", "2.2.0") is -1', () => {
      expect(compareVersions('2.2.0-beta.2', '2.2.0')).toBe(-1)
    })

    it('compareVersions("2.2.0-beta.2", "2.2.0-beta.10") is -1', () => {
      expect(compareVersions('2.2.0-beta.2', '2.2.0-beta.10')).toBe(-1)
    })

    it('compareVersions("3.0.0-beta.4", "3.0.0-alpha.9") is 1', () => {
      expect(compareVersions('3.0.0-beta.4', '3.0.0-alpha.9')).toBe(1)
    })

    it('compareVersions("7.18.3+build.5", "7.18.3") is 0', () => {
      expect(compareVersions('7.18.3+build.5', '7.18.3')).toBe(0)
    })

    it('compareVersions("10.0.0", "9.0.0") is 1', () => {
      expect(compareVersions('10.0.0', '9.0.0')).toBe(1)
    })
  })
})
