/* ============================================================
   Design tokens and type-color helpers for the Review redesign.
   Covers all STIX 2.1 SDOs, SCOs, and the pipeline's internal
   entity type names (underscore form).
   ============================================================ */

import { pairVerbs } from '../../stix/relConstraints'

export interface TypeStyle {
  hue: number
  label: string
}

// Pipeline-internal names (underscore) AND STIX-canonical names (hyphen).
// Hues are spaced to be visually distinct while grouping related types.
export const TYPE_STYLE: Record<string, TypeStyle> = {
  // ── Network SCOs ──────────────────────────────────────────────────────────
  ipv4:               { hue: 215, label: 'IPv4' },
  ipv6:               { hue: 215, label: 'IPv6' },
  domain:             { hue: 268, label: 'Domain' },
  url:                { hue: 245, label: 'URL' },
  email:              { hue: 330, label: 'Email' },
  mac_addr:           { hue: 210, label: 'MAC' },
  asn:                { hue: 205, label: 'ASN' },
  network_traffic:    { hue: 196, label: 'Net traffic' },
  // ── File / Hash SCOs ─────────────────────────────────────────────────────
  sha256:             { hue:  40, label: 'SHA-256' },
  md5:                { hue:  40, label: 'MD5' },
  sha1:               { hue:  40, label: 'SHA-1' },
  file:               { hue:  48, label: 'File' },
  // ── System SCOs ──────────────────────────────────────────────────────────
  registry_key:       { hue: 285, label: 'Registry key' },
  mutex:              { hue: 278, label: 'Mutex' },
  user_account:       { hue: 340, label: 'User account' },
  // ── Vulnerability ────────────────────────────────────────────────────────
  cve:                { hue:   8, label: 'CVE' },
  vulnerability:      { hue:   8, label: 'Vulnerability' },
  // ── ATT&CK TTPs ──────────────────────────────────────────────────────────
  technique:          { hue:  30, label: 'Technique' },
  tactic:             { hue:  50, label: 'Tactic' },
  procedure:          { hue:  90, label: 'Procedure' },
  ttp:                { hue:  30, label: 'TTP' },
  // ── Named SDOs ───────────────────────────────────────────────────────────
  malware:            { hue:  18, label: 'Malware' },
  threat_actor:       { hue:   2, label: 'Threat actor' },
  intrusion_set:      { hue:   5, label: 'Intrusion set' },
  tool:               { hue: 145, label: 'Tool' },
  campaign:           { hue: 305, label: 'Campaign' },
  infrastructure:     { hue: 180, label: 'Infrastructure' },
  identity:           { hue: 190, label: 'Identity' },
  location:           { hue: 158, label: 'Location' },
  incident:           { hue: 352, label: 'Incident' },

  // ── STIX canonical aliases (hyphenated) — used by STIX graph view ────────
  'attack-pattern':          { hue:  30, label: 'Attack pattern' },
  'threat-actor':            { hue:   2, label: 'Threat actor' },
  'intrusion-set':           { hue:   5, label: 'Intrusion set' },
  'course-of-action':        { hue: 172, label: 'Course of action' },
  'malware-analysis':        { hue:  22, label: 'Malware analysis' },
  'observed-data':           { hue: 155, label: 'Observed data' },
  'grouping':                { hue: 250, label: 'Grouping' },
  'note':                    { hue: 230, label: 'Note' },
  'opinion':                 { hue: 260, label: 'Opinion' },
  'report':                  { hue:  80, label: 'Report' },
  'sighting':                { hue: 115, label: 'Sighting' },
  // SCOs — canonical
  'domain-name':             { hue: 268, label: 'Domain' },
  'ipv4-addr':               { hue: 215, label: 'IPv4' },
  'ipv6-addr':               { hue: 215, label: 'IPv6' },
  'email-addr':              { hue: 330, label: 'Email' },
  'mac-addr':                { hue: 210, label: 'MAC' },
  'autonomous-system':       { hue: 205, label: 'ASN' },
  'network-traffic':         { hue: 196, label: 'Net traffic' },
  'windows-registry-key':    { hue: 285, label: 'Registry key' },
  'user-account':            { hue: 340, label: 'User account' },
  'x509-certificate':        { hue: 200, label: 'X.509 cert' },
  'software':                { hue: 150, label: 'Software' },
  'directory':               { hue:  60, label: 'Directory' },
  'artifact':                { hue:  70, label: 'Artifact' },
  'email-message':           { hue: 328, label: 'Email message' },
  'process':                 { hue: 192, label: 'Process' },
}

// Groups for the entity-type picker — only pipeline-internal names,
// not STIX canonical aliases (which are only needed by the graph view).
export const TYPE_GROUPS: Array<{ label: string; types: string[] }> = [
  { label: 'Network IoC',   types: ['ipv4', 'ipv6', 'domain', 'url', 'email', 'mac_addr', 'asn', 'network_traffic'] },
  { label: 'File / Hash',   types: ['sha256', 'md5', 'sha1', 'file'] },
  { label: 'Host artifact', types: ['registry_key', 'mutex', 'user_account'] },
  { label: 'Vulnerability', types: ['cve', 'vulnerability'] },
  { label: 'ATT&CK TTP',    types: ['technique', 'tactic', 'procedure', 'ttp'] },
  { label: 'Threat Intel',  types: ['malware', 'threat_actor', 'intrusion_set', 'tool', 'campaign', 'infrastructure', 'identity', 'location', 'incident'] },
]

export const SOURCE_LABEL: Record<string, { label: string; hint: string }> = {
  regex:     { label: 'regex',     hint: 'Deterministic pattern match' },
  gazetteer: { label: 'gazetteer', hint: 'Known-name dictionary' },
  semantic:  { label: 'semantic',  hint: 'Embedding similarity' },
  cyner:     { label: 'CyNER',     hint: 'Specialised CTI NER model' },
  llm:       { label: 'LLM',       hint: 'claude-sonnet-4-6' },
  manual:    { label: 'manual',    hint: 'Added by reviewer' },
  ioc:       { label: 'regex',     hint: 'Deterministic pattern match' },
}

// ── STIX 2.1 Appendix B relationship constraints ─────────────────────────────
// The table + pairVerbs() now live in src/stix/relConstraints.ts (a shared,
// dependency-free module) so the Policy page and these Review components can't
// drift apart.  Re-exported here for existing importers of this module.
export { STIX_REL_CONSTRAINTS } from '../../stix/relConstraints'

/**
 * Return the spec-defined valid verbs for a (src, tgt) STIX type pair,
 * plus the three universal verbs always allowed for any pair.
 * Returns null if no constraints are defined for the pair (any verb is valid).
 */
export function specVerbs(srcType: string, tgtType: string): string[] | null {
  return pairVerbs(srcType, tgtType)
}

// All STIX 2.1 relationship types (Section 4 + Appendix B of the OASIS spec).
export const REL_TYPES = [
  // Most common — shown first in dropdowns
  'uses', 'attributed-to', 'targets', 'indicates', 'mitigates', 'remediates',
  // Delivery / execution
  'delivers', 'drops', 'downloads', 'exploits',
  // Infrastructure / C2
  'compromises', 'hosts', 'owns', 'beacons-to', 'communicates-with', 'exfiltrates-to',
  // Attribution / identity
  'originates-from', 'authored-by', 'impersonates', 'located-at',
  // Analysis / detection — 'indicates' already listed above; not repeated here
  'based-on', 'consists-of',
  'analysis-of', 'static-analysis-of', 'dynamic-analysis-of', 'characterizes',
  'investigates',
  // SDO relations
  'controls', 'has',
  // SCO-specific
  'resolves-to', 'belongs-to',
  // Malware variants
  'variant-of',
  // Generic
  'duplicate-of', 'derived-from', 'related-to',
]

// ── helpers ─────────────────────────────────────────────────────────────────

function isDark(): boolean {
  return typeof document !== 'undefined' &&
    document.documentElement.dataset.theme === 'dark'
}

export function typeColor(type: string, mode: 'underline' | 'block' = 'underline'): Record<string, string> {
  const t = TYPE_STYLE[type]
  if (!t) return {}
  const h = t.hue
  const dark = isDark()
  if (mode === 'block') {
    return dark
      ? { background: `oklch(0.28 0.06 ${h})`, color: `oklch(0.92 0.04 ${h})`, borderBottom: `1px solid oklch(0.55 0.16 ${h})` }
      : { background: `oklch(0.94 0.05 ${h})`, color: `oklch(0.30 0.08 ${h})`, borderBottom: `1px solid oklch(0.65 0.16 ${h})` }
  }
  // underline (default)
  return dark
    ? { borderBottom: `2px solid oklch(0.62 0.18 ${h})`, background: `oklch(0.22 0.04 ${h})`, color: `oklch(0.94 0.03 ${h})` }
    : { borderBottom: `2px solid oklch(0.62 0.18 ${h})`, background: `oklch(0.97 0.025 ${h})`, color: `oklch(0.22 0.10 ${h})` }
}

export function typeDot(type: string): string {
  const t = TYPE_STYLE[type]
  if (!t) return '#999'
  return `oklch(0.58 0.18 ${t.hue})`
}

export function typeSoft(type: string): string {
  const t = TYPE_STYLE[type]
  if (!t) return '#eee'
  return isDark()
    ? `oklch(0.28 0.05 ${t.hue})`
    : `oklch(0.95 0.035 ${t.hue})`
}

export function typeInk(type: string): string {
  const t = TYPE_STYLE[type]
  if (!t) return '#333'
  return isDark()
    ? `oklch(0.88 0.07 ${t.hue})`
    : `oklch(0.32 0.10 ${t.hue})`
}

export function typeLabel(type: string): string {
  return TYPE_STYLE[type]?.label ?? type
}

export function hashHue(str: string): number {
  let h = 0
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) | 0
  return Math.abs(h) % 360
}

/** confidence 0-1 or 0-100 → display percentage string */
export function confPct(c: number): number {
  return c > 1 ? Math.round(c) : Math.round(c * 100)
}

// ── Detection coverage (ADR-0006) — readiness scale, NOT lab validation ───────
export const COVERAGE_LABEL: Record<number, string> = {
  3: 'Corroborated',     // rules from ≥2 corpora
  2: 'Covered',          // rule from 1 corpus
  1: 'Telemetry only',   // ATT&CK data source, no rule
  0: 'No coverage',
}

/** Coverage score (0-3) → theme-aware cell colors. */
export function coverageColor(score: number): { background: string; color: string; border: string } {
  const dark = isDark()
  const hue = ({ 3: 150, 2: 130, 1: 75, 0: 250 } as Record<number, number>)[score] ?? 250
  const chroma = score === 0 ? 0.02 : 0.14
  return dark
    ? {
        background: `oklch(0.30 ${chroma} ${hue})`,
        color: `oklch(0.92 0.05 ${hue})`,
        border: `oklch(0.55 ${chroma} ${hue})`,
      }
    : {
        background: `oklch(0.93 ${chroma * 0.4} ${hue})`,
        color: `oklch(0.32 ${chroma} ${hue})`,
        border: `oklch(0.65 ${chroma} ${hue})`,
      }
}

/** Suggest a default relationship type given src/tgt entity types.
 *  Based on the STIX 2.1 spec valid relationship table (Appendix B). */
/**
 * Suggest the best default relationship verb for a (srcType, tgtType) pair.
 *
 * Driven by STIX_REL_CONSTRAINTS (Appendix B of STIX 2.1 OS) — replaces the
 * old hardcoded map.  Both hyphenated STIX names ("threat-actor") and
 * underscored pipeline names ("threat_actor") are accepted; they are
 * normalised to hyphenated form before the lookup.
 *
 * Pipeline entity types that don't map directly to STIX SDO names
 * (e.g. "cve" → "vulnerability", "sha256" / "md5" → "file") are aliased.
 */
export function suggestRelType(srcType: string, tgtType: string): string {
  // Normalise underscore → hyphen and apply pipeline→STIX aliases
  const aliases: Record<string, string> = {
    cve: 'vulnerability', ttp: 'attack-pattern', technique: 'attack-pattern',
    tactic: 'attack-pattern', procedure: 'attack-pattern',
    sha256: 'file', sha1: 'file', md5: 'file',
    asn: 'autonomous-system', domain: 'domain-name',
    email: 'email-addr', ipv4: 'ipv4-addr', ipv6: 'ipv6-addr',
    mac_addr: 'mac-addr', registry_key: 'windows-registry-key',
    user_account: 'user-account', network_traffic: 'network-traffic',
    intrusion_set: 'intrusion-set', threat_actor: 'threat-actor',
    attack_pattern: 'attack-pattern', course_of_action: 'course-of-action',
    malware_analysis: 'malware-analysis',
  }
  const norm = (t: string) => {
    const h = t.replace(/_/g, '-')
    return aliases[h] ?? aliases[t] ?? h
  }

  const s = norm(srcType)
  const x = norm(tgtType)
  const verbs = specVerbs(s, x)

  if (verbs) {
    // Return the first specific verb (skip the universal fallbacks)
    const universal = ['related-to', 'duplicate-of', 'derived-from']
    const specific  = verbs.filter(v => !universal.includes(v))
    return specific[0] ?? verbs[0]
  }
  return 'related-to'
}

/**
 * Return the valid STIX 2.1 verbs for a (srcType, tgtType) pair, suitable
 * for populating a grouped <select>.
 *
 * Returns an object with:
 *   valid   — spec-defined verbs for this exact pair (+ universal verbs)
 *   others  — all other STIX verbs not in valid[]
 *   all     — every known STIX verb (for unconstrained pairs)
 *   constrained — true when the pair is in the spec
 *
 * Both underscore and hyphen type names are accepted.
 */
export function verbsForPair(srcType: string, tgtType: string): {
  valid: string[]
  others: string[]
  constrained: boolean
} {
  const aliases: Record<string, string> = {
    cve: 'vulnerability', ttp: 'attack-pattern', technique: 'attack-pattern',
    tactic: 'attack-pattern', procedure: 'attack-pattern',
    sha256: 'file', sha1: 'file', md5: 'file',
    asn: 'autonomous-system', domain: 'domain-name',
    email: 'email-addr', ipv4: 'ipv4-addr', ipv6: 'ipv6-addr',
    mac_addr: 'mac-addr', registry_key: 'windows-registry-key',
    user_account: 'user-account', network_traffic: 'network-traffic',
    intrusion_set: 'intrusion-set', threat_actor: 'threat-actor',
    attack_pattern: 'attack-pattern', course_of_action: 'course-of-action',
    malware_analysis: 'malware-analysis',
  }
  const norm = (t: string) => {
    const h = t.replace(/_/g, '-')
    return aliases[h] ?? aliases[t] ?? h
  }

  const all = REL_TYPES
  const valid = specVerbs(norm(srcType), norm(tgtType))
  if (!valid) return { valid: all, others: [], constrained: false }
  const others = all.filter(v => !valid.includes(v))
  return { valid, others, constrained: true }
}

// Entity types whose values are normalised ("refanged") by Stage 2 before
// storage — the raw source text may still contain a defanged form
// (e.g. "evil[.]com") that won't match the clean value via plain indexOf.
const _DEFANGABLE_TYPES = new Set(['domain', 'url', 'email', 'ipv4', 'ipv6'])

/**
 * Given a clean (refanged) IOC value, generate the defanged forms a CTI
 * report might use instead, so occurrences that survived in their original
 * defanged form in the raw source text can still be highlighted.
 */
export function generateDefangedVariants(value: string): string[] {
  const variants = new Set<string>()
  const dotForms = ['[.]', '(.)', '{.}']

  if (value.includes('.')) {
    for (const d of dotForms) variants.add(value.split('.').join(d))
    // Only the last dot defanged (common form, e.g. "evil.co[.]uk")
    const lastDot = value.lastIndexOf('.')
    if (lastDot !== -1) {
      for (const d of dotForms) {
        variants.add(value.slice(0, lastDot) + d + value.slice(lastDot + 1))
      }
    }
  }

  // URL scheme defanging — applied to the clean value and every dot-variant
  if (/^https?:\/\//i.test(value)) {
    for (const v of [value, ...variants]) {
      variants.add(v.replace(/^http/i, 'hxxp'))
      variants.add(v.replace('://', '[://]'))
      variants.add(v.replace(':', '[:]'))
    }
  }

  // Email "@" defanging — applied to the clean value and every dot-variant
  if (value.includes('@')) {
    const atForms = ['[at]', '(at)', '[@]', '(@)', '{@}']
    for (const v of [value, ...variants]) {
      for (const a of atForms) variants.add(v.replace('@', a))
    }
  }

  variants.delete(value)
  return [...variants]
}

/** Build non-overlapping text ranges for all entity occurrences */
export interface Range {
  start: number
  end: number
  entityId: string
}

const _isAlnum = (c: string): boolean => c >= '0' && c <= '9' || c >= 'a' && c <= 'z'

/**
 * Whole-token boundary check.  A candidate that starts/ends with an
 * alphanumeric character must not be glued to another alphanumeric character in
 * the surrounding text — otherwise "Win" highlights inside "Windows", and the
 * IP "1.2.3.4" highlights inside "11.2.3.40".  Candidates that start/end with a
 * non-alnum char (e.g. a defanged "[.]" form) impose no constraint on that side.
 * `text` is already lower-cased by the caller.
 */
function _wholeToken(text: string, cand: string, idx: number, end: number): boolean {
  if (_isAlnum(cand[0]) && idx > 0 && _isAlnum(text[idx - 1])) return false
  if (_isAlnum(cand[cand.length - 1]) && end < text.length && _isAlnum(text[end])) return false
  return true
}

export function buildRanges(text: string, entities: Array<{ id: string; value: string; entity_type: string; accepted: boolean | null }>): Range[] {
  const lower = text.toLowerCase()
  const used = new Uint8Array(text.length)
  const ranges: Range[] = []
  const sorted = [...entities]
    .filter(e => e.accepted !== false && e.value && e.value.length > 1)
    .sort((a, b) => b.value.length - a.value.length)

  for (const e of sorted) {
    const v = e.value.toLowerCase()
    const candidates = [v]
    if (_DEFANGABLE_TYPES.has(e.entity_type)) {
      candidates.push(...generateDefangedVariants(v))
    }

    for (const cand of candidates) {
      let pos = 0
      while (pos < lower.length) {
        const idx = lower.indexOf(cand, pos)
        if (idx === -1) break
        const end = idx + cand.length
        if (!_wholeToken(lower, cand, idx, end)) { pos = idx + 1; continue }
        let overlap = false
        for (let i = idx; i < end; i++) if (used[i]) { overlap = true; break }
        if (!overlap) {
          ranges.push({ start: idx, end, entityId: e.id })
          used.fill(1, idx, end)
        }
        pos = idx + 1
      }
    }
  }
  return ranges.sort((a, b) => a.start - b.start)
}
