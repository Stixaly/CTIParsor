/**
 * Relationship Policy — default link model configuration
 *
 * Lets analysts define the canonical relationships the pipeline writes between
 * STIX objects when mapping a report.  Each rule is a (source type → verb →
 * target type) triple in either "pin" (force exact verb) or "auto" (let the
 * pipeline infer) mode.  A global master switch pauses the whole model.
 *
 * Design reference: design_handoff_relationship_policy/README.md
 */
import {
  useState, useEffect, useRef, useCallback,
  type CSSProperties,
} from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getRelationshipPolicy, putRelationshipPolicy } from '../api/client'
import { UNIVERSAL_VERBS, pairVerbs } from '../stix/relConstraints'

// ── Types ─────────────────────────────────────────────────────────────────────

interface PolicyRule {
  id: string
  src: string
  verb: string
  tgt: string
  mode: 'pin' | 'auto'
  enabled: boolean
}

interface Policy {
  version: number
  global: 'enforce' | 'auto'
  rules: PolicyRule[]
}

// ── STIX object-type metadata ─────────────────────────────────────────────────

const STIX_HUE: Record<string, number> = {
  'threat-actor': 12, 'intrusion-set': 8, 'campaign': 330, 'identity': 235,
  'location': 150, 'malware': 28, 'tool': 150, 'attack-pattern': 40,
  'vulnerability': 95, 'infrastructure': 196, 'indicator': 255,
  'course-of-action': 172, 'domain-name': 290, 'ipv4-addr': 250,
  'ipv6-addr': 255, 'url': 255, 'email-addr': 350, 'email-message': 345,
  'file': 200, 'windows-registry-key': 300, 'user-account': 345,
  'mutex': 295, 'autonomous-system': 230, 'network-traffic': 196,
  'mac-addr': 235,
}

const STIX_LABEL: Record<string, string> = {
  'threat-actor': 'Threat Actor', 'intrusion-set': 'Intrusion Set',
  'campaign': 'Campaign', 'identity': 'Identity', 'location': 'Location',
  'malware': 'Malware', 'tool': 'Tool', 'attack-pattern': 'Attack Pattern',
  'vulnerability': 'Vulnerability', 'infrastructure': 'Infrastructure',
  'indicator': 'Indicator', 'course-of-action': 'Course of Action',
  'domain-name': 'Domain', 'ipv4-addr': 'IPv4', 'ipv6-addr': 'IPv6',
  'url': 'URL', 'email-addr': 'Email', 'email-message': 'Email Message',
  'file': 'File', 'windows-registry-key': 'Registry Key',
  'user-account': 'User Account', 'mutex': 'Mutex',
  'autonomous-system': 'ASN', 'network-traffic': 'Net Traffic',
  'mac-addr': 'MAC',
}

const TYPE_GROUPS = [
  { group: 'Strategic / actor',        types: ['threat-actor', 'intrusion-set', 'campaign', 'identity', 'location'] },
  { group: 'Capability',               types: ['malware', 'tool', 'attack-pattern', 'vulnerability'] },
  { group: 'Infrastructure & detection', types: ['infrastructure', 'indicator', 'course-of-action'] },
  { group: 'Observables (SCO)',         types: ['domain-name', 'ipv4-addr', 'ipv6-addr', 'url', 'email-addr', 'email-message', 'file', 'autonomous-system', 'windows-registry-key', 'user-account', 'mutex', 'mac-addr'] },
]
const ALL_TYPES = TYPE_GROUPS.flatMap(g => g.types)

// ── Verb vocabulary (mirrors VALID_REL_TYPES in stage4_stix_mapping.py) ───────

// Complete verb vocabulary, kept in sync with VALID_REL_TYPES in stage4_stix_mapping.py
const VERB_GROUPS = [
  { group: 'Delivery & execution',   verbs: ['delivers', 'drops', 'downloads', 'exploits'] },
  { group: 'Targeting & attribution', verbs: ['targets', 'attributed-to', 'originates-from', 'authored-by', 'impersonates'] },
  { group: 'Usage',                   verbs: ['uses', 'controls', 'has', 'hosts', 'owns'] },
  { group: 'Infrastructure / C2',    verbs: ['compromises', 'beacons-to', 'communicates-with', 'exfiltrates-to'] },
  { group: 'Detection & analysis',   verbs: ['indicates', 'based-on', 'consists-of', 'characterizes', 'investigates'] },
  // Malware-analysis verbs (§7.6 STIX 2.1) — missing from original prototype
  { group: 'Malware analysis',       verbs: ['analysis-of', 'static-analysis-of', 'dynamic-analysis-of'] },
  { group: 'Mitigation',             verbs: ['mitigates', 'remediates'] },
  { group: 'Location',               verbs: ['located-at'] },
  { group: 'Observable',             verbs: ['resolves-to', 'belongs-to'] },
  { group: 'Malware',                verbs: ['variant-of'] },
  { group: 'Generic',                verbs: ['duplicate-of', 'derived-from', 'related-to'] },
]

const ALL_VERBS = VERB_GROUPS.flatMap(g => g.verbs)

// ── STIX 2.1 Appendix B per-pair constraints ──────────────────────────────────
// The constraint table, UNIVERSAL_VERBS, and pairVerbs() now live in the shared,
// dependency-free module src/stix/relConstraints.ts — imported above.  This page
// previously kept its own copy of the table, which had already drifted from the
// Review components' copy; the shared module makes drift impossible.

/** True if the verb is spec-defined for the pair (or pair is unconstrained). */
function verbIsCompliant(src: string, tgt: string, verb: string): boolean {
  const allowed = pairVerbs(src, tgt)
  return allowed === null || allowed.includes(verb)
}

// ── Default rule set ──────────────────────────────────────────────────────────

let _rId = 0
const R = (src: string, verb: string, tgt: string, mode: 'pin'|'auto' = 'pin', enabled = true): PolicyRule =>
  ({ id: `rule-${++_rId}`, src, verb, tgt, mode, enabled })

const DEFAULT_RULES: PolicyRule[] = [
  R('intrusion-set',  'attributed-to',    'threat-actor'),
  R('campaign',       'attributed-to',    'threat-actor'),
  // STIX 2.1 §7.10: threat-actor → location uses 'located-at', not 'originates-from'
  R('threat-actor',   'located-at',       'location'),
  R('campaign',       'targets',          'identity'),
  R('campaign',       'targets',          'location'),
  R('threat-actor',   'targets',          'identity',    'auto'),
  R('threat-actor',   'uses',             'malware'),
  R('threat-actor',   'uses',             'tool'),
  R('campaign',       'uses',             'attack-pattern'),
  R('malware',        'uses',             'attack-pattern'),
  R('malware',        'exploits',         'vulnerability'),
  R('malware',        'communicates-with', 'domain-name'),
  R('malware',        'communicates-with', 'ipv4-addr'),
  R('malware',        'communicates-with', 'url',         'auto'),
  // email-message→url / url→file: not in Appendix B — use universal verb 'related-to'
  R('email-message',  'related-to',       'url'),
  R('url',            'related-to',       'file'),
  // malware→drops→file IS in spec; file→malware is reversed — use related-to
  R('malware',        'drops',            'file'),
  R('infrastructure', 'consists-of',      'ipv4-addr'),
  R('infrastructure', 'consists-of',      'url'),
  // domain-name→resolves-to→ipv4-addr and ipv4-addr→belongs-to→asn added to STIX_PAIR
  R('domain-name',    'resolves-to',      'ipv4-addr'),
  R('ipv4-addr',      'belongs-to',       'autonomous-system'),
  R('indicator',      'indicates',        'malware'),
  // indicator→domain-name: not in Appendix B — use universal verb
  R('indicator',      'related-to',       'domain-name'),
]

// ── Sample report for live preview ────────────────────────────────────────────

const SAMPLE_OBJECTS: Record<string, { type: string; name: string }> = {
  apt29:      { type: 'threat-actor',    name: 'APT29' },
  blizzard:   { type: 'intrusion-set',   name: 'Midnight Blizzard' },
  orbit:      { type: 'campaign',        name: 'Diplomatic Orbit 2026' },
  ru:         { type: 'location',        name: 'Russian Federation' },
  'mfa-fr':   { type: 'identity',        name: 'Min. of Foreign Affairs (FR)' },
  rootsaw:    { type: 'malware',         name: 'ROOTSAW' },
  wineloader: { type: 'malware',         name: 'WINELOADER' },
  cobalt:     { type: 'tool',            name: 'Cobalt Strike' },
  t1566:      { type: 'attack-pattern',  name: 'Spearphishing Link' },
  cve:        { type: 'vulnerability',   name: 'CVE-2026-21412' },
  c2:         { type: 'infrastructure',  name: 'Primary C2 cluster' },
  dom3:       { type: 'domain-name',     name: 'cdn-graph-sync.com' },
  ip1:        { type: 'ipv4-addr',       name: '185.225.74.19' },
  asn:        { type: 'autonomous-system', name: 'AS200651' },
  hta:        { type: 'file',            name: 'Invitation_2026.hta' },
  ind:        { type: 'indicator',       name: 'WINELOADER C2 beacon' },
  url1:       { type: 'url',             name: '…/inv/2026' },
  email:      { type: 'email-message',   name: 'Subject: EU Summit 2026' },
}

const SAMPLE_LINKS = [
  { s: 'blizzard',   t: 'apt29',      pipeline: 'attributed-to' },
  { s: 'orbit',      t: 'apt29',      pipeline: 'attributed-to' },
  { s: 'apt29',      t: 'ru',         pipeline: 'located-at' },
  { s: 'orbit',      t: 'mfa-fr',     pipeline: 'targets' },
  { s: 'apt29',      t: 'rootsaw',    pipeline: 'uses' },
  { s: 'apt29',      t: 'wineloader', pipeline: 'controls' },
  { s: 'apt29',      t: 'cobalt',     pipeline: 'uses' },
  { s: 'rootsaw',    t: 't1566',      pipeline: 'uses' },
  { s: 'wineloader', t: 'cve',        pipeline: 'related-to' },
  { s: 'wineloader', t: 'dom3',       pipeline: 'communicates-with' },
  { s: 'c2',         t: 'ip1',        pipeline: 'consists-of' },
  { s: 'dom3',       t: 'ip1',        pipeline: 'resolves-to' },
  { s: 'ip1',        t: 'asn',        pipeline: 'belongs-to' },
  { s: 'ind',        t: 'wineloader', pipeline: 'indicates' },
  { s: 'email',      t: 'url1',       pipeline: 'delivers' },
  { s: 'url1',       t: 'hta',        pipeline: 'delivers' },
  { s: 'hta',        t: 'rootsaw',    pipeline: 'drops' },
  { s: 'rootsaw',    t: 'wineloader', pipeline: 'related-to' },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function typeDot(type: string): string {
  const h = STIX_HUE[type] ?? 40
  return `oklch(0.60 0.16 ${h})`
}
const typeLabel = (t: string) => STIX_LABEL[t] ?? t

function resolveLink(
  link: { s: string; t: string; pipeline: string },
  ruleIndex: Record<string, PolicyRule>,
  globalMode: 'enforce' | 'auto',
) {
  const so = SAMPLE_OBJECTS[link.s]
  const to = SAMPLE_OBJECTS[link.t]
  const pipeVerb = link.pipeline
  if (globalMode === 'auto') {
    return { so, to, verb: pipeVerb, kind: 'auto' as const, override: null, reason: 'full-auto' }
  }
  const rule = ruleIndex[`${so.type}>${to.type}`]
  if (rule && rule.enabled && rule.mode === 'pin') {
    return {
      so, to, verb: rule.verb, kind: 'pinned' as const,
      override: rule.verb !== pipeVerb ? pipeVerb : null,
      reason: 'rule',
    }
  }
  return {
    so, to, verb: pipeVerb, kind: 'auto' as const, override: null,
    reason: rule ? (rule.enabled ? 'rule-auto' : 'rule-off') : 'no-rule',
  }
}

// ── Design tokens (CSS variable shorthands) ───────────────────────────────────
const MONO = "'JetBrains Mono', ui-monospace, monospace"
const SERIF = "'Source Serif 4', Georgia, serif"

// ── Sub-components ────────────────────────────────────────────────────────────

function TypeChip({ type }: { type: string }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 6,
      background: 'var(--bg-soft)', border: '1px solid var(--rule-soft)',
      borderRadius: 8, padding: '3px 10px', minWidth: 148,
      fontSize: 12.5, fontWeight: 600, color: 'var(--ink-2)',
    }}>
      <span style={{ width: 9, height: 9, borderRadius: '50%', background: typeDot(type), flexShrink: 0 }} />
      {typeLabel(type)}
    </span>
  )
}

function PillSwitch({ on, onClick, title }: { on: boolean; onClick: () => void; title?: string }) {
  return (
    <button
      onClick={onClick}
      title={title}
      style={{
        position: 'relative', width: 34, height: 20, borderRadius: 20,
        background: on ? 'var(--accent)' : 'var(--rule)',
        border: 'none', cursor: 'pointer', flexShrink: 0,
        transition: 'background .15s',
      }}
    >
      <span style={{
        position: 'absolute', top: 2, left: on ? 16 : 2,
        width: 16, height: 16, borderRadius: '50%',
        background: '#fff', transition: 'left .15s',
        boxShadow: '0 1px 3px rgba(0,0,0,.2)',
      }} />
    </button>
  )
}

function ModeToggle({ mode, onChange }: { mode: 'pin' | 'auto'; onChange: (m: 'pin' | 'auto') => void }) {
  return (
    <div style={{
      display: 'inline-flex', borderRadius: 7, overflow: 'hidden',
      border: '1px solid var(--rule)', background: 'var(--bg-soft)',
      flexShrink: 0,
    }}>
      {(['pin', 'auto'] as const).map(m => (
        <button
          key={m}
          onClick={() => onChange(m)}
          style={{
            padding: '3px 9px', border: 'none', cursor: 'pointer',
            fontSize: 11, fontWeight: 600, fontFamily: MONO,
            background: mode === m
              ? m === 'pin' ? 'var(--accent)' : 'var(--frost)'
              : 'transparent',
            color: mode === m ? '#fff' : 'var(--ink-3)',
            transition: 'background .1s, color .1s',
          }}
        >
          {m === 'pin' ? 'Pin' : 'Auto'}
        </button>
      ))}
    </div>
  )
}

/**
 * Verb selector with STIX 2.1 spec-compliance awareness.
 *
 * When `src` and `tgt` are both known:
 *   • Only shows the spec-defined verbs for that pair (STIX 2.1 Appendix B).
 *   • If the current value is outside the valid set it is highlighted in amber.
 *
 * When only one or neither type is known the full VERB_GROUPS are shown so
 * the analyst can still make a selection before the pair is finalised.
 */
function VerbSelect({
  value, onChange, src, tgt,
}: {
  value: string
  onChange: (v: string) => void
  src?: string
  tgt?: string
}) {
  const specVerbsForPair = src && tgt ? pairVerbs(src, tgt) : null
  // When both types are known but the pair has no Appendix B definition,
  // fall back to the three universal verbs (§5.1.2) — never show "other" verbs.
  const effectiveVerbs: string[] | null = specVerbsForPair ?? (src && tgt ? UNIVERSAL_VERBS : null)
  const compliant = effectiveVerbs ? effectiveVerbs.includes(value) : true

  const borderColor = compliant ? 'var(--rule)' : 'color-mix(in oklab, var(--warn) 40%, var(--rule))'
  const titleText = effectiveVerbs
    ? specVerbsForPair
      ? `Valid STIX 2.1 verbs for ${typeLabel(src ?? '')} → ${typeLabel(tgt ?? '')}`
      : `No Appendix B definition — only universal verbs shown`
    : undefined

  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      onClick={e => e.stopPropagation()}
      style={{
        fontFamily: MONO, fontSize: 11,
        color: compliant ? 'var(--accent)' : 'var(--warn)',
        background: 'var(--bg-elev)',
        border: `1px solid ${borderColor}`,
        borderRadius: 7, padding: '3px 8px', cursor: 'pointer',
      }}
      title={titleText}
    >
      {effectiveVerbs ? (
        // Both types known — only show the effective (spec or universal) verbs.
        // A disabled sentinel keeps the select from going blank when a saved rule
        // carries a verb outside the current valid set.
        <>
          {!effectiveVerbs.includes(value) && (
            <option value={value} disabled>⚠ {value} (non-spec — please change)</option>
          )}
          {effectiveVerbs.map(v => (
            <option key={v} value={v}>{v}</option>
          ))}
        </>
      ) : (
        // Neither type is selected yet — show the full vocabulary for browsing
        VERB_GROUPS.map(g => (
          <optgroup key={g.group} label={g.group}>
            {g.verbs.map(v => <option key={v} value={v}>{v}</option>)}
          </optgroup>
        ))
      )}
    </select>
  )
}

function TypeSelect({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      style={{
        fontSize: 11, color: value ? 'var(--ink)' : 'var(--ink-4)',
        background: 'var(--bg-soft)', border: '1px solid var(--rule)',
        borderRadius: 7, padding: '4px 8px', cursor: 'pointer',
        minWidth: 140,
      }}
    >
      <option value="">{placeholder ?? 'Select type…'}</option>
      {TYPE_GROUPS.map(g => (
        <optgroup key={g.group} label={g.group}>
          {g.types.map(t => <option key={t} value={t}>{typeLabel(t)}</option>)}
        </optgroup>
      ))}
    </select>
  )
}

// ── Rule row ──────────────────────────────────────────────────────────────────

function RuleRow({ rule, onPatch, onDelete }: {
  rule: PolicyRule
  onPatch: (p: Partial<PolicyRule>) => void
  onDelete: () => void
}) {
  const pinned = rule.mode === 'pin'
  const accentColor = !rule.enabled ? 'var(--ink-4)' : pinned ? 'var(--accent)' : 'var(--frost)'

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 8,
      padding: '10px 12px', borderRadius: 11,
      border: '1px solid var(--rule)',
      background: 'var(--bg-elev)',
      borderLeft: `3px solid ${accentColor}`,
      opacity: rule.enabled ? 1 : 0.5,
      transition: 'opacity .15s',
    }}>
      <PillSwitch on={rule.enabled} onClick={() => onPatch({ enabled: !rule.enabled })}
        title={rule.enabled ? 'Disable rule' : 'Enable rule'} />
      <TypeChip type={rule.src} />

      {/* Middle connector */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 4, flex: 1, minWidth: 0 }}>
        <span style={{ height: 1, flex: 1, background: 'var(--rule)' }} />
        {pinned
          ? <VerbSelect
              value={rule.verb}
              onChange={v => onPatch({ verb: v })}
              src={rule.src}
              tgt={rule.tgt}
            />
          : (
            <span style={{
              fontFamily: MONO, fontSize: 11, color: 'var(--frost)',
              border: '1px dashed var(--frost)', borderRadius: 7,
              padding: '3px 8px', background: 'var(--frost-soft)',
              flexShrink: 0,
            }}>
              pipeline decides
            </span>
          )
        }
        <span style={{ height: 1, flex: 1, background: 'var(--rule)' }} />
        <span style={{ color: 'var(--ink-4)', fontSize: 14 }}>›</span>
      </div>

      <TypeChip type={rule.tgt} />
      {/* STIX 2.1 compliance indicator: warn when verb is not spec-defined for this pair */}
      {pinned && !verbIsCompliant(rule.src, rule.tgt, rule.verb) && (
        <span
          title={`"${rule.verb}" is not a spec-defined verb for ${typeLabel(rule.src)} → ${typeLabel(rule.tgt)} per STIX 2.1 Appendix B. STIX allows user-defined verbs, so this will still be emitted.`}
          style={{
            fontSize: 10, color: 'var(--warn)',
            background: 'color-mix(in oklab, var(--warn) 10%, transparent)',
            border: '1px solid color-mix(in oklab, var(--warn) 30%, transparent)',
            borderRadius: 5, padding: '2px 6px', flexShrink: 0,
            fontFamily: MONO,
          }}
        >
          ⚠ non-spec
        </span>
      )}
      <ModeToggle mode={rule.mode} onChange={m => onPatch({ mode: m })} />
      <button
        onClick={onDelete}
        title="Delete rule"
        style={{
          width: 28, height: 28, border: '1px solid var(--rule)',
          borderRadius: 6, background: 'var(--bg-soft)',
          cursor: 'pointer', color: 'var(--ink-4)', fontSize: 13,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0,
        }}
        onMouseEnter={e => (e.currentTarget.style.color = 'var(--no)')}
        onMouseLeave={e => (e.currentTarget.style.color = 'var(--ink-4)')}
      >
        ✕
      </button>
    </div>
  )
}

// ── Add-rule composer ─────────────────────────────────────────────────────────

/** Pick the best default verb for a pair: first specific verb (skip universals).
 *  Falls back to UNIVERSAL_VERBS when the pair has no Appendix B definition. */
function _bestVerb(s: string, t: string, current: string): string {
  const valid = pairVerbs(s, t) ?? UNIVERSAL_VERBS
  if (valid.includes(current)) return current
  const specific = valid.filter(v => !UNIVERSAL_VERBS.includes(v))
  return specific[0] ?? valid[0] ?? current
}

function AddRuleComposer({ onAdd }: { onAdd: (r: Omit<PolicyRule, 'id'>) => void }) {
  const [open, setOpen] = useState(false)
  const [src, setSrc]   = useState('')
  const [verb, setVerb] = useState('uses')
  const [tgt, setTgt]   = useState('')
  const [mode, setMode] = useState<'pin' | 'auto'>('pin')

  const handleSrc = (s: string) => {
    setSrc(s)
    if (s && tgt) setVerb(v => _bestVerb(s, tgt, v))
  }
  const handleTgt = (t: string) => {
    setTgt(t)
    if (src && t) setVerb(v => _bestVerb(src, t, v))
  }

  const reset = () => { setSrc(''); setTgt(''); setVerb('uses'); setMode('pin'); setOpen(false) }
  const commit = () => {
    if (!src || !tgt) return
    onAdd({ src, verb, tgt, mode, enabled: true })
    reset()
  }

  if (!open) {
    return (
      <div style={{ padding: '8px 4px' }}>
        <button
          onClick={() => setOpen(true)}
          style={{
            width: '100%', padding: '10px', border: '1.5px dashed var(--accent)',
            borderRadius: 11, background: 'transparent', cursor: 'pointer',
            color: 'var(--accent)', fontSize: 13, fontWeight: 600,
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
          }}
        >
          <span style={{ fontSize: 16 }}>+</span> Add relationship rule
        </button>
      </div>
    )
  }

  return (
    <div style={{
      padding: '10px 12px', borderRadius: 11,
      border: '1.5px solid var(--accent)',
      background: 'color-mix(in oklab, var(--accent) 4%, var(--bg-elev))',
      display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap',
    }}>
      <TypeSelect value={src} onChange={handleSrc} placeholder="source type…" />
      {mode === 'pin'
        ? <VerbSelect value={verb} onChange={setVerb} src={src || undefined} tgt={tgt || undefined} />
        : <span style={{ fontFamily: MONO, fontSize: 11, color: 'var(--frost)',
            border: '1px dashed var(--frost)', borderRadius: 7, padding: '3px 8px',
            background: 'var(--frost-soft)' }}>pipeline decides</span>
      }
      <span style={{ color: 'var(--ink-4)' }}>›</span>
      <TypeSelect value={tgt} onChange={handleTgt} placeholder="target type…" />
      <ModeToggle mode={mode} onChange={setMode} />
      <span style={{ flex: 1 }} />
      <button onClick={reset} style={ghostBtn}>Cancel</button>
      <button onClick={commit} disabled={!src || !tgt} style={primaryBtn(!!src && !!tgt)}>
        Add rule
      </button>
    </div>
  )
}

// ── Rules editor (left column) ────────────────────────────────────────────────

function RulesEditor({ rules, setRules, query, paused }: {
  rules: PolicyRule[]
  setRules: (fn: (rs: PolicyRule[]) => PolicyRule[]) => void
  query: string
  paused: boolean
}) {
  const patch  = (id: string, p: Partial<PolicyRule>) =>
    setRules(rs => rs.map(r => r.id === id ? { ...r, ...p } : r))
  const remove = (id: string) =>
    setRules(rs => rs.filter(r => r.id !== id))
  const add    = (r: Omit<PolicyRule, 'id'>) =>
    setRules(rs => [...rs, { ...r, id: 'rule-' + Date.now() }])

  const q = query.trim().toLowerCase()
  const filtered = rules.filter(r =>
    !q ||
    typeLabel(r.src).toLowerCase().includes(q) ||
    typeLabel(r.tgt).toLowerCase().includes(q) ||
    r.verb.toLowerCase().includes(q) ||
    r.src.includes(q) || r.tgt.includes(q)
  )

  // Group by source category
  const groups = TYPE_GROUPS.map(g => ({
    label: g.group,
    color: typeDot(g.types[0]),
    rules: filtered.filter(r => g.types.includes(r.src)),
  })).filter(g => g.rules.length)

  return (
    <div style={{
      flex: 1, overflowY: 'auto', padding: '0 0 20px',
      opacity: paused ? 0.5 : 1,
      pointerEvents: paused ? 'none' : 'auto',
      transition: 'opacity .2s',
    }}>
      {groups.map(g => (
        <div key={g.label} style={{ marginBottom: 20 }}>
          {/* Group header */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '6px 0 8px', position: 'sticky', top: 0,
            background: 'var(--bg-elev)', zIndex: 1,
          }}>
            <span style={{ width: 10, height: 10, borderRadius: 3, background: g.color, flexShrink: 0 }} />
            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--ink-2)' }}>{g.label}</span>
            <span style={{ fontSize: 11, color: 'var(--ink-4)', fontFamily: MONO }}>{g.rules.length}</span>
            <span style={{ flex: 1, height: 1, background: 'var(--rule-soft)' }} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            {g.rules.map(r => (
              <RuleRow key={r.id} rule={r}
                onPatch={p => patch(r.id, p)}
                onDelete={() => remove(r.id)} />
            ))}
          </div>
        </div>
      ))}

      {!groups.length && (
        <div style={{ padding: '60px 0', textAlign: 'center', color: 'var(--ink-4)', fontSize: 13 }}>
          {query ? `No rules match "${query}".` : 'No rules defined yet.'}
        </div>
      )}

      {!q && <AddRuleComposer onAdd={add} />}
    </div>
  )
}

// ── Live preview (right column) ───────────────────────────────────────────────

function PreviewPanel({ rules, globalMode }: { rules: PolicyRule[]; globalMode: 'enforce' | 'auto' }) {
  const ruleIndex: Record<string, PolicyRule> = {}
  rules.forEach(r => { ruleIndex[`${r.src}>${r.tgt}`] = r })

  const resolved = SAMPLE_LINKS.map(l => resolveLink(l, ruleIndex, globalMode))
  const pinnedCount   = resolved.filter(r => r.kind === 'pinned').length
  const autoCount     = resolved.length - pinnedCount
  const overrideCount = resolved.filter(r => r.override).length

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Header */}
      <div style={{ padding: '14px 16px 12px', borderBottom: '1px solid var(--rule)', flexShrink: 0 }}>
        <div style={{ fontFamily: MONO, fontSize: 10, letterSpacing: '.12em', textTransform: 'uppercase',
                      color: 'var(--ink-4)', fontWeight: 600, marginBottom: 4 }}>
          Live preview
        </div>
        <div style={{ fontFamily: SERIF, fontSize: 15, fontWeight: 700, color: 'var(--ink)', marginBottom: 3 }}>
          APT29 spearphishing wave
        </div>
        <div style={{ fontSize: 11, color: 'var(--ink-3)', marginBottom: 8 }}>
          {Object.keys(SAMPLE_OBJECTS).length} objects · {resolved.length} candidate links
        </div>
        {/* Legend */}
        <div style={{ display: 'flex', gap: 12, fontSize: 10.5, color: 'var(--ink-3)' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{ width: 9, height: 9, borderRadius: 2, background: 'var(--accent)', flexShrink: 0 }} />
            Pinned by you
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{ width: 9, height: 9, borderRadius: 2, background: 'var(--frost)', flexShrink: 0 }} />
            Pipeline decides
          </span>
        </div>
      </div>

      {/* Link list */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 12px' }}>
        {resolved.map((r, i) => (
          <div key={i} style={{
            padding: '9px 11px', marginBottom: 6,
            background: 'var(--bg-elev)', border: '1px solid var(--rule-soft)',
            borderRadius: 10,
          }}>
            {/* Main row */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: typeDot(r.so.type) }} />
                <span style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--ink-2)' }}>{r.so.name}</span>
              </span>
              <span style={{
                fontFamily: MONO, fontSize: 10.5, fontWeight: 600, padding: '2px 8px',
                borderRadius: 6, background: r.kind === 'pinned' ? 'var(--accent)' : 'var(--frost)',
                color: '#fff',
              }}>
                {r.verb}
              </span>
              <span style={{ color: 'var(--ink-4)', fontSize: 12 }}>›</span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: typeDot(r.to.type) }} />
                <span style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--ink-2)' }}>{r.to.name}</span>
              </span>
              <span style={{ flex: 1 }} />
              {/* Badges */}
              <span style={{
                fontSize: 10, fontWeight: 600, padding: '2px 7px', borderRadius: 20,
                background: r.kind === 'pinned' ? 'var(--accent-soft)' : 'var(--frost-soft)',
                color: r.kind === 'pinned' ? 'var(--accent)' : 'var(--frost)',
              }}>
                {r.kind === 'pinned' ? 'Pinned' : 'Auto'}
              </span>
              {r.override && (
                <span style={{ fontSize: 10, fontWeight: 600, padding: '2px 7px', borderRadius: 20,
                               background: '#FEF3C7', color: 'var(--warn)' }}>
                  Override
                </span>
              )}
            </div>
            {/* Sub-note */}
            {r.override && (
              <div style={{ fontFamily: MONO, fontSize: 10, color: 'var(--ink-4)', marginTop: 4 }}>
                pinned over pipeline's <s>{r.override}</s> · <b style={{ color: 'var(--ink-3)' }}>your rule wins</b>
              </div>
            )}
            {r.reason === 'rule-off' && (
              <div style={{ fontFamily: MONO, fontSize: 10, color: 'var(--ink-4)', marginTop: 4 }}>
                matching rule disabled · pipeline kept
              </div>
            )}
            {r.reason === 'no-rule' && (
              <div style={{ fontFamily: MONO, fontSize: 10, color: 'var(--ink-4)', marginTop: 4 }}>
                no rule for this pair · pipeline kept
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Footer */}
      <div style={{
        padding: '10px 16px', borderTop: '1px solid var(--rule)',
        background: 'var(--bg-elev)', flexShrink: 0,
        display: 'flex', alignItems: 'center', gap: 8, fontSize: 12,
        color: 'var(--ink-3)',
      }}>
        <span style={{ color: 'var(--accent)' }}>⚡</span>
        <span>
          <b style={{ color: 'var(--ink-2)' }}>{pinnedCount}</b> pinned&nbsp;&nbsp;·&nbsp;&nbsp;
          <b style={{ color: 'var(--ink-2)' }}>{autoCount}</b> auto&nbsp;&nbsp;·&nbsp;&nbsp;
          <b style={{ color: 'var(--ink-2)' }}>{overrideCount}</b> override{overrideCount !== 1 ? 's' : ''}
        </span>
      </div>
    </div>
  )
}

// ── Import/Export modal ───────────────────────────────────────────────────────

function IOModal({ rules, globalMode, onClose, onImport }: {
  rules: PolicyRule[]
  globalMode: 'enforce' | 'auto'
  onClose: () => void
  onImport: (rules: PolicyRule[], gm: 'enforce' | 'auto') => void
}) {
  const [tab, setTab]   = useState<'export' | 'import'>('export')
  const [draft, setDraft] = useState('')
  const [msg, setMsg]   = useState<{ ok: boolean; t: string } | null>(null)

  const exportText = JSON.stringify(
    { version: 1, global: globalMode,
      rules: rules.map(({ src, verb, tgt, mode, enabled }) => ({ src, verb, tgt, mode, enabled })) },
    null, 2,
  )

  const copy = () => {
    navigator.clipboard?.writeText(exportText)
    setMsg({ ok: true, t: 'Copied to clipboard' })
    setTimeout(() => setMsg(null), 1800)
  }
  const download = () => {
    const blob = new Blob([exportText], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url; a.download = 'relationship-policy.json'; a.click()
    URL.revokeObjectURL(url)
  }
  const apply = () => {
    try {
      const o = JSON.parse(draft)
      if (!Array.isArray(o.rules)) throw new Error('missing rules[]')
      const clean: PolicyRule[] = o.rules.map((r: any, i: number) => ({
        id: 'rule-imp-' + i + '-' + Date.now(),
        src: r.src, verb: r.verb || 'related-to', tgt: r.tgt,
        mode: r.mode === 'auto' ? 'auto' : 'pin',
        enabled: r.enabled !== false,
      })).filter((r: PolicyRule) => r.src && r.tgt)
      if (!clean.length) throw new Error('no valid rules')
      onImport(clean, o.global === 'auto' ? 'auto' : 'enforce')
      setMsg({ ok: true, t: `Imported ${clean.length} rules` })
      setTimeout(onClose, 700)
    } catch (e: any) {
      setMsg({ ok: false, t: 'Invalid JSON — ' + e.message })
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,.4)', backdropFilter: 'blur(4px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{
        width: 560, background: 'var(--bg-elev)',
        border: '1px solid var(--rule)', borderRadius: 16,
        boxShadow: '0 12px 32px -8px rgba(31,19,10,.18)',
        overflow: 'hidden',
      }}>
        {/* Head */}
        <div style={{ padding: '16px 18px', borderBottom: '1px solid var(--rule)',
                      display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontFamily: SERIF, fontSize: 16, fontWeight: 700, color: 'var(--ink)' }}>
              Policy as JSON
            </div>
            <div style={{ fontSize: 12, color: 'var(--ink-3)', marginTop: 2 }}>
              Portable data model — version, global mode &amp; every rule.
            </div>
          </div>
          <button onClick={onClose} style={{ ...ghostBtn, padding: '4px 8px', fontSize: 16 }}>✕</button>
        </div>

        {/* Tabs */}
        <div style={{ display: 'flex', borderBottom: '1px solid var(--rule)' }}>
          {(['export', 'import'] as const).map(t => (
            <button key={t} onClick={() => { setTab(t); setMsg(null) }}
              style={{
                flex: 1, padding: '10px', border: 'none', cursor: 'pointer',
                background: tab === t ? 'var(--bg-soft)' : 'transparent',
                color: tab === t ? 'var(--accent)' : 'var(--ink-3)',
                fontWeight: 600, fontSize: 12.5, textTransform: 'capitalize',
                borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent',
              }}>
              {t}
            </button>
          ))}
        </div>

        {/* Textarea */}
        <div style={{ padding: '14px 18px' }}>
          <textarea
            readOnly={tab === 'export'}
            value={tab === 'export' ? exportText : draft}
            onChange={e => setDraft(e.target.value)}
            onFocus={e => tab === 'export' && e.target.select()}
            placeholder={tab === 'import' ? 'Paste a policy JSON export here…' : undefined}
            rows={12}
            style={{
              width: '100%', fontFamily: MONO, fontSize: 11.5,
              background: 'var(--bg-soft)', border: '1px solid var(--rule)',
              borderRadius: 8, padding: 10, resize: 'vertical',
              color: 'var(--ink)', boxSizing: 'border-box',
            }}
          />
        </div>

        {/* Footer */}
        <div style={{
          padding: '10px 18px 16px', display: 'flex', alignItems: 'center',
          gap: 8, justifyContent: 'flex-end',
        }}>
          {msg && (
            <span style={{ flex: 1, fontSize: 12,
              color: msg.ok ? 'var(--ok)' : 'var(--no)' }}>{msg.t}</span>
          )}
          {tab === 'export' ? (
            <>
              <button onClick={download} style={ghostBtn}>⬇ Download</button>
              <button onClick={copy} style={primaryBtn(true)}>Copy</button>
            </>
          ) : (
            <>
              <button onClick={onClose} style={ghostBtn}>Cancel</button>
              <button onClick={apply} disabled={!draft.trim()} style={primaryBtn(!!draft.trim())}>
                Apply policy
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Shared button styles ──────────────────────────────────────────────────────

const ghostBtn: CSSProperties = {
  padding: '6px 12px', border: '1px solid var(--rule)',
  borderRadius: 7, background: 'var(--bg-soft)', cursor: 'pointer',
  fontSize: 12, fontWeight: 500, color: 'var(--ink-2)',
}
const primaryBtn = (enabled: boolean): CSSProperties => ({
  padding: '6px 14px', border: 'none', borderRadius: 7,
  background: enabled ? 'var(--accent)' : 'var(--rule)',
  cursor: enabled ? 'pointer' : 'not-allowed',
  fontSize: 12, fontWeight: 600, color: enabled ? '#fff' : 'var(--ink-4)',
})

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Policy() {
  const qc = useQueryClient()

  // ── Remote state ────────────────────────────────────────────────────────────
  const { data: remotePolicy } = useQuery({
    queryKey: ['relationship-policy'],
    queryFn: getRelationshipPolicy,
  })

  const saveMut = useMutation({
    mutationFn: putRelationshipPolicy,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['relationship-policy'] }),
  })

  // ── Local state (seeded from server on first load) ──────────────────────────
  const [rules,      setRulesRaw]  = useState<PolicyRule[]>(DEFAULT_RULES)
  const [globalMode, setGlobalMode] = useState<'enforce' | 'auto'>('enforce')
  const [query,      setQuery]     = useState('')
  const [ioOpen,     setIoOpen]    = useState(false)

  const seeded = useRef(false)
  useEffect(() => {
    if (seeded.current || !remotePolicy) return
    const p = remotePolicy as any
    // Seed from server whenever we get a valid response — including an empty
    // rules array.  The old `if (p.rules?.length)` guard meant that an empty
    // saved policy never set seeded.current=true, so this effect would keep
    // re-running on every remotePolicy change and overwrite the user's edits.
    if (Array.isArray(p.rules)) {
      // If the server has no rules yet, fall back to the defaults so the
      // editor isn't presented blank on first visit.
      setRulesRaw(p.rules.length ? p.rules : DEFAULT_RULES)
      setGlobalMode(p.global === 'auto' ? 'auto' : 'enforce')
    }
    seeded.current = true   // always mark done once we have a server response
  }, [remotePolicy])

  // ── Auto-save with 1.5s debounce ────────────────────────────────────────────
  const saveTimer    = useRef<ReturnType<typeof setTimeout> | null>(null)
  // Always-current snapshot of `rules` used inside debounced callbacks.
  // Without this, `changeGlobalMode`'s timeout closes over a stale `rules`
  // value (the rules at the moment the mode was toggled, not 1.5 s later).
  const pendingRulesRef = useRef<PolicyRule[]>(rules)
  useEffect(() => { pendingRulesRef.current = rules }, [rules])

  const setRules = useCallback((fn: (rs: PolicyRule[]) => PolicyRule[]) => {
    // Keep the side-effect (scheduling the save timer) outside the functional
    // updater.  React Strict Mode calls updaters twice in development, which
    // would double-schedule the timer and cause two saves per edit.
    let nextRules: PolicyRule[] = []
    setRulesRaw(prev => {
      nextRules = fn(prev)
      pendingRulesRef.current = nextRules
      return nextRules
    })
    if (saveTimer.current) clearTimeout(saveTimer.current)
    saveTimer.current = setTimeout(() => {
      saveMut.mutate({ version: 1, global: globalMode, rules: pendingRulesRef.current } as any)
    }, 1500)
  }, [globalMode, saveMut])

  const changeGlobalMode = (m: 'enforce' | 'auto') => {
    setGlobalMode(m)
    if (saveTimer.current) clearTimeout(saveTimer.current)
    saveTimer.current = setTimeout(() => {
      // Use the ref so we always save the *latest* rules, not the rules that
      // were in scope when this timeout was scheduled (stale closure bug).
      saveMut.mutate({ version: 1, global: m, rules: pendingRulesRef.current } as any)
    }, 1500)
  }

  useEffect(() => () => { if (saveTimer.current) clearTimeout(saveTimer.current) }, [])

  // ── Derived counts ──────────────────────────────────────────────────────────
  const total    = rules.length
  const pinned   = rules.filter(r => r.mode === 'pin'  && r.enabled).length
  const autoCnt  = rules.filter(r => r.mode === 'auto' && r.enabled).length
  const disabled = rules.filter(r => !r.enabled).length
  const paused   = globalMode === 'auto'

  const resetDefaults = () => {
    const fresh = DEFAULT_RULES.map(r => ({ ...r, id: 'rule-' + Math.random().toString(36).slice(2) }))
    setRulesRaw(fresh)
    setGlobalMode('enforce')
    saveMut.mutate({ version: 1, global: 'enforce', rules: fresh } as any)
  }

  // ── Page ────────────────────────────────────────────────────────────────────
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg)' }}>

      {/* ── Page head ─────────────────────────────────────────────────────── */}
      <div style={{
        background: 'var(--bg-elev)', borderBottom: '1px solid var(--rule)',
        padding: '22px 30px',
        display: 'flex', alignItems: 'flex-start', gap: 24,
      }}>
        {/* Left: title */}
        <div style={{ flex: 1, maxWidth: 520 }}>
          <div style={{ fontFamily: MONO, fontSize: 10, letterSpacing: '.16em', textTransform: 'uppercase',
                        color: 'var(--ink-4)', fontWeight: 600, marginBottom: 6 }}>
            Default link model
          </div>
          <h1 style={{ fontFamily: SERIF, fontSize: 25, fontWeight: 700, color: 'var(--ink)',
                       letterSpacing: '-0.015em', margin: '0 0 8px' }}>
            Relationship policy
          </h1>
          <p style={{ fontSize: 13, color: 'var(--ink-3)', lineHeight: 1.6, margin: 0 }}>
            Define the canonical links the pipeline writes between STIX objects.{' '}
            <b style={{ color: 'var(--ink-2)', fontWeight: 600 }}>Pin</b> the exact relationship
            you want, or set a pair to{' '}
            <b style={{ color: 'var(--ink-2)', fontWeight: 600 }}>Auto</b> and let the pipeline
            infer it from context.
          </p>
        </div>

        {/* Right: master switch card */}
        <div style={{
          width: 340, flexShrink: 0,
          background: 'var(--bg)', border: '1px solid var(--rule)',
          borderRadius: 14, padding: '13px 14px',
          boxShadow: '0 1px 2px rgba(43,30,20,.05), 0 8px 24px -10px rgba(43,30,20,.10)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6,
                        fontFamily: MONO, fontSize: 10, letterSpacing: '.14em',
                        textTransform: 'uppercase', fontWeight: 700, color: 'var(--ink-3)',
                        marginBottom: 10 }}>
            ⚡ Pipeline relationship mode
          </div>

          {/* Segmented control */}
          <div style={{
            display: 'flex', background: 'var(--bg-soft)',
            border: '1px solid var(--rule)', borderRadius: 10, padding: 4, gap: 4,
          }}>
            {([
              { id: 'enforce', label: 'Enforce my model', icon: '🛡' },
              { id: 'auto',    label: 'Full auto',        icon: '🤖' },
            ] as const).map(opt => (
              <button
                key={opt.id}
                onClick={() => changeGlobalMode(opt.id)}
                style={{
                  flex: 1, padding: '8px 6px', border: 'none', borderRadius: 7,
                  cursor: 'pointer', display: 'flex', flexDirection: 'column',
                  alignItems: 'center', gap: 4, transition: 'background .15s',
                  background: globalMode === opt.id ? 'var(--bg-elev)' : 'transparent',
                  boxShadow: globalMode === opt.id
                    ? '0 1px 2px rgba(43,30,20,.06), 0 4px 12px -6px rgba(43,30,20,.10)'
                    : 'none',
                  color: globalMode === opt.id
                    ? opt.id === 'enforce' ? 'var(--accent)' : 'var(--frost)'
                    : 'var(--ink-4)',
                }}
              >
                <span style={{ fontSize: 18 }}>{opt.icon}</span>
                <span style={{ fontSize: 11, fontWeight: 600, textAlign: 'center', lineHeight: 1.3 }}>
                  {opt.label}
                </span>
              </button>
            ))}
          </div>

          {/* Caption */}
          <div style={{ display: 'flex', gap: 6, marginTop: 10,
                        fontSize: 11.5, color: 'var(--ink-3)', lineHeight: 1.5 }}>
            <span style={{ flexShrink: 0, marginTop: 1 }}>ℹ</span>
            <span>
              {globalMode === 'enforce'
                ? <><b>Pinned rules overwrite the pipeline.</b> Pairs on Auto — or with no rule — fall back to pipeline inference.</>
                : <><b>Your data model is paused.</b> The pipeline infers every relationship from report context.</>
              }
            </span>
          </div>
        </div>
      </div>

      {/* ── Stat ribbon ───────────────────────────────────────────────────── */}
      <div style={{
        background: 'var(--bg-elev)', borderBottom: '1px solid var(--rule)',
        padding: '12px 30px', display: 'flex', alignItems: 'center', gap: 0,
      }}>
        {[
          { n: total,    l: 'Rules in model',    color: 'var(--ink)' },
          { n: pinned,   l: 'Pinned links',      color: 'var(--accent)' },
          { n: autoCnt,  l: 'Pipeline-decided',  color: 'var(--frost)' },
          { n: disabled, l: 'Disabled',           color: 'var(--ink-4)' },
        ].map((s, i) => (
          <div key={s.l} style={{
            display: 'flex', flexDirection: 'column', padding: '0 24px',
            borderLeft: i > 0 ? '1px solid var(--rule-soft)' : 'none',
          }}>
            <span style={{ fontFamily: SERIF, fontSize: 24, fontWeight: 700, color: s.color, lineHeight: 1.1 }}>
              {s.n}
            </span>
            <span style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 4 }}>{s.l}</span>
          </div>
        ))}

        <span style={{ flex: 1 }} />

        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={resetDefaults} style={ghostBtn} title="Restore the default data model">
            Reset
          </button>
          <button onClick={() => setIoOpen(true)} style={ghostBtn}>
            ⬆⬇ Import / Export
          </button>
        </div>
      </div>

      {/* ── Body (two-column) ─────────────────────────────────────────────── */}
      <div style={{
        flex: 1, display: 'grid',
        gridTemplateColumns: 'minmax(0, 1.45fr) minmax(360px, 1fr)',
        overflow: 'hidden',
      }}>
        {/* Left: editor */}
        <div style={{
          display: 'flex', flexDirection: 'column',
          borderRight: '1px solid var(--rule)',
          background: 'var(--bg-elev)',
          overflow: 'hidden',
        }}>
          {/* Toolbar */}
          <div style={{
            padding: '10px 16px', borderBottom: '1px solid var(--rule-soft)',
            display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0,
          }}>
            <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--ink-2)' }}>
              Default relationships
            </span>
            {/* Filter search */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'var(--bg-soft)', border: '1px solid var(--rule)',
              borderRadius: 7, padding: '4px 9px', flex: 1, maxWidth: 280,
            }}>
              <span style={{ color: 'var(--ink-4)', fontSize: 13 }}>🔍</span>
              <input
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Filter by type or verb…"
                style={{
                  flex: 1, border: 'none', background: 'transparent',
                  fontSize: 12, color: 'var(--ink)', outline: 'none', fontFamily: 'inherit',
                }}
              />
              {query && (
                <button onClick={() => setQuery('')}
                  style={{ background: 'none', border: 'none', cursor: 'pointer',
                           color: 'var(--ink-4)', fontSize: 13, padding: 0 }}>
                  ×
                </button>
              )}
            </div>
          </div>

          {/* Full-auto paused banner */}
          {paused && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8, padding: '10px 16px',
              background: 'color-mix(in oklab, var(--frost) 8%, var(--bg-elev))',
              borderBottom: '1px solid color-mix(in oklab, var(--frost) 20%, var(--rule))',
              fontSize: 12, color: 'var(--ink-2)', flexShrink: 0,
            }}>
              <span style={{ fontSize: 16 }}>🤖</span>
              <span>
                <b>Full auto is on.</b> Your data model is paused — switch to
                &ldquo;Enforce my model&rdquo; to apply these rules.
              </span>
            </div>
          )}

          {/* Scrollable rule list */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px 0' }}>
            <RulesEditor rules={rules} setRules={setRules} query={query} paused={paused} />
          </div>
        </div>

        {/* Right: preview */}
        <div style={{ background: 'var(--bg-soft)', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <PreviewPanel rules={rules} globalMode={globalMode} />
        </div>
      </div>

      {/* ── Import/Export modal ────────────────────────────────────────────── */}
      {ioOpen && (
        <IOModal
          rules={rules}
          globalMode={globalMode}
          onClose={() => setIoOpen(false)}
          onImport={(rs, gm) => {
            setRulesRaw(rs)
            setGlobalMode(gm)
            saveMut.mutate({ version: 1, global: gm, rules: rs } as any)
          }}
        />
      )}
    </div>
  )
}
