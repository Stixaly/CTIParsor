/**
 * Provenance vocabulary for the graph (ADR-0061): why an edge or object is in
 * the bundle, and what Stage 4 did to a review row on the way.
 *
 * One place for the kind of each ledger origin, its label and stroke, and the
 * plain-language text of every reason code the backend records — the canvas,
 * the legend and the panels all read from here so they cannot disagree.
 */
import type { EdgeKind } from './graphLayout'
import type { LedgerChange, LedgerTime } from '../../types'

/** Ledger `origin` of an SRO → the edge kind it is drawn as. */
export function edgeKindOf(origin: string | undefined): EdgeKind {
  switch (origin) {
    case 'extracted':                return 'extracted'
    case 'ioc_based_on':
    case 'ioc_association':
    case 'embedded_rule_title':
    case 'targeted_location':        return 'mapping'
    case 'policy_pin':               return 'policy'
    case 'completion_reference':     return 'reference'
    case 'completion_transitive':
    case 'completion_long_distance': return 'inferred'
    default:                         return 'unknown'
  }
}

export interface KindStyle {
  label: string
  hint: string
  stroke: string
  dash?: string
}

export const EDGE_KIND_STYLE: Record<EdgeKind, KindStyle> = {
  extracted: { label: 'From the report', stroke: 'var(--ink-3)',
    hint: 'A relationship row — extracted by the LLM or drawn by an analyst — as it ships.' },
  mapping:   { label: 'Stage 4 mapping', stroke: 'var(--rule)',
    hint: 'Built by the STIX mapping from the IoCs and the LLM lists: Indicator based-on its observable, Indicator indicates malware, actor targets country/sector.' },
  policy:    { label: 'Policy rule', stroke: 'var(--accent)', dash: '7 4',
    hint: 'Forced by a pinned rule of the Relationship Policy, not stated by the report.' },
  reference: { label: 'ATT&CK reference', stroke: 'var(--frost)',
    hint: 'Curated by MITRE ATT&CK between two objects both resolved to ATT&CK ids (Stage 4b).' },
  inferred:  { label: 'Inferred', stroke: 'var(--frost)', dash: '2 4',
    hint: 'Composed from two other edges (transitive) or asked of the LLM (long-distance) — Stage 4b/4c.' },
  embedded:  { label: 'Embedded reference', stroke: 'var(--rule)', dash: '1 4',
    hint: 'A reference property of the object itself (e.g. resolves_to_refs), not a relationship.' },
  dropped:   { label: 'Not in the bundle', stroke: 'var(--no)', dash: '4 3',
    hint: 'A review row Stage 4 did not ship. Select it to see why.' },
  unknown:   { label: 'Unclassified', stroke: 'var(--ink-4)',
    hint: 'An edge whose origin the ledger does not record.' },
}

export const EDGE_KIND_ORDER: EdgeKind[] =
  ['extracted', 'mapping', 'policy', 'reference', 'inferred', 'embedded', 'dropped', 'unknown']

/** Why an object exists, for the node panel. */
export const OBJECT_ORIGIN_LABEL: Record<string, string> = {
  entity:            'Review entity',
  ioc_indicator:     'Indicator built from an IoC',
  embedded_rule:     'Detection rule quoted in the report',
  network_traffic_endpoint: 'Destination of a network-traffic observable',
  targeted_country:  'LLM “targeted countries” list',
  targeted_sector:   'LLM “targeted sectors” list',
  course_of_action:  'LLM “course of action” list',
  source_artifact:   'The source document, embedded',
  report:            'Report wrapping the bundle',
  author_identity:   'Author identity (CTIParsor)',
  marking:           'Sharing marking (TLP/PAP)',
}

/** Why an SRO exists, for the edge panel. */
export const EDGE_ORIGIN_LABEL: Record<string, string> = {
  extracted:                'Relationship row (LLM or analyst)',
  ioc_based_on:             'Indicator based-on the observable it was built from',
  ioc_association:          'LLM IoC → malware association',
  embedded_rule_title:      'Rule title names this malware/tool',
  targeted_location:        'Every actor × every targeted country/sector',
  policy_pin:               'Pinned Relationship Policy rule',
  completion_reference:     'ATT&CK curated relationship',
  completion_transitive:    'Transitive inference',
  completion_long_distance: 'Long-distance LLM inference',
  unknown:                  'Unrecorded',
}

const RELATIONSHIP_REASON: Record<string, string> = {
  unresolved_source:            'its source matches no object in the bundle',
  unresolved_target:            'its target matches no object in the bundle',
  unresolved_both:              'neither end matches an object in the bundle',
  self_loop:                    'both ends resolve to the same object (an alias), which would be a self-loop',
  observable_to_attack_pattern: 'an observable is linked to a technique only by “indicates”, through its Indicator — this project drops any other verb for this pair (a precision choice, ADR-0012; STIX itself would allow a custom one)',
  no_indicator:                 'no STIX pattern could be built for the observable, so no Indicator can stand in for it',
  invalid:                      'the STIX library rejected the relationship',
  self_loop_after_alias_merge:  'the alias merge made both ends the same object',
  duplicate_after_alias_merge:  'the alias merge made it a duplicate of another edge',
}

const ENTITY_REASON: Record<string, string> = {
  same_value:        'same value as another row',
  same_observable:   'same observable once normalised (registry hive)',
  same_technique:    'same ATT&CK technique as another row',
  alias_canonical:   'an alias of a MITRE object, named by its canonical name',
  alias_merge:       'merged into an alias by graph completion (Stage 4b)',
  no_iso_country:    'a STIX Location needs an ISO country code, and this name has none',
  not_representable: 'the value cannot be expressed as this STIX type',
  not_in_llm_lists:  'found by NER but not listed by the LLM — the first build maps named objects from the LLM lists only; a rebuild includes it',
  rule_does_not_compile: 'the YARA rule quoted in the report does not compile, so OpenCTI would refuse its Indicator and every edge to it',
  rule_does_not_parse: 'the parser OpenCTI uses for this rule type refuses the quoted rule (often a line the report’s layout cut), so OpenCTI would refuse its Indicator and every edge to it',
  no_traffic_endpoint: 'a STIX network-traffic needs a destination (an IP, or a domain with a protocol), and this value names none',
}

const VERB_REASON: Record<string, string> = {
  not_suggested: 'not a STIX-suggested verb for this pair of types, so it became related-to',
  policy_pin:    'a pinned Relationship Policy rule sets the verb for this pair of types',
  unknown_verb:  'not a STIX 2.1 relationship type',
}

export function relationshipReason(code: string | undefined): string {
  return (code && RELATIONSHIP_REASON[code]) || code || 'no reason recorded'
}

export function entityReason(code: string | undefined): string {
  return (code && ENTITY_REASON[code]) || code || 'no reason recorded'
}

/** Why a date stays out of start_time / stop_time (pipeline/temporal.export_plan). */
const TIME_WITHHELD: Record<string, string> = {
  precision_below_policy: 'its precision is coarser than the export policy allows a native timestamp',
  window_role: 'it places the relationship in a period, it does not start or end it',
  superseded_by_analyst: "the analyst's own date for this bound replaces it",
  status_ambiguous: 'the reading is ambiguous',
  status_unresolved: 'the pipeline could not resolve it',
  status_conflict: 'it contradicts the text or another date',
  conflict: 'another date of this relationship contradicts it',
  evidence_label: 'the claim is only inferred or a gap',
  qualified: 'it is approximate ("around", "early", "before" …)',
  no_offset: 'the time has no time zone',
  equal_bounds: 'start and end are the same instant, and STIX requires stop_time > start_time',
  less_precise: 'a more precise date fills the bound',
}

/** One sentence per date Stage 4 exported or kept out of the native bounds
 *  (ADR-0063 §7-8).  Every date ships in x_temporal_assertions either way. */
export function describeTime(t: LedgerTime): string {
  const what = `${t.role} ${t.value ?? '(no value)'}${t.precision ? ` (${t.precision})` : ''}`
  if (t.outcome === 'exported') return `${what} fills ${t.field}`
  if (t.outcome === 'projected') {
    return `${what} fills ${t.field}, projected on the whole day in UTC — the time and zone are the policy's, not the source's`
  }
  return `${what} kept in x_temporal_assertions only: ${TIME_WITHHELD[t.reason ?? ''] ?? t.reason ?? 'no reason recorded'}`
}

/** One sentence per change Stage 4 made to a row. */
export function describeChange(c: LedgerChange, label: (id: string) => string): string {
  if (c.kind === 'verb') {
    return `“${c.from}” → “${c.to}”: ${VERB_REASON[c.reason ?? ''] ?? c.reason ?? ''}`
  }
  if (c.kind === 'direction') {
    return `Turned around: ${label(c.to)} → ${label(c.from)} (an observable indicates a technique, not the other way round — ADR-0065)`
  }
  return `${c.end === 'source' ? 'Source' : 'Target'} ${label(c.from)} replaced by its Indicator ${label(c.to)} (an observable opposite an SDO goes through its Indicator unless STIX defines the verb on the observable itself — ADR-0041, ADR-0062)`
}
