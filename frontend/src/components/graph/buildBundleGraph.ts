/**
 * Graph data for the bundle view (ADR-0061): the STIX bundle that ships, plus
 * every review row that does not ship as drawn.
 *
 * Nodes are the bundle's objects (the report, author identity, markings and the
 * embedded source document are listed apart as bundle metadata).  Edges are its
 * SROs, each classified by why it exists, plus the objects' own *_ref
 * properties.  Review rows the bundle dropped are added as ghost nodes and
 * edges so the analyst sees them where they would have been; everything Stage 4
 * rewrote, merged or removed is listed in `diff`, and review changes the stored
 * bundle predates in `stale`.
 *
 * Joins between review rows and the ledger go by value, the way Stage 4 itself
 * receives them: relationships by (source, verb, target), entities by
 * (type, value), all case-insensitive.
 */
import type {
  BundleLedger, Entity, LedgerEntity, LedgerRelationship, Relationship,
  StixBundle, StixObject,
} from '../../types'
import type { EdgeKind, GraphEdge, GraphNode } from './graphLayout'
import type { GraphData } from './buildGraphData'
import { edgeKindOf } from './provenance'

export interface BundleNodeInfo {
  /** null for a ghost node (a review entity that is not in the bundle). */
  object: StixObject | null
  origin: string
  originInfo: Record<string, unknown>
  /** Review entities that became, or were merged into, this object. */
  rows: Array<{ entity: Entity; ledger: LedgerEntity }>
  /** Ghost only: ledger reason code, or 'not_in_build' for a row added since. */
  ghostReason?: string
}

export interface BundleEdgeInfo {
  /** null for a ghost edge or an embedded reference. */
  sro: StixObject | null
  origin: string
  /** Review relationships behind this edge (emitted into it, or merged into it). */
  rows: Array<{ rel: Relationship | null; ledger: LedgerRelationship }>
  /** Embedded reference: the property it comes from. */
  property?: string
}

export type DiffKind = 'dropped' | 'changed' | 'merged' | 'removed' | 'stale'

export interface DiffItem {
  kind: DiffKind
  subject: 'relationship' | 'entity' | 'object'
  title: string
  /** Reason code (see provenance.ts); 'added_since_build' / 'removed_since_build' for stale. */
  reason?: string
  nodeId?: string
  edgeId?: string
  ledgerRel?: LedgerRelationship
  ledgerEntity?: LedgerEntity
}

export interface BundleGraphData extends GraphData {
  nodeInfo: Map<string, BundleNodeInfo>
  edgeInfo: Map<string, BundleEdgeInfo>
  kindCounts: Partial<Record<EdgeKind, number>>
  /** Report, author identity, markings, embedded source document. */
  meta: StixObject[]
  diff: DiffItem[]
  hasLedger: boolean
}

const norm = (s: string) => s.trim().toLowerCase()
const relKey = (s: string, v: string, t: string) => `${norm(s)}\u0000${norm(v)}\u0000${norm(t)}`
const entKey = (type: string, value: string) => `${type}\u0000${norm(value)}`

const META_TYPES = new Set(['report', 'marking-definition', 'extension-definition', 'language-content'])
const META_ORIGINS = new Set(['report', 'author_identity', 'marking', 'source_artifact'])
// Reference properties that are bundle bookkeeping, not facts about the object.
const NON_FACT_REFS = new Set(['created_by_ref', 'object_marking_refs', 'object_refs', 'granular_markings'])

const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v : null)

/** A readable label for any STIX object. */
export function stixLabel(o: StixObject): string {
  switch (o.type) {
    case 'file': {
      const h = o.hashes && Object.values(o.hashes)[0]
      return str(o.name) ?? str(h) ?? 'file'
    }
    case 'autonomous-system':
      return typeof o.number === 'number' ? `AS${o.number}` : str(o.name) ?? 'AS'
    case 'windows-registry-key': return str(o.key) ?? 'registry key'
    case 'user-account':         return str(o.user_id) ?? str(o.account_login) ?? 'account'
    case 'indicator':            return str(o.name) ?? str(o.pattern) ?? 'indicator'
    case 'location':             return str(o.name) ?? str(o.country) ?? 'location'
    case 'artifact':             return 'Source document'
  }
  return str(o.name) ?? str(o.value) ?? `${o.type} ${o.id.slice(-6)}`
}

function externalId(o: StixObject): string | null {
  const refs = Array.isArray(o.external_references) ? o.external_references as Array<Record<string, unknown>> : []
  for (const r of refs) {
    if (['mitre-attack', 'capec', 'cve'].includes(String(r.source_name)) && str(r.external_id)) {
      return String(r.external_id)
    }
  }
  return null
}

/** Origin of an SRO when there is no ledger: its own provenance properties. */
function originFromProps(o: StixObject): string {
  const rule = str(o.x_inference_rule)
  if (rule?.startsWith('attack-reference')) return 'completion_reference'
  if (rule?.startsWith('transitive')) return 'completion_transitive'
  if (rule === 'long-distance') return 'completion_long_distance'
  if (str(o.x_policy_rule)) return 'policy_pin'
  return 'unknown'
}

export function buildBundleGraph(
  bundle: StixBundle | null | undefined,
  ledger: BundleLedger | null | undefined,
  rawEntities: Entity[],
  rawRelations: Relationship[],
): BundleGraphData {
  const objects = bundle?.objects ?? []
  const origins = ledger?.objects ?? {}
  const byStixId = new Map(objects.map(o => [o.id, o]))

  // The author identity is every other object's created_by_ref.
  const authorIds = new Set(objects.map(o => o.created_by_ref).filter((x): x is string => typeof x === 'string'))
  const isMeta = (o: StixObject) =>
    META_TYPES.has(o.type) || META_ORIGINS.has(origins[o.id]?.origin ?? '') || authorIds.has(o.id)
    || o.type === 'artifact'

  const meta = objects.filter(o => o.type !== 'relationship' && isMeta(o))

  // ── Nodes: the bundle's objects ──────────────────────────────────────────
  const nodes: GraphNode[] = []
  const nodeInfo = new Map<string, BundleNodeInfo>()
  for (const o of objects) {
    if (o.type === 'relationship' || isMeta(o)) continue
    const info = origins[o.id]
    nodes.push({
      id: o.id, type: o.type, name: stixLabel(o),
      confidence: typeof o.confidence === 'number' ? o.confidence / 100 : 1,
      source: info?.origin ?? 'unknown', mitre_id: externalId(o),
      context: str(o.description) ?? '', accepted: true,
    })
    const originInfo: Record<string, unknown> = { ...(info ?? {}) }
    delete originInfo.origin
    nodeInfo.set(o.id, { object: o, origin: info?.origin ?? 'unknown', originInfo, rows: [] })
  }
  const inBundle = (id: string | undefined): id is string => !!id && nodeInfo.has(id)

  const diff: DiffItem[] = []
  const hasLedger = !!ledger

  // ── Review entities → the object each became, or a ghost ────────────────
  const ledgerEntities = new Map<string, LedgerEntity[]>()
  for (const e of ledger?.entities ?? []) {
    const k = entKey(e.entity_type, e.value)
    ledgerEntities.set(k, [...(ledgerEntities.get(k) ?? []), e])
  }
  // value → node, for placing ghost edges: bundle objects first, then ghosts.
  const valueToNode = new Map<string, string>()
  for (const e of ledger?.entities ?? []) {
    if (inBundle(e.stix_id) && !valueToNode.has(norm(e.value))) valueToNode.set(norm(e.value), e.stix_id)
  }

  const live = rawEntities.filter(e => e.accepted !== false)
  const liveKeys = new Set(live.map(e => entKey(e.entity_type, e.value)))
  const ghostValues = new Map<string, string>()

  if (hasLedger) {
    for (const ent of live) {
      const entries = ledgerEntities.get(entKey(ent.entity_type, ent.value)) ?? []
      const hit = entries.find(x => x.outcome !== 'dropped' && inBundle(x.stix_id))
      if (hit && hit.stix_id) {
        nodeInfo.get(hit.stix_id)!.rows.push({ entity: ent, ledger: hit })
        if (hit.outcome === 'merged' || hit.reason === 'alias_canonical') {
          const into = nodeInfo.get(hit.stix_id)!.object
          diff.push({
            kind: 'merged', subject: 'entity', ledgerEntity: hit, reason: hit.reason,
            title: `${ent.value} → ${into ? stixLabel(into) : hit.stix_id}`, nodeId: hit.stix_id,
          })
        }
        continue
      }
      const dropped = entries.find(x => x.outcome === 'dropped')
      const reason = dropped?.reason ?? (entries.length === 0 ? 'added_since_build' : 'missing_from_bundle')
      const id = `ghost:entity:${ent.id}`
      nodes.push({
        id, type: ent.entity_type, name: ent.value, confidence: ent.confidence,
        source: ent.source, mitre_id: ent.mitre_id, context: ent.context ?? '',
        accepted: ent.accepted, ghost: true,
      })
      nodeInfo.set(id, {
        object: null, origin: 'ghost', originInfo: {},
        rows: dropped ? [{ entity: ent, ledger: dropped }] : [], ghostReason: reason,
      })
      if (!ghostValues.has(norm(ent.value))) ghostValues.set(norm(ent.value), id)
      diff.push({
        kind: entries.length === 0 ? 'stale' : 'dropped', subject: 'entity',
        ledgerEntity: dropped, reason, title: ent.value, nodeId: id,
      })
    }
    // Rejected since the build: the row's object may still ship.
    for (const ent of rawEntities) {
      if (ent.accepted !== false) continue
      const k = entKey(ent.entity_type, ent.value)
      if (liveKeys.has(k)) continue
      const hit = (ledgerEntities.get(k) ?? []).find(x => x.outcome !== 'dropped' && inBundle(x.stix_id))
      if (hit && hit.stix_id && nodeInfo.get(hit.stix_id)!.rows.length === 0) {
        diff.push({ kind: 'stale', subject: 'entity', reason: 'removed_since_build',
                    title: ent.value, nodeId: hit.stix_id, ledgerEntity: hit })
      }
    }
  }
  const nodeForValue = (v: string) => valueToNode.get(norm(v)) ?? ghostValues.get(norm(v))

  // ── Edges: the bundle's SROs ─────────────────────────────────────────────
  const dbRels = new Map<string, Relationship[]>()
  for (const r of rawRelations) {
    const k = relKey(r.source_value, r.relationship_type, r.target_value)
    dbRels.set(k, [...(dbRels.get(k) ?? []), r])
  }
  const liveRel = (l: LedgerRelationship) =>
    (dbRels.get(relKey(l.source_value, l.relationship_type, l.target_value)) ?? [])
      .find(r => r.accepted !== false) ?? null

  const ledgerByStix = new Map<string, LedgerRelationship[]>()
  for (const l of ledger?.relationships ?? []) {
    if (l.stix_id) ledgerByStix.set(l.stix_id, [...(ledgerByStix.get(l.stix_id) ?? []), l])
  }

  const edges: GraphEdge[] = []
  const edgeInfo = new Map<string, BundleEdgeInfo>()
  let unmatchedCount = 0
  for (const o of objects) {
    if (o.type !== 'relationship') continue
    const src = String(o.source_ref ?? ''), tgt = String(o.target_ref ?? '')
    if (!inBundle(src) || !inBundle(tgt)) { unmatchedCount++; continue }
    const origin = origins[o.id]?.origin ?? originFromProps(o)
    const rows = (ledgerByStix.get(o.id) ?? []).map(l => ({ rel: liveRel(l), ledger: l }))
    edges.push({
      id: o.id, source: src, target: tgt, rel: String(o.relationship_type ?? ''),
      confidence: typeof o.confidence === 'number' ? o.confidence / 100 : 1,
      accepted: true,
      evidence: str(o.description) ?? str(o.x_evidence_text) ?? '',
      kind: edgeKindOf(origin),
      changed: rows.some(r => r.ledger.changes.length > 0),
    })
    edgeInfo.set(o.id, { sro: o, origin, rows })
  }

  // ── Edges: objects' own reference properties ─────────────────────────────
  for (const o of objects) {
    if (o.type === 'relationship' || !inBundle(o.id)) continue
    for (const [prop, val] of Object.entries(o)) {
      if (NON_FACT_REFS.has(prop) || !(prop.endsWith('_ref') || prop.endsWith('_refs'))) continue
      const targets = Array.isArray(val) ? val : [val]
      for (const t of targets) {
        if (typeof t !== 'string' || !inBundle(t) || t === o.id) continue
        const id = `ref:${o.id}:${prop}:${t}`
        edges.push({ id, source: o.id, target: t, rel: prop, confidence: 1, accepted: true,
                     evidence: '', kind: 'embedded' })
        edgeInfo.set(id, { sro: null, origin: 'embedded', rows: [], property: prop })
      }
    }
  }

  // ── What Stage 4 did to the relationship rows ────────────────────────────
  const ledgerKeys = new Set<string>()
  for (const l of ledger?.relationships ?? []) {
    const k = relKey(l.source_value, l.relationship_type, l.target_value)
    ledgerKeys.add(k)
    const title = `${l.source_value} ${l.relationship_type} ${l.target_value}`
    const row = liveRel(l)
    if (!row) continue   // rejected or deleted since the build — see stale below
    if (l.outcome === 'dropped') {
      const s = nodeForValue(l.source_value), t = nodeForValue(l.target_value)
      let edgeId: string | undefined
      if (s && t && s !== t) {
        edgeId = `ghost:rel:${row.id}`
        if (!edgeInfo.has(edgeId)) {
          edges.push({ id: edgeId, source: s, target: t, rel: l.relationship_type,
                       confidence: row.confidence, accepted: true, evidence: row.evidence_text ?? '',
                       kind: 'dropped' })
          edgeInfo.set(edgeId, { sro: null, origin: 'dropped', rows: [{ rel: row, ledger: l }] })
        }
      }
      diff.push({ kind: 'dropped', subject: 'relationship', title, reason: l.reason, ledgerRel: l,
                  edgeId, nodeId: edgeId ? undefined : (l.stix_ref ?? s ?? t) })
      continue
    }
    if (l.changes.length > 0 && edgeInfo.has(l.stix_id ?? '')) {
      diff.push({ kind: 'changed', subject: 'relationship', title, ledgerRel: l, edgeId: l.stix_id })
    }
    if (l.outcome === 'merged') {
      diff.push({ kind: 'merged', subject: 'relationship', title, ledgerRel: l,
                  reason: 'merged_into_edge', edgeId: l.stix_id })
    }
  }

  for (const r of ledger?.removed ?? []) {
    diff.push({
      kind: 'removed', subject: r.kind === 'object' ? 'object' : 'relationship',
      title: r.name ?? r.stix_id, reason: r.reason,
      nodeId: r.kind === 'object' && inBundle(r.replaced_by ?? undefined) ? r.replaced_by ?? undefined : undefined,
      edgeId: r.kind === 'relationship' && r.replaced_by && edgeInfo.has(r.replaced_by) ? r.replaced_by : undefined,
    })
  }

  // ── Review relationship changes the stored bundle predates ───────────────
  if (hasLedger) {
    const liveRelKeys = new Set<string>()
    for (const r of rawRelations) {
      if (r.accepted === false) continue
      const k = relKey(r.source_value, r.relationship_type, r.target_value)
      liveRelKeys.add(k)
      if (!ledgerKeys.has(k)) {
        diff.push({ kind: 'stale', subject: 'relationship', reason: 'added_since_build',
                    title: `${r.source_value} ${r.relationship_type} ${r.target_value}`,
                    nodeId: nodeForValue(r.source_value) ?? nodeForValue(r.target_value) })
      }
    }
    const seen = new Set<string>()
    for (const l of ledger?.relationships ?? []) {
      const k = relKey(l.source_value, l.relationship_type, l.target_value)
      if (liveRelKeys.has(k) || seen.has(k)) continue
      seen.add(k)
      diff.push({ kind: 'stale', subject: 'relationship', reason: 'removed_since_build', ledgerRel: l,
                  title: `${l.source_value} ${l.relationship_type} ${l.target_value}`,
                  edgeId: l.outcome !== 'dropped' && l.stix_id && edgeInfo.has(l.stix_id) ? l.stix_id : undefined })
    }
  }

  // ── Degree, adjacency, counts ────────────────────────────────────────────
  // Ghost edges do not size nodes (they are not in the bundle), but they do
  // join the neighbour highlight so hovering a node shows what it lost.
  const deg: Record<string, number> = {}
  const adj: Record<string, Set<string>> = {}
  const byId = new Map(nodes.map(n => [n.id, n]))
  nodes.forEach(n => { deg[n.id] = 0; adj[n.id] = new Set() })
  const kindCounts: Partial<Record<EdgeKind, number>> = {}
  for (const e of edges) {
    const k = e.kind ?? 'unknown'
    kindCounts[k] = (kindCounts[k] ?? 0) + 1
    adj[e.source]?.add(e.target)
    adj[e.target]?.add(e.source)
    if (k === 'dropped') continue
    deg[e.source] = (deg[e.source] ?? 0) + 1
    deg[e.target] = (deg[e.target] ?? 0) + 1
  }
  const typeCounts: Record<string, number> = {}
  nodes.forEach(n => { typeCounts[n.type] = (typeCounts[n.type] || 0) + 1 })

  return { nodes, edges, byId, deg, adj, typeCounts, unmatchedCount,
           nodeInfo, edgeInfo, kindCounts, meta, diff, hasLedger }
}
