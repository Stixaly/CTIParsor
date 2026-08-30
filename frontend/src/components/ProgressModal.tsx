import { X, Loader2, CheckCircle2, AlertCircle } from 'lucide-react'
import { useSSE } from '../hooks/useSSE'
import { useMemo, useRef } from 'react'
import GraphCanvas, { type GraphCanvasHandle } from './graph/GraphCanvas'
import { buildGraphData } from './graph/buildGraphData'
import type { GraphNode, GraphEdge } from './graph/graphLayout'

const STAGES = [
  { n: 1, label: 'Ingestion' },
  { n: 2, label: 'Extraction' },
  { n: 3, label: 'LLM Enrichment' },
  { n: 4, label: 'STIX Mapping' },
  { n: 5, label: 'Validation' },
]

interface Props {
  jobId: string
  filename: string
  onClose: () => void
}

export default function ProgressModal({ jobId, filename, onClose }: Props) {
  const { events, done, partialGraphEvents } = useSSE(jobId)

  // Accumulate streaming graph
  const { sNodes, sEdges, byId, deg, adj } = useMemo(() => {
    const nodeMap = new Map<string, any>()
    const edgeMap = new Map<string, any>()

    for (const ev of partialGraphEvents || []) {
      const e = ev as any
      for (const n of e.nodes || []) {
        if (!nodeMap.has(n.id)) nodeMap.set(n.id, n)
      }
      for (const l of e.links || []) {
        const key = `${l.source}-${l.type}-${l.target}`
        if (!edgeMap.has(key)) edgeMap.set(key, l)
      }
    }

    const gEntities = Array.from(nodeMap.values()).map(n => ({
      id: n.id,
      job_id: jobId,
      value: n.name,
      entity_type: n.type,
      context: '',
      confidence: 1.0,
      mitre_id: null,
      accepted: true,
      source: 'llm',
    } as any)) // cast to any to bypass exact Entity matching if any strict fields are missing

    const gRelationships = Array.from(edgeMap.values()).map(l => ({
      id: `${l.source}-${l.type}-${l.target}`,
      job_id: jobId,
      source_value: l.source,
      relationship_type: l.type,
      target_value: l.target,
      confidence: 1.0,
      accepted: true,
      evidence_text: null,
    } as any))

    const layoutData = buildGraphData(gEntities, gRelationships)
    return { sNodes: layoutData.nodes, sEdges: layoutData.edges, ...layoutData }
  }, [partialGraphEvents, jobId])

  const graphRef = useRef<GraphCanvasHandle>(null)

  const completedStages = new Set(events.filter(e => e.stage).map(e => e.stage!))
  const latest = events.filter(e => e.stage !== undefined).slice(-1)[0]
  const failed = events.some(e => e.status === 'failed')
  const currentStageN = latest?.stage ?? 0

  // Latest event for a given stage (used for completed detail lines)
  const latestForStage = (n: number) =>
    [...events].reverse().find(e => e.stage === n)

  // All events for stage 3 — we want the latest running totals
  const latestStage3 = latestForStage(3)

  const getStageDetail = (n: number): string => {
    const ev = latestForStage(n)
    if (!ev) return ''

    if (n === 1) {
      return `${ev.chars?.toLocaleString() ?? '?'} chars → ${ev.chunks ?? '?'} chunks`
    }

    if (n === 2) {
      const parts: string[] = [`${ev.entities ?? 0} entities`]
      if (ev.gazetteer)     parts.push(`${ev.gazetteer} gazetteer`)
      if (ev.semantic_ttps) parts.push(`${ev.semantic_ttps} semantic TTPs`)
      if (ev.cyner)         parts.push(`${ev.cyner} CyNER`)
      if (ev.gliner)        parts.push(`${ev.gliner} GLiNER`)
      return parts.join(' · ')
    }

    if (n === 3) {
      const chunkPart = ev.total ? `chunk ${ev.chunk}/${ev.total}` : ''
      const entityParts: string[] = []
      if ((ev.malware ?? 0) > 0)        entityParts.push(`${ev.malware} malware`)
      if ((ev.actors  ?? 0) > 0)        entityParts.push(`${ev.actors} actors`)
      if ((ev.tools   ?? 0) > 0)        entityParts.push(`${ev.tools} tools`)
      if ((ev.relationships ?? 0) > 0)  entityParts.push(`${ev.relationships} rels`)
      return [chunkPart, entityParts.join(' · ')].filter(Boolean).join('  ·  ')
    }

    if (n === 4) return `${ev.objects ?? 0} STIX objects`
    if (n === 5) return ev.valid ? 'Valid ✓' : 'Validation warnings'
    return ''
  }

  // Live sub-detail shown while Stage 3 is active (entity accumulation ticker)
  const stage3Live = (() => {
    if (!latestStage3 || currentStageN !== 3) return null
    const parts: string[] = []
    if ((latestStage3.malware ?? 0) > 0)       parts.push(`${latestStage3.malware} malware`)
    if ((latestStage3.actors  ?? 0) > 0)       parts.push(`${latestStage3.actors} actors`)
    if ((latestStage3.tools   ?? 0) > 0)       parts.push(`${latestStage3.tools} tools`)
    if ((latestStage3.relationships ?? 0) > 0) parts.push(`${latestStage3.relationships} rels`)
    return parts.length ? parts.join(' · ') : null
  })()

  const hasGraph = sNodes.length > 0

  return (
    <div style={{
      position: 'fixed', inset: 0,
      background: 'rgba(0,0,0,0.55)',
      backdropFilter: 'blur(4px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      zIndex: 100,
      padding: '24px',
    }}>
      <div style={{
        background: 'var(--bg-elev)',
        border: '1px solid var(--rule)',
        borderRadius: 16,
        boxShadow: 'var(--shadow-pop)',
        width: '100%',
        maxWidth: hasGraph ? 1000 : 420,
        display: 'flex',
        flexDirection: 'row',
        overflow: 'hidden',
        maxHeight: '90vh',
        transition: 'max-width 0.3s ease',
      }}>
        {/* Left side: Progress */}
        <div style={{
          width: hasGraph ? 420 : '100%',
          padding: '24px 24px 20px',
          display: 'flex',
          flexDirection: 'column',
          flexShrink: 0,
          borderRight: hasGraph ? '1px solid var(--rule)' : 'none',
        }}>
          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 20 }}>
            <div>
              <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--ink)' }}>Processing report</div>
              <div style={{ fontSize: 12, color: 'var(--ink-3)', marginTop: 3, maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {filename}
              </div>
            </div>
            {/* Always visible */}
            {!hasGraph && (
              <button
                onClick={onClose}
                className="back"
                style={{ width: 28, height: 28, flexShrink: 0 }}
                title={done ? 'Close' : 'Dismiss — pipeline continues in background'}
              >
                <X size={15} />
              </button>
            )}
          </div>

          {/* Stage list */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, flex: 1, overflowY: 'auto' }}>
            {STAGES.map(stage => {
              const isComplete = completedStages.has(stage.n) && (done || currentStageN > stage.n)
              const isActive   = !done && currentStageN === stage.n
              const detail = getStageDetail(stage.n)

              return (
                <div key={stage.n} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <div style={{ width: 22, height: 22, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    {isComplete ? (
                      <CheckCircle2 size={18} style={{ color: 'var(--ok)' }} />
                    ) : isActive ? (
                      <Loader2 size={18} className="animate-spin" style={{ color: 'var(--accent)' }} />
                    ) : (
                      <div style={{ width: 14, height: 14, borderRadius: '50%', border: '2px solid var(--rule)' }} />
                    )}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{
                      fontSize: 13,
                      fontWeight: isActive ? 600 : 400,
                      color: isComplete ? 'var(--ink)' : isActive ? 'var(--accent)' : 'var(--ink-4)',
                    }}>
                      Stage {stage.n} — {stage.label}
                    </div>
                    {isComplete && detail && (
                      <div style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 2, fontFamily: "'JetBrains Mono', monospace" }}>
                        {detail}
                      </div>
                    )}
                    {isActive && detail && (
                      <div style={{ fontSize: 11, color: 'var(--accent)', marginTop: 2, fontFamily: "'JetBrains Mono', monospace" }}>
                        {detail}
                      </div>
                    )}
                    {isActive && stage.n === 3 && stage3Live && (
                      <div style={{ fontSize: 10.5, color: 'var(--ink-3)', marginTop: 2, fontFamily: "'JetBrains Mono', monospace" }}>
                        {stage3Live}
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>

          {/* Footer status */}
          <div style={{ marginTop: 18, paddingTop: 14, borderTop: '1px solid var(--rule)' }}>
            {failed ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--no)' }}>
                <AlertCircle size={15} />
                Pipeline failed — check server logs
              </div>
            ) : done ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--ok)' }}>
                <CheckCircle2 size={15} />
                Complete — ready for review
              </div>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--ink-3)' }}>
                <Loader2 size={15} className="animate-spin" />
                Running pipeline…
              </div>
            )}
          </div>
        </div>
        
        {/* Right side: Graph Stream */}
        {hasGraph && (
          <div style={{ flex: 1, position: 'relative', background: 'var(--canvas)', minHeight: 400 }}>
             <button
              onClick={onClose}
              className="back"
              style={{ position: 'absolute', top: 16, right: 16, zIndex: 10, width: 28, height: 28, flexShrink: 0, background: 'var(--bg)', border: '1px solid var(--rule)', borderRadius: '50%' }}
              title={done ? 'Close' : 'Dismiss — pipeline continues in background'}
            >
              <X size={15} />
            </button>
            <div style={{ position: 'absolute', top: 16, left: 16, zIndex: 10, display: 'flex', gap: 8, alignItems: 'center', background: 'var(--bg)', border: '1px solid var(--rule)', padding: '4px 10px', borderRadius: 16, fontSize: 12, fontWeight: 500 }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--accent)', animation: 'pulse 2s infinite' }} />
              Live Extractor
            </div>
            <GraphCanvas
              ref={graphRef}
              nodes={sNodes}
              edges={sEdges}
              byId={byId}
              deg={deg}
              adj={adj}
              layout="force"
              visibleTypes={new Set(['threat_actor', 'malware', 'tool', 'ttp', 'unknown'])}
              selectedId={null}
              hoverId={null}
              showLabels={true}
              onSelect={() => {}}
              onHover={() => {}}
              focusSignal={null}
            />
          </div>
        )}
      </div>
    </div>
  )
}
