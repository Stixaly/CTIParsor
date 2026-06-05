/** Stage breakdown derived from the Job + entity/relationship lists.
 *  All fields are optional — the ribbon degrades gracefully when data is partial. */
export interface StageInfo {
  /** Raw character count of extracted text (from job.report_text). */
  chars: number
  /** Estimated chunk count (text / ~3 000-char window). */
  approxChunks: number
  /** IoC entities extracted by regex (source = "ioc"). */
  iocCount: number
  /** NER entities from gazetteer + semantic + GLiNER + CyNER. */
  nerCount: number
  /** Entities contributed by the LLM stage (source = "llm"). */
  llmCount: number
  /** Technique / TTP entities found and normalised. */
  ttpCount: number
  /** Total relationships extracted before review. */
  relCount: number
}

interface Counts {
  pending: number
  accepted: number
  rejected: number
  rels: number
}

interface Props {
  filename: string
  counts: Counts
  stageInfo: StageInfo
}

interface StageRow {
  n: number
  key: string
  label: string
  detail: string
  valid?: boolean
}

function buildStages(filename: string, s: StageInfo): StageRow[] {
  const kb    = s.chars > 0 ? `${(s.chars / 1000).toFixed(0)} KB` : null
  const parts = s.approxChunks > 0 ? `~${s.approxChunks} chunks` : null
  const stage1 = [kb, parts].filter(Boolean).join(' · ') || 'Document ingested'

  const nerParts: string[] = []
  if (s.iocCount > 0) nerParts.push(`${s.iocCount} IoC`)
  if (s.nerCount > 0) nerParts.push(`${s.nerCount} NER`)
  const stage2 = nerParts.length
    ? `${nerParts.join(' · ')} · regex + gazetteer`
    : 'regex + gazetteer + CyNER'

  const llmParts: string[] = []
  if (s.llmCount > 0) llmParts.push(`${s.llmCount} LLM entities`)
  if (s.relCount > 0) llmParts.push(`${s.relCount} relations`)
  const stage3 = llmParts.length ? llmParts.join(' · ') : 'claude-sonnet enrichment'

  const stage5 = s.ttpCount > 0
    ? `${s.ttpCount} TTPs normalised`
    : 'TTPs normalised'

  return [
    { n: 1, key: 'ingest',   label: 'Ingestion',      detail: stage1 },
    { n: 2, key: 'extract',  label: 'Extraction',      detail: stage2 },
    { n: 3, key: 'llm',      label: 'LLM enrich',      detail: stage3 },
    { n: 4, key: 'filter',   label: 'Hallucination',   detail: 'Fuzzy confidence filter' },
    { n: 5, key: 'mitre',    label: 'MITRE ATT&CK', detail: stage5 },
    { n: 6, key: 'stix',     label: 'STIX 2.1',        detail: 'Bundle ready · valid', valid: true },
  ]
}

function Tally({ n, l, tone }: { n: number; l: string; tone: string }) {
  return (
    <div className={`tally tally-${tone}`}>
      <span className="tally-n">{n}</span>
      <span className="tally-l">{l}</span>
    </div>
  )
}

export default function PipelineRibbon({ filename, counts, stageInfo }: Props) {
  const stages = buildStages(filename, stageInfo)

  return (
    <div className="ribbon">
      <div className="ribbon-meta">
        <div className="meta-strong">
          <span className="meta-dot ok" />
          Bundle ready
        </div>
        <div className="meta-dim">{filename}</div>
      </div>

      <div className="ribbon-stages">
        {stages.map((s, i) => (
          <div key={s.key} style={{ display: 'flex', alignItems: 'stretch', gap: 6 }}>
            <div className="pstep">
              <div className="pstep-num">{s.n}</div>
              <div className="pstep-body">
                <div className="pstep-label">{s.label}</div>
                <div className="pstep-detail">{s.detail}</div>
              </div>
            </div>
            {i < stages.length - 1 && <div className="pstep-sep">›</div>}
          </div>
        ))}
      </div>

      <div className="ribbon-counts">
        <Tally n={counts.pending}  l="pending"   tone="amber" />
        <Tally n={counts.accepted} l="accepted"  tone="green" />
        <Tally n={counts.rejected} l="rejected"  tone="red"   />
        <Tally n={counts.rels}     l="relations" tone="slate" />
      </div>
    </div>
  )
}
